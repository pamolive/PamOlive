import pytest
from django.core.exceptions import PermissionDenied
from django.urls import reverse

from pamolive.accounts.models import User
from pamolive.audit.models import AuditEvent
from pamolive.connectors.adapters import DirectoryUser
from pamolive.connectors.models import (
    DirectoryGroupMapping,
    ExternalIdentity,
    IdentitySource,
    OIDCDefaultGroupMembership,
)
from pamolive.connectors.oidc import provision_oidc_identity
from pamolive.connectors.services import set_identity_source_configuration
from pamolive.connectors.sync import synchronize_identity_source
from pamolive.rbac.models import UserGroup


class FakeDirectoryAdapter:
    def __init__(self, users):
        self.users = users

    def fetch_users(self):
        return self.users


def create_ldap_source():
    source = IdentitySource(
        name="Test directory",
        slug="test-directory",
        kind=IdentitySource.Kind.LDAP,
        enabled=True,
    )
    set_identity_source_configuration(
        source,
        {
            "server_uri": "ldaps://ldap.example.test",
            "bind_dn": "cn=pam,dc=example,dc=test",
            "bind_password": "bind-secret",
            "base_dn": "dc=example,dc=test",
            "user_filter": "(objectClass=person)",
        },
    )
    source.save()
    return source


def create_oidc_source():
    source = IdentitySource(
        name="Test OIDC",
        slug="test-oidc",
        kind=IdentitySource.Kind.OIDC,
        enabled=True,
    )
    set_identity_source_configuration(
        source,
        {
            "issuer": "https://identity.example.test",
            "client_id": "pam-olive",
            "client_secret": "oidc-secret",
            "scopes": "openid email profile",
            "username_claim": "preferred_username",
            "email_claim": "email",
            "display_name_claim": "name",
            "groups_claim": "groups",
            "allowed_email_domains": "",
            "allowed_emails": "",
            "default_user_group": "",
        },
    )
    source.save()
    return source


@pytest.mark.django_db
def test_directory_sync_creates_user_and_reconciles_managed_membership():
    source = create_ldap_source()
    group = UserGroup.objects.create(name="Directory operators")
    DirectoryGroupMapping.objects.create(
        source=source,
        external_group="CN=Operators,DC=example,DC=test",
        user_group=group,
    )
    directory_user = DirectoryUser(
        subject="CN=Alice,DC=example,DC=test",
        username="alice",
        email="alice@example.test",
        display_name="Alice",
        groups=("CN=Operators,DC=example,DC=test",),
    )

    first_result = synchronize_identity_source(source, FakeDirectoryAdapter([directory_user]))
    user = User.objects.get(username="alice")
    second_result = synchronize_identity_source(
        source,
        FakeDirectoryAdapter(
            [
                DirectoryUser(
                    subject=directory_user.subject,
                    username="alice",
                    email="alice@example.test",
                    groups=(),
                )
            ]
        ),
    )

    assert first_result["created"] == 1
    assert first_result["memberships_added"] == 1
    assert second_result["updated"] == 1
    assert second_result["memberships_removed"] == 1
    assert not group.users.filter(pk=user.pk).exists()
    assert not user.has_usable_password()
    assert source.last_sync_status == IdentitySource.SyncStatus.SUCCESS
    assert AuditEvent.objects.filter(action="identity_source.sync.completed").count() == 2


@pytest.mark.django_db
def test_directory_sync_preserves_preexisting_manual_membership():
    source = create_ldap_source()
    group = UserGroup.objects.create(name="Manually assigned")
    mapping = DirectoryGroupMapping.objects.create(
        source=source,
        external_group="manual-group",
        user_group=group,
    )
    user = User.objects.create_user(username="bob", email="bob@example.test")
    identity = ExternalIdentity.objects.create(
        source=source,
        user=user,
        subject="uid=bob,dc=example,dc=test",
        username="bob",
    )
    group.users.add(user)

    synchronize_identity_source(
        source,
        FakeDirectoryAdapter(
            [DirectoryUser(subject=identity.subject, username="bob", groups=("manual-group",))]
        ),
    )
    membership = identity.managed_group_memberships.get(mapping=mapping)
    synchronize_identity_source(
        source,
        FakeDirectoryAdapter(
            [DirectoryUser(subject=identity.subject, username="bob", groups=())]
        ),
    )

    assert membership.preserve_membership_on_unlink
    assert group.users.filter(pk=user.pk).exists()


@pytest.mark.django_db
def test_oidc_provisioning_requires_mapped_group_and_revokes_managed_group():
    source = create_oidc_source()
    group = UserGroup.objects.create(name="OIDC users")
    DirectoryGroupMapping.objects.create(
        source=source,
        external_group="pam-users",
        user_group=group,
    )
    claims = {
        "sub": "oidc-subject-1",
        "preferred_username": "charlie",
        "email": "charlie@example.test",
        "email_verified": True,
        "name": "Charlie",
        "groups": ["pam-users"],
    }

    user = provision_oidc_identity(source, claims)
    assert group.users.filter(pk=user.pk).exists()

    with pytest.raises(PermissionDenied):
        provision_oidc_identity(source, {**claims, "groups": []})
    assert not group.users.filter(pk=user.pk).exists()


@pytest.mark.django_db
def test_oidc_provisioning_refuses_disabled_existing_identity():
    source = create_oidc_source()
    group = UserGroup.objects.create(name="OIDC users")
    DirectoryGroupMapping.objects.create(
        source=source,
        external_group="pam-users",
        user_group=group,
    )
    claims = {
        "sub": "oidc-disabled-subject",
        "preferred_username": "disabled-oidc",
        "email": "disabled-oidc@example.test",
        "email_verified": True,
        "name": "Disabled OIDC",
        "groups": ["pam-users"],
    }

    user = provision_oidc_identity(source, claims)
    identity = ExternalIdentity.objects.get(source=source, subject=claims["sub"])
    identity.enabled = False
    identity.save(update_fields=("enabled", "updated_at"))

    with pytest.raises(PermissionDenied):
        provision_oidc_identity(source, {**claims, "name": "Should Not Reactivate"})

    identity.refresh_from_db()
    user.refresh_from_db()
    assert identity.enabled is False
    assert identity.claims["name"] == "Disabled OIDC"
    assert user.is_active is True


@pytest.mark.django_db
def test_oidc_provisioning_can_authorize_verified_email_domain_without_groups():
    source = create_oidc_source()
    group = UserGroup.objects.create(name="Mopacy OIDC users")
    configuration = {
        "issuer": "https://identity.example.test",
        "client_id": "pam-olive",
        "client_secret": "oidc-secret",
        "scopes": "openid email profile",
        "username_claim": "preferred_username",
        "email_claim": "email",
        "display_name_claim": "name",
        "groups_claim": "groups",
        "allowed_email_domains": "mopacy.be",
        "allowed_emails": "",
        "default_user_group": str(group.pk),
    }
    set_identity_source_configuration(source, configuration)
    source.save(update_fields=("encrypted_configuration", "encryption_key_id", "updated_at"))

    user = provision_oidc_identity(
        source,
        {
            "sub": "infomaniak-cyriel",
            "preferred_username": "cyriel.bovy",
            "email": "cyriel.bovy@mopacy.be",
            "email_verified": True,
            "name": "Cyriel Bovy",
        },
    )

    assert user.email == "cyriel.bovy@mopacy.be"
    assert group.users.filter(pk=user.pk).exists()

@pytest.mark.django_db
def test_oidc_default_group_membership_is_reconciled_when_configuration_changes():
    source = create_oidc_source()
    first_group = UserGroup.objects.create(name="First fallback group")
    second_group = UserGroup.objects.create(name="Second fallback group")
    configuration = {
        "issuer": "https://identity.example.test",
        "client_id": "pam-olive",
        "client_secret": "oidc-secret",
        "scopes": "openid email profile",
        "username_claim": "preferred_username",
        "email_claim": "email",
        "display_name_claim": "name",
        "groups_claim": "groups",
        "allowed_email_domains": "mopacy.be",
        "allowed_emails": "",
        "default_user_group": str(first_group.pk),
    }
    set_identity_source_configuration(source, configuration)
    source.save(update_fields=("encrypted_configuration", "encryption_key_id", "updated_at"))
    claims = {
        "sub": "infomaniak-reconciled",
        "preferred_username": "reconciled.user",
        "email": "reconciled.user@mopacy.be",
        "email_verified": True,
        "name": "Reconciled User",
    }

    user = provision_oidc_identity(source, claims)
    assert first_group.users.filter(pk=user.pk).exists()
    assert not second_group.users.filter(pk=user.pk).exists()
    membership = OIDCDefaultGroupMembership.objects.get(identity__user=user)
    assert membership.user_group == first_group

    configuration["default_user_group"] = str(second_group.pk)
    set_identity_source_configuration(source, configuration)
    source.save(update_fields=("encrypted_configuration", "encryption_key_id", "updated_at"))

    provision_oidc_identity(source, claims)

    assert not first_group.users.filter(pk=user.pk).exists()
    assert second_group.users.filter(pk=user.pk).exists()
    membership = OIDCDefaultGroupMembership.objects.get(identity__user=user)
    assert membership.user_group == second_group


@pytest.mark.django_db
def test_oidc_email_domain_fallback_requires_explicit_verified_email():
    source = create_oidc_source()
    group = UserGroup.objects.create(name="Mopacy OIDC users")
    configuration = {
        "issuer": "https://identity.example.test",
        "client_id": "pam-olive",
        "client_secret": "oidc-secret",
        "scopes": "openid email profile",
        "username_claim": "preferred_username",
        "email_claim": "email",
        "display_name_claim": "name",
        "groups_claim": "groups",
        "allowed_email_domains": "mopacy.be",
        "allowed_emails": "",
        "default_user_group": str(group.pk),
    }
    set_identity_source_configuration(source, configuration)
    source.save(update_fields=("encrypted_configuration", "encryption_key_id", "updated_at"))
    claims = {
        "sub": "infomaniak-unverified",
        "preferred_username": "unverified",
        "email": "unverified@mopacy.be",
        "name": "Unverified Email",
    }

    with pytest.raises(PermissionDenied):
        provision_oidc_identity(source, claims)
    with pytest.raises(PermissionDenied):
        provision_oidc_identity(source, {**claims, "email_verified": False})

    assert not User.objects.filter(username="unverified").exists()
    assert not ExternalIdentity.objects.filter(source=source, subject=claims["sub"]).exists()


@pytest.mark.django_db
def test_active_oidc_source_is_offered_on_login_without_secret(client):
    source = create_oidc_source()

    response = client.get(reverse("login"))

    assert response.status_code == 200
    assert source.name.encode() in response.content
    assert b"oidc-secret" not in response.content
