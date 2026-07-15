from datetime import timedelta

import pytest
from django.core.exceptions import ValidationError
from django.urls import reverse
from django.utils import timezone

from cbpam.accounts.models import User
from cbpam.connectors.models import IdentitySource
from cbpam.connectors.services import (
    get_identity_source_configuration,
    set_identity_source_configuration,
    validate_identity_source_configuration,
)
from cbpam.rbac.models import Role, RoleAssignment, UserGroup
from cbpam.rbac.services import user_has_capability


def ldap_configuration(password="directory-password"):
    return {
        "server_uri": "ldaps://directory.example.test:636",
        "bind_dn": "CN=pam,OU=Services,DC=example,DC=test",
        "bind_password": password,
        "base_dn": "DC=example,DC=test",
        "user_filter": "(&(objectClass=user)(sAMAccountName={username}))",
        "group_filter": "(objectClass=group)",
        "username_attribute": "sAMAccountName",
        "email_attribute": "mail",
        "display_name_attribute": "displayName",
        "group_attribute": "memberOf",
        "use_start_tls": False,
        "connect_timeout_seconds": 10,
    }


@pytest.mark.django_db
def test_identity_source_configuration_is_encrypted():
    source = IdentitySource(
        name="Hospital directory",
        slug="hospital-directory",
        kind=IdentitySource.Kind.ACTIVE_DIRECTORY,
    )
    set_identity_source_configuration(source, ldap_configuration())
    source.save()

    assert b"directory-password" not in bytes(source.encrypted_configuration)
    assert get_identity_source_configuration(source)["bind_password"] == "directory-password"


@pytest.mark.django_db
def test_oidc_requires_https_issuer():
    with pytest.raises(ValidationError):
        validate_identity_source_configuration(
            IdentitySource.Kind.OIDC,
            {
                "issuer": "http://identity.example.test",
                "client_id": "pam-olive",
                "client_secret": "secret",
            },
        )


@pytest.mark.django_db
def test_administrator_configures_source_without_secret_disclosure(client):
    administrator = User.objects.create_user(
        username="identity-admin",
        email="identity-admin@example.test",
        password="safe-password",
    )
    UserGroup.objects.get(name="Administrateurs PAM-olive").users.add(administrator)
    client.force_login(administrator)

    response = client.post(
        reverse("console:identity_sources"),
        {
            "name": "Corporate AD",
            "slug": "corporate-ad",
            "kind": IdentitySource.Kind.ACTIVE_DIRECTORY,
            "verify_tls": "on",
            "sync_enabled": "on",
            "sync_interval_minutes": 60,
            "server_uri": "ldaps://ad.example.test:636",
            "bind_dn": "CN=pam,DC=example,DC=test",
            "bind_password": "super-secret-bind",
            "base_dn": "DC=example,DC=test",
            "user_filter": "(objectClass=user)",
            "group_filter": "(objectClass=group)",
        },
        follow=True,
    )

    source = IdentitySource.objects.get(slug="corporate-ad")
    assert response.status_code == 200
    assert b"super-secret-bind" not in response.content
    assert b"super-secret-bind" not in bytes(source.encrypted_configuration)


@pytest.mark.django_db
def test_auditor_cannot_change_identity_source(client):
    auditor = User.objects.create_user(
        username="identity-auditor",
        email="identity-auditor@example.test",
    )
    UserGroup.objects.get(name="Auditeurs PAM-olive").users.add(auditor)
    client.force_login(auditor)

    assert client.get(reverse("console:identity_sources")).status_code == 200
    assert client.post(reverse("console:identity_sources"), {}).status_code == 403


@pytest.mark.django_db
def test_direct_role_assignment_honors_validity_window():
    user = User.objects.create_user(username="temporary-operator", email="temp@example.test")
    active_role = Role.objects.create(
        name="Temporary session supervisor",
        slug="temporary-session-supervisor",
        capabilities=[Role.Capability.SESSIONS_TERMINATE],
    )
    expired_role = Role.objects.create(
        name="Expired target manager",
        slug="expired-target-manager",
        capabilities=[Role.Capability.TARGETS_MANAGE],
    )
    now = timezone.now()
    RoleAssignment.objects.create(
        user=user,
        role=active_role,
        valid_from=now - timedelta(minutes=5),
        valid_until=now + timedelta(minutes=5),
        reason="Incident supervision",
    )
    RoleAssignment.objects.create(
        user=user,
        role=expired_role,
        valid_from=now - timedelta(hours=2),
        valid_until=now - timedelta(hours=1),
        reason="Expired maintenance",
    )

    assert user_has_capability(user, Role.Capability.SESSIONS_TERMINATE)
    assert not user_has_capability(user, Role.Capability.TARGETS_MANAGE)
