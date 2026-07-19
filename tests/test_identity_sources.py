from datetime import timedelta

import pytest
from django.core.exceptions import ValidationError
from django.urls import reverse
from django.utils import timezone

from pamolive.accounts.models import User
from pamolive.audit.models import AuditEvent
from pamolive.connectors.models import IdentitySource
from pamolive.connectors.services import (
    get_identity_source_configuration,
    set_identity_source_configuration,
    validate_identity_source_configuration,
)
from pamolive.rbac.models import Role, RoleAssignment, UserGroup
from pamolive.rbac.services import user_has_capability


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


def oidc_configuration(secret="oidc-secret", issuer="https://identity.example.test"):
    return {
        "issuer": issuer,
        "client_id": "pam-olive",
        "client_secret": secret,
        "scopes": "openid email profile",
        "username_claim": "preferred_username",
        "email_claim": "email",
        "display_name_claim": "name",
        "groups_claim": "groups",
    }


def create_oidc_source(name="Infomaniak - Mopacy", slug="infomaniak", enabled=False):
    source = IdentitySource(
        name=name,
        slug=slug,
        kind=IdentitySource.Kind.OIDC,
        enabled=enabled,
    )
    set_identity_source_configuration(source, oidc_configuration())
    source.save()
    return source


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
def test_oidc_console_shows_callback_and_login_urls(client):
    administrator = User.objects.create_user(
        username="oidc-admin",
        email="oidc-admin@example.test",
        password="safe-password",
    )
    UserGroup.objects.get(name="Administrateurs PAM-olive").users.add(administrator)
    source = create_oidc_source()
    client.force_login(administrator)

    response = client.get(reverse("console:oidc_source_edit", args=(source.pk,)))

    assert response.status_code == 200
    assert b"/accounts/oidc/infomaniak/callback/" in response.content
    assert b"/accounts/oidc/infomaniak/login/" in response.content
    assert b"Tester la d\xc3\xa9couverte OIDC avant activation" in response.content


@pytest.mark.django_db
def test_disabled_oidc_source_can_be_tested_before_activation(client, monkeypatch):
    administrator = User.objects.create_user(
        username="oidc-test-admin",
        email="oidc-test-admin@example.test",
        password="safe-password",
    )
    UserGroup.objects.get(name="Administrateurs PAM-olive").users.add(administrator)
    source = create_oidc_source(enabled=False)
    client.force_login(administrator)
    requests_seen = []

    class FakeDiscoveryResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "issuer": "https://identity.example.test",
                "authorization_endpoint": "https://identity.example.test/authorize",
                "token_endpoint": "https://identity.example.test/token",
                "jwks_uri": "https://identity.example.test/jwks",
            }

    def fake_get(url, timeout, verify):
        requests_seen.append((url, timeout, verify))
        return FakeDiscoveryResponse()

    monkeypatch.setattr("pamolive.connectors.services.requests.get", fake_get)

    response = client.post(reverse("console:oidc_source_test", args=(source.pk,)), follow=True)

    assert response.status_code == 200
    assert requests_seen == [
        ("https://identity.example.test/.well-known/openid-configuration", 8, True)
    ]
    assert AuditEvent.objects.filter(
        action="console.identitysource.oidc_test_succeeded",
        resource_id=str(source.pk),
    ).exists()


@pytest.mark.django_db
def test_login_page_keeps_local_login_with_multiple_oidc_domains(client):
    create_oidc_source(name="Infomaniak - Mopacy", slug="infomaniak", enabled=True)
    create_oidc_source(name="Google Workspace", slug="google", enabled=True)

    response = client.get(reverse("login"))

    assert response.status_code == 200
    assert b"name=\"username\"" in response.content
    assert b"name=\"password\"" in response.content
    assert b"Infomaniak - Mopacy" in response.content
    assert b"Google Workspace" in response.content
    assert b"/accounts/oidc/infomaniak/login/" in response.content
    assert b"/accounts/oidc/google/login/" in response.content


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
