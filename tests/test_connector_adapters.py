from types import SimpleNamespace

import pytest
from django.http import HttpResponseRedirect
from django.urls import reverse

from pamolive.accounts.models import User
from pamolive.audit.models import AuditEvent
from pamolive.connectors.adapters import (
    DirectoryConnectionError,
    LDAPDirectoryAdapter,
    adapter_for,
)
from pamolive.connectors.models import DirectoryGroupMapping, IdentitySource
from pamolive.connectors.services import set_identity_source_configuration
from pamolive.connectors.sync import synchronize_identity_source
from pamolive.rbac.models import UserGroup


def source_with_configuration(kind=IdentitySource.Kind.LDAP):
    source = IdentitySource(
        name=f"Source {kind}",
        slug=f"source-{kind}",
        kind=kind,
        enabled=True,
        verify_tls=False,
    )
    configuration = (
        {
            "issuer": "https://identity.example.test",
            "client_id": "pam-olive",
            "client_secret": "secret",
            "groups_claim": "groups",
        }
        if kind == IdentitySource.Kind.OIDC
        else {
            "server_uri": "ldaps://ldap.example.test:636",
            "bind_dn": "cn=pam,dc=example,dc=test",
            "bind_password": "secret",
            "base_dn": "dc=example,dc=test",
            "user_filter": "(objectClass=person)",
            "username_attribute": "uid",
            "email_attribute": "mail",
            "display_name_attribute": "displayName",
            "group_attribute": "memberOf",
        }
    )
    set_identity_source_configuration(source, configuration)
    source.save()
    return source


class FakeLDAPConnection:
    def __init__(self):
        self.unbound = False
        self.extend = SimpleNamespace(
            standard=SimpleNamespace(paged_search=self.paged_search)
        )

    def paged_search(self, **kwargs):
        return iter(
            [
                {"type": "searchResRef"},
                {
                    "type": "searchResEntry",
                    "dn": "uid=alice,dc=example,dc=test",
                    "attributes": {
                        "uid": ["alice"],
                        "mail": ["alice@example.test"],
                        "displayName": ["Alice"],
                        "memberOf": "operators",
                    },
                },
                {
                    "type": "searchResEntry",
                    "dn": "uid=missing,dc=example,dc=test",
                    "attributes": {"uid": []},
                },
            ]
        )

    def unbind(self):
        self.unbound = True


@pytest.mark.django_db
def test_ldap_adapter_reads_directory_without_network(monkeypatch):
    source = source_with_configuration()
    connection = FakeLDAPConnection()
    monkeypatch.setattr("pamolive.connectors.adapters.Server", lambda *args, **kwargs: object())
    monkeypatch.setattr(
        "pamolive.connectors.adapters.Connection", lambda *args, **kwargs: connection
    )

    adapter = LDAPDirectoryAdapter(source)
    users = adapter.fetch_users()

    assert users[0].username == "alice"
    assert users[0].groups == ("operators",)
    assert connection.unbound
    assert adapter.test_connection()


@pytest.mark.django_db
def test_ldap_adapter_masks_connection_failure(monkeypatch):
    source = source_with_configuration()
    monkeypatch.setattr("pamolive.connectors.adapters.Server", lambda *args, **kwargs: object())

    def fail(*args, **kwargs):
        raise RuntimeError("bind secret must not be exposed")

    monkeypatch.setattr("pamolive.connectors.adapters.Connection", fail)

    with pytest.raises(DirectoryConnectionError, match="Connexion à l’annuaire impossible"):
        LDAPDirectoryAdapter(source).test_connection()
    with pytest.raises(ValueError):
        adapter_for(source_with_configuration(IdentitySource.Kind.OIDC))


@pytest.mark.django_db
def test_sync_failure_is_audited_without_raw_error():
    source = source_with_configuration()

    class FailingAdapter:
        def fetch_users(self):
            raise DirectoryConnectionError("Annuaire indisponible")

    with pytest.raises(DirectoryConnectionError):
        synchronize_identity_source(source, FailingAdapter())

    source.refresh_from_db()
    event = AuditEvent.objects.get(action="identity_source.sync.failed")
    assert source.last_sync_status == IdentitySource.SyncStatus.FAILED
    assert event.metadata == {"error_type": "DirectoryConnectionError"}


@pytest.mark.django_db
def test_oidc_login_and_callback_are_governed(client, monkeypatch):
    source = source_with_configuration(IdentitySource.Kind.OIDC)
    group = UserGroup.objects.create(name="OIDC operators")
    DirectoryGroupMapping.objects.create(
        source=source,
        external_group="pam-users",
        user_group=group,
    )
    claims = {
        "sub": "oidc-operator-1",
        "preferred_username": "oidc-operator",
        "email": "oidc-operator@example.test",
        "email_verified": True,
        "groups": ["pam-users"],
    }

    class FakeOIDCClient:
        def authorize_redirect(self, request, callback_uri):
            assert callback_uri.endswith(reverse("oidc_callback", args=(source.slug,)))
            return HttpResponseRedirect("https://identity.example.test/authorize")

        def authorize_access_token(self, request):
            return {"userinfo": claims}

    monkeypatch.setattr(
        "pamolive.accounts.views.oidc_client_for", lambda selected_source: FakeOIDCClient()
    )

    login_response = client.get(reverse("oidc_login", args=(source.slug,)))
    callback_response = client.get(reverse("oidc_callback", args=(source.slug,)))

    user = User.objects.get(username="oidc-operator")
    assert login_response.status_code == 302
    assert login_response.url.startswith("https://identity.example.test/")
    assert callback_response.status_code == 302
    assert callback_response.url == reverse("dashboard")
    assert group.users.filter(pk=user.pk).exists()
    assert AuditEvent.objects.filter(action="authentication.oidc.succeeded").exists()


@pytest.mark.django_db
def test_oidc_login_uses_forwarded_https_callback(client, monkeypatch, settings):
    settings.PAMOLIVE_TRUST_PROXY_HEADERS = True
    settings.SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    settings.USE_X_FORWARDED_HOST = True
    settings.ALLOWED_HOSTS = ["pamolive.mopacy.be"]
    source = source_with_configuration(IdentitySource.Kind.OIDC)
    callback_uris = []

    class FakeOIDCClient:
        def authorize_redirect(self, request, callback_uri):
            callback_uris.append(callback_uri)
            return HttpResponseRedirect("https://identity.example.test/authorize")

    monkeypatch.setattr(
        "pamolive.accounts.views.oidc_client_for", lambda selected_source: FakeOIDCClient()
    )

    response = client.get(
        reverse("oidc_login", args=(source.slug,)),
        HTTP_HOST="pamolive.mopacy.be",
        HTTP_X_FORWARDED_PROTO="https",
    )

    assert response.status_code == 302
    assert callback_uris == [
        f"https://pamolive.mopacy.be{reverse('oidc_callback', args=(source.slug,))}"
    ]


@pytest.mark.django_db
def test_oidc_login_prefers_configured_public_url(client, monkeypatch, settings):
    settings.PAMOLIVE_PUBLIC_URL = "https://pamolive.mopacy.be"
    settings.ALLOWED_HOSTS = ["pamolive.mopacy.be", "127.0.0.1"]
    source = source_with_configuration(IdentitySource.Kind.OIDC)
    callback_uris = []

    class FakeOIDCClient:
        def authorize_redirect(self, request, callback_uri):
            callback_uris.append(callback_uri)
            return HttpResponseRedirect("https://identity.example.test/authorize")

    monkeypatch.setattr(
        "pamolive.accounts.views.oidc_client_for", lambda selected_source: FakeOIDCClient()
    )

    response = client.get(
        reverse("oidc_login", args=(source.slug,)),
        HTTP_HOST="127.0.0.1",
    )

    assert response.status_code == 302
    assert callback_uris == [
        f"https://pamolive.mopacy.be{reverse('oidc_callback', args=(source.slug,))}"
    ]
