import pytest
import requests
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import override_settings

from pamolive.common.keyring import KeyringClient, KeyringError


@pytest.mark.django_db
def test_keyring_backend_migration_requires_confirmation():
    with pytest.raises(CommandError, match="MIGRATE-KEYRING-BACKEND"):
        call_command("migrate_keyring_backend", apply=True)


@pytest.mark.django_db
def test_keyring_backend_migration_empty_database_is_retryable():
    from pamolive.audit.models import AuditChainState

    AuditChainState.objects.get_or_create(pk=1)
    call_command(
        "migrate_keyring_backend",
        apply=True,
        confirm="MIGRATE-KEYRING-BACKEND",
    )
    call_command("migrate_keyring_backend")


class Response:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


@override_settings(
    PAMOLIVE_KEYRING_URL="https://keyring:8000",
    PAMOLIVE_KEYRING_TIMEOUT_SECONDS=2,
    PAMOLIVE_KEYRING_TOKEN="keyring-test-token-with-at-least-32-characters",
)
def test_http_keyring_client_uses_fixed_internal_url_and_timeout(monkeypatch):
    requests_seen = []

    def fake_post(url, *, json, headers, timeout, verify, cert):
        requests_seen.append((url, json, headers, timeout, verify, cert))
        return Response({"ciphertext": "opaque"})

    monkeypatch.setattr(requests, "post", fake_post)
    assert KeyringClient().encrypt("secret") == "opaque"
    assert requests_seen == [
        (
            "https://keyring:8000/encrypt",
            {"plaintext": "secret"},
            {"Authorization": "Bearer keyring-test-token-with-at-least-32-characters"},
            2,
            "/run/keyring-tls/ca.crt",
            ("/run/keyring-tls/client.crt", "/run/keyring-tls/client.key"),
        )
    ]


def test_http_keyring_client_does_not_leak_transport_details(monkeypatch):
    def fail(*args, **kwargs):
        raise requests.ConnectionError("sensitive network detail")

    monkeypatch.setattr(requests, "post", fail)
    with pytest.raises(KeyringError, match="keyring operation failed") as error:
        KeyringClient("http://keyring:8000").decrypt("opaque")
    assert "sensitive network detail" not in str(error.value)
