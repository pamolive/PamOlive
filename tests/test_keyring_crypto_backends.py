import base64
import importlib.util
import io
import json
from pathlib import Path

import pytest


def load_backends_module():
    path = Path(__file__).parents[1] / "keyring" / "backends.py"
    spec = importlib.util.spec_from_file_location("pamolive_keyring_backends", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_local_backend_round_trip_and_signing(tmp_path):
    backends = load_backends_module()
    backend = backends.LocalBackend(tmp_path, create=True)
    ciphertext = backend.encrypt("secret")
    assert backend.decrypt(ciphertext) == "secret"
    assert backend.verify("event", backend.sign("event")) is True
    assert (tmp_path / "master.key").stat().st_mode & 0o777 == 0o600


def test_vault_backend_uses_token_file_tls_and_hex_hmac(monkeypatch, tmp_path):
    backends = load_backends_module()
    token_path = tmp_path / "vault-token"
    token_path.write_text("vault-test-token-with-enough-entropy")
    monkeypatch.setenv("PAMOLIVE_VAULT_ADDR", "https://vault.internal")
    monkeypatch.setenv("PAMOLIVE_VAULT_TOKEN_FILE", str(token_path))
    requests = []
    digest = b"d" * 32
    vault_hmac = f"vault:v1:{base64.b64encode(digest).decode()}"
    responses = iter(
        (
            {"data": {"ciphertext": "vault:v1:ciphertext"}},
            {"data": {"plaintext": base64.b64encode(b"secret").decode()}},
            {"data": {"hmac": vault_hmac}},
            {"data": {"valid": True}},
        )
    )

    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

    def fake_urlopen(request, *, context, timeout):
        requests.append((request, context, timeout))
        return Response(json.dumps(next(responses)).encode())

    monkeypatch.setattr(backends.urllib.request, "urlopen", fake_urlopen)
    backend = backends.VaultTransitBackend()
    assert backend.encrypt("secret") == "vault:v1:ciphertext"
    assert backend.decrypt("vault:v1:ciphertext") == "secret"
    assert backend.sign("event") == vault_hmac
    assert backend.verify("event", vault_hmac) is True
    assert all(
        request.headers["X-vault-token"] == token_path.read_text()
        for request, _, _ in requests
    )
    assert all(timeout == 5 for _, _, timeout in requests)


def test_vault_mode_reads_legacy_local_ciphertext(monkeypatch, tmp_path):
    backends = load_backends_module()
    legacy = backends.LocalBackend(tmp_path, create=True)
    ciphertext = legacy.encrypt("legacy-secret")
    token_path = tmp_path / "vault-token"
    token_path.write_text("vault-test-token-with-enough-entropy")
    monkeypatch.setenv("PAMOLIVE_KEYRING_CRYPTO_BACKEND", "vault-transit")
    monkeypatch.setenv("PAMOLIVE_VAULT_ADDR", "https://vault.internal")
    monkeypatch.setenv("PAMOLIVE_VAULT_TOKEN_FILE", str(token_path))
    assert backends.RoutedBackend(tmp_path).decrypt(ciphertext) == "legacy-secret"


def test_fresh_vault_mode_does_not_create_local_master_key(monkeypatch, tmp_path):
    backends = load_backends_module()
    token_path = tmp_path / "vault-token"
    token_path.write_text("vault-test-token-with-enough-entropy")
    monkeypatch.setenv("PAMOLIVE_KEYRING_CRYPTO_BACKEND", "vault-transit")
    monkeypatch.setenv("PAMOLIVE_VAULT_ADDR", "https://vault.internal")
    monkeypatch.setenv("PAMOLIVE_VAULT_TOKEN_FILE", str(token_path))
    backends.RoutedBackend(tmp_path)
    assert not (tmp_path / "master.key").exists()


@pytest.mark.parametrize(
    "address", ("http://vault.internal", "https://user:password@vault.internal", "")
)
def test_vault_backend_rejects_unsafe_addresses(monkeypatch, tmp_path, address):
    backends = load_backends_module()
    token_path = tmp_path / "vault-token"
    token_path.write_text("vault-test-token-with-enough-entropy")
    monkeypatch.setenv("PAMOLIVE_VAULT_ADDR", address)
    monkeypatch.setenv("PAMOLIVE_VAULT_TOKEN_FILE", str(token_path))
    with pytest.raises(RuntimeError, match="HTTPS URL"):
        backends.VaultTransitBackend()
