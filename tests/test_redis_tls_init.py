import importlib.util
from pathlib import Path

import pytest
from cryptography import x509


def load_initializer(monkeypatch, tmp_path):
    monkeypatch.setenv("REDIS_TLS_SERVER_DIR", str(tmp_path / "server"))
    monkeypatch.setenv("REDIS_TLS_CLIENT_DIR", str(tmp_path / "client"))
    path = Path(__file__).parents[1] / "keyring" / "init_redis_tls.py"
    spec = importlib.util.spec_from_file_location("pamolive_redis_tls_init", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module.os, "chown", lambda *_args: None, raising=False)
    return module


def test_redis_tls_initializer_separates_client_and_server_material(monkeypatch, tmp_path):
    initializer = load_initializer(monkeypatch, tmp_path)

    initializer.main()

    server = tmp_path / "server"
    client = tmp_path / "client"
    assert (server / "ca.key").exists()
    assert (server / "server.key").exists()
    assert not (client / "ca.key").exists()
    assert not (client / "server.key").exists()
    assert (server / "ca.crt").read_bytes() == (client / "ca.crt").read_bytes()
    certificate = x509.load_pem_x509_certificate((server / "server.crt").read_bytes())
    names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "redis" in names.get_values_for_type(x509.DNSName)

    original_certificate = (server / "server.crt").read_bytes()
    initializer.main()
    assert (server / "server.crt").read_bytes() == original_certificate


def test_redis_tls_initializer_refuses_an_incomplete_bundle(monkeypatch, tmp_path):
    initializer = load_initializer(monkeypatch, tmp_path)
    initializer.main()
    client_ca = tmp_path / "client" / "ca.crt"
    client_ca.chmod(0o600)
    client_ca.unlink()

    with pytest.raises(RuntimeError, match="bundle is incomplete"):
        initializer.main()


def test_runtime_configuration_requires_verified_redis_tls():
    root = Path(__file__).parents[1]
    compose = (root / "compose.yml").read_text()
    settings = (root / "config" / "settings" / "base.py").read_text()

    assert "--port 0 --tls-port 6379" in compose
    assert "redis_tls_client:/run/redis-tls:ro" in compose
    assert "rediss://" in compose
    assert '"ssl_cert_reqs": "required"' in settings
    assert '"ssl_ca_certs": REDIS_TLS_CA_PATH' in settings
