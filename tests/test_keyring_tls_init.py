import importlib.util
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID


def _module():
    path = Path(__file__).parents[1] / "keyring" / "init_keyring_tls.py"
    spec = importlib.util.spec_from_file_location("pamolive_keyring_tls_init", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_keyring_tls_initializer_creates_server_and_client_identities(monkeypatch, tmp_path):
    module = _module()
    module.SERVER_DIR = tmp_path / "server"
    module.CLIENT_DIR = tmp_path / "client"
    module.DATA_DIR = tmp_path / "data"
    monkeypatch.setattr(module.os, "chown", lambda *_args: None)

    module.main()

    server = x509.load_pem_x509_certificate((module.SERVER_DIR / "server.crt").read_bytes())
    client = x509.load_pem_x509_certificate((module.CLIENT_DIR / "client.crt").read_bytes())
    assert ExtendedKeyUsageOID.SERVER_AUTH in server.extensions.get_extension_for_class(
        x509.ExtendedKeyUsage
    ).value
    assert ExtendedKeyUsageOID.CLIENT_AUTH in client.extensions.get_extension_for_class(
        x509.ExtendedKeyUsage
    ).value
    assert (module.SERVER_DIR / "server.key").stat().st_mode & 0o777 == 0o400
    assert (module.CLIENT_DIR / "client.key").stat().st_mode & 0o777 == 0o400
