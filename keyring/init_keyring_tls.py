import ipaddress
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

SERVER_DIR = Path("/keyring-server-tls")
CLIENT_DIR = Path("/keyring-client-tls")
DATA_DIR = Path("/data")
RUNTIME_UID = int(os.environ.get("PAMOLIVE_RUNTIME_UID", "10001"))
RUNTIME_GID = int(os.environ.get("PAMOLIVE_RUNTIME_GID", "10001"))


def _private(path, key, uid):
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o400)
    os.chown(path, uid, RUNTIME_GID)


def _certificate(path, certificate, uid):
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    path.chmod(0o444)
    os.chown(path, uid, RUNTIME_GID)


def _certificate_for(ca_key, ca_cert, common_name, usage, names=()):
    now = datetime.now(UTC)
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
    )
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(list(names)), critical=False)
    return key, builder.sign(ca_key, hashes.SHA256())


def main():
    SERVER_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    CLIENT_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    expected = [SERVER_DIR / name for name in ("ca.crt", "server.crt", "server.key")] + [
        CLIENT_DIR / name for name in ("ca.crt", "client.crt", "client.key")
    ]
    if not all(path.exists() for path in expected):
        if any(path.exists() for path in expected):
            raise RuntimeError("Keyring mTLS bundle is incomplete; rotate it explicitly")
        now = datetime.now(UTC)
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PAM-olive keyring CA")])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        server_key, server_cert = _certificate_for(
            ca_key,
            ca_cert,
            "keyring",
            ExtendedKeyUsageOID.SERVER_AUTH,
            (x509.DNSName("keyring"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))),
        )
        client_key, client_cert = _certificate_for(
            ca_key, ca_cert, "pamolive-app", ExtendedKeyUsageOID.CLIENT_AUTH
        )
        _certificate(SERVER_DIR / "ca.crt", ca_cert, RUNTIME_UID)
        _private(SERVER_DIR / "server.key", server_key, RUNTIME_UID)
        _certificate(SERVER_DIR / "server.crt", server_cert, RUNTIME_UID)
        _certificate(CLIENT_DIR / "ca.crt", ca_cert, RUNTIME_UID)
        _private(CLIENT_DIR / "client.key", client_key, RUNTIME_UID)
        _certificate(CLIENT_DIR / "client.crt", client_cert, RUNTIME_UID)
    for path in DATA_DIR.iterdir():
        os.chown(path, RUNTIME_UID, RUNTIME_GID)
    os.chown(DATA_DIR, RUNTIME_UID, RUNTIME_GID)
    print("Keyring mTLS material is ready.")


if __name__ == "__main__":
    main()
