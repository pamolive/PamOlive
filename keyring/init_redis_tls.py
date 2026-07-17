import ipaddress
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

SERVER_DIR = Path(os.environ.get("REDIS_TLS_SERVER_DIR", "/redis-server-tls"))
CLIENT_DIR = Path(os.environ.get("REDIS_TLS_CLIENT_DIR", "/redis-client-tls"))
REDIS_UID = int(os.environ.get("REDIS_RUNTIME_UID", "999"))
REDIS_GID = int(os.environ.get("REDIS_RUNTIME_GID", "1000"))

SERVER_FILES = {
    "ca_key": SERVER_DIR / "ca.key",
    "ca_cert": SERVER_DIR / "ca.crt",
    "server_key": SERVER_DIR / "server.key",
    "server_cert": SERVER_DIR / "server.crt",
}
CLIENT_CA = CLIENT_DIR / "ca.crt"


def _write_private_key(path, key):
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o400)


def _write_certificate(path, certificate):
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    path.chmod(0o444)


def _existing_bundle_is_valid():
    paths = [*SERVER_FILES.values(), CLIENT_CA]
    existing = [path.exists() for path in paths]
    if not any(existing):
        return False
    if not all(existing):
        missing = ", ".join(str(path) for path in paths if not path.exists())
        raise RuntimeError(f"Redis TLS bundle is incomplete; missing: {missing}")
    if SERVER_FILES["ca_cert"].read_bytes() != CLIENT_CA.read_bytes():
        raise RuntimeError("Redis server and client CA certificates do not match")
    certificate = x509.load_pem_x509_certificate(SERVER_FILES["server_cert"].read_bytes())
    if certificate.not_valid_after_utc <= datetime.now(UTC) + timedelta(days=30):
        raise RuntimeError("Redis TLS certificate expires within 30 days; rotate it explicitly")
    names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    if "redis" not in names.get_values_for_type(x509.DNSName):
        raise RuntimeError("Redis TLS certificate does not contain the redis DNS name")
    return True


def _create_bundle():
    now = datetime.now(UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PAM-olive Redis CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "redis")])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("redis"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    _write_private_key(SERVER_FILES["ca_key"], ca_key)
    _write_certificate(SERVER_FILES["ca_cert"], ca_cert)
    _write_private_key(SERVER_FILES["server_key"], server_key)
    _write_certificate(SERVER_FILES["server_cert"], server_cert)
    CLIENT_CA.write_bytes(SERVER_FILES["ca_cert"].read_bytes())
    CLIENT_CA.chmod(0o444)

    for path in SERVER_FILES.values():
        os.chown(path, REDIS_UID, REDIS_GID)


def main():
    SERVER_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    CLIENT_DIR.mkdir(parents=True, exist_ok=True, mode=0o755)
    if not _existing_bundle_is_valid():
        _create_bundle()
    print("Redis TLS material is ready.")


if __name__ == "__main__":
    main()
