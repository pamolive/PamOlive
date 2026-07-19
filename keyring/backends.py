import base64
import hashlib
import hmac
import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class KeyringBackendError(RuntimeError):
    pass


class InvalidCiphertext(KeyringBackendError):
    pass


class BackendUnavailable(KeyringBackendError):
    pass


def _derive_key(master_key: bytes, purpose: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"pam-olive-keyring-v1",
        info=purpose,
    ).derive(master_key)


class LocalBackend:
    name = "local"

    def __init__(self, data_dir: Path, *, create: bool):
        self.master_key_path = data_dir / "master.key"
        data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            master_key = self.master_key_path.read_bytes()
        except FileNotFoundError:
            if not create:
                raise
            master_key = os.urandom(32)
            descriptor = os.open(
                self.master_key_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            try:
                os.write(descriptor, master_key)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        if len(master_key) != 32:
            raise RuntimeError("The keyring master key must contain exactly 32 bytes")
        os.chmod(self.master_key_path, 0o600)
        encryption_key = _derive_key(master_key, b"encryption")
        self.cipher = Fernet(base64.urlsafe_b64encode(encryption_key))
        self.signing_key = _derive_key(master_key, b"audit-signing")

    def encrypt(self, plaintext: str) -> str:
        return self.cipher.encrypt(plaintext.encode()).decode()

    def decrypt(self, ciphertext: str) -> str:
        try:
            return self.cipher.decrypt(ciphertext.encode()).decode()
        except (InvalidToken, UnicodeDecodeError):
            raise InvalidCiphertext("Ciphertext is invalid") from None

    def sign(self, payload: str) -> str:
        return hmac.new(self.signing_key, payload.encode(), hashlib.sha256).hexdigest()

    def verify(self, payload: str, signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)


class VaultTransitBackend:
    name = "vault-transit"

    def __init__(self):
        address = os.environ.get("PAMOLIVE_VAULT_ADDR", "").rstrip("/")
        parsed = urllib.parse.urlsplit(address)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise RuntimeError("PAMOLIVE_VAULT_ADDR must be an HTTPS URL without credentials")
        self.address = address
        self.mount = os.environ.get("PAMOLIVE_VAULT_TRANSIT_MOUNT", "transit").strip("/")
        self.key_name = os.environ.get("PAMOLIVE_VAULT_KEY_NAME", "pamolive")
        if not self.mount or "/" in self.key_name or not self.key_name:
            raise RuntimeError("Vault Transit mount and key name must be non-empty path segments")
        token_path = Path(
            os.environ.get("PAMOLIVE_VAULT_TOKEN_FILE", "/run/secrets/pamolive_vault_token")
        )
        try:
            self.token = token_path.read_text().strip()
        except OSError as exc:
            raise RuntimeError("Vault token file is unavailable") from exc
        if len(self.token) < 16:
            raise RuntimeError("Vault token file is empty or invalid")
        self.namespace = os.environ.get("PAMOLIVE_VAULT_NAMESPACE", "").strip()
        self.timeout = float(os.environ.get("PAMOLIVE_VAULT_TIMEOUT_SECONDS", "5"))
        ca_path = os.environ.get("PAMOLIVE_VAULT_CA_PATH", "").strip()
        self.ssl_context = ssl.create_default_context(cafile=ca_path or None)

    def _request(self, operation: str, payload: dict) -> dict:
        url = f"{self.address}/v1/{self.mount}/{operation}/{urllib.parse.quote(self.key_name)}"
        headers = {"Content-Type": "application/json", "X-Vault-Token": self.token}
        if self.namespace:
            headers["X-Vault-Namespace"] = self.namespace
        request = urllib.request.Request(
            url,
            data=json.dumps(payload, separators=(",", ":")).encode(),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(
                request, context=self.ssl_context, timeout=self.timeout
            ) as response:
                result = json.load(response)
            return result["data"]
        except urllib.error.HTTPError as exc:
            if exc.code == 400 and operation == "decrypt":
                raise InvalidCiphertext("Ciphertext is invalid") from None
            raise BackendUnavailable("Vault Transit rejected the operation") from exc
        except (OSError, ValueError, KeyError) as exc:
            raise BackendUnavailable("Vault Transit is unavailable") from exc

    def encrypt(self, plaintext: str) -> str:
        encoded = base64.b64encode(plaintext.encode()).decode()
        return self._request("encrypt", {"plaintext": encoded})["ciphertext"]

    def decrypt(self, ciphertext: str) -> str:
        encoded = self._request("decrypt", {"ciphertext": ciphertext})["plaintext"]
        try:
            return base64.b64decode(encoded, validate=True).decode()
        except (ValueError, UnicodeDecodeError):
            raise BackendUnavailable("Vault Transit returned invalid plaintext") from None

    def sign(self, payload: str) -> str:
        encoded = base64.b64encode(payload.encode()).decode()
        vault_hmac = self._request("hmac", {"input": encoded, "algorithm": "sha2-256"})[
            "hmac"
        ]
        try:
            _vault, _version, digest = vault_hmac.split(":", 2)
            raw_digest = base64.b64decode(digest, validate=True)
        except (ValueError, TypeError):
            raise BackendUnavailable("Vault Transit returned an invalid HMAC") from None
        if len(raw_digest) != hashlib.sha256().digest_size:
            raise BackendUnavailable("Vault Transit returned an invalid HMAC")
        if len(vault_hmac) > 64:
            raise BackendUnavailable("Vault Transit returned an oversized HMAC")
        return vault_hmac

    def verify(self, payload: str, signature: str) -> bool:
        if not signature.startswith("vault:"):
            return False
        encoded = base64.b64encode(payload.encode()).decode()
        result = self._request(
            "verify",
            {"input": encoded, "hmac": signature, "algorithm": "sha2-256"},
        )
        return result.get("valid") is True


class RoutedBackend:
    def __init__(self, data_dir: Path):
        backend_name = os.environ.get("PAMOLIVE_KEYRING_CRYPTO_BACKEND", "local")
        if backend_name == "local":
            self.active = LocalBackend(data_dir, create=True)
            self.legacy_local = None
        elif backend_name == "vault-transit":
            self.active = VaultTransitBackend()
            try:
                self.legacy_local = LocalBackend(data_dir, create=False)
            except FileNotFoundError:
                self.legacy_local = None
        else:
            raise RuntimeError(f"Unsupported keyring crypto backend: {backend_name!r}")

    @property
    def name(self):
        return self.active.name

    def encrypt(self, plaintext: str) -> str:
        return self.active.encrypt(plaintext)

    def decrypt(self, ciphertext: str) -> str:
        if ciphertext.startswith("vault:"):
            if not isinstance(self.active, VaultTransitBackend):
                raise InvalidCiphertext("Vault ciphertext requires the vault-transit backend")
            return self.active.decrypt(ciphertext)
        backend = self.legacy_local or self.active
        return backend.decrypt(ciphertext)

    def sign(self, payload: str) -> str:
        return self.active.sign(payload)

    def verify(self, payload: str, signature: str) -> bool:
        if self.active.verify(payload, signature):
            return True
        return bool(self.legacy_local and self.legacy_local.verify(payload, signature))
