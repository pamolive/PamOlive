import hashlib
import hmac

import requests
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


class KeyringError(RuntimeError):
    pass


class KeyringClient:
    def __init__(self, base_url=None, timeout=None):
        self.base_url = (base_url or settings.CBPAM_KEYRING_URL).rstrip("/")
        self.timeout = timeout or settings.CBPAM_KEYRING_TIMEOUT_SECONDS

    def _post(self, path, payload):
        try:
            response = requests.post(
                f"{self.base_url}{path}",
                json=payload,
                timeout=self.timeout,
            )
            response.raise_for_status()
            return response.json()
        except (requests.RequestException, ValueError, KeyError) as exc:
            raise KeyringError("The keyring operation failed") from exc

    def encrypt(self, plaintext):
        return self._post("/encrypt", {"plaintext": plaintext})["ciphertext"]

    def decrypt(self, ciphertext):
        return self._post("/decrypt", {"ciphertext": ciphertext})["plaintext"]

    def sign(self, payload):
        return self._post("/sign", {"payload": payload})["signature"]

    def verify(self, payload, signature):
        return bool(
            self._post(
                "/verify",
                {"payload": payload, "signature": signature},
            )["valid"]
        )


class LocalTestKeyringClient:
    """In-process test backend. It must never be enabled in production."""

    def __init__(self):
        from cryptography.fernet import Fernet

        self._cipher = Fernet(settings.CBPAM_TEST_KEYRING_ENCRYPTION_KEY.encode())
        self._signing_key = settings.CBPAM_TEST_KEYRING_SIGNING_KEY.encode()

    def encrypt(self, plaintext):
        return self._cipher.encrypt(plaintext.encode()).decode()

    def decrypt(self, ciphertext):
        try:
            return self._cipher.decrypt(ciphertext.encode()).decode()
        except Exception as exc:
            raise KeyringError("The keyring operation failed") from exc

    def sign(self, payload):
        return hmac.new(
            self._signing_key,
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()

    def verify(self, payload, signature):
        return hmac.compare_digest(self.sign(payload), signature)


def get_keyring_client():
    backend = settings.CBPAM_KEYRING_BACKEND
    if backend == "http":
        return KeyringClient()
    if backend == "local-test":
        return LocalTestKeyringClient()
    raise ImproperlyConfigured(f"Unsupported keyring backend: {backend!r}")
