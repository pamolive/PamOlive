import base64
import hashlib
import hmac
import json
import struct
import time

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


class VaultError(Exception):
    pass


class VaultCipher:
    def __init__(self, key=None, *, key_id=None):
        configured_keys = dict(getattr(settings, "CBPAM_VAULT_KEYS", {}) or {})
        legacy_key = key or settings.CBPAM_VAULT_KEY
        if legacy_key:
            configured_keys.setdefault("legacy", legacy_key)
        if not configured_keys:
            raise ImproperlyConfigured("CBPAM_VAULT_KEY is required for vault operations")
        self.active_key_id = key_id or getattr(
            settings,
            "CBPAM_VAULT_ACTIVE_KEY_ID",
            "legacy",
        )
        if self.active_key_id not in configured_keys:
            raise ImproperlyConfigured(
                f"Vault key identifier {self.active_key_id!r} is not configured"
            )
        try:
            self._fernets = {
                identifier: Fernet(value.encode() if isinstance(value, str) else value)
                for identifier, value in configured_keys.items()
            }
        except (TypeError, ValueError) as exc:
            raise ImproperlyConfigured("A configured vault key is not a valid Fernet key") from exc

    def encrypt(self, secret: str) -> bytes:
        return self._fernets[self.active_key_id].encrypt(secret.encode())

    def decrypt(self, token: bytes, *, key_id=None) -> str:
        if key_id:
            fernet = self._fernets.get(key_id)
            if not fernet:
                raise VaultError(f"Vault key identifier {key_id!r} is unavailable")
            candidates = (fernet,)
        else:
            active = self._fernets[self.active_key_id]
            candidates = (active,) + tuple(
                fernet for fernet in self._fernets.values() if fernet is not active
            )
        for fernet in candidates:
            try:
                return fernet.decrypt(bytes(token)).decode()
            except InvalidToken:
                continue
        raise VaultError("Credential could not be decrypted")

    def encrypt_payload(self, payload: dict) -> bytes:
        return self.encrypt(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))

    def decrypt_payload(self, token: bytes, *, key_id=None) -> dict:
        return json.loads(self.decrypt(token, key_id=key_id))


def normalize_totp_secret(secret):
    return secret.replace(" ", "").replace("-", "").upper()


def totp_code(secret, timestamp=None, interval=30, digits=6):
    normalized = normalize_totp_secret(secret)
    padding = "=" * ((8 - len(normalized) % 8) % 8)
    key = base64.b32decode(normalized + padding, casefold=True)
    counter = int((timestamp or time.time()) // interval)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10**digits)).zfill(digits)


def verify_totp(secret, token, window=1):
    if not token or not token.isdigit():
        return False
    now = time.time()
    return any(
        hmac.compare_digest(totp_code(secret, now + offset * 30), token)
        for offset in range(-window, window + 1)
    )
