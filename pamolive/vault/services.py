import base64
import hashlib
import hmac
import json
import struct
import time

from pamolive.common.keyring import KeyringError, get_keyring_client


class VaultError(Exception):
    pass


class VaultCipher:
    def __init__(self, key=None, *, key_id=None):
        if key is not None or key_id is not None:
            raise TypeError("Encryption keys are managed exclusively by the keyring service")
        self.active_key_id = "keyring-v1"
        self._client = get_keyring_client()

    def encrypt(self, secret: str) -> bytes:
        return self._client.encrypt(secret).encode()

    def decrypt(self, token: bytes, *, key_id=None) -> str:
        if key_id and key_id != self.active_key_id:
            raise VaultError(
                f"Secret uses legacy key {key_id!r}; run migrate_secrets_to_keyring"
            )
        try:
            return self._client.decrypt(bytes(token).decode())
        except (KeyringError, UnicodeDecodeError) as exc:
            raise VaultError("Credential could not be decrypted") from exc

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
