import json
import os

from cryptography.fernet import Fernet, InvalidToken

from .services import VaultError


class LegacyVaultCipher:
    """Read-only bridge used exclusively by migrate_secrets_to_keyring."""

    def __init__(self):
        configured = json.loads(os.environ.get("CBPAM_VAULT_KEYS", "{}"))
        legacy_key = os.environ.get("CBPAM_VAULT_KEY", "")
        if legacy_key:
            configured.setdefault("legacy", legacy_key)
        if not configured:
            raise VaultError("No legacy vault key is available for migration")
        self._ciphers = {
            identifier: Fernet(value.encode())
            for identifier, value in configured.items()
        }

    def decrypt(self, token, *, key_id):
        cipher = self._ciphers.get(key_id)
        if cipher is None:
            raise VaultError(f"Legacy vault key {key_id!r} is unavailable")
        try:
            return cipher.decrypt(bytes(token)).decode()
        except (InvalidToken, UnicodeDecodeError) as exc:
            raise VaultError("A legacy secret could not be decrypted") from exc
