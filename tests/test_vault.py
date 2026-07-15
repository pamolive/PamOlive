from cryptography.fernet import Fernet

from cbpam.vault.services import VaultCipher


def test_vault_round_trip():
    cipher = VaultCipher(Fernet.generate_key())
    encrypted = cipher.encrypt("never-log-this-secret")
    assert b"never-log-this-secret" not in encrypted
    assert cipher.decrypt(encrypted) == "never-log-this-secret"
