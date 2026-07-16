from cbpam.vault.services import VaultCipher


def test_vault_round_trip():
    cipher = VaultCipher()
    encrypted = cipher.encrypt("never-log-this-secret")
    assert b"never-log-this-secret" not in encrypted
    assert cipher.decrypt(encrypted) == "never-log-this-secret"
