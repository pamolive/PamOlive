import hashlib
import hmac
from io import StringIO

import pytest
from cryptography.fernet import Fernet
from django.core.management import call_command
from django.core.management.base import CommandError

from cbpam.accounts.models import User
from cbpam.audit.models import AuditEvent
from cbpam.audit.services import record_event, verify_audit_chain
from cbpam.targets.models import Target
from cbpam.vault.models import Credential, PersonalVaultItem
from cbpam.vault.services import VaultCipher


@pytest.mark.django_db
def test_keyring_migration_is_dry_run_first_resumable_and_audited(monkeypatch):
    legacy_key = Fernet.generate_key()
    legacy_audit_key = b"legacy-audit-signing-key-with-at-least-32-characters"
    monkeypatch.setenv("CBPAM_VAULT_KEY", legacy_key.decode())
    monkeypatch.setenv("CBPAM_AUDIT_SIGNING_KEY", legacy_audit_key.decode())
    legacy_cipher = Fernet(legacy_key)

    user = User.objects.create_user(username="keyring-migration-user")
    target = Target.objects.create(
        name="keyring-migration-target",
        hostname="migration.test.invalid",
        port=22,
        protocol=Target.Protocol.SSH,
    )
    credential = Credential.objects.create(
        name="legacy-credential",
        target=target,
        username="root",
        kind=Credential.Kind.PASSWORD,
        encrypted_secret=legacy_cipher.encrypt(b"legacy-password"),
        secret_encryption_key_id="legacy",
    )
    personal = PersonalVaultItem.objects.create(
        owner=user,
        name="legacy-personal-item",
        item_type=PersonalVaultItem.ItemType.NOTE,
        encrypted_payload=legacy_cipher.encrypt(b'{"notes":"legacy-note"}'),
        encryption_key_id="legacy",
    )
    event = record_event(
        actor=user,
        action="audit.legacy_fixture",
        resource=user,
    )
    legacy_signature = hmac.new(
        legacy_audit_key,
        event.event_hash.encode(),
        hashlib.sha256,
    ).hexdigest()
    AuditEvent.objects.filter(pk=event.pk).update(signature=legacy_signature)

    dry_run_output = StringIO()
    call_command("migrate_secrets_to_keyring", stdout=dry_run_output)
    credential.refresh_from_db()
    assert "DRY-RUN" in dry_run_output.getvalue()
    assert credential.secret_encryption_key_id == "legacy"

    with pytest.raises(CommandError):
        call_command("migrate_secrets_to_keyring", "--apply")

    call_command(
        "migrate_secrets_to_keyring",
        "--apply",
        "--confirm",
        "MIGRATE-TO-KEYRING",
    )
    credential.refresh_from_db()
    personal.refresh_from_db()
    assert credential.secret_encryption_key_id == "keyring-v1"
    assert personal.encryption_key_id == "keyring-v1"
    assert (
        VaultCipher().decrypt(
            credential.encrypted_secret,
            key_id=credential.secret_encryption_key_id,
        )
        == "legacy-password"
    )
    assert VaultCipher().decrypt_payload(
        personal.encrypted_payload,
        key_id=personal.encryption_key_id,
    ) == {"notes": "legacy-note"}
    assert verify_audit_chain().valid
    assert AuditEvent.objects.filter(
        action="security.keyring_migration_completed"
    ).exists()

    second_run = StringIO()
    call_command("migrate_secrets_to_keyring", stdout=second_run)
    assert "migrated=0" in second_run.getvalue()
