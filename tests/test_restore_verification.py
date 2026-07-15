from io import StringIO

import pytest
from django.core.management import CommandError, call_command

from cbpam.accounts.models import User
from cbpam.audit.models import AuditEvent
from cbpam.audit.services import record_event
from cbpam.vault.models import PersonalVaultItem
from cbpam.vault.services import VaultCipher


@pytest.mark.django_db
def test_verify_restore_checks_marker_audit_migrations_and_encrypted_fields():
    user = User.objects.create_user(username="restore-marker")
    cipher = VaultCipher()
    PersonalVaultItem.objects.create(
        owner=user,
        name="Restore marker secret",
        item_type=PersonalVaultItem.ItemType.NOTE,
        encrypted_payload=cipher.encrypt_payload({"note": "restore-fixture"}),
        encryption_key_id=cipher.active_key_id,
    )
    record_event(actor=user, action="restore.marker_created", resource=user)
    output = StringIO()

    call_command("verify_restore", expect_user="restore-marker", stdout=output)

    assert "Restauration valide" in output.getvalue()
    assert "audit=1" in output.getvalue()
    assert "champs_chiffrés=1" in output.getvalue()
    assert "migrations=0" in output.getvalue()


@pytest.mark.django_db
def test_verify_restore_rejects_missing_marker_and_corrupt_audit():
    with pytest.raises(CommandError, match="marqueur"):
        call_command("verify_restore", expect_user="missing-marker")

    user = User.objects.create_user(username="corrupt-restore-marker")
    event = record_event(actor=user, action="restore.marker_created", resource=user)
    AuditEvent.objects.filter(pk=event.pk).update(event_hash="0" * 64)

    with pytest.raises(CommandError, match="audit restaurée est invalide"):
        call_command("verify_restore", expect_user="corrupt-restore-marker")
