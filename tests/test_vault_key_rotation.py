import pytest
from cryptography.fernet import Fernet
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import override_settings

from cbpam.accounts.models import User
from cbpam.audit.models import AuditEvent
from cbpam.connectors.models import Connector, IdentitySource
from cbpam.mfa.models import MFADevice
from cbpam.operations.models import RotationJob
from cbpam.targets.models import Target
from cbpam.vault.key_rotation import rotate_vault_encryption
from cbpam.vault.models import Credential, PersonalVaultItem
from cbpam.vault.services import VaultCipher


@pytest.mark.django_db
def test_vault_key_rotation_dry_run_apply_and_old_key_removal():
    legacy_key = Fernet.generate_key().decode()
    new_key = Fernet.generate_key().decode()
    keyring = {"legacy": legacy_key, "v2": new_key}

    with override_settings(
        CBPAM_VAULT_KEY="",
        CBPAM_VAULT_KEYS=keyring,
        CBPAM_VAULT_ACTIVE_KEY_ID="legacy",
    ):
        legacy_cipher = VaultCipher()
        user = User.objects.create_user(username="key-rotation-user")
        target = Target.objects.create(
            name="key-rotation-target",
            hostname="key-rotation.test.invalid",
            port=22,
            protocol=Target.Protocol.SSH,
        )
        credential = Credential.objects.create(
            name="key-rotation-credential",
            target=target,
            username="root",
            kind=Credential.Kind.PASSWORD,
            encrypted_secret=legacy_cipher.encrypt("legacy-password"),
            encrypted_totp_secret=legacy_cipher.encrypt("JBSWY3DPEHPK3PXP"),
        )
        personal = PersonalVaultItem.objects.create(
            owner=user,
            name="key-rotation-personal",
            item_type=PersonalVaultItem.ItemType.NOTE,
            encrypted_payload=legacy_cipher.encrypt_payload({"notes": "legacy-note"}),
        )
        mfa = MFADevice.objects.create(
            user=user,
            name="TOTP",
            kind=MFADevice.Kind.TOTP,
            encrypted_configuration=legacy_cipher.encrypt("JBSWY3DPEHPK3PXP"),
        )
        connector = Connector.objects.create(
            name="key-rotation-connector",
            kind="test",
            encrypted_configuration=legacy_cipher.encrypt_payload({"token": "legacy-token"}),
        )
        source = IdentitySource.objects.create(
            name="key-rotation-source",
            slug="key-rotation-source",
            kind=IdentitySource.Kind.OIDC,
            encrypted_configuration=legacy_cipher.encrypt_payload(
                {"client_secret": "legacy-client-secret"}
            ),
        )
        job = RotationJob.objects.create(
            credential=credential,
            requested_by=user,
            backend="test",
            previous_key_version=credential.key_version,
            status=RotationJob.Status.FAILED,
            encrypted_candidate_secret=legacy_cipher.encrypt("candidate-password"),
        )

    with override_settings(
        CBPAM_VAULT_KEY="",
        CBPAM_VAULT_KEYS=keyring,
        CBPAM_VAULT_ACTIVE_KEY_ID="v2",
    ):
        dry_run = rotate_vault_encryption(apply=False)
        credential.refresh_from_db()
        assert dry_run.scanned_fields == 7
        assert dry_run.fields_to_reencrypt == 7
        assert dry_run.reencrypted_fields == 0
        assert credential.secret_encryption_key_id == "legacy"
        assert not AuditEvent.objects.filter(action="vault.master_key_rotated").exists()

        applied = rotate_vault_encryption(apply=True)
        assert applied.reencrypted_fields == 7
        assert AuditEvent.objects.filter(action="vault.master_key_rotated").exists()

    credential.refresh_from_db()
    personal.refresh_from_db()
    mfa.refresh_from_db()
    connector.refresh_from_db()
    source.refresh_from_db()
    job.refresh_from_db()
    assert credential.secret_encryption_key_id == "v2"
    assert credential.totp_encryption_key_id == "v2"
    assert personal.encryption_key_id == "v2"
    assert mfa.encryption_key_id == "v2"
    assert connector.encryption_key_id == "v2"
    assert source.encryption_key_id == "v2"
    assert job.candidate_encryption_key_id == "v2"

    with override_settings(
        CBPAM_VAULT_KEY="",
        CBPAM_VAULT_KEYS={"v2": new_key},
        CBPAM_VAULT_ACTIVE_KEY_ID="v2",
    ):
        cipher = VaultCipher()
        assert (
            cipher.decrypt(
                credential.encrypted_secret,
                key_id=credential.secret_encryption_key_id,
            )
            == "legacy-password"
        )
        assert cipher.decrypt_payload(
            personal.encrypted_payload,
            key_id=personal.encryption_key_id,
        ) == {"notes": "legacy-note"}


@pytest.mark.django_db
def test_vault_key_command_requires_exact_confirmation():
    new_key = Fernet.generate_key().decode()
    with override_settings(
        CBPAM_VAULT_KEY="",
        CBPAM_VAULT_KEYS={"v2": new_key},
        CBPAM_VAULT_ACTIVE_KEY_ID="v2",
    ):
        with pytest.raises(CommandError):
            call_command("rotate_vault_key", "--apply")
