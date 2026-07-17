from dataclasses import dataclass

from django.db import transaction

from pamolive.audit.models import AuditChainState, SIEMIntegration
from pamolive.audit.services import record_event
from pamolive.connectors.models import Connector, IdentitySource
from pamolive.mfa.models import MFADevice
from pamolive.operations.models import RotationJob

from .models import Credential, PersonalVaultItem
from .services import VaultCipher


@dataclass(frozen=True)
class VaultKeyRotationReport:
    active_key_id: str
    scanned_fields: int
    fields_to_reencrypt: int
    reencrypted_fields: int
    applied: bool


ENCRYPTED_MODEL_FIELDS = (
    (
        Credential,
        (
            ("encrypted_secret", "secret_encryption_key_id"),
            ("encrypted_totp_secret", "totp_encryption_key_id"),
        ),
    ),
    (PersonalVaultItem, (("encrypted_payload", "encryption_key_id"),)),
    (MFADevice, (("encrypted_configuration", "encryption_key_id"),)),
    (Connector, (("encrypted_configuration", "encryption_key_id"),)),
    (IdentitySource, (("encrypted_configuration", "encryption_key_id"),)),
    (
        RotationJob,
        (("encrypted_candidate_secret", "candidate_encryption_key_id"),),
    ),
    (
        SIEMIntegration,
        (("encrypted_auth_token", "auth_token_encryption_key_id"),),
    ),
)


@transaction.atomic
def rotate_vault_encryption(*, apply=False, actor=None):
    cipher = VaultCipher()
    scanned_fields = 0
    fields_to_reencrypt = 0
    reencrypted_fields = 0

    for model, encrypted_fields in ENCRYPTED_MODEL_FIELDS:
        queryset = model.objects.order_by("pk")
        if apply:
            queryset = queryset.select_for_update()
        for instance in queryset.iterator(chunk_size=200):
            update_fields = []
            for encrypted_field, key_id_field in encrypted_fields:
                encrypted_value = getattr(instance, encrypted_field)
                if not encrypted_value:
                    continue
                scanned_fields += 1
                source_key_id = getattr(instance, key_id_field)
                plaintext = cipher.decrypt(encrypted_value, key_id=source_key_id)
                if source_key_id == cipher.active_key_id:
                    continue
                fields_to_reencrypt += 1
                if apply:
                    setattr(instance, encrypted_field, cipher.encrypt(plaintext))
                    setattr(instance, key_id_field, cipher.active_key_id)
                    update_fields.extend((encrypted_field, key_id_field))
                    reencrypted_fields += 1
            if apply and update_fields:
                instance.save(update_fields=(*dict.fromkeys(update_fields), "updated_at"))

    if apply and reencrypted_fields:
        record_event(
            actor=actor,
            action="vault.master_key_rotated",
            resource=AuditChainState.objects.get(pk=1),
            metadata={
                "active_key_id": cipher.active_key_id,
                "reencrypted_fields": reencrypted_fields,
            },
        )
    return VaultKeyRotationReport(
        active_key_id=cipher.active_key_id,
        scanned_fields=scanned_fields,
        fields_to_reencrypt=fields_to_reencrypt,
        reencrypted_fields=reencrypted_fields,
        applied=apply,
    )
