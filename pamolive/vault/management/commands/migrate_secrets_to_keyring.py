import hashlib
import hmac
import os

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from pamolive.audit.models import AuditChainState, AuditEvent
from pamolive.audit.services import _canonical_payload, _payload_hash, record_event
from pamolive.common.keyring import get_keyring_client
from pamolive.vault.key_rotation import ENCRYPTED_MODEL_FIELDS
from pamolive.vault.legacy import LegacyVaultCipher
from pamolive.vault.services import VaultCipher

CONFIRMATION = "MIGRATE-TO-KEYRING"


class Command(BaseCommand):
    help = "Re-encrypt legacy secrets and re-sign audit events with the isolated keyring."

    def add_arguments(self, parser):
        parser.add_argument("--apply", action="store_true")
        parser.add_argument("--confirm", default="")

    def handle(self, *args, **options):
        if options["apply"] and options["confirm"] != CONFIRMATION:
            raise CommandError(f"--apply requires --confirm {CONFIRMATION}")

        try:
            report = self._run(apply=options["apply"])
        except Exception as exc:
            raise CommandError(f"Migration aborted without committing changes: {exc}") from exc

        mode = "APPLIED" if options["apply"] else "DRY-RUN"
        self.stdout.write(
            self.style.SUCCESS(
                f"{mode}: secrets={report['secrets']} migrated={report['migrated']} "
                f"audit_events={report['audit_events']} resigned={report['resigned']}"
            )
        )

    @transaction.atomic
    def _run(self, *, apply):
        state = AuditChainState.objects.select_for_update().get(pk=1)
        legacy_cipher = LegacyVaultCipher()
        keyring_cipher = VaultCipher()
        keyring = get_keyring_client()
        legacy_audit_key = os.environ.get("PAMOLIVE_AUDIT_SIGNING_KEY", "").encode()
        if not legacy_audit_key:
            raise CommandError("PAMOLIVE_AUDIT_SIGNING_KEY is required for audit migration")

        secrets = migrated = 0
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
                    secrets += 1
                    key_id = getattr(instance, key_id_field)
                    if key_id == keyring_cipher.active_key_id:
                        keyring_cipher.decrypt(encrypted_value, key_id=key_id)
                        continue
                    plaintext = legacy_cipher.decrypt(encrypted_value, key_id=key_id)
                    if apply:
                        setattr(instance, encrypted_field, keyring_cipher.encrypt(plaintext))
                        setattr(instance, key_id_field, keyring_cipher.active_key_id)
                        update_fields.extend((encrypted_field, key_id_field))
                        migrated += 1
                if apply and update_fields:
                    instance.save(update_fields=(*dict.fromkeys(update_fields), "updated_at"))

        previous_hash = ""
        previous_sequence = 0
        audit_events = resigned = 0
        queryset = AuditEvent.objects.order_by("sequence")
        if apply:
            queryset = queryset.select_for_update()
        for event in queryset.iterator(chunk_size=500):
            audit_events += 1
            if event.sequence != previous_sequence + 1 or event.previous_hash != previous_hash:
                raise CommandError(f"Audit chain is broken at event {event.pk}")
            payload = _canonical_payload(
                sequence=event.sequence,
                occurred_at=event.occurred_at,
                actor_id=event.actor_id,
                action=event.action,
                resource_type=event.resource_type,
                resource_id=event.resource_id,
                source_ip=event.source_ip,
                metadata=event.metadata,
                previous_hash=event.previous_hash,
                hash_version=event.hash_version,
            )
            if event.hash_version == 2 and event.event_hash != _payload_hash(payload):
                raise CommandError(f"Audit event hash is invalid at {event.pk}")
            keyring_valid = bool(event.signature) and keyring.verify(
                event.event_hash,
                event.signature,
            )
            legacy_signature = hmac.new(
                legacy_audit_key,
                event.event_hash.encode(),
                hashlib.sha256,
            ).hexdigest()
            legacy_valid = hmac.compare_digest(event.signature, legacy_signature)
            if event.hash_version == 2 and not keyring_valid and not legacy_valid:
                raise CommandError(f"Audit signature is invalid at event {event.pk}")
            if not keyring_valid and apply:
                AuditEvent.objects.filter(pk=event.pk).update(
                    signature=keyring.sign(event.event_hash)
                )
                resigned += 1
            previous_hash = event.event_hash
            previous_sequence = event.sequence

        if state.last_sequence != previous_sequence or state.last_hash != previous_hash:
            raise CommandError("Audit chain head does not match the last event")

        if apply:
            record_event(
                actor=None,
                action="security.keyring_migration_completed",
                resource=state,
                metadata={"migrated_secrets": migrated, "resigned_events": resigned},
            )
        return {
            "secrets": secrets,
            "migrated": migrated,
            "audit_events": audit_events,
            "resigned": resigned,
        }
