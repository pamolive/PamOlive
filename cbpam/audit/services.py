import hashlib
import json
from dataclasses import dataclass

from django.db import transaction
from django.utils import timezone

from cbpam.common.keyring import get_keyring_client

from .models import AuditChainState, AuditEvent

SENSITIVE_METADATA_FRAGMENTS = (
    "authorization",
    "cookie",
    "credential",
    "key",
    "password",
    "secret",
    "ticket",
    "token",
)


@dataclass(frozen=True)
class AuditVerification:
    valid: bool
    checked_events: int
    legacy_events: int
    issues: tuple[str, ...]
    head_hash: str


def _canonical_payload(
    *,
    sequence,
    occurred_at,
    actor_id,
    action,
    resource_type,
    resource_id,
    source_ip,
    metadata,
    previous_hash,
    hash_version=2,
):
    return {
        "action": action,
        "actor": str(actor_id) if actor_id else None,
        "hash_version": hash_version,
        "metadata": metadata or {},
        "occurred_at": occurred_at.isoformat(),
        "previous_hash": previous_hash,
        "resource_id": str(resource_id),
        "resource_type": resource_type,
        "sequence": sequence,
        "source_ip": str(source_ip) if source_ip else None,
    }


def _payload_hash(payload):
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


def _signature(event_hash):
    return get_keyring_client().sign(event_hash)


@transaction.atomic
def record_event(*, actor, action: str, resource, metadata=None, source_ip=None):
    state = AuditChainState.objects.select_for_update().get(pk=1)
    sequence = state.last_sequence + 1
    occurred_at = timezone.now()
    payload = _canonical_payload(
        sequence=sequence,
        occurred_at=occurred_at,
        actor_id=actor.pk if actor else None,
        action=action,
        resource_type=resource._meta.label_lower,
        resource_id=resource.pk,
        source_ip=source_ip,
        metadata=metadata or {},
        previous_hash=state.last_hash,
    )
    event_hash = _payload_hash(payload)
    event = AuditEvent.objects.create(
        occurred_at=occurred_at,
        sequence=sequence,
        hash_version=2,
        actor=actor,
        action=action,
        resource_type=payload["resource_type"],
        resource_id=payload["resource_id"],
        source_ip=source_ip,
        metadata=payload["metadata"],
        previous_hash=state.last_hash,
        event_hash=event_hash,
        signature=_signature(event_hash),
    )
    state.last_sequence = sequence
    state.last_hash = event_hash
    state.save(update_fields=("last_sequence", "last_hash", "updated_at"))
    from .models import SIEMIntegration

    if SIEMIntegration.objects.filter(enabled=True).exists():
        from .tasks import forward_audit_event

        transaction.on_commit(lambda: forward_audit_event.delay(str(event.pk)), robust=True)
    return event


def verify_audit_chain():
    previous_hash = ""
    previous_sequence = 0
    issues = []
    checked_events = 0
    legacy_events = 0
    for event in AuditEvent.objects.order_by("sequence").iterator(chunk_size=1000):
        checked_events += 1
        if event.sequence != previous_sequence + 1:
            issues.append(f"Séquence discontinue à l’événement {event.id}.")
        if event.previous_hash != previous_hash:
            issues.append(f"Chaînage invalide à l’événement {event.id}.")
        if event.hash_version == 1:
            legacy_events += 1
        elif event.hash_version == 2:
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
            expected_hash = _payload_hash(payload)
            if event.event_hash != expected_hash:
                issues.append(f"Empreinte invalide à l’événement {event.id}.")
            if not event.signature or not get_keyring_client().verify(
                event.event_hash,
                event.signature,
            ):
                issues.append(f"Signature invalide à l’événement {event.id}.")
        else:
            issues.append(f"Version de hash inconnue à l’événement {event.id}.")
        previous_hash = event.event_hash
        previous_sequence = event.sequence

    state = AuditChainState.objects.get(pk=1)
    if state.last_sequence != previous_sequence or state.last_hash != previous_hash:
        issues.append("La tête de chaîne ne correspond pas au dernier événement.")
    return AuditVerification(
        valid=not issues,
        checked_events=checked_events,
        legacy_events=legacy_events,
        issues=tuple(issues),
        head_hash=previous_hash,
    )


def redact_metadata(value):
    if isinstance(value, dict):
        redacted = {}
        for key, nested in value.items():
            normalized = str(key).casefold()
            if any(fragment in normalized for fragment in SENSITIVE_METADATA_FRAGMENTS):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = redact_metadata(nested)
        return redacted
    if isinstance(value, list):
        return [redact_metadata(item) for item in value]
    return value
