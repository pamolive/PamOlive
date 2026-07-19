import hashlib
import json
import socket
import ssl

import requests
from django.utils import timezone

from pamolive.common.outbound import validate_outbound_host, validate_outbound_url
from pamolive.vault.services import VaultCipher

from .models import SIEMDelivery, SIEMIntegration
from .services import redact_metadata


def event_payload(event):
    return {
        "schema": "pam-olive.audit.v1",
        "id": str(event.pk),
        "sequence": event.sequence,
        "occurred_at": event.occurred_at.isoformat(),
        "actor": event.actor.username if event.actor else None,
        "action": event.action,
        "resource_type": event.resource_type,
        "resource_id": event.resource_id,
        "source_ip": event.source_ip,
        "metadata": redact_metadata(event.metadata),
        "previous_hash": event.previous_hash,
        "event_hash": event.event_hash,
        "signature": event.signature,
    }


def _auth_token(integration):
    if not integration.encrypted_auth_token:
        return ""
    return VaultCipher().decrypt(
        bytes(integration.encrypted_auth_token),
        key_id=integration.auth_token_encryption_key_id or None,
    )


def _send_https(integration, payload):
    validate_outbound_url(integration.endpoint)
    headers = {"Content-Type": "application/json", "User-Agent": "PAM-olive-SIEM/1"}
    token = _auth_token(integration)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = requests.post(
        integration.endpoint,
        json=payload,
        headers=headers,
        timeout=(5, 10),
        verify=True,
    )
    response.raise_for_status()


def _send_syslog_tls(integration, payload):
    validate_outbound_host(integration.host, port=integration.port)
    body = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    message = f"<134>1 {payload['occurred_at']} pam-olive audit - - - {body}".encode()
    framed = str(len(message)).encode() + b" " + message
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection((integration.host, integration.port), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname=integration.host) as secured:
            secured.sendall(framed)


def deliver_event(integration, event):
    payload = event_payload(event)
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    payload_hash = hashlib.sha256(canonical.encode()).hexdigest()
    now = timezone.now()
    try:
        if integration.kind == SIEMIntegration.Kind.HTTPS_WEBHOOK:
            _send_https(integration, payload)
        else:
            _send_syslog_tls(integration, payload)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"[:500]
        SIEMDelivery.objects.update_or_create(
            integration=integration,
            event=event,
            defaults={"status": SIEMDelivery.Status.FAILED, "payload_hash": payload_hash,
                      "error": error, "attempted_at": now, "delivered_at": None},
        )
        SIEMIntegration.objects.filter(pk=integration.pk).update(
            last_delivery_at=now, last_status=SIEMDelivery.Status.FAILED, last_error=error
        )
        raise
    SIEMDelivery.objects.update_or_create(
        integration=integration,
        event=event,
        defaults={"status": SIEMDelivery.Status.DELIVERED, "payload_hash": payload_hash,
                  "error": "", "attempted_at": now, "delivered_at": now},
    )
    SIEMIntegration.objects.filter(pk=integration.pk).update(
        last_delivery_at=now, last_status=SIEMDelivery.Status.DELIVERED, last_error=""
    )
