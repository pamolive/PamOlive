from unittest.mock import MagicMock, Mock, patch

import pytest
import requests
from django.core.exceptions import ValidationError

from cbpam.accounts.models import User
from cbpam.audit.models import SIEMDelivery, SIEMIntegration
from cbpam.audit.services import record_event
from cbpam.audit.siem import deliver_event, event_payload
from cbpam.audit.tasks import forward_audit_event
from cbpam.vault.services import VaultCipher


@pytest.mark.django_db
def test_siem_payload_redacts_sensitive_metadata():
    user = User.objects.create_user(username="siem-user")
    event = record_event(
        actor=user,
        action="test.siem",
        resource=user,
        metadata={"ticket": "secret-ticket", "result": "allowed"},
    )

    payload = event_payload(event)

    assert payload["metadata"]["ticket"] == "[REDACTED]"
    assert payload["metadata"]["result"] == "allowed"
    assert payload["event_hash"] == event.event_hash
    assert payload["signature"] == event.signature


@pytest.mark.django_db
@patch("cbpam.audit.siem.requests.post")
def test_https_siem_delivery_uses_encrypted_bearer_token(post):
    post.return_value = Mock(raise_for_status=Mock())
    user = User.objects.create_user(username="siem-delivery-user")
    event = record_event(actor=user, action="test.delivery", resource=user)
    cipher = VaultCipher()
    integration = SIEMIntegration.objects.create(
        name="SOC collector",
        kind=SIEMIntegration.Kind.HTTPS_WEBHOOK,
        endpoint="https://siem.example.test/events",
        encrypted_auth_token=cipher.encrypt("collector-token"),
        auth_token_encryption_key_id=cipher.active_key_id,
        enabled=False,
    )

    deliver_event(integration, event)

    headers = post.call_args.kwargs["headers"]
    assert headers["Authorization"] == "Bearer collector-token"
    assert SIEMDelivery.objects.get(integration=integration, event=event).status == "delivered"


@pytest.mark.django_db
def test_siem_rejects_plain_http_endpoint():
    integration = SIEMIntegration(
        name="Unsafe",
        kind=SIEMIntegration.Kind.HTTPS_WEBHOOK,
        endpoint="http://siem.example.test/events",
    )

    with pytest.raises(ValidationError):
        integration.full_clean()


@pytest.mark.django_db
@patch("cbpam.audit.siem.requests.post")
def test_failed_siem_delivery_is_recorded(post):
    post.side_effect = requests.RequestException("collector unavailable")
    user = User.objects.create_user(username="siem-failure-user")
    event = record_event(actor=user, action="test.failed_delivery", resource=user)
    integration = SIEMIntegration.objects.create(
        name="Unavailable collector",
        kind=SIEMIntegration.Kind.HTTPS_WEBHOOK,
        endpoint="https://siem.example.test/events",
        enabled=False,
    )

    with pytest.raises(requests.RequestException):
        deliver_event(integration, event)

    delivery = SIEMDelivery.objects.get(integration=integration, event=event)
    integration.refresh_from_db()
    assert delivery.status == SIEMDelivery.Status.FAILED
    assert "collector unavailable" in delivery.error
    assert integration.last_status == SIEMDelivery.Status.FAILED


@pytest.mark.django_db
@patch("cbpam.audit.siem.ssl.create_default_context")
@patch("cbpam.audit.siem.socket.create_connection")
def test_syslog_tls_delivery_uses_octet_counted_framing(create_connection, create_context):
    raw_socket = MagicMock()
    tls_socket = MagicMock()
    create_connection.return_value.__enter__.return_value = raw_socket
    create_context.return_value.wrap_socket.return_value.__enter__.return_value = tls_socket
    user = User.objects.create_user(username="syslog-user")
    event = record_event(actor=user, action="test.syslog", resource=user)
    integration = SIEMIntegration.objects.create(
        name="TLS syslog",
        kind=SIEMIntegration.Kind.SYSLOG_TLS,
        host="siem.example.test",
        port=6514,
        enabled=False,
    )

    deliver_event(integration, event)

    create_connection.assert_called_once_with(("siem.example.test", 6514), timeout=10)
    create_context.return_value.wrap_socket.assert_called_once_with(
        raw_socket, server_hostname="siem.example.test"
    )
    framed = tls_socket.sendall.call_args.args[0]
    length, message = framed.split(b" ", 1)
    assert int(length) == len(message)
    assert b"pam-olive audit" in message


@pytest.mark.django_db
@patch("cbpam.audit.tasks.deliver_event")
def test_celery_task_forwards_to_each_enabled_integration(deliver):
    user = User.objects.create_user(username="task-user")
    event = record_event(actor=user, action="test.task", resource=user)
    integration = SIEMIntegration.objects.create(
        name="Enabled collector",
        kind=SIEMIntegration.Kind.HTTPS_WEBHOOK,
        endpoint="https://siem.example.test/events",
        enabled=True,
    )

    forward_audit_event(str(event.pk))

    deliver.assert_called_once()
    assert deliver.call_args.args == (integration, event)
