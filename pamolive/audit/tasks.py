from celery import shared_task
from requests import RequestException

from .models import AuditEvent, SIEMIntegration
from .siem import deliver_event


@shared_task(
    autoretry_for=(OSError, RequestException), retry_backoff=True, retry_backoff_max=300,
    retry_jitter=True, max_retries=5,
)
def forward_audit_event(event_id):
    event = AuditEvent.objects.select_related("actor").get(pk=event_id)
    for integration in SIEMIntegration.objects.filter(enabled=True).iterator():
        deliver_event(integration, event)
