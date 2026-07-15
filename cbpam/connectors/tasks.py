from celery import shared_task

from .models import IdentitySource
from .sync import synchronize_identity_source


@shared_task(
    autoretry_for=(ConnectionError, TimeoutError),
    retry_backoff=True,
    retry_jitter=True,
    max_retries=3,
)
def sync_identity_source(source_id):
    source = IdentitySource.objects.get(pk=source_id)
    return synchronize_identity_source(source)
