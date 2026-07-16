from django.conf import settings
from django.db import models

from cbpam.approvals.models import AccessRequest
from cbpam.common.models import UUIDTimeStampedModel
from cbpam.policies.models import AccessPolicy
from cbpam.targets.models import Target
from cbpam.vault.models import Credential


class PrivilegedSession(UUIDTimeStampedModel):
    class Status(models.TextChoices):
        CREATED = "created", "Created"
        ACTIVE = "active", "Active"
        TERMINATING = "terminating", "Termination requested"
        CLOSED = "closed", "Closed"
        FAILED = "failed", "Failed"

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    target = models.ForeignKey(Target, on_delete=models.PROTECT)
    credential = models.ForeignKey(
        Credential,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="privileged_sessions",
    )
    policy = models.ForeignKey(
        AccessPolicy,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="privileged_sessions",
    )
    access_request = models.ForeignKey(
        AccessRequest,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="sessions",
    )
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.CREATED)
    expires_at = models.DateTimeField(null=True, blank=True, db_index=True)
    started_at = models.DateTimeField(null=True, blank=True)
    ended_at = models.DateTimeField(null=True, blank=True)
    last_activity_at = models.DateTimeField(null=True, blank=True)
    client_ip = models.GenericIPAddressField(null=True, blank=True)
    justification = models.CharField(max_length=1000)
    recording_reference = models.CharField(max_length=500, blank=True)
    termination_reason = models.CharField(max_length=255, blank=True)
    termination_requested_at = models.DateTimeField(null=True, blank=True)
    termination_requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="terminated_privileged_sessions",
    )


class SessionTicket(UUIDTimeStampedModel):
    session = models.OneToOneField(
        PrivilegedSession,
        on_delete=models.PROTECT,
        related_name="ticket",
    )
    token_hash = models.CharField(max_length=64, unique=True)
    expires_at = models.DateTimeField(db_index=True)
    consumed_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    source_ip = models.GenericIPAddressField(null=True, blank=True)

    def __str__(self):
        return f"Ticket de session {self.session_id}"
