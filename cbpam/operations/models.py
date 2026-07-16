from django.conf import settings
from django.db import models
from django.db.models import Q
from django.utils import timezone

from cbpam.common.models import UUIDTimeStampedModel
from cbpam.vault.models import Credential


class RotationJob(UUIDTimeStampedModel):
    class Status(models.TextChoices):
        PENDING = "pending", "En attente"
        RUNNING = "running", "En cours"
        SUCCEEDED = "succeeded", "Réussie"
        FAILED = "failed", "Échec"
        ACTION_REQUIRED = "action_required", "Action requise"
        CANCELLED = "cancelled", "Annulée"

    credential = models.ForeignKey(
        Credential,
        on_delete=models.PROTECT,
        related_name="rotation_jobs",
    )
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="requested_rotation_jobs",
    )
    reason = models.CharField(max_length=250, blank=True)
    backend = models.CharField(max_length=100, blank=True)
    status = models.CharField(
        max_length=24,
        choices=Status.choices,
        default=Status.PENDING,
        db_index=True,
    )
    scheduled_for = models.DateTimeField(default=timezone.now, db_index=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    previous_key_version = models.PositiveIntegerField()
    new_key_version = models.PositiveIntegerField(null=True, blank=True)
    encrypted_candidate_secret = models.BinaryField(blank=True)
    candidate_encryption_key_id = models.CharField(max_length=64, default="keyring-v1")
    error_code = models.CharField(max_length=80, blank=True)
    error_message = models.CharField(max_length=250, blank=True)

    class Meta:
        ordering = ("-created_at",)
        constraints = [
            models.UniqueConstraint(
                fields=("credential",),
                condition=Q(status__in=("pending", "running")),
                name="unique_active_rotation_per_credential",
            )
        ]

    def __str__(self):
        return f"{self.credential} · {self.get_status_display()}"
