from django.conf import settings
from django.db import models
from django.db.models import Q
from django.utils import timezone

from pamolive.common.models import UUIDTimeStampedModel
from pamolive.vault.models import Credential


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


class AccessReviewCampaign(UUIDTimeStampedModel):
    class Status(models.TextChoices):
        OPEN = "open", "Ouverte"
        CLOSED = "closed", "Clôturée"

    name = models.CharField(max_length=160)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.OPEN)
    due_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="created_access_review_campaigns",
    )
    closed_at = models.DateTimeField(null=True, blank=True)
    closed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="closed_access_review_campaigns",
    )

    class Meta:
        ordering = ("-created_at",)

    @property
    def pending_count(self):
        return self.items.filter(decision=AccessReviewItem.Decision.PENDING).count()

    @property
    def decided_count(self):
        return self.items.exclude(decision=AccessReviewItem.Decision.PENDING).count()

    def __str__(self):
        return self.name


class AccessReviewItem(UUIDTimeStampedModel):
    class Decision(models.TextChoices):
        PENDING = "pending", "À revoir"
        KEEP = "keep", "Maintenir"
        REVOKE = "revoke", "Révoquer"

    campaign = models.ForeignKey(
        AccessReviewCampaign,
        on_delete=models.PROTECT,
        related_name="items",
    )
    policy = models.ForeignKey(
        "policies.AccessPolicy",
        on_delete=models.PROTECT,
        related_name="access_review_items",
    )
    snapshot = models.JSONField(default=dict, blank=True)
    risk_score = models.PositiveSmallIntegerField(default=0)
    decision = models.CharField(
        max_length=16,
        choices=Decision.choices,
        default=Decision.PENDING,
        db_index=True,
    )
    decided_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="access_review_decisions",
    )
    decided_at = models.DateTimeField(null=True, blank=True)
    comment = models.TextField(blank=True)

    class Meta:
        ordering = ("-risk_score", "policy__name")
        constraints = [
            models.UniqueConstraint(
                fields=("campaign", "policy"),
                name="unique_policy_per_access_review_campaign",
            )
        ]

    def __str__(self):
        return f"{self.campaign} · {self.policy} · {self.get_decision_display()}"
