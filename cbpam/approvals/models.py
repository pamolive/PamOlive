from django.conf import settings
from django.db import models

from cbpam.common.models import UUIDTimeStampedModel
from cbpam.policies.models import AccessPolicy
from cbpam.targets.models import Target


class AccessRequest(UUIDTimeStampedModel):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        APPROVED = "approved", "Approved"
        REJECTED = "rejected", "Rejected"
        CANCELLED = "cancelled", "Cancelled"
        EXPIRED = "expired", "Expired"

    requester = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="access_requests"
    )
    target = models.ForeignKey(Target, on_delete=models.PROTECT)
    policy = models.ForeignKey(AccessPolicy, on_delete=models.PROTECT)
    reason = models.TextField()
    ticket_reference = models.CharField(max_length=255, blank=True)
    requested_duration_minutes = models.PositiveIntegerField()
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    decided_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="access_decisions",
    )
    decided_at = models.DateTimeField(null=True, blank=True)
    decision_comment = models.TextField(blank=True)

    @property
    def approval_count(self):
        return self.decisions.filter(decision=ApprovalDecision.Decision.APPROVE).count()


class ApprovalDecision(UUIDTimeStampedModel):
    class Decision(models.TextChoices):
        APPROVE = "approve", "Approuver"
        REJECT = "reject", "Refuser"

    access_request = models.ForeignKey(
        AccessRequest,
        on_delete=models.PROTECT,
        related_name="decisions",
    )
    approver = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="approval_decisions",
    )
    decision = models.CharField(max_length=10, choices=Decision.choices)
    comment = models.TextField(blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=("access_request", "approver"),
                name="unique_approval_decision_per_approver",
            )
        ]
        ordering = ("created_at",)

    def save(self, *args, **kwargs):
        if self.pk and ApprovalDecision.objects.filter(pk=self.pk).exists():
            raise RuntimeError("Approval decisions are immutable")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise RuntimeError("Approval decisions cannot be deleted")

    def __str__(self):
        return f"{self.approver}: {self.get_decision_display()}"
