import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from cbpam.common.models import UUIDTimeStampedModel


class AuditChainState(models.Model):
    id = models.PositiveSmallIntegerField(primary_key=True, default=1, editable=False)
    last_sequence = models.PositiveBigIntegerField(default=0)
    last_hash = models.CharField(max_length=64, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Chaîne d’audit · {self.last_sequence} événements"


class AuditEvent(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    occurred_at = models.DateTimeField(default=timezone.now, editable=False, db_index=True)
    sequence = models.PositiveBigIntegerField(unique=True)
    hash_version = models.PositiveSmallIntegerField(default=2)
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.PROTECT)
    action = models.CharField(max_length=150, db_index=True)
    resource_type = models.CharField(max_length=100)
    resource_id = models.CharField(max_length=100)
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    previous_hash = models.CharField(max_length=64, blank=True)
    event_hash = models.CharField(max_length=64, unique=True)
    signature = models.CharField(max_length=64, blank=True)

    class Meta:
        ordering = ["-occurred_at"]

    def __str__(self):
        return f"{self.occurred_at} {self.action}"

    def save(self, *args, **kwargs):
        if self.pk and AuditEvent.objects.filter(pk=self.pk).exists():
            raise RuntimeError("Audit events are immutable")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise RuntimeError("Audit events cannot be deleted")


class SIEMIntegration(UUIDTimeStampedModel):
    class Kind(models.TextChoices):
        HTTPS_WEBHOOK = "https_webhook", "HTTPS webhook"
        SYSLOG_TLS = "syslog_tls", "Syslog over TLS"

    name = models.CharField(max_length=120, unique=True)
    kind = models.CharField(max_length=30, choices=Kind.choices)
    endpoint = models.URLField(blank=True)
    host = models.CharField(max_length=253, blank=True)
    port = models.PositiveIntegerField(default=6514)
    verify_tls = models.BooleanField(default=True)
    enabled = models.BooleanField(default=True)
    encrypted_auth_token = models.BinaryField(null=True, blank=True, editable=False)
    auth_token_encryption_key_id = models.CharField(max_length=64, blank=True, editable=False)
    last_delivery_at = models.DateTimeField(null=True, blank=True, editable=False)
    last_status = models.CharField(max_length=20, blank=True, editable=False)
    last_error = models.CharField(max_length=500, blank=True, editable=False)

    class Meta:
        ordering = ("name",)

    def __str__(self):
        return self.name

    def clean(self):
        if self.kind == self.Kind.HTTPS_WEBHOOK:
            if not self.endpoint.startswith("https://"):
                raise ValidationError({"endpoint": "An HTTPS URL is required."})
        elif self.kind == self.Kind.SYSLOG_TLS and not self.host:
            raise ValidationError({"host": "A syslog host is required."})


class SIEMDelivery(models.Model):
    class Status(models.TextChoices):
        DELIVERED = "delivered", "Delivered"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    integration = models.ForeignKey(
        SIEMIntegration,
        on_delete=models.PROTECT,
        related_name="deliveries",
    )
    event = models.ForeignKey(
        AuditEvent,
        on_delete=models.PROTECT,
        related_name="siem_deliveries",
    )
    attempted_at = models.DateTimeField(default=timezone.now, db_index=True)
    delivered_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=Status.choices)
    payload_hash = models.CharField(max_length=64)
    error = models.CharField(max_length=500, blank=True)

    class Meta:
        ordering = ("-attempted_at",)
        constraints = [
            models.UniqueConstraint(
                fields=("integration", "event"),
                name="audit_unique_siem_delivery",
            )
        ]

    def __str__(self):
        return f"{self.integration} · audit event {self.event.sequence} · {self.status}"
