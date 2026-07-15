from django.conf import settings
from django.db import models

from cbpam.common.models import UUIDTimeStampedModel


class MFADevice(UUIDTimeStampedModel):
    class Kind(models.TextChoices):
        TOTP = "totp", "TOTP"
        WEBAUTHN = "webauthn", "WebAuthn"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="mfa_devices"
    )
    name = models.CharField(max_length=100)
    kind = models.CharField(max_length=20, choices=Kind.choices)
    encrypted_configuration = models.BinaryField()
    encryption_key_id = models.CharField(max_length=64, default="legacy")
    confirmed = models.BooleanField(default=False)
    last_used_at = models.DateTimeField(null=True, blank=True)
