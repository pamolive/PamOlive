from django.conf import settings
from django.db import models

from cbpam.approvals.models import AccessRequest
from cbpam.common.models import UUIDTimeStampedModel
from cbpam.policies.models import AccessPolicy
from cbpam.targets.models import Target


class PersonalVaultGroup(UUIDTimeStampedModel):
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="personal_vault_groups",
    )
    name = models.CharField(max_length=120)

    class Meta:
        ordering = ("name",)
        constraints = [
            models.UniqueConstraint(
                fields=("owner", "name"),
                name="unique_personal_vault_group_name_per_owner",
            )
        ]

    def __str__(self):
        return self.name


class Credential(UUIDTimeStampedModel):
    class RotationStatus(models.TextChoices):
        NEVER = "never", "Jamais exécutée"
        SUCCEEDED = "succeeded", "Réussie"
        FAILED = "failed", "Échec"
        BLOCKED = "blocked", "Action requise"

    class AccountType(models.TextChoices):
        LOCAL = "local", "Compte local"
        DOMAIN = "domain", "Compte de domaine"
        SERVICE = "service", "Compte de service"
        APPLICATION = "application", "Compte d’application"

    class Kind(models.TextChoices):
        PASSWORD = "password", "Password"
        SSH_KEY = "ssh_key", "SSH private key"
        TOTP = "totp", "TOTP seed"

    name = models.CharField(max_length=150)
    target = models.ForeignKey(Target, on_delete=models.CASCADE, related_name="credentials")
    domain = models.ForeignKey(
        "targets.Domain",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="credentials",
    )
    username = models.CharField(max_length=255)
    account_type = models.CharField(
        max_length=20,
        choices=AccountType.choices,
        default=AccountType.LOCAL,
    )
    kind = models.CharField(max_length=20, choices=Kind.choices)
    encrypted_secret = models.BinaryField()
    secret_encryption_key_id = models.CharField(max_length=64, default="legacy")
    encrypted_totp_secret = models.BinaryField(null=True, blank=True)
    totp_encryption_key_id = models.CharField(max_length=64, default="legacy")
    key_version = models.PositiveIntegerField(default=1)
    checkout_enabled = models.BooleanField(default=True)
    rotation_enabled = models.BooleanField(default=False)
    rotation_interval_days = models.PositiveIntegerField(null=True, blank=True)
    rotation_backend = models.CharField(max_length=100, blank=True)
    rotation_policy = models.ForeignKey(
        "policies.SecretRotationPolicy",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="credentials",
    )
    last_rotated_at = models.DateTimeField(null=True, blank=True)
    next_rotation_at = models.DateTimeField(null=True, blank=True, db_index=True)
    last_rotation_status = models.CharField(
        max_length=20,
        choices=RotationStatus.choices,
        default=RotationStatus.NEVER,
    )
    rotation_failure_count = models.PositiveSmallIntegerField(default=0)
    last_checked_out_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.name

    @property
    def effective_rotation_interval_days(self):
        if self.rotation_policy_id and self.rotation_policy.enabled:
            return self.rotation_policy.interval_days
        return self.rotation_interval_days

    @property
    def effective_rotation_backend(self):
        if self.rotation_policy_id and self.rotation_policy.enabled:
            return self.rotation_policy.connector_key
        return self.rotation_backend

    @property
    def automatic_rotation_enabled(self):
        return bool(
            (self.rotation_policy_id and self.rotation_policy.enabled)
            or self.rotation_enabled
        )


class PersonalVaultItem(UUIDTimeStampedModel):
    class ItemType(models.TextChoices):
        LOGIN = "login", "Identifiant"
        TOTP = "totp", "TOTP"
        CARD = "card", "Carte bancaire"
        NOTE = "note", "Note sécurisée"

    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="personal_vault_items",
    )
    group = models.ForeignKey(
        PersonalVaultGroup,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="items",
    )
    name = models.CharField(max_length=180)
    item_type = models.CharField(max_length=20, choices=ItemType.choices)
    encrypted_payload = models.BinaryField()
    encryption_key_id = models.CharField(max_length=64, default="legacy")
    favorite = models.BooleanField(default=False)

    class Meta:
        ordering = ("-favorite", "name")

    def __str__(self):
        return self.name


class SecretLease(UUIDTimeStampedModel):
    class Purpose(models.TextChoices):
        REVEAL = "reveal", "Consultation interactive"
        SESSION = "session", "Ouverture de session"
        ROTATION = "rotation", "Rotation"

    credential = models.ForeignKey(
        Credential,
        on_delete=models.PROTECT,
        related_name="leases",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="secret_leases",
    )
    policy = models.ForeignKey(AccessPolicy, on_delete=models.PROTECT)
    access_request = models.ForeignKey(
        AccessRequest,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="secret_leases",
    )
    purpose = models.CharField(max_length=20, choices=Purpose.choices)
    token_hash = models.CharField(max_length=64, unique=True)
    expires_at = models.DateTimeField(db_index=True)
    max_uses = models.PositiveSmallIntegerField(default=1)
    use_count = models.PositiveSmallIntegerField(default=0)
    consumed_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    source_ip = models.GenericIPAddressField(null=True, blank=True)

    def __str__(self):
        return f"{self.credential} · {self.get_purpose_display()}"
