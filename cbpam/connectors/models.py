from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models

from cbpam.common.models import UUIDTimeStampedModel
from cbpam.rbac.models import UserGroup


class Connector(UUIDTimeStampedModel):
    name = models.CharField(max_length=150, unique=True)
    kind = models.CharField(max_length=100)
    enabled = models.BooleanField(default=False)
    encrypted_configuration = models.BinaryField(blank=True)
    encryption_key_id = models.CharField(max_length=64, default="keyring-v1")


class IdentitySource(UUIDTimeStampedModel):
    class Kind(models.TextChoices):
        LDAP = "ldap", "LDAP"
        ACTIVE_DIRECTORY = "active_directory", "Microsoft Active Directory"
        OIDC = "oidc", "OpenID Connect"

    class SyncStatus(models.TextChoices):
        NEVER = "never", "Jamais synchronisé"
        RUNNING = "running", "Synchronisation en cours"
        SUCCESS = "success", "Synchronisation réussie"
        FAILED = "failed", "Synchronisation en échec"

    name = models.CharField(max_length=150, unique=True)
    slug = models.SlugField(max_length=150, unique=True)
    kind = models.CharField(max_length=30, choices=Kind.choices)
    enabled = models.BooleanField(default=False)
    verify_tls = models.BooleanField(default=True)
    encrypted_configuration = models.BinaryField()
    encryption_key_id = models.CharField(max_length=64, default="keyring-v1")
    sync_enabled = models.BooleanField(default=False)
    sync_interval_minutes = models.PositiveIntegerField(
        default=60,
        validators=[MinValueValidator(5), MaxValueValidator(10080)],
    )
    last_sync_at = models.DateTimeField(null=True, blank=True)
    last_sync_status = models.CharField(
        max_length=20,
        choices=SyncStatus.choices,
        default=SyncStatus.NEVER,
    )
    last_error = models.TextField(blank=True)

    def __str__(self):
        return self.name


class ExternalIdentity(UUIDTimeStampedModel):
    source = models.ForeignKey(
        IdentitySource,
        on_delete=models.PROTECT,
        related_name="external_identities",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="external_identities",
    )
    subject = models.CharField(max_length=512)
    username = models.CharField(max_length=255)
    email = models.EmailField(blank=True)
    claims = models.JSONField(default=dict, blank=True)
    enabled = models.BooleanField(default=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=("source", "subject"),
                name="unique_external_identity_subject",
            ),
            models.UniqueConstraint(
                fields=("source", "user"),
                name="unique_external_identity_user",
            ),
        ]

    def __str__(self):
        return f"{self.source}: {self.username}"


class DirectoryGroupMapping(UUIDTimeStampedModel):
    source = models.ForeignKey(
        IdentitySource,
        on_delete=models.CASCADE,
        related_name="group_mappings",
    )
    external_group = models.CharField(max_length=512)
    user_group = models.ForeignKey(
        UserGroup,
        on_delete=models.PROTECT,
        related_name="directory_mappings",
    )
    auto_create_users = models.BooleanField(default=True)
    enabled = models.BooleanField(default=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=("source", "external_group"),
                name="unique_directory_group_mapping",
            )
        ]

    def __str__(self):
        return f"{self.external_group} → {self.user_group}"


class ExternalGroupMembership(UUIDTimeStampedModel):
    identity = models.ForeignKey(
        ExternalIdentity,
        on_delete=models.CASCADE,
        related_name="managed_group_memberships",
    )
    mapping = models.ForeignKey(
        DirectoryGroupMapping,
        on_delete=models.CASCADE,
        related_name="managed_memberships",
    )
    preserve_membership_on_unlink = models.BooleanField(default=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=("identity", "mapping"),
                name="unique_external_group_membership",
            )
        ]

    def __str__(self):
        return f"{self.identity} → {self.mapping.user_group}"
