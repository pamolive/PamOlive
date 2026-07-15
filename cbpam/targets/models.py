from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils import timezone

from cbpam.common.models import UUIDTimeStampedModel


class Domain(UUIDTimeStampedModel):
    class Kind(models.TextChoices):
        LOCAL = "local", "Domaine local"
        ACTIVE_DIRECTORY = "active_directory", "Microsoft Active Directory"

    name = models.CharField(max_length=150, unique=True)
    kind = models.CharField(max_length=30, choices=Kind.choices, default=Kind.LOCAL)
    dns_name = models.CharField(max_length=255, blank=True)
    description = models.TextField(blank=True)
    enabled = models.BooleanField(default=True)

    def __str__(self):
        return self.name


class Target(UUIDTimeStampedModel):
    class SSHHostKeyPolicy(models.TextChoices):
        TRUST_ON_FIRST_USE = "tofu", "Trust on first use"
        STRICT = "strict", "Require prior administrator approval"

    class Kind(models.TextChoices):
        DEVICE = "device", "Équipement"
        APPLICATION = "application", "Application"
        WEB_APPLICATION = "web_application", "Application web"

    class Protocol(models.TextChoices):
        SSH = "ssh", "SSH"
        RDP = "rdp", "RDP"
        WEB = "web", "HTTPS / Web"
        VNC = "vnc", "VNC"
        TELNET = "telnet", "TELNET"
        RAW_TCP = "raw_tcp", "TCP brut"

    class RDPSecurity(models.TextChoices):
        NLA = "nla", "NLA / CredSSP"
        NLA_EXT = "nla-ext", "NLA étendu"
        TLS = "tls", "TLS / RDSTLS"

    class RDPResizeMethod(models.TextChoices):
        DISPLAY_UPDATE = "display-update", "Display Update (RDP 8.1+)"
        RECONNECT = "reconnect", "Reconnexion"

    name = models.CharField(max_length=150, unique=True)
    kind = models.CharField(max_length=30, choices=Kind.choices, default=Kind.DEVICE)
    domain = models.ForeignKey(
        Domain,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="targets",
    )
    hostname = models.CharField(max_length=255)
    port = models.PositiveIntegerField(validators=[MinValueValidator(1), MaxValueValidator(65535)])
    protocol = models.CharField(max_length=16, choices=Protocol.choices)
    ssh_host_key_policy = models.CharField(
        max_length=16,
        choices=SSHHostKeyPolicy.choices,
        default=SSHHostKeyPolicy.TRUST_ON_FIRST_USE,
    )
    platform = models.CharField(max_length=100, blank=True)
    description = models.TextField(blank=True)
    enabled = models.BooleanField(default=True)
    labels = models.JSONField(default=dict, blank=True)
    rdp_security = models.CharField(
        max_length=16,
        choices=RDPSecurity.choices,
        default=RDPSecurity.NLA,
    )
    rdp_certificate_fingerprints = models.TextField(blank=True)
    rdp_server_layout = models.CharField(max_length=32, default="fr-be-azerty")
    rdp_resize_method = models.CharField(
        max_length=20,
        choices=RDPResizeMethod.choices,
        default=RDPResizeMethod.DISPLAY_UPDATE,
    )

    def __str__(self):
        return self.name


class TargetGroup(UUIDTimeStampedModel):
    name = models.CharField(max_length=120, unique=True)
    description = models.TextField(blank=True)
    targets = models.ManyToManyField(Target, related_name="target_groups", blank=True)
    enabled = models.BooleanField(default=True)

    def __str__(self):
        return self.name


class TargetHostKey(UUIDTimeStampedModel):
    target = models.ForeignKey(Target, on_delete=models.PROTECT, related_name="host_keys")
    key_type = models.CharField(max_length=64, editable=False)
    public_key = models.TextField()
    fingerprint_sha256 = models.CharField(max_length=100, editable=False)
    comment = models.CharField(max_length=255, blank=True)
    trusted_at = models.DateTimeField(default=timezone.now, editable=False)
    trusted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="trusted_target_host_keys",
    )
    revoked_at = models.DateTimeField(null=True, blank=True, editable=False)
    revoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="revoked_target_host_keys",
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=("target", "fingerprint_sha256"),
                name="unique_target_host_key_fingerprint",
            )
        ]

    def save(self, *args, **kwargs):
        from .services import parse_ssh_public_key

        key_type, public_key, fingerprint = parse_ssh_public_key(self.public_key)
        self.key_type = key_type
        self.public_key = public_key
        self.fingerprint_sha256 = fingerprint
        return super().save(*args, **kwargs)

    @property
    def active(self):
        return self.revoked_at is None

    def __str__(self):
        return f"{self.target} · {self.fingerprint_sha256}"
