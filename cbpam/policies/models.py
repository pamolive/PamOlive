from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models

from cbpam.common.models import UUIDTimeStampedModel
from cbpam.rbac.models import Role, UserGroup
from cbpam.targets.models import Target, TargetGroup


class TimeFrame(UUIDTimeStampedModel):
    name = models.CharField(max_length=150, unique=True)
    weekdays = models.JSONField(default=list, blank=True)
    start_time = models.TimeField(null=True, blank=True)
    end_time = models.TimeField(null=True, blank=True)
    valid_from = models.DateTimeField(null=True, blank=True)
    valid_until = models.DateTimeField(null=True, blank=True)
    enabled = models.BooleanField(default=True)

    def __str__(self):
        return self.name


class SecretRotationPolicy(UUIDTimeStampedModel):
    class Strategy(models.TextChoices):
        GENERATED_PASSWORD = "generated_password", "Mot de passe généré"

    name = models.CharField(max_length=150, unique=True)
    target_groups = models.ManyToManyField(
        TargetGroup,
        related_name="rotation_policies",
        blank=True,
    )
    strategy = models.CharField(
        max_length=32,
        choices=Strategy.choices,
        default=Strategy.GENERATED_PASSWORD,
    )
    interval_days = models.PositiveIntegerField(
        default=30,
        validators=[MinValueValidator(1), MaxValueValidator(3650)],
    )
    password_length = models.PositiveSmallIntegerField(
        default=32,
        validators=[MinValueValidator(16), MaxValueValidator(128)],
    )
    connector_key = models.CharField(max_length=100, blank=True)
    enabled = models.BooleanField(default=True)

    def __str__(self):
        return self.name


class AccessPolicy(UUIDTimeStampedModel):
    class Action(models.TextChoices):
        REQUEST_ACCESS = "request_access", "Demander un accès"
        START_SESSION = "start_session", "Démarrer une session"
        VIEW_SECRET = "view_secret", "Consulter un secret"
        REVEAL_TOTP = "reveal_totp", "Consulter un code TOTP"
        APPROVE_REQUEST = "approve_request", "Approuver une demande"
        MANAGE_TARGETS = "manage_targets", "Administrer les cibles"

    name = models.CharField(max_length=150, unique=True)
    roles = models.ManyToManyField(Role, blank=True)
    targets = models.ManyToManyField(Target, related_name="policies", blank=True)
    credentials = models.ManyToManyField(
        "vault.Credential",
        related_name="access_policies",
        blank=True,
    )
    user_groups = models.ManyToManyField(UserGroup, related_name="policies")
    target_groups = models.ManyToManyField(TargetGroup, related_name="policies")
    approver_groups = models.ManyToManyField(
        UserGroup,
        related_name="approval_policies",
        blank=True,
    )
    time_frames = models.ManyToManyField(
        TimeFrame,
        related_name="access_policies",
        blank=True,
    )
    actions = models.JSONField(default=list)
    protocols = models.JSONField(default=list, blank=True)
    requires_approval = models.BooleanField(default=True)
    approval_quorum = models.PositiveSmallIntegerField(
        default=1,
        validators=[MinValueValidator(1), MaxValueValidator(10)],
    )
    ticket_required = models.BooleanField(default=False)
    requires_mfa = models.BooleanField(default=True)
    max_duration_minutes = models.PositiveIntegerField(default=60)
    max_concurrent_sessions = models.PositiveSmallIntegerField(
        default=1,
        validators=[MinValueValidator(1), MaxValueValidator(50)],
    )
    allow_clipboard_copy = models.BooleanField(default=False)
    allow_clipboard_paste = models.BooleanField(default=False)
    valid_from = models.DateTimeField(null=True, blank=True)
    valid_until = models.DateTimeField(null=True, blank=True)
    weekdays = models.JSONField(default=list, blank=True)
    access_start_time = models.TimeField(null=True, blank=True)
    access_end_time = models.TimeField(null=True, blank=True)
    source_cidrs = models.JSONField(default=list, blank=True)
    enabled = models.BooleanField(default=True)

    def __str__(self):
        return self.name

    def allows(self, action):
        return action in self.actions

    @property
    def action_labels(self):
        labels = dict(self.Action.choices)
        return [labels.get(action, action) for action in self.actions]
