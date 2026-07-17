from django.conf import settings
from django.contrib.auth.models import Permission
from django.db import models
from django.utils import timezone

from pamolive.common.models import UUIDTimeStampedModel


class Role(UUIDTimeStampedModel):
    class Capability(models.TextChoices):
        CONSOLE_ACCESS = "console.access", "Accéder à l’administration"
        CONFIGURATION_VIEW = "configuration.view", "Consulter la configuration"
        USERS_VIEW = "users.view", "Consulter les utilisateurs"
        USERS_MANAGE = "users.manage", "Gérer les utilisateurs"
        GROUPS_VIEW = "groups.view", "Consulter les groupes"
        GROUPS_MANAGE = "groups.manage", "Gérer les groupes"
        ROLES_VIEW = "roles.view", "Consulter les rôles"
        ROLES_MANAGE = "roles.manage", "Gérer les rôles"
        IDENTITY_SOURCES_VIEW = "identity_sources.view", "Consulter les sources d’identité"
        IDENTITY_SOURCES_MANAGE = "identity_sources.manage", "Gérer les sources d’identité"
        IDENTITY_SOURCES_SYNC = "identity_sources.sync", "Synchroniser les sources d’identité"
        TARGETS_VIEW = "targets.view", "Consulter les cibles"
        TARGETS_MANAGE = "targets.manage", "Gérer les cibles"
        TARGET_GROUPS_VIEW = "target_groups.view", "Consulter les groupes de cibles"
        TARGET_GROUPS_MANAGE = "target_groups.manage", "Gérer les groupes de cibles"
        DOMAINS_VIEW = "domains.view", "Consulter les domaines"
        DOMAINS_MANAGE = "domains.manage", "Gérer les domaines"
        CREDENTIALS_VIEW_METADATA = (
            "credentials.view_metadata",
            "Consulter les métadonnées des identifiants",
        )
        CREDENTIALS_MANAGE = "credentials.manage", "Gérer les identifiants"
        CREDENTIALS_REVEAL = "credentials.reveal", "Révéler les secrets autorisés"
        CREDENTIALS_ROTATE = "credentials.rotate", "Déclencher la rotation des secrets"
        POLICIES_VIEW = "policies.view", "Consulter les politiques"
        POLICIES_MANAGE = "policies.manage", "Gérer les politiques"
        APPROVALS_VIEW = "approvals.view", "Consulter les approbations"
        APPROVALS_DECIDE = "approvals.decide", "Décider des approbations"
        AUDIT_VIEW = "audit.view", "Consulter l’audit"
        AUDIT_EXPORT = "audit.export", "Exporter les événements d’audit"
        SESSIONS_VIEW = "sessions.view", "Consulter les sessions"
        SESSIONS_TERMINATE = "sessions.terminate", "Terminer une session"
        SESSIONS_JOIN = "sessions.join", "Rejoindre une session supervisée"
        SYSTEM_VIEW = "system.view", "Consulter l’état du système"
        SYSTEM_MANAGE = "system.manage", "Gérer les paramètres système"

    name = models.CharField(max_length=100, unique=True)
    slug = models.SlugField(max_length=100, unique=True, null=True, blank=True)
    description = models.TextField(blank=True)
    permissions = models.ManyToManyField(Permission, blank=True)
    capabilities = models.JSONField(default=list, blank=True)
    is_system = models.BooleanField(default=False)
    enabled = models.BooleanField(default=True)

    def __str__(self):
        return self.name

    def allows(self, capability):
        return capability in self.capabilities


class RoleAssignment(UUIDTimeStampedModel):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    valid_from = models.DateTimeField(default=timezone.now)
    valid_until = models.DateTimeField(null=True, blank=True)
    assigned_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="granted_role_assignments",
    )
    reason = models.TextField(blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["user", "role"], name="unique_role_assignment")
        ]


class UserGroup(UUIDTimeStampedModel):
    name = models.CharField(max_length=120, unique=True)
    description = models.TextField(blank=True)
    users = models.ManyToManyField(
        settings.AUTH_USER_MODEL, related_name="pam_user_groups", blank=True
    )
    roles = models.ManyToManyField(Role, related_name="user_groups", blank=True)
    enabled = models.BooleanField(default=True)

    def __str__(self):
        return self.name

    @property
    def has_active_policy(self):
        return self.policies.filter(enabled=True).exists()
