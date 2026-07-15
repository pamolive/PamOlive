from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from cbpam.accounts.models import User
from cbpam.approvals.models import AccessRequest, ApprovalDecision
from cbpam.audit.models import AuditChainState, AuditEvent
from cbpam.connectors.models import (
    Connector,
    DirectoryGroupMapping,
    ExternalGroupMembership,
    ExternalIdentity,
    IdentitySource,
)
from cbpam.mfa.models import MFADevice
from cbpam.operations.models import RotationJob
from cbpam.policies.models import AccessPolicy, SecretRotationPolicy, TimeFrame
from cbpam.rbac.models import Role, RoleAssignment, UserGroup
from cbpam.sessions.models import PrivilegedSession, SessionTicket
from cbpam.targets.models import Domain, Target, TargetGroup, TargetHostKey
from cbpam.vault.models import Credential, PersonalVaultItem, SecretLease


@admin.register(User)
class CBPAMUserAdmin(UserAdmin):
    list_display = ("username", "email", "display_name", "is_active", "is_staff")
    fieldsets = UserAdmin.fieldsets + (
        ("CBPAM", {"fields": ("display_name", "is_service_account")}),
    )
    add_fieldsets = UserAdmin.add_fieldsets + (
        ("CBPAM", {"fields": ("email", "display_name", "is_service_account")}),
    )


@admin.register(Target)
class TargetAdmin(admin.ModelAdmin):
    list_display = ("name", "kind", "domain", "hostname", "port", "protocol", "enabled")
    list_filter = ("kind", "protocol", "enabled")
    search_fields = ("name", "hostname")


@admin.register(AccessRequest)
class AccessRequestAdmin(admin.ModelAdmin):
    list_display = ("requester", "target", "status", "requested_duration_minutes", "created_at")
    list_filter = ("status",)
    search_fields = ("requester__username", "target__name", "reason")


@admin.register(ApprovalDecision)
class ApprovalDecisionAdmin(admin.ModelAdmin):
    list_display = ("created_at", "access_request", "approver", "decision")
    readonly_fields = (
        "id",
        "created_at",
        "updated_at",
        "access_request",
        "approver",
        "decision",
        "comment",
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(AuditEvent)
class AuditEventAdmin(admin.ModelAdmin):
    list_display = ("sequence", "occurred_at", "actor", "action", "resource_type", "resource_id")
    list_filter = ("action", "resource_type")
    search_fields = ("action", "resource_id", "event_hash")
    readonly_fields = (
        "id",
        "sequence",
        "hash_version",
        "occurred_at",
        "actor",
        "action",
        "resource_type",
        "resource_id",
        "source_ip",
        "metadata",
        "previous_hash",
        "event_hash",
        "signature",
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(AuditChainState)
class AuditChainStateAdmin(admin.ModelAdmin):
    list_display = ("last_sequence", "last_hash", "updated_at")
    readonly_fields = ("last_sequence", "last_hash", "updated_at")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(Credential)
class CredentialAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "target",
        "domain",
        "username",
        "account_type",
        "kind",
        "key_version",
        "last_rotated_at",
    )
    exclude = ("encrypted_secret", "encrypted_totp_secret")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(RotationJob)
class RotationJobAdmin(admin.ModelAdmin):
    list_display = (
        "created_at",
        "credential",
        "backend",
        "status",
        "previous_key_version",
        "new_key_version",
    )
    exclude = ("encrypted_candidate_secret",)
    readonly_fields = (
        "credential",
        "requested_by",
        "reason",
        "backend",
        "status",
        "scheduled_for",
        "started_at",
        "completed_at",
        "previous_key_version",
        "new_key_version",
        "error_code",
        "error_message",
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


admin.site.register(Role)
admin.site.register(RoleAssignment)
admin.site.register(UserGroup)
admin.site.register(AccessPolicy)
admin.site.register(TimeFrame)
admin.site.register(SecretRotationPolicy)
admin.site.register(TargetGroup)
admin.site.register(PrivilegedSession)
admin.site.register(MFADevice)
admin.site.register(Connector)
admin.site.register(Domain)
admin.site.register(DirectoryGroupMapping)
admin.site.register(ExternalIdentity)
admin.site.register(ExternalGroupMembership)
admin.site.register(PersonalVaultItem)


@admin.register(TargetHostKey)
class TargetHostKeyAdmin(admin.ModelAdmin):
    list_display = (
        "target",
        "key_type",
        "fingerprint_sha256",
        "trusted_at",
        "revoked_at",
    )
    readonly_fields = (
        "target",
        "key_type",
        "public_key",
        "fingerprint_sha256",
        "comment",
        "trusted_at",
        "trusted_by",
        "revoked_at",
        "revoked_by",
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(SecretLease)
class SecretLeaseAdmin(admin.ModelAdmin):
    list_display = (
        "created_at",
        "credential",
        "user",
        "purpose",
        "expires_at",
        "use_count",
        "revoked_at",
    )
    exclude = ("token_hash",)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(SessionTicket)
class SessionTicketAdmin(admin.ModelAdmin):
    list_display = ("created_at", "session", "expires_at", "consumed_at", "revoked_at")
    exclude = ("token_hash",)
    readonly_fields = ("session", "expires_at", "consumed_at", "revoked_at", "source_ip")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(IdentitySource)
class IdentitySourceAdmin(admin.ModelAdmin):
    list_display = ("name", "kind", "enabled", "last_sync_status", "last_sync_at")
    exclude = ("encrypted_configuration",)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


def superuser_only(request):
    return request.user.is_active and request.user.is_superuser


admin.site.has_permission = superuser_only

admin.site.site_header = "PAM-olive · Administration technique"
admin.site.site_title = "PAM-olive"
admin.site.index_title = "Maintenance avancée"
