import base64
import csv
import hashlib
import io
import json

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.db.models import Count, Q
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.dateparse import parse_date
from django.views.decorators.http import require_POST

from cbpam.accounts.models import User
from cbpam.approvals.models import AccessRequest, ApprovalDecision
from cbpam.approvals.services import decide_access_request
from cbpam.audit.models import AuditEvent
from cbpam.audit.services import record_event, redact_metadata, verify_audit_chain
from cbpam.connectors.models import DirectoryGroupMapping, IdentitySource
from cbpam.operations.models import RotationJob
from cbpam.operations.services import queue_rotation
from cbpam.operations.tasks import execute_rotation_job
from cbpam.policies.models import AccessPolicy, SecretRotationPolicy, TimeFrame
from cbpam.rbac.models import Role, UserGroup
from cbpam.rbac.services import can_view_configuration, capability_required, user_has_capability
from cbpam.sessions.control import notify_gateway_termination
from cbpam.sessions.models import PrivilegedSession
from cbpam.sessions.services import request_session_termination
from cbpam.targets.models import Domain, Target, TargetGroup, TargetHostKey
from cbpam.vault.models import Credential

from .forms import (
    AccessPolicyForm,
    DirectoryGroupMappingForm,
    DomainForm,
    LDAPIdentitySourceForm,
    OIDCIdentitySourceForm,
    RoleForm,
    SecretRotationPolicyForm,
    TargetCredentialForm,
    TargetForm,
    TargetGroupForm,
    TargetHostKeyForm,
    TimeFrameForm,
    UserCreateForm,
    UserGroupForm,
    UserUpdateForm,
)


def _configuration_permission(request, capability, view_capability=None):
    can_manage = user_has_capability(request.user, capability)
    if not can_manage and not can_view_configuration(
        request.user, capability, view_capability=view_capability
    ):
        raise PermissionDenied
    if request.method == "POST" and not can_manage:
        raise PermissionDenied
    return can_manage


def _save_form(request, form, success_message, redirect_name):
    if form.is_valid():
        resource = form.save()
        record_event(
            actor=request.user,
            action=f"console.{resource._meta.model_name}.saved",
            resource=resource,
        )
        messages.success(request, success_message)
        return redirect(redirect_name)
    return None


def _render_resource(
    request,
    form,
    objects,
    resource,
    editing,
    can_manage,
    extra_context=None,
):
    if not can_manage:
        for field in form.fields.values():
            field.disabled = True
    context = {
        "form": form,
        "objects": objects,
        "resource": resource,
        "editing": editing,
        "can_manage": can_manage,
    }
    context.update(extra_context or {})
    return render(
        request,
        "console/resource.html",
        context,
    )


@login_required
def host_keys(request):
    can_manage = _configuration_permission(
        request,
        Role.Capability.TARGETS_MANAGE,
        Role.Capability.TARGETS_VIEW,
    )
    form = TargetHostKeyForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        host_key = form.save(commit=False)
        host_key.trusted_by = request.user
        host_key.save()
        record_event(
            actor=request.user,
            action="target.host_key_trusted",
            resource=host_key,
            metadata={
                "target_id": str(host_key.target_id),
                "fingerprint": host_key.fingerprint_sha256,
            },
            source_ip=request.META.get("REMOTE_ADDR"),
        )
        messages.success(request, "La clé d’hôte SSH a été approuvée et auditée.")
        return redirect("console:host_keys")
    if not can_manage:
        for field in form.fields.values():
            field.disabled = True
    objects = TargetHostKey.objects.select_related(
        "target", "trusted_by", "revoked_by"
    ).order_by("target__name", "-trusted_at")
    return render(
        request,
        "console/host_keys.html",
        {"form": form, "host_keys": objects, "can_manage": can_manage},
    )


@require_POST
@login_required
@capability_required(Role.Capability.TARGETS_MANAGE)
def revoke_host_key(request, pk):
    host_key = get_object_or_404(TargetHostKey, pk=pk, revoked_at__isnull=True)
    host_key.revoked_at = timezone.now()
    host_key.revoked_by = request.user
    host_key.save(update_fields=("revoked_at", "revoked_by", "updated_at"))
    record_event(
        actor=request.user,
        action="target.host_key_revoked",
        resource=host_key,
        metadata={
            "target_id": str(host_key.target_id),
            "fingerprint": host_key.fingerprint_sha256,
        },
        source_ip=request.META.get("REMOTE_ADDR"),
    )
    messages.success(request, "La clé d’hôte SSH a été révoquée.")
    return redirect("console:host_keys")


@login_required
@capability_required(Role.Capability.CONSOLE_ACCESS)
def dashboard(request):
    groups_without_policy = (
        UserGroup.objects.filter(enabled=True).exclude(policies__enabled=True).distinct().count()
    )
    targets_without_credentials = Target.objects.filter(
        enabled=True, credentials__isnull=True
    ).count()
    context = {
        "user_count": User.objects.filter(is_active=True).count(),
        "user_group_count": UserGroup.objects.filter(enabled=True).count(),
        "target_count": Target.objects.filter(enabled=True).count(),
        "target_group_count": TargetGroup.objects.filter(enabled=True).count(),
        "domain_count": Domain.objects.filter(enabled=True).count(),
        "identity_source_count": IdentitySource.objects.filter(enabled=True).count(),
        "policy_count": AccessPolicy.objects.filter(enabled=True).count(),
        "pending_approval_count": AccessRequest.objects.filter(
            status=AccessRequest.Status.PENDING
        ).count(),
        "groups_without_policy": groups_without_policy,
        "targets_without_credentials": targets_without_credentials,
    }
    return render(request, "console/dashboard.html", context)


@login_required
@capability_required(Role.Capability.CONSOLE_ACCESS)
def users(request, pk=None):
    can_manage = _configuration_permission(
        request, Role.Capability.USERS_MANAGE, Role.Capability.USERS_VIEW
    )
    instance = get_object_or_404(User, pk=pk) if pk else None
    form_class = UserUpdateForm if instance else UserCreateForm
    form = form_class(request.POST or None, instance=instance)
    if request.method == "POST":
        response = _save_form(request, form, "Utilisateur enregistré.", "console:users")
        if response:
            return response
    return _render_resource(
        request, form, User.objects.order_by("username"), "users", instance, can_manage
    )


@login_required
@capability_required(Role.Capability.CONSOLE_ACCESS)
def user_groups(request, pk=None):
    can_manage = _configuration_permission(
        request, Role.Capability.GROUPS_MANAGE, Role.Capability.GROUPS_VIEW
    )
    instance = get_object_or_404(UserGroup, pk=pk) if pk else None
    form = UserGroupForm(request.POST or None, instance=instance)
    if request.method == "POST":
        response = _save_form(
            request, form, "Groupe d’utilisateurs enregistré.", "console:user_groups"
        )
        if response:
            return response
    objects = UserGroup.objects.annotate(
        member_count=Count("users", distinct=True)
    ).prefetch_related("policies", "roles")
    return _render_resource(request, form, objects, "user_groups", instance, can_manage)


@login_required
@capability_required(Role.Capability.CONSOLE_ACCESS)
def roles(request, pk=None):
    can_manage = _configuration_permission(
        request, Role.Capability.ROLES_MANAGE, Role.Capability.ROLES_VIEW
    )
    instance = get_object_or_404(Role, pk=pk) if pk else None
    form = RoleForm(request.POST or None, instance=instance)
    if request.method == "POST":
        response = _save_form(request, form, "Rôle enregistré.", "console:roles")
        if response:
            return response
    return _render_resource(
        request, form, Role.objects.order_by("name"), "roles", instance, can_manage
    )


@login_required
@capability_required(Role.Capability.CONSOLE_ACCESS)
def _identity_sources(request, *, kind, form_class, resource, redirect_name, pk=None):
    can_manage = _configuration_permission(
        request,
        Role.Capability.IDENTITY_SOURCES_MANAGE,
        Role.Capability.IDENTITY_SOURCES_VIEW,
    )
    kinds = kind if isinstance(kind, (tuple, list, set)) else (kind,)
    instance = get_object_or_404(IdentitySource, pk=pk, kind__in=kinds) if pk else None
    form = form_class(request.POST or None, instance=instance)
    if request.method == "POST":
        response = _save_form(
            request,
            form,
            "Source d’identité enregistrée.",
            redirect_name,
        )
        if response:
            return response
    objects = IdentitySource.objects.filter(kind__in=kinds).annotate(
        identity_count=Count("external_identities", distinct=True),
        mapping_count=Count("group_mappings", distinct=True),
    ).order_by("name")
    return _render_resource(
        request, form, objects, resource, instance, can_manage
    )


@login_required
@capability_required(Role.Capability.CONSOLE_ACCESS)
def ldap_sources(request, pk=None):
    return _identity_sources(
        request,
        kind=(IdentitySource.Kind.LDAP, IdentitySource.Kind.ACTIVE_DIRECTORY),
        form_class=LDAPIdentitySourceForm,
        resource="ldap_sources",
        redirect_name="console:ldap_sources",
        pk=pk,
    )


@login_required
@capability_required(Role.Capability.CONSOLE_ACCESS)
def oidc_sources(request, pk=None):
    return _identity_sources(
        request,
        kind=IdentitySource.Kind.OIDC,
        form_class=OIDCIdentitySourceForm,
        resource="oidc_sources",
        redirect_name="console:oidc_sources",
        pk=pk,
    )


@login_required
@capability_required(Role.Capability.CONSOLE_ACCESS)
def identity_sources(request, pk=None):
    return _identity_sources(
        request,
        kind=(IdentitySource.Kind.LDAP, IdentitySource.Kind.ACTIVE_DIRECTORY),
        form_class=LDAPIdentitySourceForm,
        resource="identity_sources",
        redirect_name="console:identity_sources",
        pk=pk,
    )


@login_required
@capability_required(Role.Capability.CONSOLE_ACCESS)
def directory_mappings(request, pk=None):
    can_manage = _configuration_permission(
        request,
        Role.Capability.IDENTITY_SOURCES_MANAGE,
        Role.Capability.IDENTITY_SOURCES_VIEW,
    )
    instance = get_object_or_404(DirectoryGroupMapping, pk=pk) if pk else None
    form = DirectoryGroupMappingForm(request.POST or None, instance=instance)
    if request.method == "POST":
        response = _save_form(
            request,
            form,
            "Correspondance de groupe enregistrée.",
            "console:directory_mappings",
        )
        if response:
            return response
    objects = DirectoryGroupMapping.objects.select_related("source", "user_group").order_by(
        "source__name", "external_group"
    )
    return _render_resource(
        request, form, objects, "directory_mappings", instance, can_manage
    )


@login_required
@capability_required(Role.Capability.CONSOLE_ACCESS)
def targets(request, pk=None):
    can_manage = _configuration_permission(
        request, Role.Capability.TARGETS_MANAGE, Role.Capability.TARGETS_VIEW
    )
    instance = get_object_or_404(Target, pk=pk) if pk else None
    form = TargetForm(request.POST or None, instance=instance)
    if request.method == "POST" and form.is_valid():
        with transaction.atomic():
            target = form.save()
            credential = form.save_initial_credential(target)
            record_event(actor=request.user, action="console.target.saved", resource=target)
            if credential:
                record_event(
                    actor=request.user,
                    action="console.credential.created",
                    resource=credential,
                )
        messages.success(request, "Cible et identifiant local enregistrés.")
        return redirect("console:targets")
    return _render_resource(
        request,
        form,
        Target.objects.annotate(credential_count=Count("credentials")).order_by("name"),
        "targets",
        instance,
        can_manage,
    )


@login_required
@capability_required(Role.Capability.CONSOLE_ACCESS)
def target_groups(request, pk=None):
    can_manage = _configuration_permission(
        request,
        Role.Capability.TARGET_GROUPS_MANAGE,
        Role.Capability.TARGET_GROUPS_VIEW,
    )
    instance = get_object_or_404(TargetGroup, pk=pk) if pk else None
    form = TargetGroupForm(request.POST or None, instance=instance)
    if request.method == "POST":
        response = _save_form(
            request, form, "Groupe de cibles enregistré.", "console:target_groups"
        )
        if response:
            return response
    objects = TargetGroup.objects.annotate(target_count=Count("targets", distinct=True))
    return _render_resource(request, form, objects, "target_groups", instance, can_manage)


@login_required
@capability_required(Role.Capability.CONSOLE_ACCESS)
def domains(request, pk=None):
    can_manage = _configuration_permission(
        request, Role.Capability.DOMAINS_MANAGE, Role.Capability.DOMAINS_VIEW
    )
    instance = get_object_or_404(Domain, pk=pk) if pk else None
    form = DomainForm(request.POST or None, instance=instance)
    if request.method == "POST":
        response = _save_form(
            request, form, "Domaine enregistré.", "console:domains"
        )
        if response:
            return response
    objects = Domain.objects.annotate(
        target_count=Count("targets", distinct=True),
        credential_count=Count("credentials", distinct=True),
    ).order_by("name")
    return _render_resource(request, form, objects, "domains", instance, can_manage)


@login_required
@capability_required(Role.Capability.CONSOLE_ACCESS)
def credentials(request, pk=None):
    can_manage = _configuration_permission(
        request,
        Role.Capability.CREDENTIALS_MANAGE,
        Role.Capability.CREDENTIALS_VIEW_METADATA,
    )
    instance = get_object_or_404(Credential, pk=pk) if pk else None
    form = TargetCredentialForm(request.POST or None, instance=instance)
    if request.method == "POST":
        response = _save_form(
            request, form, "Identifiant de cible enregistré.", "console:credentials"
        )
        if response:
            return response
    objects = Credential.objects.select_related("target").order_by("target__name", "name")
    return _render_resource(
        request,
        form,
        objects,
        "credentials",
        instance,
        can_manage,
        {
            "can_rotate": user_has_capability(
                request.user,
                Role.Capability.CREDENTIALS_ROTATE,
            )
        },
    )


@require_POST
@login_required
@capability_required(Role.Capability.CREDENTIALS_ROTATE)
def rotate_credential(request, pk):
    credential = get_object_or_404(Credential, pk=pk)
    job, created = queue_rotation(
        credential=credential,
        requested_by=request.user,
        reason="Rotation manuelle depuis la console",
    )
    if created:
        transaction.on_commit(lambda: execute_rotation_job.delay(str(job.pk)), robust=True)
        messages.success(request, "La rotation a été placée dans la file sécurisée.")
    else:
        messages.info(request, "Une rotation est déjà en attente ou en cours.")
    return redirect("console:rotation_jobs")


@login_required
def rotation_jobs(request):
    if not (
        user_has_capability(request.user, Role.Capability.CREDENTIALS_VIEW_METADATA)
        or user_has_capability(request.user, Role.Capability.CREDENTIALS_ROTATE)
    ):
        raise PermissionDenied
    jobs = RotationJob.objects.select_related(
        "credential",
        "credential__target",
        "requested_by",
    ).order_by("-created_at")[:200]
    return render(request, "console/rotation_jobs.html", {"rotation_jobs": jobs})


@login_required
@capability_required(Role.Capability.CONSOLE_ACCESS)
def policies(request, pk=None):
    can_manage = _configuration_permission(
        request, Role.Capability.POLICIES_MANAGE, Role.Capability.POLICIES_VIEW
    )
    instance = get_object_or_404(AccessPolicy, pk=pk) if pk else None
    form = AccessPolicyForm(request.POST or None, instance=instance)
    if request.method == "POST":
        response = _save_form(request, form, "Politique enregistrée.", "console:policies")
        if response:
            return response
    objects = AccessPolicy.objects.prefetch_related(
        "user_groups", "target_groups", "approver_groups"
    ).order_by("name")
    return _render_resource(request, form, objects, "policies", instance, can_manage)


@login_required
@capability_required(Role.Capability.CONSOLE_ACCESS)
def time_frames(request, pk=None):
    can_manage = _configuration_permission(
        request, Role.Capability.POLICIES_MANAGE, Role.Capability.POLICIES_VIEW
    )
    instance = get_object_or_404(TimeFrame, pk=pk) if pk else None
    form = TimeFrameForm(request.POST or None, instance=instance)
    if request.method == "POST":
        response = _save_form(
            request, form, "Plage horaire enregistrée.", "console:time_frames"
        )
        if response:
            return response
    return _render_resource(
        request, form, TimeFrame.objects.order_by("name"), "time_frames", instance, can_manage
    )


@login_required
@capability_required(Role.Capability.CONSOLE_ACCESS)
def rotation_policies(request, pk=None):
    can_manage = _configuration_permission(
        request, Role.Capability.POLICIES_MANAGE, Role.Capability.POLICIES_VIEW
    )
    instance = get_object_or_404(SecretRotationPolicy, pk=pk) if pk else None
    form = SecretRotationPolicyForm(request.POST or None, instance=instance)
    if request.method == "POST":
        response = _save_form(
            request,
            form,
            "Politique de rotation enregistrée.",
            "console:rotation_policies",
        )
        if response:
            return response
    objects = SecretRotationPolicy.objects.prefetch_related("target_groups").order_by("name")
    return _render_resource(
        request, form, objects, "rotation_policies", instance, can_manage
    )


@login_required
@capability_required(Role.Capability.APPROVALS_VIEW)
def approvals(request):
    can_decide = user_has_capability(request.user, Role.Capability.APPROVALS_DECIDE)
    if request.method == "POST":
        if not can_decide:
            raise PermissionDenied
        access_request = get_object_or_404(AccessRequest, pk=request.POST.get("request_id"))
        try:
            decide_access_request(
                access_request=access_request,
                actor=request.user,
                approve=request.POST.get("decision") == "approve",
                comment=request.POST.get("comment", ""),
            )
            messages.success(request, "La demande a été traitée.")
        except (PermissionDenied, ValidationError) as error:
            messages.error(request, str(error))
        return redirect("console:approvals")
    requests = AccessRequest.objects.select_related(
        "requester", "target", "policy", "decided_by"
    ).annotate(
        recorded_approval_count=Count(
            "decisions",
            filter=Q(decisions__decision=ApprovalDecision.Decision.APPROVE),
        )
    )
    if can_decide and not request.user.is_superuser:
        requests = requests.filter(
            Q(policy__approver_groups__isnull=True)
            | Q(policy__approver_groups__users=request.user)
        ).distinct()
    requests = requests.order_by("status", "-created_at")
    return render(
        request,
        "console/approvals.html",
        {"requests": requests, "can_decide": can_decide},
    )


@login_required
@capability_required(Role.Capability.AUDIT_VIEW)
def audit(request):
    events = _audit_events(request).order_by("-sequence")[:200]
    return render(
        request,
        "console/audit.html",
        {
            "events": events,
            "integrity": verify_audit_chain(),
            "can_export": user_has_capability(request.user, Role.Capability.AUDIT_EXPORT),
            "filters": {
                "action": request.GET.get("action", ""),
                "actor": request.GET.get("actor", ""),
                "from": request.GET.get("from", ""),
                "to": request.GET.get("to", ""),
            },
        },
    )


def _audit_events(request):
    events = AuditEvent.objects.select_related("actor")
    action = request.GET.get("action", "").strip()[:150]
    actor = request.GET.get("actor", "").strip()[:150]
    from_date = parse_date(request.GET.get("from", ""))
    to_date = parse_date(request.GET.get("to", ""))
    if action:
        events = events.filter(action__icontains=action)
    if actor:
        events = events.filter(
            Q(actor__username__icontains=actor)
            | Q(actor__display_name__icontains=actor)
            | Q(actor__email__icontains=actor)
        )
    if from_date:
        events = events.filter(occurred_at__date__gte=from_date)
    if to_date:
        events = events.filter(occurred_at__date__lte=to_date)
    return events


def _audit_row(event):
    return {
        "sequence": event.sequence,
        "occurred_at": event.occurred_at.isoformat(),
        "actor": event.actor.username if event.actor else None,
        "action": event.action,
        "resource_type": event.resource_type,
        "resource_id": event.resource_id,
        "source_ip": event.source_ip,
        "metadata": redact_metadata(event.metadata),
        "previous_hash": event.previous_hash,
        "event_hash": event.event_hash,
        "signature": event.signature,
        "hash_version": event.hash_version,
    }


def _csv_safe(value):
    rendered = "" if value is None else str(value)
    return f"'{rendered}" if rendered.startswith(("=", "+", "-", "@")) else rendered


@login_required
@capability_required(Role.Capability.AUDIT_EXPORT)
def audit_export(request, export_format):
    if export_format not in {"csv", "jsonl"}:
        return HttpResponse("Format d’export non pris en charge.", status=404)
    integrity = verify_audit_chain()
    if not integrity.valid:
        return HttpResponse(
            "Export bloqué : l’intégrité de la chaîne d’audit doit être vérifiée.",
            status=409,
        )

    rows = [_audit_row(event) for event in _audit_events(request).order_by("sequence")[:10000]]
    if export_format == "jsonl":
        content = "".join(
            f"{json.dumps(row, ensure_ascii=False, sort_keys=True)}\n" for row in rows
        )
        content_type = "application/x-ndjson; charset=utf-8"
    else:
        output = io.StringIO(newline="")
        fieldnames = tuple(rows[0]) if rows else (
            "sequence",
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
            "hash_version",
        )
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            serialized = {
                key: json.dumps(value, ensure_ascii=False, sort_keys=True)
                if key == "metadata"
                else value
                for key, value in row.items()
            }
            writer.writerow({key: _csv_safe(value) for key, value in serialized.items()})
        content = output.getvalue()
        content_type = "text/csv; charset=utf-8"

    encoded = content.encode()
    digest = hashlib.sha256(encoded).digest()
    digest_hex = digest.hex()
    record_event(
        actor=request.user,
        action="audit.exported",
        resource=request.user,
        metadata={"format": export_format, "event_count": len(rows), "sha256": digest_hex},
        source_ip=request.META.get("REMOTE_ADDR"),
    )
    response = HttpResponse(encoded, content_type=content_type)
    response["Content-Disposition"] = f'attachment; filename="pam-olive-audit.{export_format}"'
    response["Digest"] = f"sha-256={base64.b64encode(digest).decode()}"
    response["X-Content-SHA256"] = digest_hex
    response["Cache-Control"] = "private, no-store, must-revalidate"
    return response


@login_required
@capability_required(Role.Capability.SESSIONS_VIEW)
def sessions(request):
    objects = PrivilegedSession.objects.select_related(
        "user",
        "target",
        "credential",
        "access_request",
        "termination_requested_by",
    ).order_by("-created_at")[:200]
    return render(
        request,
        "console/sessions.html",
        {
            "sessions": objects,
            "can_terminate": user_has_capability(
                request.user,
                Role.Capability.SESSIONS_TERMINATE,
            ),
        },
    )


@require_POST
@login_required
@capability_required(Role.Capability.SESSIONS_TERMINATE)
def terminate_session(request, pk):
    session = get_object_or_404(PrivilegedSession, pk=pk)
    updated, notify_gateway = request_session_termination(session, actor=request.user)
    if notify_gateway:
        if notify_gateway_termination(updated.pk):
            messages.success(request, "La coupure a été transmise au broker SSH.")
        else:
            messages.warning(
                request,
                "La terminaison reste en attente : le broker n’a pas répondu.",
            )
    else:
        messages.success(request, "La session ou son ticket a été fermé.")
    return redirect("console:sessions")
