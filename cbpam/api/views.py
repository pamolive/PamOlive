from django.conf import settings
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.core.exceptions import PermissionDenied
from django.db import connection
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.cache import patch_cache_control
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_POST

from cbpam.accounts.forms import MFAConfirmForm, ProfileForm
from cbpam.approvals.forms import AccessRequestForm
from cbpam.approvals.models import AccessRequest
from cbpam.audit.services import record_event
from cbpam.common.network import request_client_ip
from cbpam.mfa.models import MFADevice
from cbpam.mfa.services import begin_totp_enrollment, confirm_totp_device, qr_svg, totp_uri
from cbpam.policies.models import AccessPolicy
from cbpam.policies.services import (
    actions_for_target,
    credential_allows_action,
    policies_allowing,
    target_groups_for_user,
    targets_for_policies,
)
from cbpam.sessions.models import PrivilegedSession
from cbpam.sessions.services import issue_session_ticket
from cbpam.vault.forms import PersonalVaultItemForm
from cbpam.vault.leases import consume_secret_lease, issue_secret_lease
from cbpam.vault.models import Credential, PersonalVaultItem
from cbpam.vault.services import VaultCipher, totp_code


def health(request):
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1")
    return JsonResponse({"status": "ok", "database": "ok"})


@login_required
def dashboard(request):
    user_requests = AccessRequest.objects.filter(requester=request.user)
    context = {
        "target_groups": target_groups_for_user(request.user)[:4],
        "personal_secret_count": request.user.personal_vault_items.count(),
        "pending_requests": user_requests.filter(status=AccessRequest.Status.PENDING)
        .select_related("target")
        .order_by("-created_at")[:4],
        "pending_request_count": user_requests.filter(status=AccessRequest.Status.PENDING).count(),
        "active_sessions": PrivilegedSession.objects.filter(
            user=request.user, status=PrivilegedSession.Status.ACTIVE
        ).select_related("target"),
    }
    return render(request, "dashboard.html", context)


@login_required
def passwords_page(request):
    source_ip = request_client_ip(request)
    form = PersonalVaultItemForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        cipher = VaultCipher()
        item = PersonalVaultItem.objects.create(
            owner=request.user,
            name=form.cleaned_data["name"],
            item_type=form.cleaned_data["item_type"],
            favorite=form.cleaned_data["favorite"],
            encrypted_payload=cipher.encrypt_payload(form.encrypted_payload_data()),
            encryption_key_id=cipher.active_key_id,
        )
        record_event(actor=request.user, action="personal_vault.item_created", resource=item)
        messages.success(request, "L’élément a été ajouté à votre coffre personnel.")
        return redirect("passwords")

    target_credentials = []
    allowed_targets = targets_for_policies(
        policies_allowing(
            request.user,
            AccessPolicy.Action.VIEW_SECRET,
            source_ip=source_ip,
        )
    ).prefetch_related("credentials")
    for target in allowed_targets:
        actions = actions_for_target(request.user, target, source_ip=source_ip)
        for credential in target.credentials.all():
            if not credential_allows_action(
                request.user,
                credential,
                AccessPolicy.Action.VIEW_SECRET,
                source_ip=source_ip,
            ):
                continue
            target_credentials.append(
                {"credential": credential, "actions": actions, "target": target}
            )
    return render(
        request,
        "passwords.html",
        {
            "form": form,
            "personal_items": request.user.personal_vault_items.all(),
            "target_credentials": target_credentials,
        },
    )


@require_POST
@login_required
def reveal_personal_item(request, pk):
    item = get_object_or_404(PersonalVaultItem, pk=pk, owner=request.user)
    payload = VaultCipher().decrypt_payload(
        item.encrypted_payload,
        key_id=item.encryption_key_id,
    )
    if payload.get("totp_secret"):
        payload["totp_code"] = totp_code(payload["totp_secret"])
    record_event(actor=request.user, action="personal_vault.item_revealed", resource=item)
    return render(request, "vault/reveal.html", {"item": item, "payload": payload})


@require_POST
@login_required
def reveal_target_credential(request, pk):
    credential = get_object_or_404(Credential.objects.select_related("target"), pk=pk)
    source_ip = request_client_ip(request)
    actions = actions_for_target(request.user, credential.target, source_ip=source_ip)
    if AccessPolicy.Action.VIEW_SECRET not in actions:
        raise PermissionDenied
    _lease, token = issue_secret_lease(
        user=request.user,
        credential=credential,
        source_ip=source_ip,
    )
    _consumed_lease, secret = consume_secret_lease(
        token=token,
        expected_user=request.user,
    )
    cipher = VaultCipher()
    payload = {
        "username": credential.username,
        "password": secret,
    }
    if credential.encrypted_totp_secret and AccessPolicy.Action.REVEAL_TOTP in actions:
        payload["totp_code"] = totp_code(
            cipher.decrypt(
                credential.encrypted_totp_secret,
                key_id=credential.totp_encryption_key_id,
            )
        )
    return render(
        request,
        "vault/reveal.html",
        {"item": credential, "payload": payload, "is_target_credential": True},
    )


@login_required
def targets_page(request):
    source_ip = request_client_ip(request)
    target_groups = list(target_groups_for_user(request.user))
    for group in target_groups:
        group.visible_targets = []
        for target in group.targets.all():
            actions = actions_for_target(request.user, target, source_ip=source_ip)
            group.visible_targets.append(
                {
                    "target": target,
                    "actions": actions,
                    "credentials": [
                        credential
                        for credential in target.credentials.all()
                        if credential_allows_action(
                            request.user,
                            credential,
                            AccessPolicy.Action.START_SESSION,
                            source_ip=source_ip,
                        )
                    ],
                }
            )
    return render(
        request,
        "targets.html",
        {
            "target_groups": target_groups,
            "pending_request_count": AccessRequest.objects.filter(
                requester=request.user, status=AccessRequest.Status.PENDING
            ).count(),
        },
    )


@never_cache
@require_POST
@login_required
def start_session(request, pk):
    credential = get_object_or_404(Credential.objects.select_related("target"), pk=pk)
    session, _ticket, raw_ticket = issue_session_ticket(
        user=request.user,
        credential=credential,
        source_ip=request_client_ip(request),
    )
    if credential.target.protocol == credential.target.Protocol.RDP:
        template_name = "sessions/rdp_launch.html"
        context = {
            "privileged_session": session,
            "session_ticket": raw_ticket,
            "rdp_origin": settings.CBPAM_RDP_PUBLIC_ORIGIN,
        }
    else:
        template_name = "sessions/terminal.html"
        context = {"privileged_session": session, "session_ticket": raw_ticket}
    response = render(request, template_name, context)
    patch_cache_control(response, no_cache=True, no_store=True, must_revalidate=True, private=True)
    return response


@login_required
def account_page(request):
    profile_form = ProfileForm(instance=request.user)
    password_form = PasswordChangeForm(request.user)
    if request.method == "POST":
        action = request.POST.get("action")
        if action == "profile":
            profile_form = ProfileForm(request.POST, instance=request.user)
            if profile_form.is_valid():
                profile_form.save()
                record_event(
                    actor=request.user, action="account.profile_updated", resource=request.user
                )
                messages.success(request, "Votre profil a été mis à jour.")
                return redirect("account")
        elif action == "password":
            password_form = PasswordChangeForm(request.user, request.POST)
            if password_form.is_valid():
                user = password_form.save()
                update_session_auth_hash(request, user)
                record_event(actor=request.user, action="account.password_changed", resource=user)
                messages.success(request, "Votre mot de passe a été modifié.")
                return redirect("account")
    mfa_device = request.user.mfa_devices.filter(kind=MFADevice.Kind.TOTP, confirmed=True).first()
    for form in (profile_form, password_form):
        for field in form.fields.values():
            field.widget.attrs["class"] = "console-input"
    return render(
        request,
        "account.html",
        {"profile_form": profile_form, "password_form": password_form, "mfa_device": mfa_device},
    )


@require_POST
@login_required
def mfa_setup(request):
    device, secret = begin_totp_enrollment(request.user)
    uri = totp_uri(request.user, secret)
    return render(
        request,
        "mfa/setup.html",
        {"device": device, "secret": secret, "qr_svg": qr_svg(uri), "form": MFAConfirmForm()},
    )


@require_POST
@login_required
def mfa_confirm(request, pk):
    device = get_object_or_404(
        MFADevice, pk=pk, user=request.user, kind=MFADevice.Kind.TOTP, confirmed=False
    )
    form = MFAConfirmForm(request.POST)
    if form.is_valid() and confirm_totp_device(device, form.cleaned_data["token"]):
        record_event(actor=request.user, action="account.mfa_enabled", resource=device)
        messages.success(request, "L’authentification MFA est maintenant activée.")
        return redirect("account")
    messages.error(request, "Le code TOTP est incorrect. Recommencez l’activation.")
    return redirect("account")


@login_required
def requests_page(request):
    form = AccessRequestForm(
        request.POST or None,
        user=request.user,
        source_ip=request_client_ip(request),
    )
    if request.method == "POST" and form.is_valid():
        access_request = form.save(commit=False)
        access_request.requester = request.user
        if not access_request.policy.requires_approval:
            access_request.status = AccessRequest.Status.APPROVED
            access_request.decided_at = timezone.now()
        access_request.save()
        record_event(
            actor=request.user,
            action="access_request.created",
            resource=access_request,
            metadata={"status": access_request.status},
        )
        messages.success(request, "Votre demande d’accès a été enregistrée.")
        return redirect("requests")
    requests = AccessRequest.objects.filter(requester=request.user).select_related(
        "target", "policy", "decided_by"
    )
    return render(request, "requests.html", {"form": form, "requests": requests})
