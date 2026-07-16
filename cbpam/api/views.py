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
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_POST

from cbpam.accounts.forms import (
    MFAConfirmForm,
    MFASecurityForm,
    PreferencesForm,
    ProfileForm,
)
from cbpam.accounts.models import PlatformSecurityPolicy, User
from cbpam.api.forms import PrivilegedActionJustificationForm
from cbpam.approvals.forms import AccessRequestForm
from cbpam.approvals.models import AccessRequest
from cbpam.audit.services import record_event
from cbpam.common.network import request_client_ip
from cbpam.mfa.models import MFADevice
from cbpam.mfa.services import (
    begin_totp_enrollment,
    confirm_totp_device,
    device_secret,
    qr_svg,
    replace_recovery_codes,
    reset_user_mfa,
    totp_uri,
)
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
from cbpam.vault.forms import PersonalVaultGroupForm, PersonalVaultItemForm
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
    action = request.POST.get("action", "item")
    form = PersonalVaultItemForm(
        request.POST if request.method == "POST" and action == "item" else None,
        owner=request.user,
    )
    group_form = PersonalVaultGroupForm(
        request.POST if request.method == "POST" and action == "group" else None,
        owner=request.user,
    )
    if request.method == "POST" and action == "item" and form.is_valid():
        cipher = VaultCipher()
        item = PersonalVaultItem.objects.create(
            owner=request.user,
            group=form.cleaned_data["group"],
            name=form.cleaned_data["name"],
            item_type=form.cleaned_data["item_type"],
            favorite=form.cleaned_data["favorite"],
            encrypted_payload=cipher.encrypt_payload(form.encrypted_payload_data()),
            encryption_key_id=cipher.active_key_id,
        )
        record_event(actor=request.user, action="personal_vault.item_created", resource=item)
        messages.success(request, "L’élément a été ajouté à votre coffre personnel.")
        return redirect("passwords")
    if request.method == "POST" and action == "group" and group_form.is_valid():
        group = group_form.save()
        record_event(
            actor=request.user,
            action="personal_vault.group_created",
            resource=group,
        )
        messages.success(request, "Le groupe de mots de passe a été créé.")
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
            "group_form": group_form,
            "personal_groups": request.user.personal_vault_groups.prefetch_related("items"),
            "ungrouped_items": request.user.personal_vault_items.filter(group__isnull=True),
            "personal_items": request.user.personal_vault_items.select_related("group"),
            "target_credentials": target_credentials,
        },
    )


@login_required
def edit_personal_item(request, pk):
    item = get_object_or_404(PersonalVaultItem, pk=pk, owner=request.user)
    cipher = VaultCipher()
    payload = cipher.decrypt_payload(item.encrypted_payload, key_id=item.encryption_key_id)
    initial = {
        **payload,
        "name": item.name,
        "item_type": item.item_type,
        "favorite": item.favorite,
        "group": item.group,
    }
    form = PersonalVaultItemForm(
        request.POST or None,
        initial=initial,
        owner=request.user,
    )
    if request.method == "POST" and form.is_valid():
        item.name = form.cleaned_data["name"]
        item.item_type = form.cleaned_data["item_type"]
        item.favorite = form.cleaned_data["favorite"]
        item.group = form.cleaned_data["group"]
        item.encrypted_payload = cipher.encrypt_payload(form.encrypted_payload_data())
        item.encryption_key_id = cipher.active_key_id
        item.save(
            update_fields=(
                "name",
                "item_type",
                "favorite",
                "group",
                "encrypted_payload",
                "encryption_key_id",
                "updated_at",
            )
        )
        record_event(
            actor=request.user,
            action="personal_vault.item_updated",
            resource=item,
        )
        messages.success(request, "L’élément du coffre a été modifié.")
        return redirect("passwords")
    return render(request, "vault/edit.html", {"form": form, "item": item})


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
    return render(
        request,
        "vault/reveal.html",
        {
            "item": item,
            "payload": payload,
            "totp_refresh_url": (
                request.build_absolute_uri(
                    f"/passwords/personal/{item.pk}/totp/"
                )
                if payload.get("totp_secret")
                else ""
            ),
        },
    )


@require_POST
@login_required
def reveal_target_credential(request, pk):
    credential = get_object_or_404(Credential.objects.select_related("target"), pk=pk)
    source_ip = request_client_ip(request)
    actions = actions_for_target(request.user, credential.target, source_ip=source_ip)
    if AccessPolicy.Action.VIEW_SECRET not in actions:
        raise PermissionDenied
    justification_form = PrivilegedActionJustificationForm(request.POST)
    if not justification_form.is_valid():
        return render(
            request,
            "vault/reveal_denied.html",
            {"message": "A valid business justification is required before revealing this secret."},
            status=400,
        )
    justification = justification_form.cleaned_data["justification"]
    _lease, token = issue_secret_lease(
        user=request.user,
        credential=credential,
        justification=justification,
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
        request.session[f"target_secret_grant:{credential.pk}"] = int(
            timezone.now().timestamp()
        ) + 120
    return render(
        request,
        "vault/reveal.html",
        {
            "item": credential,
            "payload": payload,
            "is_target_credential": True,
            "totp_refresh_url": (
                request.build_absolute_uri(
                    f"/passwords/target/{credential.pk}/totp/"
                )
                if payload.get("totp_code")
                else ""
            ),
        },
    )


def _totp_json(secret):
    now = timezone.now().timestamp()
    remaining = 30 - (int(now) % 30)
    response = JsonResponse(
        {"code": totp_code(secret, timestamp=now), "remaining": remaining, "period": 30}
    )
    patch_cache_control(response, no_cache=True, no_store=True, must_revalidate=True, private=True)
    return response


@never_cache
@login_required
def personal_item_totp(request, pk):
    item = get_object_or_404(PersonalVaultItem, pk=pk, owner=request.user)
    payload = VaultCipher().decrypt_payload(
        item.encrypted_payload, key_id=item.encryption_key_id
    )
    if not payload.get("totp_secret"):
        raise PermissionDenied
    return _totp_json(payload["totp_secret"])


@never_cache
@login_required
def target_credential_totp(request, pk):
    credential = get_object_or_404(Credential.objects.select_related("target"), pk=pk)
    grant_expires_at = int(request.session.get(f"target_secret_grant:{credential.pk}", 0))
    if (
        grant_expires_at < int(timezone.now().timestamp())
        or not credential.encrypted_totp_secret
        or not credential_allows_action(
            request.user,
            credential,
            AccessPolicy.Action.REVEAL_TOTP,
            source_ip=request_client_ip(request),
        )
    ):
        raise PermissionDenied
    secret = VaultCipher().decrypt(
        credential.encrypted_totp_secret, key_id=credential.totp_encryption_key_id
    )
    return _totp_json(secret)


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
    source_ip = request_client_ip(request)
    if not credential_allows_action(
        request.user,
        credential,
        AccessPolicy.Action.START_SESSION,
        source_ip=source_ip,
    ):
        raise PermissionDenied
    justification_form = PrivilegedActionJustificationForm(request.POST)
    if not justification_form.is_valid():
        response = render(
            request,
            "sessions/start_denied.html",
            {
                "target": credential.target,
                "reason": (
                    "A valid business justification is required for every "
                    "privileged session."
                ),
            },
            status=400,
        )
        patch_cache_control(
            response, no_cache=True, no_store=True, must_revalidate=True, private=True
        )
        return response
    try:
        session, _ticket, raw_ticket = issue_session_ticket(
            user=request.user,
            credential=credential,
            justification=justification_form.cleaned_data["justification"],
            source_ip=source_ip,
        )
    except PermissionDenied as error:
        if "clé d’hôte SSH approuvée" not in str(error):
            raise
        record_event(
            actor=request.user,
            action="session.start_denied",
            resource=credential.target,
            metadata={"reason": str(error), "credential_id": str(credential.pk)},
        )
        response = render(
            request,
            "sessions/start_denied.html",
            {"target": credential.target, "reason": str(error)},
        )
        patch_cache_control(
            response, no_cache=True, no_store=True, must_revalidate=True, private=True
        )
        return response
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
    preferences_form = PreferencesForm(instance=request.user)
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
        elif action == "preferences":
            preferences_form = PreferencesForm(request.POST, instance=request.user)
            if preferences_form.is_valid():
                preferences_form.save()
                record_event(
                    actor=request.user,
                    action="account.preferences_updated",
                    resource=request.user,
                )
                messages.success(request, "Vos préférences ont été mises à jour.")
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
    for form in (profile_form, preferences_form, password_form):
        for field in form.fields.values():
            field.widget.attrs["class"] = "console-input"
    return render(
        request,
        "account.html",
        {
            "profile_form": profile_form,
            "preferences_form": preferences_form,
            "password_form": password_form,
            "mfa_device": mfa_device,
            "mfa_security_form": MFASecurityForm(user=request.user),
            "recovery_code_count": request.user.mfa_recovery_codes.filter(
                used_at__isnull=True
            ).count(),
        },
    )


@require_POST
@login_required
def update_ui_preferences(request):
    theme = request.POST.get("preferred_theme", "")
    language = request.POST.get("preferred_language", "")
    update_fields = []
    if theme in User.Theme.values:
        request.user.preferred_theme = theme
        update_fields.append("preferred_theme")
    if language in User.Language.values:
        request.user.preferred_language = language
        request.session["preferred_language"] = language
        update_fields.append("preferred_language")
    if not update_fields:
        return JsonResponse({"detail": "Invalid preference."}, status=400)
    update_fields.append("updated_at") if hasattr(request.user, "updated_at") else None
    request.user.save(update_fields=update_fields)
    record_event(
        actor=request.user,
        action="account.preferences_updated",
        resource=request.user,
        metadata={"fields": update_fields},
    )
    response_data = {
        "theme": request.user.preferred_theme,
        "language": request.user.preferred_language,
    }
    next_path = request.POST.get("next", "")
    if next_path and url_has_allowed_host_and_scheme(
        next_path,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        return redirect(next_path)
    return JsonResponse(
        response_data
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


@never_cache
@login_required
def mfa_enrollment_required(request):
    confirmed_device = request.user.mfa_devices.filter(
        kind=MFADevice.Kind.TOTP,
        confirmed=True,
    ).first()
    if confirmed_device:
        return redirect("dashboard")

    device = request.user.mfa_devices.filter(
        kind=MFADevice.Kind.TOTP,
        confirmed=False,
    ).first()
    if device is None:
        device, secret = begin_totp_enrollment(request.user)
    else:
        secret = device_secret(device)
    uri = totp_uri(request.user, secret)
    response = render(
        request,
        "mfa/enrollment_required.html",
        {
            "device": device,
            "secret": secret,
            "qr_svg": qr_svg(uri),
            "form": MFAConfirmForm(),
        },
    )
    patch_cache_control(
        response,
        no_cache=True,
        no_store=True,
        must_revalidate=True,
        private=True,
    )
    return response


@require_POST
@login_required
def mfa_confirm(request, pk):
    device = get_object_or_404(
        MFADevice, pk=pk, user=request.user, kind=MFADevice.Kind.TOTP, confirmed=False
    )
    form = MFAConfirmForm(request.POST)
    if form.is_valid() and confirm_totp_device(device, form.cleaned_data["token"]):
        recovery_codes = replace_recovery_codes(request.user, device)
        record_event(actor=request.user, action="account.mfa_enabled", resource=device)
        request.session["new_mfa_recovery_codes"] = recovery_codes
        request.session["mfa_recovery_regenerated"] = False
        return redirect("mfa_recovery_codes")
    messages.error(request, "Le code TOTP est incorrect. Recommencez l’activation.")
    policy, _created = PlatformSecurityPolicy.objects.get_or_create(pk=1)
    if policy.require_mfa_for_all_users:
        return redirect("mfa_enrollment_required")
    return redirect("account")


@never_cache
@login_required
def mfa_recovery_codes(request):
    recovery_codes = request.session.pop("new_mfa_recovery_codes", None)
    regenerated = request.session.pop("mfa_recovery_regenerated", False)
    if not recovery_codes:
        return redirect("account")
    response = render(
        request,
        "mfa/recovery_codes.html",
        {"recovery_codes": recovery_codes, "regenerated": regenerated},
    )
    patch_cache_control(response, no_cache=True, no_store=True, must_revalidate=True, private=True)
    return response


@never_cache
@require_POST
@login_required
def mfa_reset(request):
    form = MFASecurityForm(request.POST, user=request.user)
    if not form.is_valid():
        messages.error(request, "La MFA n’a pas été réinitialisée : vérifiez vos codes.")
        return redirect("account")
    device = request.user.mfa_devices.filter(confirmed=True).first()
    reset_user_mfa(request.user)
    record_event(actor=request.user, action="account.mfa_reset", resource=device)
    messages.success(request, "La MFA a été désactivée. Vous pouvez l’activer à nouveau.")
    policy, _created = PlatformSecurityPolicy.objects.get_or_create(pk=1)
    if policy.require_mfa_for_all_users:
        return redirect("mfa_enrollment_required")
    return redirect("account")


@never_cache
@require_POST
@login_required
def mfa_recovery_regenerate(request):
    form = MFASecurityForm(request.POST, user=request.user)
    device = get_object_or_404(
        MFADevice, user=request.user, kind=MFADevice.Kind.TOTP, confirmed=True
    )
    if not form.is_valid():
        messages.error(request, "Les codes n’ont pas été renouvelés : vérifiez vos codes.")
        return redirect("account")
    recovery_codes = replace_recovery_codes(request.user, device)
    record_event(actor=request.user, action="account.mfa_recovery_regenerated", resource=device)
    request.session["new_mfa_recovery_codes"] = recovery_codes
    request.session["mfa_recovery_regenerated"] = True
    return redirect("mfa_recovery_codes")


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
