import time
from functools import wraps
from urllib.parse import urlencode

from django.conf import settings
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.http import JsonResponse
from django.shortcuts import redirect
from django.urls import reverse

from .models import PlatformSecurityPolicy

MFA_SESSION_KEY = "pam_mfa_verified_at"


def mark_mfa_verified(request, *, timestamp=None):
    request.session[MFA_SESSION_KEY] = int(timestamp or time.time())
    request.session.modified = True


def sensitive_mfa_window_seconds(policy):
    return int(policy.sensitive_action_mfa_window_minutes) * 60


def user_has_recent_mfa(request, *, policy=None, now=None):
    if not request.user.is_authenticated or request.user.is_service_account:
        return False
    if not request.user.mfa_enrolled:
        return False
    policy = policy or getattr(request, "platform_security_policy", None)
    if policy is None:
        policy, _created = PlatformSecurityPolicy.objects.get_or_create(pk=1)
    return mfa_timestamp_is_recent(
        request.session.get(MFA_SESSION_KEY),
        policy=policy,
        now=now,
    )


def mfa_timestamp_is_recent(verified_at, *, policy=None, now=None):
    policy = policy or PlatformSecurityPolicy.objects.get_or_create(pk=1)[0]
    if verified_at is None:
        return False
    try:
        verified_at = int(verified_at)
    except (TypeError, ValueError):
        return False
    return int(now or time.time()) - verified_at <= sensitive_mfa_window_seconds(policy)


def sensitive_mfa_required(request, *, action_label="cette action sensible"):
    if getattr(settings, "PAMOLIVE_TEST_BYPASS_GLOBAL_MFA", False):
        return None
    if not request.user.mfa_enrolled:
        return redirect(reverse("mfa_setup_required"))
    policy = getattr(request, "platform_security_policy", None)
    if policy is None:
        policy, _created = PlatformSecurityPolicy.objects.get_or_create(pk=1)
    if user_has_recent_mfa(request, policy=policy):
        return None
    if request.headers.get("HX-Request") or request.path.startswith("/api/"):
        return JsonResponse(
            {
                "detail": (
                    "Une vérification MFA récente est requise avant "
                    f"{action_label}."
                ),
                "mfa_required": True,
                "mfa_verify_url": reverse("mfa_verify"),
            },
            status=403,
        )
    messages.warning(
        request,
        (
            "Confirmez votre MFA avant "
            f"{action_label}. La validation reste valable "
            f"{policy.sensitive_action_mfa_window_minutes} minutes."
        ),
    )
    query = urlencode({"next": request.get_full_path(), "action": action_label})
    return redirect(f"{reverse('mfa_verify')}?{query}")


def require_recent_mfa(action_label):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(request, *args, **kwargs):
            response = sensitive_mfa_required(request, action_label=action_label)
            if response is not None:
                return response
            return view_func(request, *args, **kwargs)

        return wrapped

    return decorator


def require_recent_mfa_or_raise(request, *, action_label):
    if not user_has_recent_mfa(request):
        raise PermissionDenied(f"Une MFA récente est requise avant {action_label}.")


class ConsoleConfigurationStepUpMiddleware:
    configuration_prefixes = (
        "/admin/system/",
        "/admin/users/",
        "/admin/user-groups/",
        "/admin/roles/",
        "/admin/identity-sources/",
        "/admin/ldap-sources/",
        "/admin/oidc-sources/",
        "/admin/directory-mappings/",
        "/admin/domains/",
        "/admin/targets/",
        "/admin/host-keys/",
        "/admin/target-groups/",
        "/admin/credentials/",
        "/admin/policies/",
        "/admin/time-frames/",
        "/admin/rotation-policies/",
    )

    passive_suffixes = ("/test/",)

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if (
            request.method == "POST"
            and request.user.is_authenticated
            and request.path.startswith(self.configuration_prefixes)
            and not request.path.endswith(self.passive_suffixes)
        ):
            response = sensitive_mfa_required(
                request,
                action_label="modifier la configuration",
            )
            if response is not None:
                return response
        return self.get_response(request)
