from django.conf import settings
from django.shortcuts import redirect
from django.urls import reverse

from .models import PlatformSecurityPolicy


class MFAEnrollmentMiddleware:
    allowed_prefixes = ("/mfa/setup/", "/account/mfa/", "/accounts/logout/")

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if (
            request.path.startswith("/django-admin/")
            and request.user.is_authenticated
            and request.user.is_superuser
            and not request.user.mfa_enrolled
        ):
            return redirect(reverse("mfa_setup_required"))
        if getattr(settings, "PAMOLIVE_TEST_BYPASS_GLOBAL_MFA", False):
            return self.get_response(request)
        if request.user.is_authenticated and not request.user.is_service_account:
            policy = getattr(request, "platform_security_policy", None)
            if policy is None:
                policy, _created = PlatformSecurityPolicy.objects.get_or_create(pk=1)
            if (
                policy.require_mfa_for_all_users
                and not request.user.mfa_enrolled
                and not request.path.startswith(self.allowed_prefixes)
            ):
                return redirect(reverse("mfa_setup_required"))
        return self.get_response(request)
