from django.conf import settings
from django.shortcuts import redirect
from django.urls import reverse

from .models import PlatformSecurityPolicy


class MFAEnrollmentMiddleware:
    allowed_prefixes = ("/account/mfa/", "/accounts/logout/")

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if getattr(settings, "CBPAM_TEST_BYPASS_GLOBAL_MFA", False):
            return self.get_response(request)
        if request.user.is_authenticated and not request.user.is_service_account:
            policy = getattr(request, "platform_security_policy", None)
            if policy is None:
                policy, _created = PlatformSecurityPolicy.objects.get_or_create(pk=1)
            enrolled = request.user.mfa_devices.filter(kind="totp", confirmed=True).exists()
            if (
                policy.require_mfa_for_all_users
                and not enrolled
                and not request.path.startswith(self.allowed_prefixes)
            ):
                return redirect(reverse("mfa_enrollment_required"))
        return self.get_response(request)
