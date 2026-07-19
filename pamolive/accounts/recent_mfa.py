import time

from django.conf import settings

from pamolive.mfa.services import verify_user_mfa

MFA_VERIFIED_AT_SESSION_KEY = "pam_mfa_verified_at"


def mark_mfa_verified(request, *, verified_at=None):
    request.session[MFA_VERIFIED_AT_SESSION_KEY] = int(
        time.time() if verified_at is None else verified_at
    )


def has_recent_mfa(request):
    if getattr(settings, "PAMOLIVE_TEST_BYPASS_GLOBAL_MFA", False):
        return True
    verified_at = request.session.get(MFA_VERIFIED_AT_SESSION_KEY)
    if not isinstance(verified_at, int):
        return False
    maximum_age = getattr(settings, "PAMOLIVE_MFA_STEP_UP_MAX_AGE_SECONDS", 300)
    age = int(time.time()) - verified_at
    return 0 <= age <= maximum_age


def verify_mfa_step_up(request, token):
    if not verify_user_mfa(request.user, token):
        return False
    mark_mfa_verified(request)
    return True
