import logging
import time

from django.contrib.auth import logout
from django.http import JsonResponse
from django.shortcuts import redirect
from django.urls import reverse

from pamolive.audit.services import record_event

from .models import PlatformSecurityPolicy

logger = logging.getLogger(__name__)


class SessionSecurityMiddleware:
    passive_paths = frozenset({"/admin/status/"})

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            expired_response = self._apply_policy(request)
            if expired_response is not None:
                return expired_response
        return self.get_response(request)

    def _apply_policy(self, request):
        policy, _created = PlatformSecurityPolicy.objects.get_or_create(pk=1)
        request.platform_security_policy = policy
        now = int(time.time())
        started_at = int(request.session.get("pam_session_started_at", now))
        last_activity_at = int(request.session.get("pam_last_activity_at", now))
        idle_seconds = policy.idle_timeout_minutes * 60
        absolute_seconds = policy.absolute_session_minutes * 60
        reason = None
        if now - started_at >= absolute_seconds:
            reason = "absolute"
        elif now - last_activity_at >= idle_seconds:
            reason = "idle"
        if reason:
            actor = request.user
            try:
                record_event(
                    actor=actor,
                    action="authentication.session.expired",
                    resource=actor,
                    metadata={"reason": reason},
                )
            except Exception:  # pragma: no cover - expiration must still be enforced
                logger.exception("Unable to audit session expiration")
            logout(request)
            if request.path.startswith("/api/") or request.headers.get("HX-Request"):
                return JsonResponse({"detail": "Session expired."}, status=401)
            return redirect(f"{reverse('login')}?expired={reason}")

        request.session.setdefault("pam_session_started_at", now)
        if request.path not in self.passive_paths:
            request.session["pam_last_activity_at"] = now
        request.session.set_expiry(idle_seconds)
        return None
