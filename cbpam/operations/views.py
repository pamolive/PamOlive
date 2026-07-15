import hmac
import uuid
from importlib.metadata import PackageNotFoundError, version

from django.conf import settings
from django.core.cache import cache
from django.db import connection
from django.http import HttpResponse, JsonResponse
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET

from cbpam.accounts.models import User
from cbpam.approvals.models import AccessRequest
from cbpam.audit.models import AuditChainState, AuditEvent
from cbpam.audit.services import verify_audit_chain
from cbpam.sessions.models import PrivilegedSession
from cbpam.vault.models import Credential

from .models import RotationJob


def _operations_authorized(request):
    expected = settings.CBPAM_OPERATIONS_TOKEN
    authorization = request.headers.get("Authorization", "")
    scheme, separator, provided = authorization.partition(" ")
    return bool(
        expected
        and separator
        and scheme.casefold() == "bearer"
        and hmac.compare_digest(provided, expected)
    )


@never_cache
@require_GET
def liveness(request):
    return JsonResponse({"status": "ok", "service": "pam-olive"})


@never_cache
@require_GET
def readiness(request):
    checks = {}
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            if cursor.fetchone()[0] != 1:
                raise RuntimeError("database probe returned an unexpected result")
        checks["database"] = "ok"
    except Exception:
        checks["database"] = "failed"

    probe_key = f"pam-olive:readiness:{uuid.uuid4()}"
    try:
        cache.set(probe_key, "ok", timeout=5)
        if cache.get(probe_key) != "ok":
            raise RuntimeError("cache probe returned an unexpected result")
        cache.delete(probe_key)
        checks["cache"] = "ok"
    except Exception:
        checks["cache"] = "failed"

    ready = all(value == "ok" for value in checks.values())
    return JsonResponse(
        {"status": "ready" if ready else "not_ready", "checks": checks},
        status=200 if ready else 503,
    )


@never_cache
@require_GET
def audit_integrity(request):
    if not _operations_authorized(request):
        return JsonResponse({"detail": "Forbidden"}, status=403)
    verification = verify_audit_chain()
    return JsonResponse(
        {
            "status": "ok" if verification.valid else "failed",
            "checked_events": verification.checked_events,
            "legacy_events": verification.legacy_events,
            "head_hash": verification.head_hash,
            "issue_count": len(verification.issues),
        },
        status=200 if verification.valid else 503,
    )


def _project_version():
    try:
        return version("pam-olive")
    except PackageNotFoundError:
        return "development"


@never_cache
@require_GET
def metrics(request):
    if not _operations_authorized(request):
        return HttpResponse("Forbidden\n", status=403, content_type="text/plain")
    now = timezone.now()
    state = AuditChainState.objects.get(pk=1)
    values = {
        "pam_olive_users_active": User.objects.filter(is_active=True).count(),
        "pam_olive_access_requests_pending": AccessRequest.objects.filter(
            status=AccessRequest.Status.PENDING
        ).count(),
        "pam_olive_sessions_active": PrivilegedSession.objects.filter(
            status=PrivilegedSession.Status.ACTIVE
        ).count(),
        "pam_olive_sessions_terminating": PrivilegedSession.objects.filter(
            status=PrivilegedSession.Status.TERMINATING
        ).count(),
        "pam_olive_credentials_rotation_due": Credential.objects.filter(
            rotation_enabled=True,
            next_rotation_at__lte=now,
        ).count(),
        "pam_olive_rotation_jobs_failed": RotationJob.objects.filter(
            status=RotationJob.Status.FAILED
        ).count(),
        "pam_olive_rotation_jobs_action_required": RotationJob.objects.filter(
            status=RotationJob.Status.ACTION_REQUIRED
        ).count(),
        "pam_olive_audit_events_total": AuditEvent.objects.count(),
        "pam_olive_audit_head_sequence": state.last_sequence,
    }
    lines = [
        "# HELP pam_olive_build_info PAM-olive build information.",
        "# TYPE pam_olive_build_info gauge",
        f'pam_olive_build_info{{version="{_project_version()}"}} 1',
    ]
    for name, value in values.items():
        lines.extend(
            (
                f"# TYPE {name} gauge",
                f"{name} {value}",
            )
        )
    return HttpResponse(
        "\n".join(lines) + "\n",
        content_type="text/plain; version=0.0.4; charset=utf-8",
    )
