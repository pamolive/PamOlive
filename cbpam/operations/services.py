import hmac
import secrets
from dataclasses import dataclass
from datetime import timedelta

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.module_loading import import_string

from cbpam.audit.services import record_event
from cbpam.vault.models import Credential
from cbpam.vault.services import VaultCipher

from .models import RotationJob


@dataclass(frozen=True)
class RotationBackendError(Exception):
    code: str
    safe_message: str
    transient: bool = False

    def __str__(self):
        return self.safe_message


_backend_instances = {}


def register_rotation_backend(name, backend):
    """Register an already-instantiated backend, primarily for built-ins and tests."""
    if not name or not hasattr(backend, "rotate"):
        raise ValueError("A rotation backend needs a name and a rotate method")
    _backend_instances[name] = backend


def clear_rotation_backends():
    _backend_instances.clear()


def get_rotation_backend(name):
    if name in _backend_instances:
        return _backend_instances[name]
    dotted_path = settings.CBPAM_ROTATION_BACKENDS.get(name)
    if not dotted_path:
        raise RotationBackendError(
            "backend_not_configured",
            "Aucun fournisseur de rotation n’est configuré pour cet identifiant.",
        )
    try:
        backend_class = import_string(dotted_path)
        backend = backend_class()
    except (ImportError, AttributeError, TypeError, ImproperlyConfigured) as exc:
        raise RotationBackendError(
            "backend_invalid",
            "Le fournisseur de rotation configuré est indisponible.",
        ) from exc
    if not hasattr(backend, "rotate"):
        raise RotationBackendError(
            "backend_invalid",
            "Le fournisseur de rotation ne respecte pas le contrat requis.",
        )
    _backend_instances[name] = backend
    return backend


def _candidate_secret(backend, credential):
    generator = getattr(backend, "generate_secret", None)
    if generator:
        candidate = generator(credential)
    elif credential.kind == Credential.Kind.PASSWORD:
        candidate = secrets.token_urlsafe(32)
    else:
        raise RotationBackendError(
            "secret_generation_unsupported",
            "Ce type de secret exige un générateur fourni par le connecteur de rotation.",
        )
    if not isinstance(candidate, str) or not candidate or len(candidate.encode()) > 65_536:
        raise RotationBackendError(
            "candidate_secret_invalid",
            "Le fournisseur a produit un secret invalide.",
        )
    return candidate


@transaction.atomic
def queue_rotation(*, credential, requested_by=None, reason="", scheduled_for=None):
    locked_credential = Credential.objects.select_for_update().select_related(
        "rotation_policy"
    ).get(pk=credential.pk)
    existing = RotationJob.objects.filter(
        credential=locked_credential,
        status__in=(RotationJob.Status.PENDING, RotationJob.Status.RUNNING),
    ).first()
    if existing:
        return existing, False
    job = RotationJob.objects.create(
        credential=locked_credential,
        requested_by=requested_by,
        reason=(reason or "")[:250],
        backend=locked_credential.effective_rotation_backend,
        scheduled_for=scheduled_for or timezone.now(),
        previous_key_version=locked_credential.key_version,
    )
    record_event(
        actor=requested_by,
        action="credential.rotation_queued",
        resource=job,
        metadata={
            "credential_id": str(locked_credential.pk),
            "backend": locked_credential.effective_rotation_backend or "unconfigured",
            "scheduled_for": job.scheduled_for.isoformat(),
        },
    )
    return job, True


def _finish_without_rotation(job_id, *, status, code, message):
    with transaction.atomic():
        job = RotationJob.objects.select_for_update().select_related("credential").get(pk=job_id)
        if job.status not in (RotationJob.Status.PENDING, RotationJob.Status.RUNNING):
            return job
        now = timezone.now()
        job.status = status
        job.completed_at = now
        job.error_code = code[:80]
        job.error_message = message[:250]
        job.save(
            update_fields=(
                "status",
                "completed_at",
                "error_code",
                "error_message",
                "updated_at",
            )
        )
        credential = job.credential
        if status == RotationJob.Status.FAILED:
            credential.last_rotation_status = Credential.RotationStatus.FAILED
            credential.rotation_failure_count += 1
            retry_hours = min(24, 2 ** min(credential.rotation_failure_count, 5))
        else:
            credential.last_rotation_status = Credential.RotationStatus.BLOCKED
            retry_hours = 24
        credential.next_rotation_at = now + timedelta(hours=retry_hours)
        credential.save(
            update_fields=(
                "last_rotation_status",
                "rotation_failure_count",
                "next_rotation_at",
                "updated_at",
            )
        )
        record_event(
            actor=job.requested_by,
            action=(
                "credential.rotation_failed"
                if status == RotationJob.Status.FAILED
                else "credential.rotation_action_required"
            ),
            resource=job,
            metadata={"credential_id": str(credential.pk), "error_code": code},
        )
        return job


def execute_rotation(job_id):
    with transaction.atomic():
        job = RotationJob.objects.select_for_update().select_related("credential").get(pk=job_id)
        if job.status != RotationJob.Status.PENDING or job.scheduled_for > timezone.now():
            return job
        try:
            backend = get_rotation_backend(job.backend)
            current_secret = VaultCipher().decrypt(
                job.credential.encrypted_secret,
                key_id=job.credential.secret_encryption_key_id,
            )
            candidate = _candidate_secret(backend, job.credential)
            if hmac.compare_digest(candidate, current_secret):
                raise RotationBackendError(
                    "secret_unchanged",
                    "Le nouveau secret doit être différent du secret actuel.",
                )
        except RotationBackendError as exc:
            action_required = exc.code in {
                "backend_not_configured",
                "backend_invalid",
                "secret_generation_unsupported",
            }
            status = (
                RotationJob.Status.ACTION_REQUIRED
                if action_required
                else RotationJob.Status.FAILED
            )
            return _finish_without_rotation(
                job.pk,
                status=status,
                code=exc.code,
                message=exc.safe_message,
            )
        except Exception:
            return _finish_without_rotation(
                job.pk,
                status=RotationJob.Status.FAILED,
                code="vault_preparation_failed",
                message="La préparation sécurisée de la rotation a échoué.",
            )

        job.status = RotationJob.Status.RUNNING
        job.started_at = timezone.now()
        cipher = VaultCipher()
        job.encrypted_candidate_secret = cipher.encrypt(candidate)
        job.candidate_encryption_key_id = cipher.active_key_id
        job.save(
            update_fields=(
                "status",
                "started_at",
                "encrypted_candidate_secret",
                "candidate_encryption_key_id",
                "updated_at",
            )
        )
        credential_id = job.credential_id

    try:
        backend.rotate(job.credential, current_secret, candidate)
    except RotationBackendError as exc:
        return _finish_without_rotation(
            job.pk,
            status=RotationJob.Status.FAILED,
            code=exc.code,
            message=exc.safe_message,
        )
    except Exception:
        return _finish_without_rotation(
            job.pk,
            status=RotationJob.Status.FAILED,
            code="backend_unexpected_failure",
            message="Le fournisseur de rotation a échoué sans détail publiable.",
        )

    with transaction.atomic():
        job = RotationJob.objects.select_for_update().get(pk=job.pk)
        credential = Credential.objects.select_for_update().select_related(
            "rotation_policy"
        ).get(pk=credential_id)
        if job.status != RotationJob.Status.RUNNING:
            raise ValidationError("Rotation job is no longer running")
        now = timezone.now()
        credential.encrypted_secret = job.encrypted_candidate_secret
        credential.secret_encryption_key_id = job.candidate_encryption_key_id
        credential.key_version += 1
        credential.last_rotated_at = now
        credential.last_rotation_status = Credential.RotationStatus.SUCCEEDED
        credential.rotation_failure_count = 0
        credential.next_rotation_at = (
            now + timedelta(days=credential.effective_rotation_interval_days)
            if credential.automatic_rotation_enabled
            and credential.effective_rotation_interval_days
            else None
        )
        credential.save(
            update_fields=(
                "encrypted_secret",
                "secret_encryption_key_id",
                "key_version",
                "last_rotated_at",
                "last_rotation_status",
                "rotation_failure_count",
                "next_rotation_at",
                "updated_at",
            )
        )
        job.status = RotationJob.Status.SUCCEEDED
        job.completed_at = now
        job.new_key_version = credential.key_version
        job.encrypted_candidate_secret = b""
        job.error_code = ""
        job.error_message = ""
        job.save(
            update_fields=(
                "status",
                "completed_at",
                "new_key_version",
                "encrypted_candidate_secret",
                "error_code",
                "error_message",
                "updated_at",
            )
        )
        record_event(
            actor=job.requested_by,
            action="credential.rotation_succeeded",
            resource=job,
            metadata={
                "credential_id": str(credential.pk),
                "previous_key_version": job.previous_key_version,
                "new_key_version": job.new_key_version,
                "backend": job.backend,
            },
        )
        return job


def schedule_due_rotations(*, now=None, limit=100):
    now = now or timezone.now()
    queued = []
    credentials = Credential.objects.select_related("rotation_policy").filter(
        Q(rotation_enabled=True) | Q(rotation_policy__enabled=True)
    ).order_by(
        "next_rotation_at", "created_at"
    )[:limit]
    for credential in credentials:
        due_at = credential.next_rotation_at
        if (
            due_at is None
            and credential.last_rotated_at
            and credential.effective_rotation_interval_days
        ):
            due_at = credential.last_rotated_at + timedelta(
                days=credential.effective_rotation_interval_days
            )
            Credential.objects.filter(pk=credential.pk).update(next_rotation_at=due_at)
        if due_at is None or due_at <= now:
            job, created = queue_rotation(
                credential=credential,
                reason="Rotation périodique planifiée",
                scheduled_for=now,
            )
            if created:
                queued.append(job)
    return queued
