from datetime import timedelta

import pytest
from django.utils import timezone

from cbpam.accounts.models import User
from cbpam.audit.models import AuditEvent
from cbpam.operations.models import RotationJob
from cbpam.operations.services import (
    clear_rotation_backends,
    execute_rotation,
    queue_rotation,
    register_rotation_backend,
    schedule_due_rotations,
)
from cbpam.targets.models import Target
from cbpam.vault.models import Credential
from cbpam.vault.services import VaultCipher


class SuccessfulBackend:
    def __init__(self):
        self.calls = []

    def generate_secret(self, credential):
        return "new-generated-password"

    def rotate(self, credential, current_secret, new_secret):
        self.calls.append((credential.pk, current_secret, new_secret))


class FailingBackend(SuccessfulBackend):
    def rotate(self, credential, current_secret, new_secret):
        raise RuntimeError(f"provider leaked {current_secret} and {new_secret}")


@pytest.fixture(autouse=True)
def isolated_rotation_registry():
    clear_rotation_backends()
    yield
    clear_rotation_backends()


@pytest.fixture
def rotation_credential(db):
    target = Target.objects.create(
        name="rotation-target",
        hostname="rotation.test.invalid",
        port=22,
        protocol=Target.Protocol.SSH,
    )
    return Credential.objects.create(
        name="rotation-account",
        target=target,
        username="operator",
        kind=Credential.Kind.PASSWORD,
        encrypted_secret=VaultCipher().encrypt("old-password"),
        rotation_enabled=True,
        rotation_interval_days=30,
        rotation_backend="test-success",
        next_rotation_at=timezone.now() - timedelta(minutes=1),
    )


@pytest.mark.django_db
def test_rotation_updates_target_vault_only_after_backend_success(rotation_credential):
    backend = SuccessfulBackend()
    register_rotation_backend("test-success", backend)
    actor = User.objects.create_user(username="rotation-admin", email="rotate@example.test")
    job, created = queue_rotation(credential=rotation_credential, requested_by=actor)

    completed = execute_rotation(job.pk)
    rotation_credential.refresh_from_db()

    assert created is True
    assert completed.status == RotationJob.Status.SUCCEEDED
    assert completed.previous_key_version == 1
    assert completed.new_key_version == 2
    assert completed.encrypted_candidate_secret == b""
    assert VaultCipher().decrypt(rotation_credential.encrypted_secret) == "new-generated-password"
    assert rotation_credential.key_version == 2
    assert rotation_credential.last_rotation_status == Credential.RotationStatus.SUCCEEDED
    assert rotation_credential.rotation_failure_count == 0
    assert rotation_credential.next_rotation_at > timezone.now() + timedelta(days=29)
    assert backend.calls == [
        (rotation_credential.pk, "old-password", "new-generated-password")
    ]
    assert AuditEvent.objects.filter(action="credential.rotation_succeeded").exists()


@pytest.mark.django_db
def test_missing_backend_blocks_without_changing_secret(rotation_credential):
    rotation_credential.rotation_backend = "missing-backend"
    rotation_credential.save(update_fields=("rotation_backend", "updated_at"))
    job, _created = queue_rotation(credential=rotation_credential)

    completed = execute_rotation(job.pk)
    rotation_credential.refresh_from_db()

    assert completed.status == RotationJob.Status.ACTION_REQUIRED
    assert completed.error_code == "backend_not_configured"
    assert VaultCipher().decrypt(rotation_credential.encrypted_secret) == "old-password"
    assert rotation_credential.key_version == 1
    assert rotation_credential.last_rotation_status == Credential.RotationStatus.BLOCKED


@pytest.mark.django_db
def test_backend_exception_is_sanitized_and_candidate_is_recoverable(rotation_credential):
    register_rotation_backend("test-success", FailingBackend())
    job, _created = queue_rotation(credential=rotation_credential)

    failed = execute_rotation(job.pk)
    rotation_credential.refresh_from_db()

    assert failed.status == RotationJob.Status.FAILED
    assert failed.error_code == "backend_unexpected_failure"
    assert "old-password" not in failed.error_message
    assert "new-generated-password" not in failed.error_message
    assert VaultCipher().decrypt(failed.encrypted_candidate_secret) == "new-generated-password"
    assert VaultCipher().decrypt(rotation_credential.encrypted_secret) == "old-password"
    assert rotation_credential.rotation_failure_count == 1
    assert not AuditEvent.objects.filter(metadata__icontains="old-password").exists()


@pytest.mark.django_db
def test_queue_rotation_is_idempotent_while_job_is_active(rotation_credential):
    first, first_created = queue_rotation(credential=rotation_credential)
    second, second_created = queue_rotation(credential=rotation_credential)
    assert first_created is True
    assert second_created is False
    assert second.pk == first.pk
    assert RotationJob.objects.count() == 1


@pytest.mark.django_db
def test_scheduler_queues_only_due_credentials(rotation_credential):
    future = Credential.objects.create(
        name="future-rotation-account",
        target=rotation_credential.target,
        username="future",
        kind=Credential.Kind.PASSWORD,
        encrypted_secret=VaultCipher().encrypt("future-password"),
        rotation_enabled=True,
        rotation_interval_days=30,
        rotation_backend="test-success",
        next_rotation_at=timezone.now() + timedelta(days=5),
    )

    queued = schedule_due_rotations()

    assert [job.credential_id for job in queued] == [rotation_credential.pk]
    assert not RotationJob.objects.filter(credential=future).exists()
