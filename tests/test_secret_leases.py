import time
from datetime import timedelta

import pytest
from django.core.exceptions import PermissionDenied, ValidationError
from django.utils import timezone

from pamolive.accounts.models import User
from pamolive.approvals.models import AccessRequest
from pamolive.audit.models import AuditEvent
from pamolive.mfa.models import MFADevice
from pamolive.policies.models import AccessPolicy
from pamolive.rbac.models import UserGroup
from pamolive.targets.models import Target, TargetGroup
from pamolive.vault.leases import (
    consume_secret_lease,
    issue_secret_lease,
    revoke_secret_lease,
)
from pamolive.vault.models import Credential, SecretLease
from pamolive.vault.services import VaultCipher


def lease_fixture(*, requires_approval=False, requires_mfa=False):
    user = User.objects.create_user(username="lease-user", email="lease-user@test.invalid")
    target = Target.objects.create(
        name="Lease target",
        hostname="lease-target.test.invalid",
        port=22,
        protocol=Target.Protocol.SSH,
    )
    credential = Credential.objects.create(
        name="Lease credential",
        target=target,
        username="root",
        kind=Credential.Kind.PASSWORD,
        encrypted_secret=VaultCipher().encrypt("leased-password"),
    )
    user_group = UserGroup.objects.create(name="Lease users")
    user_group.users.add(user)
    target_group = TargetGroup.objects.create(name="Lease targets")
    target_group.targets.add(target)
    policy = AccessPolicy.objects.create(
        name="Lease policy",
        actions=[AccessPolicy.Action.VIEW_SECRET],
        requires_approval=requires_approval,
        requires_mfa=requires_mfa,
    )
    policy.user_groups.add(user_group)
    policy.target_groups.add(target_group)
    return user, credential, policy


@pytest.mark.django_db
def test_secret_lease_is_hashed_single_use_and_audited():
    user, credential, _policy = lease_fixture()

    with pytest.raises(ValidationError, match="business justification"):
        issue_secret_lease(user=user, credential=credential, justification="")

    lease, token = issue_secret_lease(
        user=user,
        credential=credential,
        justification="Routine operational access test",
        lifetime_seconds=30,
    )
    consumed, secret = consume_secret_lease(token=token, expected_user=user)

    assert token not in lease.token_hash
    assert secret == "leased-password"
    assert consumed.use_count == 1
    credential.refresh_from_db()
    assert credential.last_checked_out_at is not None
    with pytest.raises(PermissionDenied, match="déjà été consommé"):
        consume_secret_lease(token=token, expected_user=user)
    assert AuditEvent.objects.filter(action="credential.secret_lease.issued").exists()
    assert AuditEvent.objects.filter(action="credential.secret_lease.consumed").exists()


@pytest.mark.django_db
def test_secret_lease_requires_active_approval_and_mfa():
    user, credential, policy = lease_fixture(requires_approval=True, requires_mfa=True)
    with pytest.raises(PermissionDenied, match="Aucune autorisation active"):
        issue_secret_lease(
            user=user,
            credential=credential,
            justification="Routine operational access test",
        )

    access_request = AccessRequest.objects.create(
        requester=user,
        target=credential.target,
        policy=policy,
        reason="Incident",
        requested_duration_minutes=30,
        status=AccessRequest.Status.APPROVED,
        decided_at=timezone.now(),
    )
    with pytest.raises(PermissionDenied, match="Aucune autorisation active"):
        issue_secret_lease(
            user=user,
            credential=credential,
            justification="Routine operational access test",
        )

    MFADevice.objects.create(
        user=user,
        name="Confirmed TOTP",
        kind=MFADevice.Kind.TOTP,
        encrypted_configuration=VaultCipher().encrypt("JBSWY3DPEHPK3PXP"),
        confirmed=True,
    )
    lease, _token = issue_secret_lease(
        user=user,
        credential=credential,
        justification="Routine operational access test",
        mfa_verified_at=int(time.time()),
    )

    assert lease.access_request == access_request


@pytest.mark.django_db
def test_expired_revoked_or_foreign_lease_is_rejected():
    user, credential, _policy = lease_fixture()
    other = User.objects.create_user(username="other-lease-user", email="other@test.invalid")

    with pytest.raises(ValidationError, match="15 et 300"):
        issue_secret_lease(
            user=user,
            credential=credential,
            justification="Routine operational access test",
            lifetime_seconds=5,
        )
    lease, token = issue_secret_lease(
        user=user,
        credential=credential,
        justification="Routine operational access test",
    )
    with pytest.raises(PermissionDenied, match="autre utilisateur"):
        consume_secret_lease(token=token, expected_user=other)

    revoke_secret_lease(lease, user)
    with pytest.raises(PermissionDenied, match="expiré"):
        consume_secret_lease(token=token, expected_user=user)

    expired_lease, expired_token = issue_secret_lease(
        user=user,
        credential=credential,
        justification="Routine operational access test",
    )
    SecretLease.objects.filter(pk=expired_lease.pk).update(
        expires_at=timezone.now() - timedelta(seconds=1)
    )
    with pytest.raises(PermissionDenied, match="expiré"):
        consume_secret_lease(token=expired_token, expected_user=user)
