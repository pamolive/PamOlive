import base64
from datetime import datetime, time, timedelta

import pytest
from django.core.exceptions import PermissionDenied
from django.utils import timezone

from pamolive.accounts.models import User
from pamolive.console.forms import AccessPolicyForm
from pamolive.policies.models import AccessPolicy, TimeFrame
from pamolive.policies.services import policy_is_current
from pamolive.rbac.models import UserGroup
from pamolive.sessions.services import consume_session_ticket, issue_session_ticket
from pamolive.targets.models import Target, TargetGroup, TargetHostKey
from pamolive.vault.leases import issue_secret_lease
from pamolive.vault.models import Credential
from pamolive.vault.services import VaultCipher


def public_host_key():
    algorithm = b"ssh-ed25519"
    material = b"\x04" * 32
    blob = (
        len(algorithm).to_bytes(4, "big")
        + algorithm
        + len(material).to_bytes(4, "big")
        + material
    )
    return f"ssh-ed25519 {base64.b64encode(blob).decode()}"


def constrained_policy_fixture():
    user = User.objects.create_user(
        username="constrained-user",
        email="constrained@test.invalid",
    )
    target = Target.objects.create(
        name="Constrained target",
        hostname="constrained.test.invalid",
        port=22,
        protocol=Target.Protocol.SSH,
    )
    TargetHostKey.objects.create(target=target, public_key=public_host_key())
    allowed = Credential.objects.create(
        name="Allowed account",
        target=target,
        username="allowed",
        kind=Credential.Kind.PASSWORD,
        encrypted_secret=VaultCipher().encrypt("allowed-secret"),
    )
    denied = Credential.objects.create(
        name="Denied account",
        target=target,
        username="denied",
        kind=Credential.Kind.PASSWORD,
        encrypted_secret=VaultCipher().encrypt("denied-secret"),
    )
    users = UserGroup.objects.create(name="Constrained users")
    users.users.add(user)
    targets = TargetGroup.objects.create(name="Constrained targets")
    targets.targets.add(target)
    policy = AccessPolicy.objects.create(
        name="Constrained policy",
        actions=[AccessPolicy.Action.VIEW_SECRET, AccessPolicy.Action.START_SESSION],
        requires_approval=False,
        requires_mfa=False,
    )
    policy.user_groups.add(users)
    policy.target_groups.add(targets)
    return user, target, allowed, denied, policy, users, targets


@pytest.mark.django_db
def test_policy_restricts_specific_credentials_and_protocols():
    user, _target, allowed, denied, policy, _users, _targets = constrained_policy_fixture()
    policy.credentials.add(allowed)

    lease, _token = issue_secret_lease(
        user=user, credential=allowed, justification="Investigate production alert"
    )
    assert lease.policy == policy
    with pytest.raises(PermissionDenied, match="Aucune autorisation active"):
        issue_secret_lease(
            user=user, credential=denied, justification="Investigate production alert"
        )

    policy.protocols = [Target.Protocol.RDP]
    policy.save(update_fields=("protocols", "updated_at"))
    with pytest.raises(PermissionDenied, match="Aucune autorisation active"):
        issue_secret_lease(
            user=user, credential=allowed, justification="Investigate production alert"
        )


@pytest.mark.django_db
def test_policy_enforces_source_cidr():
    user, _target, allowed, _denied, policy, _users, _targets = constrained_policy_fixture()
    policy.source_cidrs = ["10.0.0.0/8", "2001:db8::/32"]
    policy.save(update_fields=("source_cidrs", "updated_at"))

    with pytest.raises(PermissionDenied, match="Aucune autorisation active"):
        issue_secret_lease(
            user=user,
            credential=allowed,
            justification="Investigate production alert",
            source_ip="192.0.2.10",
        )
    lease, _token = issue_secret_lease(
        user=user,
        credential=allowed,
        justification="Investigate production alert",
        source_ip="10.20.30.40",
    )
    assert lease.policy == policy


@pytest.mark.django_db
def test_policy_handles_validity_weekdays_and_overnight_window():
    _user, _target, _allowed, _denied, policy, _users, _targets = constrained_policy_fixture()
    monday_late = timezone.make_aware(datetime(2026, 7, 13, 23, 30))
    tuesday_early = monday_late + timedelta(hours=2)
    monday_midday = monday_late.replace(hour=12)
    policy.valid_from = monday_late - timedelta(days=1)
    policy.valid_until = monday_late + timedelta(days=2)
    policy.weekdays = [0, 1]
    policy.access_start_time = time(22, 0)
    policy.access_end_time = time(6, 0)

    assert policy_is_current(policy, at=monday_late)
    assert policy_is_current(policy, at=tuesday_early)
    assert not policy_is_current(policy, at=monday_midday)
    policy.weekdays = [2]
    assert not policy_is_current(policy, at=monday_late)


@pytest.mark.django_db
def test_policy_uses_reusable_time_frames_instead_of_legacy_schedule():
    _user, _target, _allowed, _denied, policy, _users, _targets = constrained_policy_fixture()
    monday_late = timezone.make_aware(datetime(2026, 7, 13, 23, 30))
    frame = TimeFrame.objects.create(
        name="Maintenance de nuit",
        weekdays=[0, 1],
        start_time=time(22, 0),
        end_time=time(6, 0),
    )
    policy.time_frames.add(frame)
    policy.weekdays = [4]

    assert policy_is_current(policy, at=monday_late)
    assert policy_is_current(policy, at=monday_late + timedelta(hours=2))
    assert not policy_is_current(policy, at=monday_late.replace(hour=12))


@pytest.mark.django_db
def test_policy_limits_concurrent_sessions():
    user, _target, allowed, _denied, policy, _users, _targets = constrained_policy_fixture()
    session, _ticket, token = issue_session_ticket(
        user=user, credential=allowed, justification="Investigate production alert"
    )
    consume_session_ticket(session_id=session.pk, token=token, user=user)

    with pytest.raises(PermissionDenied, match="sessions simultanées"):
        issue_session_ticket(
            user=user, credential=allowed, justification="Investigate production alert"
        )

    policy.max_concurrent_sessions = 2
    policy.save(update_fields=("max_concurrent_sessions", "updated_at"))
    second, _second_ticket, _second_token = issue_session_ticket(
        user=user,
        credential=allowed,
        justification="Investigate production alert",
    )
    assert second.policy == policy


@pytest.mark.django_db
def test_pending_ticket_reserves_concurrent_session_capacity():
    user, _target, allowed, _denied, _policy, _users, _targets = constrained_policy_fixture()
    session, _ticket, token = issue_session_ticket(
        user=user, credential=allowed, justification="Investigate production alert"
    )

    with pytest.raises(PermissionDenied, match="sessions simultanées"):
        issue_session_ticket(
            user=user, credential=allowed, justification="Investigate production alert"
        )

    consume_session_ticket(session_id=session.pk, token=token, user=user)


@pytest.mark.django_db
def test_policy_form_rejects_invalid_network_and_validity_order():
    _user, _target, _allowed, _denied, _policy, users, targets = constrained_policy_fixture()
    now = timezone.localtime().replace(second=0, microsecond=0)
    form = AccessPolicyForm(
        data={
            "name": "Invalid constrained policy",
            "user_groups": [users.pk],
            "target_groups": [targets.pk],
            "actions": [AccessPolicy.Action.START_SESSION],
            "approval_quorum": 1,
            "max_duration_minutes": 30,
            "max_concurrent_sessions": 1,
            "valid_from": (now + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M"),
            "valid_until": now.strftime("%Y-%m-%dT%H:%M"),
            "source_cidrs": "10.0.0.0/8\nnot-a-network",
            "enabled": "on",
        }
    )

    assert not form.is_valid()
    assert "source_cidrs" in form.errors
    assert "valid_until" in form.errors
