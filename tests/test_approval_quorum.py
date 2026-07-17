import pytest
from django.core.exceptions import PermissionDenied, ValidationError

from pamolive.accounts.models import User
from pamolive.approvals.models import AccessRequest, ApprovalDecision
from pamolive.approvals.services import decide_access_request
from pamolive.policies.models import AccessPolicy
from pamolive.rbac.models import Role, UserGroup
from pamolive.targets.models import Target


def create_request(policy, requester, target, reason="Maintenance"):
    return AccessRequest.objects.create(
        requester=requester,
        target=target,
        policy=policy,
        reason=reason,
        requested_duration_minutes=30,
    )


@pytest.mark.django_db
def test_policy_quorum_requires_two_distinct_approvers():
    requester = User.objects.create_user(username="requester", email="requester@test.invalid")
    first = User.objects.create_user(username="approver-one", email="one@test.invalid")
    second = User.objects.create_user(username="approver-two", email="two@test.invalid")
    approver_group = UserGroup.objects.create(name="Production approvers")
    approver_group.roles.add(Role.objects.get(slug="approver"))
    approver_group.users.add(first, second)
    target = Target.objects.create(
        name="Production database",
        hostname="database.test.invalid",
        port=22,
        protocol=Target.Protocol.SSH,
    )
    policy = AccessPolicy.objects.create(name="Two-person rule", approval_quorum=2)
    policy.targets.add(target)
    policy.approver_groups.add(approver_group)
    access_request = create_request(policy, requester, target)

    first_result = decide_access_request(
        access_request=access_request,
        actor=first,
        approve=True,
        comment="First review",
    )
    with pytest.raises(ValidationError, match="déjà rendu"):
        decide_access_request(
            access_request=access_request,
            actor=first,
            approve=True,
        )
    second_result = decide_access_request(
        access_request=access_request,
        actor=second,
        approve=True,
        comment="Second review",
    )

    assert first_result.status == AccessRequest.Status.PENDING
    assert second_result.status == AccessRequest.Status.APPROVED
    assert ApprovalDecision.objects.filter(access_request=access_request).count() == 2


@pytest.mark.django_db
def test_only_policy_approver_group_may_decide():
    requester = User.objects.create_user(username="asker", email="asker@test.invalid")
    allowed = User.objects.create_user(username="allowed", email="allowed@test.invalid")
    administrator = User.objects.create_user(
        username="admin-capability", email="admin@test.invalid"
    )
    allowed_group = UserGroup.objects.create(name="Allowed approvers")
    allowed_group.roles.add(Role.objects.get(slug="approver"))
    allowed_group.users.add(allowed)
    UserGroup.objects.get(name="Administrateurs PAM-olive").users.add(administrator)
    target = Target.objects.create(
        name="Restricted server",
        hostname="restricted.test.invalid",
        port=22,
        protocol=Target.Protocol.SSH,
    )
    policy = AccessPolicy.objects.create(name="Restricted approvers")
    policy.targets.add(target)
    policy.approver_groups.add(allowed_group)
    access_request = create_request(policy, requester, target)

    with pytest.raises(PermissionDenied, match="pas approbateur"):
        decide_access_request(
            access_request=access_request,
            actor=administrator,
            approve=True,
        )


@pytest.mark.django_db
def test_rejection_is_immediate_and_decision_is_immutable():
    requester = User.objects.create_user(username="request-owner", email="owner@test.invalid")
    approver = User.objects.create_user(username="rejector", email="rejector@test.invalid")
    UserGroup.objects.get(name="Approbateurs PAM-olive").users.add(approver)
    target = Target.objects.create(
        name="Critical server",
        hostname="critical.test.invalid",
        port=3389,
        protocol=Target.Protocol.RDP,
    )
    policy = AccessPolicy.objects.create(name="Critical access", approval_quorum=3)
    policy.targets.add(target)
    access_request = create_request(policy, requester, target)

    result = decide_access_request(
        access_request=access_request,
        actor=approver,
        approve=False,
        comment="Maintenance window unavailable",
    )
    decision = result.decisions.get()

    assert result.status == AccessRequest.Status.REJECTED
    decision.comment = "Changed"
    with pytest.raises(RuntimeError, match="immutable"):
        decision.save()
    with pytest.raises(RuntimeError, match="cannot be deleted"):
        decision.delete()
