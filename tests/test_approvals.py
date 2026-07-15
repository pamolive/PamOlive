import pytest
from django.core.exceptions import PermissionDenied

from cbpam.accounts.models import User
from cbpam.approvals.models import AccessRequest
from cbpam.approvals.services import decide_access_request
from cbpam.policies.models import AccessPolicy
from cbpam.targets.models import Target


@pytest.mark.django_db
def test_requester_cannot_self_approve():
    user = User.objects.create_user(
        username="alice", email="alice@example.test", password="safe-test-password"
    )
    target = Target.objects.create(name="server-1", hostname="10.0.0.1", port=22, protocol="ssh")
    policy = AccessPolicy.objects.create(name="admins")
    policy.targets.add(target)
    request = AccessRequest.objects.create(
        requester=user,
        target=target,
        policy=policy,
        reason="Maintenance",
        requested_duration_minutes=30,
    )
    with pytest.raises(PermissionDenied):
        decide_access_request(access_request=request, actor=user, approve=True)
