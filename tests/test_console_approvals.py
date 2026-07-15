import pytest
from django.urls import reverse

from cbpam.accounts.models import User
from cbpam.approvals.models import AccessRequest
from cbpam.policies.models import AccessPolicy
from cbpam.rbac.models import UserGroup
from cbpam.targets.models import Target


@pytest.mark.django_db
def test_administrator_can_approve_another_users_request(client):
    administrator = User.objects.create_user(username="admin", email="admin@example.test")
    requester = User.objects.create_user(username="requester", email="requester@example.test")
    UserGroup.objects.get(name="Administrateurs PAM-olive").users.add(administrator)
    target = Target.objects.create(
        name="Production", hostname="10.0.0.10", port=22, protocol=Target.Protocol.SSH
    )
    policy = AccessPolicy.objects.create(name="Production access")
    access_request = AccessRequest.objects.create(
        requester=requester,
        target=target,
        policy=policy,
        reason="Incident",
        requested_duration_minutes=30,
    )
    client.force_login(administrator)

    response = client.post(
        reverse("console:approvals"),
        {"request_id": access_request.pk, "decision": "approve", "comment": "Approved"},
    )

    access_request.refresh_from_db()
    assert response.status_code == 302
    assert access_request.status == AccessRequest.Status.APPROVED
    assert access_request.decided_by == administrator


@pytest.mark.django_db
def test_administrator_cannot_approve_own_request_through_console(client):
    administrator = User.objects.create_user(username="admin", email="admin@example.test")
    UserGroup.objects.get(name="Administrateurs PAM-olive").users.add(administrator)
    target = Target.objects.create(
        name="Production", hostname="10.0.0.10", port=22, protocol=Target.Protocol.SSH
    )
    policy = AccessPolicy.objects.create(name="Production access")
    access_request = AccessRequest.objects.create(
        requester=administrator,
        target=target,
        policy=policy,
        reason="Incident",
        requested_duration_minutes=30,
    )
    client.force_login(administrator)

    response = client.post(
        reverse("console:approvals"),
        {"request_id": access_request.pk, "decision": "approve"},
    )

    access_request.refresh_from_db()
    assert response.status_code == 302
    assert access_request.status == AccessRequest.Status.PENDING
