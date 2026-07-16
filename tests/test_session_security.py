import time

import pytest
from django.urls import reverse

from cbpam.accounts.models import PlatformSecurityPolicy, User
from cbpam.audit.models import AuditEvent
from cbpam.rbac.models import UserGroup


@pytest.mark.django_db
def test_idle_timeout_is_enforced_server_side(client):
    user = User.objects.create_user(username="idle-user", password="a-long-test-password")
    PlatformSecurityPolicy.objects.create(idle_timeout_minutes=5, absolute_session_minutes=60)
    client.force_login(user)
    session = client.session
    session["pam_session_started_at"] = int(time.time()) - 600
    session["pam_last_activity_at"] = int(time.time()) - 301
    session.save()

    response = client.get(reverse("dashboard"))

    assert response.status_code == 302
    assert response.url.endswith("/accounts/login/?expired=idle")
    assert "_auth_user_id" not in client.session
    assert AuditEvent.objects.filter(action="authentication.session.expired").exists()


@pytest.mark.django_db
def test_absolute_timeout_wins_over_recent_activity(client):
    user = User.objects.create_user(username="absolute-user", password="a-long-test-password")
    PlatformSecurityPolicy.objects.create(idle_timeout_minutes=15, absolute_session_minutes=30)
    client.force_login(user)
    session = client.session
    session["pam_session_started_at"] = int(time.time()) - 1801
    session["pam_last_activity_at"] = int(time.time())
    session.save()

    response = client.get(reverse("dashboard"))

    assert response.status_code == 302
    assert response.url.endswith("/accounts/login/?expired=absolute")


@pytest.mark.django_db
def test_administrator_can_update_session_policy(client):
    administrator = User.objects.create_user(username="policy-admin")
    UserGroup.objects.get(name="Administrateurs PAM-olive").users.add(administrator)
    client.force_login(administrator)

    response = client.post(
        reverse("console:security_policy"),
        {"idle_timeout_minutes": 10, "absolute_session_minutes": 240},
    )

    assert response.status_code == 302
    policy = PlatformSecurityPolicy.objects.get(pk=1)
    assert policy.idle_timeout_minutes == 10
    assert policy.absolute_session_minutes == 240
