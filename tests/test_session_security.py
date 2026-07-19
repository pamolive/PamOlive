import json
import time

import pytest
from django.contrib.messages.storage.fallback import FallbackStorage
from django.core.exceptions import PermissionDenied
from django.test import override_settings
from django.urls import reverse

from pamolive.accounts.models import PlatformSecurityPolicy, User
from pamolive.accounts.sensitive_actions import (
    MFA_SESSION_KEY,
    ConsoleConfigurationStepUpMiddleware,
    mfa_timestamp_is_recent,
    require_recent_mfa_or_raise,
    sensitive_mfa_required,
    user_has_recent_mfa,
)
from pamolive.audit.models import AuditEvent
from pamolive.mfa.models import MFADevice
from pamolive.rbac.models import UserGroup
from pamolive.vault.services import VaultCipher


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
    MFADevice.objects.create(
        user=administrator,
        name="Confirmed TOTP",
        kind=MFADevice.Kind.TOTP,
        encrypted_configuration=VaultCipher().encrypt("JBSWY3DPEHPK3PXP"),
        confirmed=True,
    )
    client.force_login(administrator)
    session = client.session
    session[MFA_SESSION_KEY] = int(time.time())
    session.save()

    response = client.post(
        reverse("console:security_policy"),
        {
            "idle_timeout_minutes": 10,
            "absolute_session_minutes": 240,
            "require_mfa_for_all_users": "on",
            "sensitive_action_mfa_window_minutes": 10,
        },
    )

    assert response.status_code == 302
    policy = PlatformSecurityPolicy.objects.get(pk=1)
    assert policy.idle_timeout_minutes == 10
    assert policy.absolute_session_minutes == 240
    assert policy.sensitive_action_mfa_window_minutes == 10


@pytest.mark.django_db
@override_settings(PAMOLIVE_TEST_BYPASS_GLOBAL_MFA=False)
def test_sensitive_mfa_helpers_fail_closed(rf):
    policy = PlatformSecurityPolicy.objects.create(sensitive_action_mfa_window_minutes=5)
    user = User.objects.create_user(username="sensitive-helper")
    request = rf.post("/api/sensitive/", HTTP_HX_REQUEST="true")
    request.user = user
    request.session = {}
    request.platform_security_policy = policy

    assert mfa_timestamp_is_recent(None, policy=policy, now=1_000) is False
    assert mfa_timestamp_is_recent("invalid", policy=policy, now=1_000) is False
    assert mfa_timestamp_is_recent(700, policy=policy, now=1_000) is True
    assert mfa_timestamp_is_recent(699, policy=policy, now=1_000) is False
    assert user_has_recent_mfa(request, policy=policy, now=1_000) is False

    response = sensitive_mfa_required(request, action_label="tester une action")
    assert response.status_code == 302
    assert response.url == reverse("mfa_setup_required")

    MFADevice.objects.create(
        user=user,
        name="Confirmed helper TOTP",
        kind=MFADevice.Kind.TOTP,
        encrypted_configuration=VaultCipher().encrypt("JBSWY3DPEHPK3PXP"),
        confirmed=True,
    )
    response = sensitive_mfa_required(request, action_label="tester une action")
    assert response.status_code == 403
    assert json.loads(response.content)["mfa_required"] is True

    with pytest.raises(PermissionDenied, match="MFA récente"):
        require_recent_mfa_or_raise(request, action_label="tester une action")
    request.session[MFA_SESSION_KEY] = int(time.time())
    assert user_has_recent_mfa(request, policy=policy) is True
    assert sensitive_mfa_required(request) is None
    assert require_recent_mfa_or_raise(request, action_label="tester une action") is None


@pytest.mark.django_db
@override_settings(PAMOLIVE_TEST_BYPASS_GLOBAL_MFA=False)
def test_configuration_step_up_middleware_challenges_admin_post(rf):
    policy = PlatformSecurityPolicy.objects.create(sensitive_action_mfa_window_minutes=5)
    user = User.objects.create_user(username="configuration-step-up")
    MFADevice.objects.create(
        user=user,
        name="Confirmed configuration TOTP",
        kind=MFADevice.Kind.TOTP,
        encrypted_configuration=VaultCipher().encrypt("JBSWY3DPEHPK3PXP"),
        confirmed=True,
    )
    request = rf.post("/admin/targets/new/")
    request.user = user
    request.session = {}
    request.platform_security_policy = policy
    request._messages = FallbackStorage(request)
    middleware = ConsoleConfigurationStepUpMiddleware(lambda _request: "allowed")

    response = middleware(request)

    assert response.status_code == 302
    assert reverse("mfa_verify") in response.url
    assert middleware(rf.get("/admin/targets/")) == "allowed"
