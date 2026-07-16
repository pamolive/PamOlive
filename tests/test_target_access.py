import pytest
from django.urls import reverse

from cbpam.accounts.models import User
from cbpam.audit.models import AuditEvent
from cbpam.policies.models import AccessPolicy
from cbpam.rbac.models import UserGroup
from cbpam.targets.models import Target, TargetGroup
from cbpam.vault.models import Credential
from cbpam.vault.services import VaultCipher


def grant_target_actions(user, target, actions):
    user_group = UserGroup.objects.create(name=f"Group-{user.username}")
    user_group.users.add(user)
    target_group = TargetGroup.objects.create(name=f"Targets-{user.username}")
    target_group.targets.add(target)
    policy = AccessPolicy.objects.create(
        name=f"Policy-{user.username}",
        actions=actions,
        requires_approval=False,
        requires_mfa=False,
    )
    policy.user_groups.add(user_group)
    policy.target_groups.add(target_group)
    return target_group


@pytest.mark.django_db
def test_target_password_and_totp_require_policy_actions(client):
    user = User.objects.create_user(username="operator", email="operator@example.test")
    target = Target.objects.create(
        name="NAS", hostname="192.168.0.25", port=22, protocol=Target.Protocol.SSH
    )
    cipher = VaultCipher()
    credential = Credential.objects.create(
        name="Local admin",
        target=target,
        username="administrator",
        kind=Credential.Kind.PASSWORD,
        encrypted_secret=cipher.encrypt("target-password"),
        encrypted_totp_secret=cipher.encrypt("JBSWY3DPEHPK3PXP"),
    )
    client.force_login(user)

    assert client.post(
        reverse("reveal_target_credential", args=[credential.pk]),
        {"justification": "Investigate production access issue"},
    ).status_code == 403

    grant_target_actions(
        user,
        target,
        [AccessPolicy.Action.VIEW_SECRET, AccessPolicy.Action.REVEAL_TOTP],
    )
    missing_reason = client.post(reverse("reveal_target_credential", args=[credential.pk]))
    response = client.post(
        reverse("reveal_target_credential", args=[credential.pk]),
        {"justification": "Investigate production access issue"},
    )

    assert missing_reason.status_code == 400
    assert response.status_code == 200
    assert b"target-password" in response.content
    assert b"Code TOTP actuel" in response.content
    assert AuditEvent.objects.filter(action="credential.secret_lease.consumed").exists()

    totp_response = client.get(reverse("target_credential_totp", args=[credential.pk]))
    assert totp_response.status_code == 200
    assert len(totp_response.json()["code"]) == 6
    assert 1 <= totp_response.json()["remaining"] <= 30
    assert "no-store" in totp_response.headers["Cache-Control"]
    assert b"data-secret-close" in response.content


@pytest.mark.django_db
def test_targets_page_only_contains_authorized_target_groups(client):
    user = User.objects.create_user(username="operator", email="operator@example.test")
    allowed = Target.objects.create(
        name="Allowed", hostname="10.0.0.1", port=22, protocol=Target.Protocol.SSH
    )
    hidden = Target.objects.create(
        name="Hidden", hostname="10.0.0.2", port=3389, protocol=Target.Protocol.RDP
    )
    allowed_group = grant_target_actions(user, allowed, [AccessPolicy.Action.REQUEST_ACCESS])
    hidden_group = TargetGroup.objects.create(name="Secret infrastructure")
    hidden_group.targets.add(hidden)
    client.force_login(user)

    response = client.get(reverse("targets"))

    assert response.status_code == 200
    assert allowed_group.name.encode() in response.content
    assert b"Allowed" in response.content
    assert hidden_group.name.encode() not in response.content
    assert b"Hidden" not in response.content


@pytest.mark.django_db
def test_session_opens_new_tab_and_missing_host_key_has_clear_message(client):
    user = User.objects.create_user(username="session-user")
    target = Target.objects.create(
        name="SSH without trusted key",
        hostname="10.0.0.8",
        port=22,
        protocol=Target.Protocol.SSH,
        ssh_host_key_policy=Target.SSHHostKeyPolicy.STRICT,
    )
    credential = Credential.objects.create(
        name="root",
        target=target,
        username="root",
        kind=Credential.Kind.PASSWORD,
        encrypted_secret=VaultCipher().encrypt("secret"),
    )
    grant_target_actions(user, target, [AccessPolicy.Action.START_SESSION])
    client.force_login(user)

    target_page = client.get(reverse("targets"))
    assert b'target="_blank"' in target_page.content

    missing_reason = client.post(reverse("start_session", args=[credential.pk]))
    response = client.post(
        reverse("start_session", args=[credential.pk]),
        {"justification": "Investigate production access issue"},
    )
    assert missing_reason.status_code == 400
    assert response.status_code == 200
    assert b"Session non ouverte" in response.content
    assert b"cl\xc3\xa9 d\xe2\x80\x99h\xc3\xb4te SSH" in response.content


@pytest.mark.django_db
def test_superadministrator_has_no_justification_bypass(client):
    superadministrator = User.objects.create_superuser(
        username="reason-superadmin",
        email="reason-superadmin@example.test",
        password="safe-test-password",
    )
    target = Target.objects.create(
        name="Justified SSH",
        hostname="192.0.2.50",
        port=22,
        protocol=Target.Protocol.SSH,
    )
    credential = Credential.objects.create(
        name="Privileged local account",
        target=target,
        username="operator",
        kind=Credential.Kind.PASSWORD,
        encrypted_secret=VaultCipher().encrypt("secret"),
    )
    grant_target_actions(
        superadministrator,
        target,
        [AccessPolicy.Action.VIEW_SECRET, AccessPolicy.Action.START_SESSION],
    )
    client.force_login(superadministrator)

    assert client.post(
        reverse("reveal_target_credential", args=[credential.pk])
    ).status_code == 400
    assert client.post(reverse("start_session", args=[credential.pk])).status_code == 400


@pytest.mark.django_db
def test_administrator_creates_target_with_initial_local_credential(client):
    administrator = User.objects.create_user(
        username="admin", email="admin@example.test", password="safe-password"
    )
    UserGroup.objects.get(name="Administrateurs PAM-olive").users.add(administrator)
    client.force_login(administrator)

    invalid = client.post(
        reverse("console:targets"),
        {"name": "Incomplete", "hostname": "10.0.0.3", "port": 22, "protocol": "ssh"},
    )
    assert invalid.status_code == 200
    assert not Target.objects.filter(name="Incomplete").exists()

    valid = client.post(
        reverse("console:targets"),
        {
            "name": "Complete",
            "hostname": "10.0.0.4",
            "port": 22,
            "protocol": "ssh",
            "enabled": "on",
            "credential_name": "root local",
            "credential_username": "root",
            "credential_password": "secret-local-password",
        },
    )
    target = Target.objects.get(name="Complete")
    assert valid.status_code == 302
    assert target.credentials.count() == 1
    assert (
        VaultCipher().decrypt(target.credentials.get().encrypted_secret) == "secret-local-password"
    )

    unsupported = client.post(
        reverse("console:targets"),
        {
            "name": "Unsupported web app",
            "hostname": "example.test",
            "port": 443,
            "protocol": "web",
            "credential_name": "service",
            "credential_username": "service",
            "credential_password": "secret",
        },
    )
    assert unsupported.status_code == 200
    assert not Target.objects.filter(name="Unsupported web app").exists()
