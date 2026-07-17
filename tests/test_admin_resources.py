import pytest
from django.urls import reverse

from pamolive.accounts.models import User
from pamolive.policies.models import AccessPolicy, SecretRotationPolicy, TimeFrame
from pamolive.rbac.models import Role, UserGroup
from pamolive.targets.models import Target, TargetGroup
from pamolive.vault.models import Credential
from pamolive.vault.services import VaultCipher


@pytest.fixture
def administrator(db):
    user = User.objects.create_user(
        username="functional-admin",
        email="functional-admin@example.test",
        password="safe-admin-password",
    )
    UserGroup.objects.get(name="Administrateurs PAM-olive").users.add(user)
    return user


@pytest.mark.django_db
def test_administration_subtabs_render(client, administrator):
    client.force_login(administrator)

    for name in (
        "console:roles",
        "console:identity_sources",
        "console:ldap_sources",
        "console:oidc_sources",
        "console:directory_mappings",
        "console:domains",
        "console:target_groups",
        "console:credentials",
        "console:policies",
        "console:time_frames",
        "console:rotation_policies",
        "console:approvals",
        "console:sessions",
        "console:audit",
    ):
        assert client.get(reverse(name)).status_code == 200


@pytest.mark.django_db
def test_administrator_can_configure_role_groups_credentials_and_policy(client, administrator):
    client.force_login(administrator)
    target = Target.objects.create(
        name="Database", hostname="10.0.0.20", port=22, protocol=Target.Protocol.SSH
    )

    role_response = client.post(
        reverse("console:roles"),
        {
            "name": "Database operator",
            "slug": "database-operator",
            "description": "Database access",
            "capabilities": [Role.Capability.SESSIONS_VIEW],
            "enabled": "on",
        },
    )
    role = Role.objects.get(slug="database-operator")
    assert role_response.status_code == 302

    group_response = client.post(
        reverse("console:user_groups"),
        {
            "name": "Database team",
            "description": "DBA",
            "users": [administrator.pk],
            "roles": [role.pk],
            "enabled": "on",
        },
    )
    user_group = UserGroup.objects.get(name="Database team")
    assert group_response.status_code == 302

    target_group_response = client.post(
        reverse("console:target_groups"),
        {
            "name": "Database targets",
            "description": "Databases",
            "targets": [target.pk],
            "enabled": "on",
        },
    )
    target_group = TargetGroup.objects.get(name="Database targets")
    assert target_group_response.status_code == 302

    credential_response = client.post(
        reverse("console:credentials"),
        {
            "name": "DB local admin",
            "target": target.pk,
            "username": "dbadmin",
            "kind": Credential.Kind.PASSWORD,
            "secret": "db-password",
            "totp_secret": "JBSWY3DPEHPK3PXP",
        },
    )
    credential = Credential.objects.get(name="DB local admin")
    assert credential_response.status_code == 302
    assert VaultCipher().decrypt(credential.encrypted_secret) == "db-password"

    policy_response = client.post(
        reverse("console:policies"),
        {
            "name": "Database policy",
            "user_groups": [user_group.pk],
            "target_groups": [target_group.pk],
            "actions": [
                AccessPolicy.Action.REQUEST_ACCESS,
                AccessPolicy.Action.VIEW_SECRET,
            ],
            "requires_approval": "on",
            "requires_mfa": "on",
            "max_duration_minutes": 60,
            "enabled": "on",
        },
    )
    assert policy_response.status_code == 302
    assert AccessPolicy.objects.filter(name="Database policy").exists()


@pytest.mark.django_db
def test_administrator_can_create_local_user(client, administrator):
    client.force_login(administrator)

    response = client.post(
        reverse("console:users"),
        {
            "username": "new-user",
            "display_name": "New User",
            "email": "new-user@example.test",
            "is_active": "on",
            "password1": "correct-horse-battery-staple",
            "password2": "correct-horse-battery-staple",
        },
    )

    assert response.status_code == 302
    assert User.objects.filter(username="new-user").exists()


@pytest.mark.django_db
def test_administrator_creates_time_frame_and_rotation_policy(client, administrator):
    client.force_login(administrator)
    target_group = TargetGroup.objects.create(name="Managed Linux")

    time_response = client.post(
        reverse("console:time_frames"),
        {
            "name": "Nuits de semaine",
            "weekdays": [0, 1, 2, 3, 4],
            "start_time": "22:00",
            "end_time": "06:00",
            "enabled": "on",
        },
    )
    rotation_response = client.post(
        reverse("console:rotation_policies"),
        {
            "name": "Comptes Linux mensuels",
            "target_groups": [target_group.pk],
            "strategy": SecretRotationPolicy.Strategy.GENERATED_PASSWORD,
            "interval_days": 30,
            "password_length": 32,
            "connector_key": "linux-ssh",
            "enabled": "on",
        },
    )

    assert time_response.status_code == 302
    assert rotation_response.status_code == 302
    assert TimeFrame.objects.get(name="Nuits de semaine").weekdays == [0, 1, 2, 3, 4]
    policy = SecretRotationPolicy.objects.get(name="Comptes Linux mensuels")
    assert list(policy.target_groups.all()) == [target_group]
