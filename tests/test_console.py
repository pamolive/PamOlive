import pytest
from django.urls import reverse

from pamolive.accounts.models import User
from pamolive.approvals.models import AccessRequest
from pamolive.console.forms import AccessPolicyForm
from pamolive.mfa.services import begin_totp_enrollment, confirm_totp_device, device_secret
from pamolive.policies.models import AccessPolicy
from pamolive.policies.services import policies_for_user, targets_for_policies
from pamolive.rbac.models import UserGroup
from pamolive.targets.models import Target, TargetGroup
from pamolive.vault.services import totp_code


@pytest.fixture
def staff_user(db):
    user = User.objects.create_user(
        username="admin-olive",
        password="correct-horse-battery-staple",
    )
    group = UserGroup.objects.get(name="Administrateurs PAM-olive")
    group.users.add(user)
    return user


@pytest.mark.django_db
def test_product_console_is_separate_from_django_admin(client, staff_user):
    client.force_login(staff_user)

    console_response = client.get(reverse("console:dashboard"))
    users_response = client.get(reverse("console:users"))
    policies_response = client.get(reverse("console:policies"))
    technical_response = client.get("/django-admin/")

    assert console_response.status_code == 200
    assert b"PAM-olive" in console_response.content
    assert b"Groupes utilisateurs" in console_response.content
    assert b"Politiques" in console_response.content
    assert users_response.status_code == 200
    assert b"Utilisateurs" in users_response.content
    assert b"Mot de passe" in users_response.content
    assert policies_response.status_code == 200
    assert b"Politiques" in policies_response.content
    assert technical_response.status_code == 302

    superuser = User.objects.create_superuser(
        username="root-olive", email="root@example.test", password="a-safe-super-password"
    )
    client.force_login(superuser)
    technical_response = client.get("/django-admin/")
    assert technical_response.status_code == 302
    assert technical_response.url == reverse("mfa_setup_required")

    device, _secret = begin_totp_enrollment(superuser)
    assert confirm_totp_device(device, totp_code(device_secret(device)))
    technical_response = client.get("/django-admin/")
    assert technical_response.status_code == 200
    assert b"Administration technique" in technical_response.content


@pytest.mark.django_db
def test_django_admin_login_redirects_to_product_login_for_mfa(client):
    User.objects.create_superuser(
        username="root-olive",
        email="root@example.test",
        password="a-safe-super-password",
    )

    login_page = client.get("/django-admin/login/?next=/django-admin/")
    password_only_attempt = client.post(
        "/django-admin/login/?next=/django-admin/",
        {"username": "root-olive", "password": "a-safe-super-password"},
    )

    assert login_page.status_code == 302
    assert login_page.url == f"{reverse('login')}?next=/django-admin/"
    assert password_only_attempt.status_code == 302
    assert password_only_attempt.url == f"{reverse('login')}?next=/django-admin/"


@pytest.mark.django_db
def test_product_console_requires_administrator_role(client):
    user = User.objects.create_user(username="olive", password="a-long-password-for-tests")
    client.force_login(user)

    response = client.get(reverse("console:dashboard"))

    assert response.status_code == 403


@pytest.mark.django_db
def test_group_without_active_policy_grants_no_access():
    user = User.objects.create_user(username="olive")
    group = UserGroup.objects.create(name="Operations")
    group.users.add(user)

    assert not policies_for_user(user).exists()
    assert not targets_for_policies(policies_for_user(user)).exists()


@pytest.mark.django_db
def test_policy_form_requires_user_and_target_groups():
    form = AccessPolicyForm(
        data={
            "name": "Production",
            "actions": [AccessPolicy.Action.REQUEST_ACCESS],
            "max_duration_minutes": 60,
            "requires_approval": True,
            "requires_mfa": True,
            "enabled": True,
        }
    )

    assert not form.is_valid()
    assert "user_groups" in form.errors
    assert "target_groups" in form.errors


@pytest.mark.django_db
def test_policy_links_a_user_group_to_a_target_group(client):
    user = User.objects.create_user(username="olive")
    user_group = UserGroup.objects.create(name="Operations")
    user_group.users.add(user)
    target = Target.objects.create(
        name="Linux production",
        hostname="10.0.0.10",
        port=22,
        protocol=Target.Protocol.SSH,
    )
    target_group = TargetGroup.objects.create(name="Production")
    target_group.targets.add(target)
    policy = AccessPolicy.objects.create(
        name="Operations production",
        actions=[AccessPolicy.Action.REQUEST_ACCESS, AccessPolicy.Action.START_SESSION],
        max_duration_minutes=30,
    )
    policy.user_groups.add(user_group)
    policy.target_groups.add(target_group)
    client.force_login(user)

    dashboard_response = client.get(reverse("dashboard"))
    request_response = client.post(
        reverse("requests"),
        {
            "policy": policy.pk,
            "target": target.pk,
            "reason": "Maintenance planifiee",
            "requested_duration_minutes": 20,
        },
    )

    assert dashboard_response.status_code == 200
    assert list(dashboard_response.context["target_groups"])[0] == target_group
    assert request_response.status_code == 302
    assert AccessRequest.objects.filter(requester=user, target=target, policy=policy).exists()


@pytest.mark.django_db
def test_requests_are_a_real_separate_page(client):
    user = User.objects.create_user(username="olive")
    client.force_login(user)

    response = client.get(reverse("requests"))

    assert response.status_code == 200
    assert b"Mes demandes" in response.content
    assert b"Aucune politique disponible" in response.content
