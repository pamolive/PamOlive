import pytest
from django.urls import reverse

from pamolive.accounts.models import User
from pamolive.audit.models import AuditChainState
from pamolive.audit.services import record_event
from pamolive.rbac.models import UserGroup
from pamolive.vault.models import PersonalVaultGroup, PersonalVaultItem
from pamolive.vault.services import VaultCipher


@pytest.mark.django_db
def test_user_creates_group_and_edits_own_vault_item(client):
    user = User.objects.create_user(username="vault-editor", email="vault-editor@test.invalid")
    client.force_login(user)

    created_group = client.post(
        reverse("passwords"),
        {"action": "group", "name": "Work"},
    )
    group = PersonalVaultGroup.objects.get(owner=user, name="Work")
    created_item = client.post(
        reverse("passwords"),
        {
            "action": "item",
            "name": "Git",
            "item_type": PersonalVaultItem.ItemType.LOGIN,
            "group": str(group.pk),
            "username": "olive",
            "password": "first-secret",
        },
    )
    item = PersonalVaultItem.objects.get(owner=user, name="Git")

    assert created_group.status_code == 302
    assert created_item.status_code == 302
    assert item.group == group

    edit_page = client.get(reverse("edit_personal_item", args=[item.pk]))
    updated = client.post(
        reverse("edit_personal_item", args=[item.pk]),
        {
            "name": "Git production",
            "item_type": PersonalVaultItem.ItemType.LOGIN,
            "group": str(group.pk),
            "username": "olive-admin",
            "password": "second-secret",
        },
    )
    item.refresh_from_db()
    payload = VaultCipher().decrypt_payload(
        item.encrypted_payload,
        key_id=item.encryption_key_id,
    )

    assert edit_page.status_code == 200
    assert b"data-vault-form" in edit_page.content
    assert updated.status_code == 302
    assert item.name == "Git production"
    assert payload["password"] == "second-secret"
    assert payload["username"] == "olive-admin"


@pytest.mark.django_db
def test_user_cannot_edit_another_users_vault_item(client):
    owner = User.objects.create_user(username="vault-owner", email="owner-vault@test.invalid")
    attacker = User.objects.create_user(
        username="vault-attacker", email="attacker-vault@test.invalid"
    )
    item = PersonalVaultItem.objects.create(
        owner=owner,
        name="Private",
        item_type=PersonalVaultItem.ItemType.NOTE,
        encrypted_payload=VaultCipher().encrypt_payload({"notes": "private"}),
    )
    client.force_login(attacker)

    assert client.get(reverse("edit_personal_item", args=[item.pk])).status_code == 404


@pytest.mark.django_db
def test_theme_language_home_navigation_and_brand_assets(client):
    user = User.objects.create_user(username="preferences", email="preferences@test.invalid")
    client.force_login(user)

    changed = client.post(
        reverse("update_ui_preferences"),
        {"preferred_theme": User.Theme.LIGHT, "preferred_language": User.Language.ENGLISH},
    )
    page = client.get(reverse("dashboard"))
    client.logout()
    login_page = client.get(reverse("login"))
    user.refresh_from_db()

    assert changed.status_code == 200
    assert user.preferred_theme == User.Theme.LIGHT
    assert user.preferred_language == User.Language.ENGLISH
    assert b'data-theme-preference="light"' in page.content
    assert b">Home<" in page.content
    assert b"pam-olive-green.png" in page.content
    assert b"pam-olive-black.png" in page.content
    for url in (
        b"https://mopacy.be",
        b"https://github.com/pamolive/PamOlive",
        b"https://discord.gg/RqUBXjc7HE",
        b"https://www.linkedin.com/company/pam-olive",
    ):
        assert url in page.content
        assert url in login_page.content
    assert page.content.count(b'rel="noopener noreferrer"') >= 4


@pytest.mark.django_db
def test_admin_live_dashboard_reports_sessions_health_and_failures(client):
    administrator = User.objects.create_user(
        username="live-admin",
        email="live-admin@test.invalid",
    )
    UserGroup.objects.get(name="Administrateurs PAM-olive").users.add(administrator)
    chain = AuditChainState.objects.get(pk=1)
    record_event(
        actor=None,
        action="authentication.password.failed",
        resource=chain,
        metadata={"username": "failed-user"},
        source_ip="192.0.2.10",
    )
    client.force_login(administrator)

    page = client.get(reverse("console:dashboard"))
    status = client.get(reverse("console:dashboard_status"))

    assert page.status_code == 200
    assert b"data-admin-dashboard-url" in page.content
    assert status.status_code == 200
    assert status.json()["connected_users"] >= 1
    assert status.json()["failed_logins"] == 1
    assert status.json()["database"] == "ok"
    assert status.json()["cache"] == "ok"
    assert status.json()["failures"][0]["username"] == "failed-user"
