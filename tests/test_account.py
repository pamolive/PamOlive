import pytest
from django.urls import reverse

from cbpam.accounts.models import User
from cbpam.vault.forms import PersonalVaultItemForm
from cbpam.vault.models import PersonalVaultItem


@pytest.mark.django_db
def test_user_updates_profile_and_password(client):
    user = User.objects.create_user(
        username="profile-user",
        email="profile@example.test",
        password="old-correct-horse-password",
    )
    client.force_login(user)

    profile_response = client.post(
        reverse("account"),
        {
            "action": "profile",
            "display_name": "Olive User",
            "email": "profile@example.test",
            "first_name": "Olive",
            "last_name": "User",
        },
    )
    password_response = client.post(
        reverse("account"),
        {
            "action": "password",
            "old_password": "old-correct-horse-password",
            "new_password1": "new-correct-horse-password",
            "new_password2": "new-correct-horse-password",
        },
    )

    user.refresh_from_db()
    assert profile_response.status_code == 302
    assert password_response.status_code == 302
    assert user.display_name == "Olive User"
    assert user.check_password("new-correct-horse-password")


@pytest.mark.django_db
def test_mfa_setup_renders_local_qr_code(client):
    user = User.objects.create_user(username="qr-user", email="qr@example.test")
    client.force_login(user)

    response = client.post(reverse("mfa_setup"))

    assert response.status_code == 200
    assert b"<svg" in response.content
    assert b"Activer d" in response.content


@pytest.mark.parametrize(
    ("item_type", "expected_field"),
    [
        (PersonalVaultItem.ItemType.LOGIN, "password"),
        (PersonalVaultItem.ItemType.TOTP, "totp_secret"),
        (PersonalVaultItem.ItemType.CARD, "card_number"),
        (PersonalVaultItem.ItemType.NOTE, "notes"),
    ],
)
def test_personal_vault_types_validate_required_secret(item_type, expected_field):
    form = PersonalVaultItemForm(data={"name": "Missing value", "item_type": item_type})

    assert not form.is_valid()
    assert expected_field in form.errors
