import pytest
from django.urls import reverse

from cbpam.accounts.models import User
from cbpam.audit.models import AuditEvent
from cbpam.vault.models import PersonalVaultItem
from cbpam.vault.services import VaultCipher


@pytest.mark.django_db
def test_user_can_store_and_reveal_a_personal_login(client):
    user = User.objects.create_user(username="olive")
    client.force_login(user)

    response = client.post(
        reverse("passwords"),
        {
            "name": "Git hosting",
            "item_type": PersonalVaultItem.ItemType.LOGIN,
            "application": "Git",
            "website_url": "https://git.example.test",
            "username": "olive@example.test",
            "password": "private-password",
            "totp_secret": "JBSWY3DPEHPK3PXP",
        },
    )

    assert response.status_code == 302
    item = PersonalVaultItem.objects.get(owner=user)
    assert b"private-password" not in bytes(item.encrypted_payload)
    assert VaultCipher().decrypt_payload(item.encrypted_payload)["password"] == "private-password"

    reveal = client.post(reverse("reveal_personal_item", args=[item.pk]))
    assert reveal.status_code == 200
    assert b"private-password" in reveal.content
    assert b"Code TOTP actuel" in reveal.content
    assert AuditEvent.objects.filter(action="personal_vault.item_revealed").exists()


@pytest.mark.django_db
def test_user_cannot_reveal_another_personal_vault(client):
    owner = User.objects.create_user(username="owner", email="owner@example.test")
    attacker = User.objects.create_user(username="attacker", email="attacker@example.test")
    item = PersonalVaultItem.objects.create(
        owner=owner,
        name="Private",
        item_type=PersonalVaultItem.ItemType.NOTE,
        encrypted_payload=VaultCipher().encrypt_payload({"notes": "hidden"}),
    )
    client.force_login(attacker)

    assert client.post(reverse("reveal_personal_item", args=[item.pk])).status_code == 404
