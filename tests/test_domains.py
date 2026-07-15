import pytest
from django.urls import reverse

from cbpam.accounts.models import User
from cbpam.rbac.models import UserGroup
from cbpam.targets.models import Domain, Target
from cbpam.vault.models import Credential


@pytest.mark.django_db
def test_domain_account_requires_domain_in_console(client):
    administrator = User.objects.create_user(
        username="domain-admin",
        email="domain-admin@example.test",
        password="safe-password",
    )
    UserGroup.objects.get(name="Administrateurs PAM-olive").users.add(administrator)
    target = Target.objects.create(
        name="Domain server",
        hostname="server.example.test",
        port=22,
        protocol=Target.Protocol.SSH,
    )
    client.force_login(administrator)

    response = client.post(
        reverse("console:credentials"),
        {
            "name": "Domain administrator",
            "target": target.pk,
            "username": "administrator",
            "account_type": Credential.AccountType.DOMAIN,
            "kind": Credential.Kind.PASSWORD,
            "secret": "target-password",
        },
    )

    assert response.status_code == 200
    assert not Credential.objects.filter(name="Domain administrator").exists()


@pytest.mark.django_db
def test_administrator_creates_domain_and_domain_account(client):
    administrator = User.objects.create_user(
        username="domain-manager",
        email="domain-manager@example.test",
        password="safe-password",
    )
    UserGroup.objects.get(name="Administrateurs PAM-olive").users.add(administrator)
    client.force_login(administrator)

    domain_response = client.post(
        reverse("console:domains"),
        {
            "name": "EXAMPLE",
            "kind": Domain.Kind.ACTIVE_DIRECTORY,
            "dns_name": "example.test",
            "description": "Corporate domain",
            "enabled": "on",
        },
    )
    domain = Domain.objects.get(name="EXAMPLE")
    target = Target.objects.create(
        name="Corporate server",
        kind=Target.Kind.DEVICE,
        domain=domain,
        hostname="corp.example.test",
        port=3389,
        protocol=Target.Protocol.RDP,
    )
    credential_response = client.post(
        reverse("console:credentials"),
        {
            "name": "EXAMPLE administrator",
            "target": target.pk,
            "domain": domain.pk,
            "username": "administrator",
            "account_type": Credential.AccountType.DOMAIN,
            "kind": Credential.Kind.PASSWORD,
            "secret": "target-password",
            "checkout_enabled": "on",
        },
    )

    assert domain_response.status_code == 302
    assert credential_response.status_code == 302
    assert Credential.objects.get(name="EXAMPLE administrator").domain == domain
