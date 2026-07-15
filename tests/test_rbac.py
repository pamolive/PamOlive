import pytest
from django.urls import reverse

from cbpam.accounts.models import User
from cbpam.rbac.models import Role, UserGroup
from cbpam.rbac.services import user_capabilities, user_has_capability


@pytest.mark.django_db
def test_user_accumulates_roles_from_multiple_groups():
    user = User.objects.create_user(username="multi")
    first_role = Role.objects.create(
        name="Target manager",
        slug="target-manager",
        capabilities=[Role.Capability.TARGETS_MANAGE],
    )
    second_role = Role.objects.create(
        name="Audit reader",
        slug="audit-reader",
        capabilities=[Role.Capability.AUDIT_VIEW],
    )
    first_group = UserGroup.objects.create(name="Infrastructure")
    second_group = UserGroup.objects.create(name="Compliance")
    first_group.roles.add(first_role)
    second_group.roles.add(second_role)
    first_group.users.add(user)
    second_group.users.add(user)

    assert user_has_capability(user, Role.Capability.TARGETS_MANAGE)
    assert user_has_capability(user, Role.Capability.AUDIT_VIEW)
    assert len(user_capabilities(user)) == 2


@pytest.mark.django_db
def test_auditor_can_read_but_cannot_modify_configuration(client):
    auditor = User.objects.create_user(username="auditor")
    UserGroup.objects.get(name="Auditeurs PAM-olive").users.add(auditor)
    client.force_login(auditor)

    assert client.get(reverse("console:users")).status_code == 200
    assert client.get(reverse("console:audit")).status_code == 200
    assert client.post(reverse("console:users"), {"username": "forbidden"}).status_code == 403


@pytest.mark.django_db
def test_superuser_has_every_capability():
    user = User.objects.create_superuser(
        username="root", email="root@example.test", password="safe"
    )

    assert user_has_capability(user, Role.Capability.ROLES_MANAGE)
    assert user.can_access_console
