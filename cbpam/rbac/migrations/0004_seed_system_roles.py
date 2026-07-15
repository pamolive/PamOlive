from django.db import migrations


def seed_system_roles(apps, schema_editor):
    Role = apps.get_model("rbac", "Role")
    UserGroup = apps.get_model("rbac", "UserGroup")
    User = apps.get_model("accounts", "User")

    administrator, _ = Role.objects.update_or_create(
        slug="administrator",
        defaults={
            "name": "Administrateur",
            "description": "Administration fonctionnelle complète de PAM-olive.",
            "capabilities": [
                "console.access",
                "configuration.view",
                "users.manage",
                "groups.manage",
                "roles.manage",
                "targets.manage",
                "credentials.manage",
                "policies.manage",
                "approvals.view",
                "approvals.decide",
                "audit.view",
                "sessions.view",
            ],
            "is_system": True,
            "enabled": True,
        },
    )
    auditor, _ = Role.objects.update_or_create(
        slug="auditor",
        defaults={
            "name": "Auditeur",
            "description": "Consultation en lecture seule des configurations, sessions et audits.",
            "capabilities": [
                "console.access",
                "configuration.view",
                "approvals.view",
                "audit.view",
                "sessions.view",
            ],
            "is_system": True,
            "enabled": True,
        },
    )
    user_role, _ = Role.objects.update_or_create(
        slug="user",
        defaults={
            "name": "Utilisateur",
            "description": "Coffre personnel, demandes et accès accordés par les politiques.",
            "capabilities": [],
            "is_system": True,
            "enabled": True,
        },
    )

    admin_group, _ = UserGroup.objects.get_or_create(
        name="Administrateurs PAM-olive",
        defaults={"description": "Administrateurs fonctionnels de la plateforme."},
    )
    auditor_group, _ = UserGroup.objects.get_or_create(
        name="Auditeurs PAM-olive",
        defaults={"description": "Auditeurs en lecture seule."},
    )
    user_group, _ = UserGroup.objects.get_or_create(
        name="Utilisateurs PAM-olive",
        defaults={"description": "Utilisateurs standards de la plateforme."},
    )
    admin_group.roles.add(administrator)
    auditor_group.roles.add(auditor)
    user_group.roles.add(user_role)

    for user in User.objects.filter(is_superuser=False):
        if user.is_staff:
            admin_group.users.add(user)
        else:
            user_group.users.add(user)


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0001_initial"),
        ("rbac", "0003_role_capabilities_role_enabled_role_is_system_and_more"),
    ]

    operations = [migrations.RunPython(seed_system_roles, migrations.RunPython.noop)]
