from django.db import migrations


ADMIN_CAPABILITIES = [
    "console.access",
    "configuration.view",
    "users.view",
    "users.manage",
    "groups.view",
    "groups.manage",
    "roles.view",
    "roles.manage",
    "identity_sources.view",
    "identity_sources.manage",
    "identity_sources.sync",
    "targets.view",
    "targets.manage",
    "target_groups.view",
    "target_groups.manage",
    "domains.view",
    "domains.manage",
    "credentials.view_metadata",
    "credentials.manage",
    "credentials.reveal",
    "credentials.rotate",
    "policies.view",
    "policies.manage",
    "approvals.view",
    "approvals.decide",
    "audit.view",
    "audit.export",
    "sessions.view",
    "sessions.terminate",
    "sessions.join",
    "system.view",
    "system.manage",
]

AUDITOR_CAPABILITIES = [
    "console.access",
    "configuration.view",
    "users.view",
    "groups.view",
    "roles.view",
    "identity_sources.view",
    "targets.view",
    "target_groups.view",
    "domains.view",
    "credentials.view_metadata",
    "policies.view",
    "approvals.view",
    "audit.view",
    "audit.export",
    "sessions.view",
    "system.view",
]

APPROVER_CAPABILITIES = [
    "console.access",
    "approvals.view",
    "approvals.decide",
]


def expand_system_roles(apps, schema_editor):
    Role = apps.get_model("rbac", "Role")
    UserGroup = apps.get_model("rbac", "UserGroup")

    roles = {
        "administrator": ("Administrateur", ADMIN_CAPABILITIES),
        "auditor": ("Auditeur", AUDITOR_CAPABILITIES),
        "approver": ("Approbateur", APPROVER_CAPABILITIES),
        "user": ("Utilisateur", []),
    }
    for slug, (name, capabilities) in roles.items():
        role, _created = Role.objects.update_or_create(
            slug=slug,
            defaults={
                "name": name,
                "capabilities": capabilities,
                "is_system": True,
                "enabled": True,
            },
        )
        if slug == "approver":
            group, _group_created = UserGroup.objects.get_or_create(
                name="Approbateurs PAM-olive",
                defaults={
                    "description": "Utilisateurs autorisés à traiter les demandes d’autrui.",
                    "enabled": True,
                },
            )
            group.roles.add(role)


class Migration(migrations.Migration):
    dependencies = [("rbac", "0005_roleassignment_assigned_by_roleassignment_reason_and_more")]

    operations = [migrations.RunPython(expand_system_roles, migrations.RunPython.noop)]
