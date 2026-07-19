import django.db.models.deletion
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("connectors", "0005_keyring_defaults"),
        ("rbac", "0006_expand_system_roles"),
    ]

    operations = [
        migrations.CreateModel(
            name="OIDCDefaultGroupMembership",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("preserve_membership_on_unlink", models.BooleanField(default=False)),
                (
                    "identity",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="oidc_default_group_membership",
                        to="connectors.externalidentity",
                    ),
                ),
                (
                    "user_group",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="oidc_default_memberships",
                        to="rbac.usergroup",
                    ),
                ),
            ],
        ),
    ]
