import django.db.models.deletion
import django.utils.timezone
import uuid

from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("vault", "0006_credential_rotation_orchestration"),
    ]

    operations = [
        migrations.CreateModel(
            name="RotationJob",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("reason", models.CharField(blank=True, max_length=250)),
                ("backend", models.CharField(blank=True, max_length=100)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("pending", "En attente"),
                            ("running", "En cours"),
                            ("succeeded", "Réussie"),
                            ("failed", "Échec"),
                            ("action_required", "Action requise"),
                            ("cancelled", "Annulée"),
                        ],
                        db_index=True,
                        default="pending",
                        max_length=24,
                    ),
                ),
                ("scheduled_for", models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                ("previous_key_version", models.PositiveIntegerField()),
                ("new_key_version", models.PositiveIntegerField(blank=True, null=True)),
                ("encrypted_candidate_secret", models.BinaryField(blank=True)),
                ("error_code", models.CharField(blank=True, max_length=80)),
                ("error_message", models.CharField(blank=True, max_length=250)),
                (
                    "credential",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="rotation_jobs",
                        to="vault.credential",
                    ),
                ),
                (
                    "requested_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="requested_rotation_jobs",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={"ordering": ("-created_at",)},
        ),
        migrations.AddConstraint(
            model_name="rotationjob",
            constraint=models.UniqueConstraint(
                condition=models.Q(("status__in", ("pending", "running"))),
                fields=("credential",),
                name="unique_active_rotation_per_credential",
            ),
        ),
    ]
