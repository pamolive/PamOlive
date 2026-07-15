from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("vault", "0005_secretlease")]

    operations = [
        migrations.AddField(
            model_name="credential",
            name="last_rotation_status",
            field=models.CharField(
                choices=[
                    ("never", "Jamais exécutée"),
                    ("succeeded", "Réussie"),
                    ("failed", "Échec"),
                    ("blocked", "Action requise"),
                ],
                default="never",
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name="credential",
            name="next_rotation_at",
            field=models.DateTimeField(blank=True, db_index=True, null=True),
        ),
        migrations.AddField(
            model_name="credential",
            name="rotation_backend",
            field=models.CharField(blank=True, max_length=100),
        ),
        migrations.AddField(
            model_name="credential",
            name="rotation_failure_count",
            field=models.PositiveSmallIntegerField(default=0),
        ),
    ]
