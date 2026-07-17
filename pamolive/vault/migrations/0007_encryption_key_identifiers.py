from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("vault", "0006_credential_rotation_orchestration")]

    operations = [
        migrations.AddField(
            model_name="credential",
            name="secret_encryption_key_id",
            field=models.CharField(default="legacy", max_length=64),
        ),
        migrations.AddField(
            model_name="credential",
            name="totp_encryption_key_id",
            field=models.CharField(default="legacy", max_length=64),
        ),
        migrations.AddField(
            model_name="personalvaultitem",
            name="encryption_key_id",
            field=models.CharField(default="legacy", max_length=64),
        ),
    ]
