from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("vault", "0010_secretlease_justification")]

    operations = [
        migrations.AlterField(
            model_name="credential",
            name="secret_encryption_key_id",
            field=models.CharField(default="keyring-v1", max_length=64),
        ),
        migrations.AlterField(
            model_name="credential",
            name="totp_encryption_key_id",
            field=models.CharField(default="keyring-v1", max_length=64),
        ),
        migrations.AlterField(
            model_name="personalvaultitem",
            name="encryption_key_id",
            field=models.CharField(default="keyring-v1", max_length=64),
        ),
    ]
