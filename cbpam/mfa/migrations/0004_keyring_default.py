from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("mfa", "0003_mfarecoverycode")]

    operations = [
        migrations.AlterField(
            model_name="mfadevice",
            name="encryption_key_id",
            field=models.CharField(default="keyring-v1", max_length=64),
        ),
    ]
