from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("mfa", "0004_keyring_default")]

    operations = [
        migrations.AddField(
            model_name="mfadevice",
            name="last_accepted_totp_counter",
            field=models.BigIntegerField(blank=True, editable=False, null=True),
        ),
    ]
