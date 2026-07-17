from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("mfa", "0001_initial")]

    operations = [
        migrations.AddField(
            model_name="mfadevice",
            name="encryption_key_id",
            field=models.CharField(default="legacy", max_length=64),
        )
    ]
