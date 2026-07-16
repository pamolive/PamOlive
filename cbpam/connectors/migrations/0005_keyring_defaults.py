from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("connectors", "0004_encryption_key_identifiers")]

    operations = [
        migrations.AlterField(
            model_name="connector",
            name="encryption_key_id",
            field=models.CharField(default="keyring-v1", max_length=64),
        ),
        migrations.AlterField(
            model_name="identitysource",
            name="encryption_key_id",
            field=models.CharField(default="keyring-v1", max_length=64),
        ),
    ]
