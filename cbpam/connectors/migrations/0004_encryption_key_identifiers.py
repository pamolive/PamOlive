from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("connectors", "0003_externalgroupmembership")]

    operations = [
        migrations.AddField(
            model_name="connector",
            name="encryption_key_id",
            field=models.CharField(default="legacy", max_length=64),
        ),
        migrations.AddField(
            model_name="identitysource",
            name="encryption_key_id",
            field=models.CharField(default="legacy", max_length=64),
        ),
    ]
