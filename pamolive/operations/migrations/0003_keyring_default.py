from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("operations", "0002_rotationjob_candidate_encryption_key_id")]

    operations = [
        migrations.AlterField(
            model_name="rotationjob",
            name="candidate_encryption_key_id",
            field=models.CharField(default="keyring-v1", max_length=64),
        ),
    ]
