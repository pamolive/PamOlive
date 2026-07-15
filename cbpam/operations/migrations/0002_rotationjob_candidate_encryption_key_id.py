from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("operations", "0001_initial")]

    operations = [
        migrations.AddField(
            model_name="rotationjob",
            name="candidate_encryption_key_id",
            field=models.CharField(default="legacy", max_length=64),
        )
    ]
