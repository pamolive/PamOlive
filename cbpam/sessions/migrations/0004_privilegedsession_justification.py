from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("privileged_sessions", "0003_privilegedsession_termination_requested_at_and_more")]

    operations = [
        migrations.AddField(
            model_name="privilegedsession",
            name="justification",
            field=models.CharField(
                default="Legacy session created before mandatory justification",
                max_length=1000,
            ),
            preserve_default=False,
        ),
    ]
