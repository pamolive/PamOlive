from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("accounts", "0003_platformsecuritypolicy")]

    operations = [
        migrations.AddField(
            model_name="platformsecuritypolicy",
            name="require_mfa_for_all_users",
            field=models.BooleanField(
                default=True,
                help_text="Require every interactive user to enroll and use MFA at sign-in.",
            ),
        ),
    ]
