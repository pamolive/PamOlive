import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("accounts", "0004_platformsecuritypolicy_require_mfa")]

    operations = [
        migrations.AddField(
            model_name="platformsecuritypolicy",
            name="sensitive_action_mfa_window_minutes",
            field=models.PositiveSmallIntegerField(
                choices=[(2, "2 minutes"), (5, "5 minutes"), (10, "10 minutes"), (15, "15 minutes")],
                default=5,
                help_text=(
                    "Require a fresh MFA verification before sensitive actions within this window."
                ),
                validators=[
                    django.core.validators.MinValueValidator(2),
                    django.core.validators.MaxValueValidator(15),
                ],
            ),
        ),
    ]
