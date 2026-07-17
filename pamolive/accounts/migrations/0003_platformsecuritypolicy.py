import django.core.validators
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0002_user_preferred_language_user_preferred_theme"),
    ]

    operations = [
        migrations.CreateModel(
            name="PlatformSecurityPolicy",
            fields=[
                (
                    "id",
                    models.PositiveSmallIntegerField(
                        default=1, editable=False, primary_key=True, serialize=False
                    ),
                ),
                (
                    "idle_timeout_minutes",
                    models.PositiveIntegerField(
                        default=15,
                        help_text=(
                            "Disconnect an authenticated browser after this period without activity."
                        ),
                        validators=[
                            django.core.validators.MinValueValidator(1),
                            django.core.validators.MaxValueValidator(1440),
                        ],
                    ),
                ),
                (
                    "absolute_session_minutes",
                    models.PositiveIntegerField(
                        default=480,
                        help_text="Require a new sign-in after this total session duration.",
                        validators=[
                            django.core.validators.MinValueValidator(5),
                            django.core.validators.MaxValueValidator(10080),
                        ],
                    ),
                ),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "updated_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="updated_platform_security_policies",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
    ]
