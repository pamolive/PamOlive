from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models


class User(AbstractUser):
    class Theme(models.TextChoices):
        DARK = "dark", "Dark"
        LIGHT = "light", "Light"
        SYSTEM = "system", "System"

    class Language(models.TextChoices):
        ENGLISH = "en", "English"
        FRENCH = "fr", "Français"
        SPANISH = "es", "Español"

    email = models.EmailField(unique=True)
    display_name = models.CharField(max_length=150, blank=True)
    is_service_account = models.BooleanField(default=False)
    preferred_theme = models.CharField(
        max_length=10,
        choices=Theme.choices,
        default=Theme.DARK,
    )
    preferred_language = models.CharField(
        max_length=5,
        choices=Language.choices,
        default=Language.FRENCH,
    )

    def __str__(self):
        return self.display_name or self.email or self.username

    def has_capability(self, capability):
        from cbpam.rbac.services import user_has_capability

        return user_has_capability(self, capability)

    @property
    def can_access_console(self):
        from cbpam.rbac.models import Role

        return self.has_capability(Role.Capability.CONSOLE_ACCESS)


class PlatformSecurityPolicy(models.Model):
    id = models.PositiveSmallIntegerField(primary_key=True, default=1, editable=False)
    idle_timeout_minutes = models.PositiveIntegerField(
        default=15,
        validators=(MinValueValidator(1), MaxValueValidator(1440)),
        help_text="Disconnect an authenticated browser after this period without activity.",
    )
    absolute_session_minutes = models.PositiveIntegerField(
        default=480,
        validators=(MinValueValidator(5), MaxValueValidator(10080)),
        help_text="Require a new sign-in after this total session duration.",
    )
    require_mfa_for_all_users = models.BooleanField(
        default=True,
        help_text="Require every interactive user to enroll and use MFA at sign-in.",
    )
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(
        "accounts.User",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="updated_platform_security_policies",
    )

    def __str__(self):
        return "PAM-olive platform security policy"

    def save(self, *args, **kwargs):
        self.pk = 1
        self.full_clean()
        return super().save(*args, **kwargs)

    def clean(self):
        if self.absolute_session_minutes < self.idle_timeout_minutes:
            raise ValidationError(
                "The absolute session duration must be greater than the idle timeout."
            )
