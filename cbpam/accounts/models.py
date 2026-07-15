from django.contrib.auth.models import AbstractUser
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
