from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    email = models.EmailField(unique=True)
    display_name = models.CharField(max_length=150, blank=True)
    is_service_account = models.BooleanField(default=False)

    def __str__(self):
        return self.display_name or self.email or self.username

    def has_capability(self, capability):
        from cbpam.rbac.services import user_has_capability

        return user_has_capability(self, capability)

    @property
    def can_access_console(self):
        from cbpam.rbac.models import Role

        return self.has_capability(Role.Capability.CONSOLE_ACCESS)
