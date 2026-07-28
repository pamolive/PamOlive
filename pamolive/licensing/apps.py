from django.apps import AppConfig


class LicensingConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "pamolive.licensing"

    def ready(self):
        from . import checks, signals  # noqa: F401

