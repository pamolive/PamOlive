from django.contrib.auth import get_user_model
from django.db.models.signals import pre_save
from django.dispatch import receiver

from pamolive.targets.models import Target

from .limits import enforce_active_user_limit, enforce_target_limit


@receiver(pre_save, sender=get_user_model())
def enforce_user_license_limit(sender, instance, **kwargs):
    enforce_active_user_limit(instance)


@receiver(pre_save, sender=Target)
def enforce_target_license_limit(sender, instance, **kwargs):
    enforce_target_limit(instance)
