from django.core.exceptions import ValidationError

from .exceptions import LicenseError
from .services import cluster_enabled, get_license_status


def assert_cluster_allowed():
    status = get_license_status()
    if cluster_enabled() and not status.cluster_allowed:
        raise LicenseError("Le cluster est réservé aux éditions Lab, Business et Enterprise.")
    if cluster_enabled() and not status.valid:
        raise LicenseError(status.reason or "La licence active n'est pas valide.")


def enforce_active_user_limit(user):
    status = get_license_status()
    if not status.valid or status.max_users is None or not getattr(user, "is_active", False):
        return

    User = user.__class__
    active_users = User.objects.filter(is_active=True)
    if user.pk:
        active_users = active_users.exclude(pk=user.pk)
    if active_users.count() >= status.max_users:
        raise ValidationError(
            f"L'édition {status.edition} limite l'instance à "
            f"{status.max_users} utilisateurs actifs."
        )


def enforce_target_limit(target):
    status = get_license_status()
    if not status.valid or status.max_targets is None:
        return

    Target = target.__class__
    targets = Target.objects.all()
    if target.pk:
        targets = targets.exclude(pk=target.pk)
    if targets.count() >= status.max_targets:
        raise ValidationError(
            f"L'édition {status.edition} limite l'instance à {status.max_targets} targets."
        )
