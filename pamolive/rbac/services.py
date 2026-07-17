from functools import wraps

from django.core.exceptions import PermissionDenied
from django.db.models import Q
from django.utils import timezone

from .models import Role, RoleAssignment


def user_capabilities(user):
    if not user.is_authenticated:
        return set()
    if user.is_superuser:
        return {value for value, _label in Role.Capability.choices}
    group_roles = Role.objects.filter(
        enabled=True,
        user_groups__enabled=True,
        user_groups__users=user,
    ).distinct()
    now = timezone.now()
    direct_roles = Role.objects.filter(
        enabled=True,
        roleassignment__in=RoleAssignment.objects.filter(
            user=user,
            valid_from__lte=now,
        ).filter(Q(valid_until__isnull=True) | Q(valid_until__gt=now)),
    ).distinct()
    roles = list(group_roles) + list(direct_roles)
    return {capability for role in roles for capability in role.capabilities}


def user_has_capability(user, capability):
    return capability in user_capabilities(user)


def capability_required(capability):
    def decorator(view):
        @wraps(view)
        def wrapped(request, *args, **kwargs):
            if not request.user.is_authenticated:
                raise PermissionDenied
            if not user_has_capability(request.user, capability):
                raise PermissionDenied
            return view(request, *args, **kwargs)

        return wrapped

    return decorator


def can_view_configuration(user, manage_capability, view_capability=None):
    return user_has_capability(user, manage_capability) or user_has_capability(
        user, view_capability or Role.Capability.CONFIGURATION_VIEW
    )
