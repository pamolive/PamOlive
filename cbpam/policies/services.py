import ipaddress

from django.db.models import Prefetch, Q
from django.utils import timezone

from cbpam.targets.models import Target, TargetGroup

from .models import AccessPolicy


def policies_for_user(user):
    if not user.is_authenticated:
        return AccessPolicy.objects.none()
    return (
        AccessPolicy.objects.filter(
            enabled=True,
            user_groups__enabled=True,
            user_groups__users=user,
        )
        .prefetch_related("target_groups", "target_groups__targets", "credentials")
        .distinct()
    )


def _source_is_allowed(policy, source_ip):
    if not policy.source_cidrs:
        return True
    if not source_ip:
        return False
    try:
        address = ipaddress.ip_address(source_ip)
        networks = [ipaddress.ip_network(cidr, strict=False) for cidr in policy.source_cidrs]
    except ValueError:
        return False
    return any(address in network for network in networks)


def policy_is_current(policy, *, at=None, source_ip=None):
    at = at or timezone.now()
    if policy.valid_from and at < policy.valid_from:
        return False
    if policy.valid_until and at >= policy.valid_until:
        return False
    local_at = timezone.localtime(at)
    if policy.weekdays and local_at.weekday() not in {int(day) for day in policy.weekdays}:
        return False
    current_time = local_at.time().replace(tzinfo=None)
    start = policy.access_start_time
    end = policy.access_end_time
    if start and end:
        if start <= end and not start <= current_time < end:
            return False
        if start > end and not (current_time >= start or current_time < end):
            return False
    elif start and current_time < start:
        return False
    elif end and current_time >= end:
        return False
    return _source_is_allowed(policy, source_ip)


def policies_allowing(user, action, *, source_ip=None, at=None):
    policy_ids = [
        policy.pk
        for policy in policies_for_user(user)
        if policy.allows(action) and policy_is_current(policy, at=at, source_ip=source_ip)
    ]
    return AccessPolicy.objects.filter(pk__in=policy_ids).prefetch_related("credentials")


def policy_allows_credential(policy, credential):
    if policy.protocols and credential.target.protocol not in policy.protocols:
        return False
    credential_ids = {item.pk for item in policy.credentials.all()}
    return not credential_ids or credential.pk in credential_ids


def credential_allows_action(user, credential, action, *, source_ip=None, at=None):
    for policy in policies_allowing(user, action, source_ip=source_ip, at=at):
        target_covered = (
            policy.targets.filter(pk=credential.target_id).exists()
            or policy.target_groups.filter(
                enabled=True,
                targets=credential.target_id,
            ).exists()
        )
        if target_covered and policy_allows_credential(policy, credential):
            return True
    return False


def targets_for_policies(policies):
    return Target.objects.filter(
        Q(target_groups__enabled=True, target_groups__policies__in=policies)
        | Q(policies__in=policies),
        enabled=True,
    ).distinct()


def target_groups_for_user(user):
    policies = policies_for_user(user)
    return (
        TargetGroup.objects.filter(enabled=True, policies__in=policies)
        .prefetch_related(
            Prefetch(
                "targets",
                queryset=Target.objects.filter(enabled=True).prefetch_related("credentials"),
            )
        )
        .distinct()
    )


def actions_for_target(user, target, *, source_ip=None, at=None):
    actions = set()
    for policy in policies_for_user(user):
        if not policy_is_current(policy, at=at, source_ip=source_ip):
            continue
        if policy.protocols and target.protocol not in policy.protocols:
            continue
        if (
            policy.targets.filter(pk=target.pk).exists()
            or policy.target_groups.filter(enabled=True, targets=target).exists()
        ):
            actions.update(policy.actions)
    return actions
