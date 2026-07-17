import ipaddress

from django.db.models import Prefetch, Q
from django.utils import timezone

from pamolive.targets.models import Target, TargetGroup

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
    time_frames = list(policy.time_frames.filter(enabled=True))
    if time_frames:
        if not any(_time_frame_is_current(frame, local_at) for frame in time_frames):
            return False
    elif not _legacy_schedule_is_current(policy, local_at):
        return False
    return _source_is_allowed(policy, source_ip)


def _clock_is_current(current_time, start, end):
    if start and end:
        if start <= end:
            return start <= current_time < end
        return current_time >= start or current_time < end
    if start:
        return current_time >= start
    if end:
        return current_time < end
    return True


def _time_frame_is_current(frame, local_at):
    if frame.valid_from and local_at < timezone.localtime(frame.valid_from):
        return False
    if frame.valid_until and local_at >= timezone.localtime(frame.valid_until):
        return False
    if frame.weekdays and local_at.weekday() not in {int(day) for day in frame.weekdays}:
        return False
    return _clock_is_current(
        local_at.time().replace(tzinfo=None), frame.start_time, frame.end_time
    )


def _legacy_schedule_is_current(policy, local_at):
    if policy.weekdays and local_at.weekday() not in {int(day) for day in policy.weekdays}:
        return False
    return _clock_is_current(
        local_at.time().replace(tzinfo=None),
        policy.access_start_time,
        policy.access_end_time,
    )


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
