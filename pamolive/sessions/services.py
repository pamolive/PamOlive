import hashlib
import secrets
from datetime import timedelta

from django.conf import settings
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from pamolive.audit.services import record_event
from pamolive.common.justification import normalize_justification
from pamolive.policies.models import AccessPolicy
from pamolive.vault.leases import authorizing_policy_for

from .models import PrivilegedSession, SessionTicket


def _token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


@transaction.atomic
def issue_session_ticket(
    *, user, credential, justification, lifetime_seconds=60, source_ip=None, mfa_verified_at=None
):
    justification = normalize_justification(justification)
    if credential.target.protocol not in {
        credential.target.Protocol.SSH,
        credential.target.Protocol.RDP,
    }:
        raise PermissionDenied("Cette cible ne prend pas en charge les sessions interactives.")
    if (
        credential.target.protocol == credential.target.Protocol.RDP
        and not settings.PAMOLIVE_RDP_ENABLED
    ):
        raise PermissionDenied("Le courtage RDP n'est pas activé sur cette installation.")
    if (
        credential.target.protocol == credential.target.Protocol.SSH
        and credential.target.ssh_host_key_policy
        == credential.target.SSHHostKeyPolicy.STRICT
        and not credential.target.host_keys.filter(revoked_at__isnull=True).exists()
    ):
        raise PermissionDenied("Aucune clé d’hôte SSH approuvée n’est disponible pour cette cible.")
    if lifetime_seconds < 15 or lifetime_seconds > 120:
        raise ValidationError("La durée du ticket doit être comprise entre 15 et 120 secondes.")

    policy, access_request = authorizing_policy_for(
        user,
        credential,
        AccessPolicy.Action.START_SESSION,
        source_ip=source_ip,
        mfa_verified_at=mfa_verified_at,
    )
    # Serialize quota decisions for a policy. Counting alone is racy under
    # PostgreSQL READ COMMITTED and pending tickets already reserve capacity.
    policy = AccessPolicy.objects.select_for_update().get(pk=policy.pk)
    now = timezone.now()
    concurrent = PrivilegedSession.objects.filter(
        user=user,
        target=credential.target,
        policy=policy,
    ).filter(
        Q(
            status__in=(
                PrivilegedSession.Status.ACTIVE,
                PrivilegedSession.Status.TERMINATING,
            )
        )
        | Q(
            status=PrivilegedSession.Status.CREATED,
            ticket__expires_at__gt=now,
            ticket__consumed_at__isnull=True,
            ticket__revoked_at__isnull=True,
        )
    ).count()
    if concurrent >= policy.max_concurrent_sessions:
        raise PermissionDenied("Le nombre maximal de sessions simultanées est atteint.")
    duration = policy.max_duration_minutes
    if access_request:
        duration = min(duration, access_request.requested_duration_minutes)
    session = PrivilegedSession.objects.create(
        user=user,
        target=credential.target,
        credential=credential,
        policy=policy,
        access_request=access_request,
        expires_at=now + timedelta(minutes=duration),
        client_ip=source_ip,
        justification=justification,
    )
    raw_token = secrets.token_urlsafe(32)
    ticket = SessionTicket.objects.create(
        session=session,
        token_hash=_token_hash(raw_token),
        expires_at=now + timedelta(seconds=lifetime_seconds),
        source_ip=source_ip,
    )
    record_event(
        actor=user,
        action="session.ticket_issued",
        resource=session,
        metadata={
            "credential_id": str(credential.pk),
            "policy_id": str(policy.pk),
            "protocol": credential.target.protocol,
            "justification": justification,
        },
        source_ip=source_ip,
    )
    return session, ticket, raw_token


@transaction.atomic
def consume_session_ticket(*, session_id, token, user, source_ip=None):
    try:
        ticket = (
            SessionTicket.objects.select_for_update()
            .select_related("session", "session__user", "session__target")
            .get(session_id=session_id, token_hash=_token_hash(token))
        )
    except SessionTicket.DoesNotExist as error:
        raise PermissionDenied("Ticket de session invalide.") from error

    now = timezone.now()
    session = ticket.session
    if ticket.revoked_at or ticket.consumed_at or ticket.expires_at <= now:
        raise PermissionDenied("Ce ticket de session a expiré ou a déjà été consommé.")
    if session.user_id != user.pk:
        raise PermissionDenied("Ce ticket appartient à un autre utilisateur.")
    if session.status != PrivilegedSession.Status.CREATED:
        raise PermissionDenied("Cette session ne peut plus être ouverte.")
    if session.expires_at and session.expires_at <= now:
        raise PermissionDenied("L’autorisation de session a expiré.")
    if ticket.source_ip and source_ip and ticket.source_ip != source_ip:
        raise PermissionDenied("L’adresse d’origine de la session a changé.")

    policy = AccessPolicy.objects.select_for_update().get(pk=session.policy_id)
    concurrent = PrivilegedSession.objects.filter(
        user=session.user,
        target=session.target,
        policy=policy,
        status__in=(
            PrivilegedSession.Status.ACTIVE,
            PrivilegedSession.Status.TERMINATING,
        ),
    ).exclude(pk=session.pk).count()
    if concurrent >= policy.max_concurrent_sessions:
        raise PermissionDenied("Le nombre maximal de sessions simultanées est atteint.")

    ticket.consumed_at = now
    ticket.save(update_fields=("consumed_at", "updated_at"))
    session.status = PrivilegedSession.Status.ACTIVE
    session.started_at = now
    session.last_activity_at = now
    session.save(update_fields=("status", "started_at", "last_activity_at", "updated_at"))
    record_event(
        actor=user,
        action="session.opened",
        resource=session,
        metadata={"protocol": session.target.protocol},
        source_ip=source_ip,
    )
    return session


@transaction.atomic
def close_session(session, *, actor=None, reason="user_disconnect", failed=False):
    locked = PrivilegedSession.objects.select_for_update().get(pk=session.pk)
    if locked.status in {PrivilegedSession.Status.CLOSED, PrivilegedSession.Status.FAILED}:
        return locked
    now = timezone.now()
    locked.status = (
        PrivilegedSession.Status.FAILED if failed else PrivilegedSession.Status.CLOSED
    )
    locked.ended_at = now
    locked.last_activity_at = now
    locked.termination_reason = reason[:255]
    locked.save(
        update_fields=(
            "status",
            "ended_at",
            "last_activity_at",
            "termination_reason",
            "updated_at",
        )
    )
    record_event(
        actor=actor,
        action="session.failed" if failed else "session.closed",
        resource=locked,
        metadata={"reason": locked.termination_reason},
    )
    return locked


@transaction.atomic
def request_session_termination(session, *, actor):
    locked = PrivilegedSession.objects.select_for_update().get(pk=session.pk)
    if locked.status in {PrivilegedSession.Status.CLOSED, PrivilegedSession.Status.FAILED}:
        return locked, False
    now = timezone.now()
    locked.termination_requested_at = now
    locked.termination_requested_by = actor
    if locked.status == PrivilegedSession.Status.CREATED:
        SessionTicket.objects.filter(
            session=locked,
            consumed_at__isnull=True,
            revoked_at__isnull=True,
        ).update(revoked_at=now)
        locked.status = PrivilegedSession.Status.CLOSED
        locked.ended_at = now
        locked.termination_reason = "admin_terminated_before_start"
        notify_gateway = False
    else:
        locked.status = PrivilegedSession.Status.TERMINATING
        locked.termination_reason = "admin_termination_requested"
        notify_gateway = True
    locked.save(
        update_fields=(
            "status",
            "ended_at",
            "termination_reason",
            "termination_requested_at",
            "termination_requested_by",
            "updated_at",
        )
    )
    record_event(
        actor=actor,
        action="session.termination_requested",
        resource=locked,
        metadata={"previous_status": session.status},
    )
    return locked, notify_gateway
