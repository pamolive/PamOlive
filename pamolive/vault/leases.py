import hashlib
import secrets
from datetime import timedelta

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from pamolive.approvals.models import AccessRequest
from pamolive.audit.services import record_event
from pamolive.common.justification import normalize_justification
from pamolive.mfa.models import MFADevice
from pamolive.policies.models import AccessPolicy
from pamolive.policies.services import policies_allowing, policy_allows_credential

from .models import SecretLease
from .services import VaultCipher


def _token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def _active_approval(user, credential, policy):
    requests = AccessRequest.objects.filter(
        requester=user,
        target=credential.target,
        policy=policy,
        status=AccessRequest.Status.APPROVED,
    ).order_by("-decided_at", "-updated_at")
    now = timezone.now()
    for access_request in requests:
        approved_at = access_request.decided_at or access_request.updated_at
        if approved_at + timedelta(minutes=access_request.requested_duration_minutes) > now:
            return access_request
    return None


def authorizing_policy_for(
    user,
    credential,
    action=AccessPolicy.Action.VIEW_SECRET,
    *,
    source_ip=None,
):
    candidates = policies_allowing(user, action, source_ip=source_ip).filter(
        Q(targets=credential.target)
        | Q(target_groups__enabled=True, target_groups__targets=credential.target)
    ).distinct()
    for policy in candidates:
        if not policy_allows_credential(policy, credential):
            continue
        access_request = _active_approval(user, credential, policy)
        if policy.requires_approval and not access_request:
            continue
        if policy.requires_mfa and not MFADevice.objects.filter(
            user=user,
            confirmed=True,
        ).exists():
            continue
        return policy, access_request
    raise PermissionDenied("Aucune autorisation active ne permet cette opération.")


def issue_secret_lease(
    *,
    user,
    credential,
    justification,
    purpose=SecretLease.Purpose.REVEAL,
    lifetime_seconds=60,
    source_ip=None,
):
    justification = normalize_justification(justification)
    if not credential.checkout_enabled or not credential.target.enabled:
        raise PermissionDenied("Cet identifiant n’est pas disponible à la consultation.")
    if lifetime_seconds < 15 or lifetime_seconds > 300:
        raise ValidationError("La durée d’un bail doit être comprise entre 15 et 300 secondes.")
    action = (
        AccessPolicy.Action.START_SESSION
        if purpose == SecretLease.Purpose.SESSION
        else AccessPolicy.Action.VIEW_SECRET
    )
    policy, access_request = authorizing_policy_for(
        user,
        credential,
        action,
        source_ip=source_ip,
    )
    token = secrets.token_urlsafe(32)
    lease = SecretLease.objects.create(
        credential=credential,
        user=user,
        policy=policy,
        access_request=access_request,
        purpose=purpose,
        token_hash=_token_hash(token),
        expires_at=timezone.now() + timedelta(seconds=lifetime_seconds),
        source_ip=source_ip,
        justification=justification,
    )
    record_event(
        actor=user,
        action="credential.secret_lease.issued",
        resource=lease,
        metadata={
            "credential_id": str(credential.pk),
            "purpose": purpose,
            "justification": justification,
        },
        source_ip=source_ip,
    )
    return lease, token


@transaction.atomic
def consume_secret_lease(*, token, expected_user=None, expected_purpose=None):
    try:
        lease = SecretLease.objects.select_for_update().select_related(
            "credential", "credential__target", "user"
        ).get(token_hash=_token_hash(token))
    except SecretLease.DoesNotExist as error:
        raise PermissionDenied("Bail de secret invalide.") from error
    now = timezone.now()
    if lease.revoked_at or lease.expires_at <= now or lease.use_count >= lease.max_uses:
        raise PermissionDenied("Ce bail de secret a expiré ou a déjà été consommé.")
    if expected_user is not None and lease.user_id != expected_user.pk:
        raise PermissionDenied("Ce bail appartient à un autre utilisateur.")
    if expected_purpose is not None and lease.purpose != expected_purpose:
        raise PermissionDenied("Ce bail ne permet pas cette opération.")

    lease.use_count += 1
    lease.consumed_at = now
    lease.save(update_fields=("use_count", "consumed_at", "updated_at"))
    credential = lease.credential
    credential.last_checked_out_at = now
    credential.save(update_fields=("last_checked_out_at", "updated_at"))
    record_event(
        actor=lease.user,
        action="credential.secret_lease.consumed",
        resource=lease,
        metadata={
            "credential_id": str(credential.pk),
            "purpose": lease.purpose,
            "justification": lease.justification,
        },
        source_ip=lease.source_ip,
    )
    return lease, VaultCipher().decrypt(
        credential.encrypted_secret,
        key_id=credential.secret_encryption_key_id,
    )


def revoke_secret_lease(lease, actor):
    if lease.revoked_at:
        return lease
    lease.revoked_at = timezone.now()
    lease.save(update_fields=("revoked_at", "updated_at"))
    record_event(actor=actor, action="credential.secret_lease.revoked", resource=lease)
    return lease
