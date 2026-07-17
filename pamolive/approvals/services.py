from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone

from pamolive.audit.services import record_event
from pamolive.rbac.models import Role
from pamolive.rbac.services import user_has_capability

from .models import AccessRequest, ApprovalDecision


def _actor_may_decide(access_request, actor):
    if actor.is_superuser:
        return True
    if not user_has_capability(actor, Role.Capability.APPROVALS_DECIDE):
        return False
    approver_groups = access_request.policy.approver_groups.filter(enabled=True)
    if not approver_groups.exists():
        return True
    return approver_groups.filter(users=actor).exists()


@transaction.atomic
def decide_access_request(
    *, access_request: AccessRequest, actor, approve: bool, comment: str = ""
):
    locked = (
        AccessRequest.objects.select_for_update()
        .select_related("policy", "requester")
        .get(pk=access_request.pk)
    )
    if locked.status != AccessRequest.Status.PENDING:
        raise ValidationError("Seules les demandes en attente peuvent recevoir une décision.")
    if actor == locked.requester:
        raise PermissionDenied("Un demandeur ne peut pas approuver sa propre demande.")
    if not _actor_may_decide(locked, actor):
        raise PermissionDenied("Vous n’êtes pas approbateur pour cette politique.")
    if locked.decisions.filter(approver=actor).exists():
        raise ValidationError("Vous avez déjà rendu une décision pour cette demande.")

    decision = ApprovalDecision.objects.create(
        access_request=locked,
        approver=actor,
        decision=(
            ApprovalDecision.Decision.APPROVE
            if approve
            else ApprovalDecision.Decision.REJECT
        ),
        comment=comment,
    )
    approval_count = locked.decisions.filter(
        decision=ApprovalDecision.Decision.APPROVE
    ).count()
    quorum = max(1, locked.policy.approval_quorum)

    if not approve:
        locked.status = AccessRequest.Status.REJECTED
    elif approval_count >= quorum:
        locked.status = AccessRequest.Status.APPROVED

    if locked.status != AccessRequest.Status.PENDING:
        locked.decided_by = actor
        locked.decided_at = timezone.now()
        locked.decision_comment = comment
        locked.save(
            update_fields=(
                "status",
                "decided_by",
                "decided_at",
                "decision_comment",
                "updated_at",
            )
        )

    record_event(
        actor=actor,
        action=(
            f"access_request.{locked.status}"
            if locked.status != AccessRequest.Status.PENDING
            else "access_request.approval_recorded"
        ),
        resource=locked,
        metadata={
            "decision_id": str(decision.pk),
            "approval_count": approval_count,
            "quorum": quorum,
        },
    )
    return locked
