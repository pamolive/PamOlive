from dataclasses import dataclass
from datetime import timedelta

from django.db import transaction
from django.db.models import Count
from django.utils import timezone

from pamolive.audit.models import AuditEvent, SIEMDelivery
from pamolive.audit.services import record_event
from pamolive.policies.models import AccessPolicy
from pamolive.sessions.models import PrivilegedSession
from pamolive.vault.models import Credential

from .models import AccessReviewCampaign, AccessReviewItem, RotationJob


@dataclass(frozen=True)
class RiskResult:
    score: int
    level: str
    reasons: tuple[str, ...]


def _policy_size(policy):
    return {
        "users": sum(group.users.count() for group in policy.user_groups.all()),
        "targets": sum(group.targets.count() for group in policy.target_groups.all()),
        "credentials": policy.credentials.count(),
    }


def score_access_policy(policy):
    score = 0
    reasons = []
    actions = set(policy.actions or [])
    protocols = set(policy.protocols or [])
    size = _policy_size(policy)

    if not policy.enabled:
        return RiskResult(0, "inactive", ("Politique inactive",))
    if not policy.requires_approval:
        score += 25
        reasons.append("Accès sans approbation")
    if not policy.requires_mfa:
        score += 25
        reasons.append("MFA non obligatoire")
    if policy.approval_quorum < 2 and policy.requires_approval:
        score += 8
        reasons.append("Quorum d'approbation inférieur à 2")
    if AccessPolicy.Action.VIEW_SECRET in actions:
        score += 15
        reasons.append("Révélation de secret autorisée")
    if AccessPolicy.Action.REVEAL_TOTP in actions:
        score += 20
        reasons.append("Révélation TOTP autorisée")
    if AccessPolicy.Action.START_SESSION in actions:
        score += 12
        reasons.append("Ouverture de session privilégiée autorisée")
    if policy.max_duration_minutes > 480:
        score += 12
        reasons.append("Durée de session supérieure à 8h")
    elif policy.max_duration_minutes > 120:
        score += 6
        reasons.append("Durée de session supérieure à 2h")
    if policy.max_concurrent_sessions > 3:
        score += 10
        reasons.append("Concurrence de sessions élevée")
    elif policy.max_concurrent_sessions > 1:
        score += 5
        reasons.append("Plusieurs sessions simultanées autorisées")
    if not policy.time_frames.exists():
        score += 8
        reasons.append("Aucune plage horaire")
    if not policy.source_cidrs:
        score += 8
        reasons.append("Aucune restriction réseau source")
    if policy.allow_clipboard_copy:
        score += 5
        reasons.append("Copie presse-papiers autorisée")
    if policy.allow_clipboard_paste:
        score += 5
        reasons.append("Collage presse-papiers autorisé")
    if ("ssh" in protocols or not protocols) and not policy.command_deny_patterns:
        score += 5
        reasons.append("Pas de commandes SSH bloquées")
    if size["users"] > 20:
        score += 12
        reasons.append("Large population d'utilisateurs")
    elif size["users"] > 5:
        score += 6
        reasons.append("Population d'utilisateurs significative")
    if size["targets"] > 20:
        score += 12
        reasons.append("Large périmètre de cibles")
    elif size["targets"] > 5:
        score += 6
        reasons.append("Périmètre de cibles significatif")

    score = min(score, 100)
    if score >= 70:
        level = "critical"
    elif score >= 45:
        level = "high"
    elif score >= 20:
        level = "medium"
    else:
        level = "low"
    return RiskResult(score, level, tuple(reasons or ("Contrôles principaux en place",)))


def policy_entitlement_snapshot(policy):
    risk = score_access_policy(policy)
    return {
        "policy_id": str(policy.pk),
        "name": policy.name,
        "enabled": policy.enabled,
        "actions": list(policy.actions or []),
        "protocols": list(policy.protocols or []),
        "requires_approval": policy.requires_approval,
        "approval_quorum": policy.approval_quorum,
        "requires_mfa": policy.requires_mfa,
        "max_duration_minutes": policy.max_duration_minutes,
        "max_concurrent_sessions": policy.max_concurrent_sessions,
        "user_groups": [group.name for group in policy.user_groups.all()],
        "target_groups": [group.name for group in policy.target_groups.all()],
        "risk_score": risk.score,
        "risk_level": risk.level,
        "risk_reasons": list(risk.reasons),
    }


def ranked_policy_risks(limit=25):
    policies = AccessPolicy.objects.prefetch_related(
        "user_groups__users",
        "target_groups__targets",
        "credentials",
        "time_frames",
    ).order_by("name")
    ranked = [
        {"policy": policy, "risk": score_access_policy(policy)}
        for policy in policies
    ]
    return sorted(ranked, key=lambda item: item["risk"].score, reverse=True)[:limit]


@transaction.atomic
def create_access_review_campaign(*, name, created_by=None, due_at=None):
    campaign = AccessReviewCampaign.objects.create(
        name=name,
        created_by=created_by,
        due_at=due_at,
    )
    policies = AccessPolicy.objects.prefetch_related(
        "user_groups__users",
        "target_groups__targets",
        "credentials",
        "time_frames",
    ).order_by("name")
    items = [
        AccessReviewItem(
            campaign=campaign,
            policy=policy,
            snapshot=policy_entitlement_snapshot(policy),
            risk_score=score_access_policy(policy).score,
        )
        for policy in policies
    ]
    AccessReviewItem.objects.bulk_create(items)
    record_event(
        actor=created_by,
        action="governance.access_review.created",
        resource=campaign,
        metadata={"items": len(items), "due_at": due_at.isoformat() if due_at else ""},
    )
    return campaign


@transaction.atomic
def decide_access_review_item(*, item, decision, actor, comment=""):
    locked = AccessReviewItem.objects.select_for_update().select_related("policy").get(pk=item.pk)
    if locked.campaign.status != AccessReviewCampaign.Status.OPEN:
        raise ValueError("La campagne de revue est clôturée.")
    if decision not in {
        AccessReviewItem.Decision.KEEP,
        AccessReviewItem.Decision.REVOKE,
    }:
        raise ValueError("Décision de revue invalide.")
    locked.decision = decision
    locked.decided_by = actor
    locked.decided_at = timezone.now()
    locked.comment = comment[:2000]
    locked.save(update_fields=("decision", "decided_by", "decided_at", "comment", "updated_at"))
    if decision == AccessReviewItem.Decision.REVOKE and locked.policy.enabled:
        locked.policy.enabled = False
        locked.policy.save(update_fields=("enabled", "updated_at"))
    record_event(
        actor=actor,
        action=f"governance.access_review.{decision}",
        resource=locked,
        metadata={
            "campaign_id": str(locked.campaign_id),
            "policy_id": str(locked.policy_id),
            "risk_score": locked.risk_score,
            "comment": locked.comment,
        },
    )
    return locked


def security_findings(limit=50):
    now = timezone.now()
    findings = []
    failed_siem = SIEMDelivery.objects.filter(status=SIEMDelivery.Status.FAILED).count()
    if failed_siem:
        findings.append(
            {
                "severity": "high",
                "title": "Livraisons SIEM en échec",
                "detail": f"{failed_siem} livraison(s) SIEM ont échoué.",
            }
        )
    stale_sessions = PrivilegedSession.objects.filter(
        status__in=(PrivilegedSession.Status.ACTIVE, PrivilegedSession.Status.TERMINATING),
        expires_at__lt=now,
    ).count()
    if stale_sessions:
        findings.append(
            {
                "severity": "critical",
                "title": "Sessions expirées encore ouvertes",
                "detail": f"{stale_sessions} session(s) dépassent leur expiration.",
            }
        )
    rotation_issues = RotationJob.objects.filter(
        status__in=(RotationJob.Status.FAILED, RotationJob.Status.ACTION_REQUIRED)
    ).count()
    if rotation_issues:
        findings.append(
            {
                "severity": "high",
                "title": "Rotations de secrets à traiter",
                "detail": f"{rotation_issues} rotation(s) sont en échec ou requièrent une action.",
            }
        )
    command_denials = AuditEvent.objects.filter(
        action="session.command_denied",
        occurred_at__gte=now - timedelta(hours=24),
    ).count()
    if command_denials:
        findings.append(
            {
                "severity": "high",
                "title": "Commandes SSH bloquées",
                "detail": f"{command_denials} commande(s) bloquées sur les dernières 24h.",
            }
        )
    high_risk = [item for item in ranked_policy_risks(limit=10) if item["risk"].score >= 70]
    for item in high_risk:
        findings.append(
            {
                "severity": "critical",
                "title": f"Politique à risque critique : {item['policy'].name}",
                "detail": ", ".join(item["risk"].reasons[:3]),
            }
        )
    old_pending = AccessReviewItem.objects.filter(
        decision=AccessReviewItem.Decision.PENDING,
        campaign__due_at__lt=now,
        campaign__status=AccessReviewCampaign.Status.OPEN,
    ).count()
    if old_pending:
        findings.append(
            {
                "severity": "medium",
                "title": "Recertifications en retard",
                "detail": f"{old_pending} habilitation(s) attendent une décision.",
            }
        )
    return findings[:limit]


def compliance_report():
    risks = ranked_policy_risks(limit=1000)
    campaigns = AccessReviewCampaign.objects.annotate(item_count=Count("items")).order_by(
        "-created_at"
    )[:10]
    return {
        "generated_at": timezone.now().isoformat(),
        "controls": {
            "mfa_enforced_policies": AccessPolicy.objects.filter(
                enabled=True, requires_mfa=True
            ).count(),
            "approval_enforced_policies": AccessPolicy.objects.filter(
                enabled=True, requires_approval=True
            ).count(),
            "direct_access_policies": AccessPolicy.objects.filter(
                enabled=True, requires_approval=False
            ).count(),
            "active_credentials": Credential.objects.filter(target__enabled=True).count(),
            "active_sessions": PrivilegedSession.objects.filter(
                status=PrivilegedSession.Status.ACTIVE
            ).count(),
            "open_access_reviews": AccessReviewCampaign.objects.filter(
                status=AccessReviewCampaign.Status.OPEN
            ).count(),
        },
        "top_policy_risks": [
            {
                "policy": item["policy"].name,
                "score": item["risk"].score,
                "level": item["risk"].level,
                "reasons": list(item["risk"].reasons),
            }
            for item in risks[:20]
        ],
        "recent_access_reviews": [
            {
                "name": campaign.name,
                "status": campaign.status,
                "due_at": campaign.due_at.isoformat() if campaign.due_at else "",
                "items": campaign.item_count,
            }
            for campaign in campaigns
        ],
        "findings": security_findings(),
    }
