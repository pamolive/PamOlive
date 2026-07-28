import pytest
from django.urls import reverse

from pamolive.accounts.models import User
from pamolive.audit.models import AuditEvent
from pamolive.operations.governance import (
    create_access_review_campaign,
    decide_access_review_item,
    ranked_policy_risks,
    score_access_policy,
)
from pamolive.operations.models import AccessReviewItem
from pamolive.policies.models import AccessPolicy
from pamolive.rbac.models import UserGroup
from pamolive.targets.models import Target, TargetGroup


def entitlement_fixture():
    owner = User.objects.create_user(
        username="governance-owner",
        email="governance-owner@example.test",
    )
    user_group = UserGroup.objects.create(name="Privileged operators")
    user_group.users.add(owner)
    target = Target.objects.create(
        name="Critical production",
        hostname="10.0.0.20",
        port=22,
        protocol=Target.Protocol.SSH,
    )
    target_group = TargetGroup.objects.create(name="Critical targets")
    target_group.targets.add(target)
    policy = AccessPolicy.objects.create(
        name="Critical direct access",
        actions=[
            AccessPolicy.Action.START_SESSION,
            AccessPolicy.Action.VIEW_SECRET,
            AccessPolicy.Action.REVEAL_TOTP,
        ],
        requires_approval=False,
        requires_mfa=False,
        max_duration_minutes=720,
        max_concurrent_sessions=4,
        source_cidrs=[],
    )
    policy.user_groups.add(user_group)
    policy.target_groups.add(target_group)
    return owner, policy


@pytest.mark.django_db
def test_policy_risk_scoring_and_access_review_revocation():
    owner, policy = entitlement_fixture()

    risk = score_access_policy(policy)
    campaign = create_access_review_campaign(
        name="Quarterly critical review",
        created_by=owner,
    )
    item = campaign.items.get(policy=policy)
    decided = decide_access_review_item(
        item=item,
        decision=AccessReviewItem.Decision.REVOKE,
        actor=owner,
        comment="Access no longer justified",
    )

    policy.refresh_from_db()
    assert risk.score >= 70
    assert ranked_policy_risks()[0]["policy"] == policy
    assert item.snapshot["risk_score"] == risk.score
    assert decided.decision == AccessReviewItem.Decision.REVOKE
    assert policy.enabled is False
    assert AuditEvent.objects.filter(action="governance.access_review.created").exists()
    assert AuditEvent.objects.filter(action="governance.access_review.revoke").exists()


@pytest.mark.django_db
def test_governance_console_and_report_are_available_to_admin(client):
    _owner, _policy = entitlement_fixture()
    administrator = User.objects.create_user(
        username="governance-admin",
        email="governance-admin@example.test",
    )
    UserGroup.objects.get(name="Administrateurs PAM-olive").users.add(administrator)
    client.force_login(administrator)

    center = client.get(reverse("console:governance_center"))
    reviews = client.get(reverse("console:access_reviews"))
    report = client.get(reverse("console:governance_report_export"))

    assert center.status_code == 200
    assert b"Centre de contr" in center.content
    assert reviews.status_code == 200
    assert report.status_code == 200
    assert report.json()["top_policy_risks"][0]["policy"] == "Critical direct access"
