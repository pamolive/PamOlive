# IAM governance

PAM-olive includes an enterprise IAM governance layer for privileged access:
entitlement inventory, risk scoring, access reviews, revocation decisions, security
findings, and compliance evidence.

## Entitlement catalog

Each access policy is treated as an entitlement:

- who receives the entitlement through user groups;
- which target groups and credentials it covers;
- which actions are allowed;
- whether MFA, approval, source networks, time frames, and command controls apply.

The governance center ranks entitlements by risk so administrators can work on the
most exposed paths first.

## Risk score

The score is computed from PAM-specific controls:

- direct access without approval;
- missing MFA;
- secret or TOTP reveal;
- privileged-session start;
- weak approval quorum;
- long duration;
- high concurrency;
- unrestricted source networks;
- no time frame;
- clipboard permissions;
- missing SSH deny rules;
- broad user or target scope.

Scores are capped at 100 and classified as low, medium, high, or critical.

## Access reviews

An access-review campaign snapshots all policies at creation time. Reviewers can
decide each entitlement:

- **Maintain** keeps the policy active and records the decision;
- **Revoke** disables the policy and records the decision.

Every campaign creation and decision is written into the immutable audit chain.

## Security findings

The governance center highlights operational signals such as:

- failed SIEM deliveries;
- expired sessions still open;
- failed or blocked credential rotations;
- SSH commands blocked during the last 24 hours;
- critical-risk policies;
- overdue recertifications.

## Compliance report

The report is exported as JSON from the console and contains:

- generated timestamp;
- MFA and approval coverage;
- direct-access policies;
- active credentials and sessions;
- open access reviews;
- top policy risks;
- recent campaigns;
- active findings.

This report is designed as evidence for internal audits, customer security reviews,
and enterprise IAM/PAM governance rituals.
