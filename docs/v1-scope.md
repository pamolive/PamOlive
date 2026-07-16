# PAM-olive V1 Scope

## Vision

PAM-olive V1 is an open-source bastion designed to govern, deliver, and trace
privileged access. Its architecture uses proven PAM concepts, including separation
of identities, resources, authorizations, approvals, sessions, and audit. The
product, code, and identity remain specific to PAM-olive.

## Mandatory release criteria

A release may be declared a “V1 candidate” only when all the following criteria are met:

1. Super Administrator, Administrator, Auditor, Approver, and User roles are enforced
   server-side with distinct read and modify permissions.
2. A user may belong to multiple groups and receive the controlled union of their
   active authorizations.
3. Local, LDAP/Active Directory, and OpenID Connect identities are modeled, testable,
   and synchronizable without storing directory passwords in plain text.
4. SSH and RDP equipment, domains, target groups, and privileged accounts are
   represented separately. Application targets remain outside the first stable scope.
5. Secrets are encrypted at rest, versioned, revealed only after authorization and
   a mandatory business justification, and every access is audited.
6. Policies explicitly link user groups, target groups, accounts, protocols, time
   windows, global and action-level MFA, and approval workflows.
7. An approver can never approve their own request. Decisions, reasons, and durations
   are immutable in audit history.
8. SSH brokering is isolated from the web process, verifies time-limited authorization,
   and produces a session trace. RDP launch provides at least a governed flow and a
   documented traceability strategy.
9. Auditors may view and export events and sessions without revealing secrets or
   modifying configuration.
10. Restore, key rotation, health checks, metrics, and operational alerts are documented
    and tested.
11. Migrations are additive, automated tests cover at least 90% of the business core,
    and Django security checks report no blocking errors.
12. Both a fresh installation and an upgrade from v0.2 are reproducible with Docker
    Compose without data loss.

## V1 functional domains

- Identities: local accounts, external identities, MFA, preferences, and lifecycle.
- RBAC: permission profiles, groups, temporary delegations, and restrictions.
- Inventory: SSH/RDP equipment, domains, target groups, and target accounts.
- Vaults: personal vault, target vault, TOTP, SSH keys, and rotation metadata.
- Authorizations: access rules, protocols, actions, MFA, schedules, and approvals.
- Approvals: requests, quorum, decisions, expiration, and history.
- Sessions: preparation, launch, monitoring, termination, and recording.
- Audit: integrity chain, filters, exports, alerts, and SIEM integration.
- Connectors: LDAP/AD, OIDC, SMTP, SIEM, and external vaults through extensible interfaces.
- API: versioned endpoints, constrained service tokens, and OpenAPI documentation.

## Initially out of scope

- Exact reproduction of a proprietary interface or source code.
- Intrusive network discovery enabled by default.
- Automatic rotation on every operating system without a validated plugin.
- Multi-site high availability before validating single-site V1.

## Development NAS safety rule

The reference NAS contains critical data outside PAM-olive. No deletion, reset, or
modification of NAS data, volumes, containers, or accounts is authorized during local
V1 development. A future deployment requires explicit authorization, a verified backup,
and a non-destructive rollback plan.
