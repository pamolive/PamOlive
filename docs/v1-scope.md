# PAM-olive V1 Scope

## Vision

PAM-olive V1 is an open-source bastion designed to govern, deliver, and trace
privileged access. Its architecture uses proven PAM concepts, including separation
of identities, resources, authorizations, approvals, sessions, and audit. The
product, code, and identity remain specific to PAM-olive.

## Mandatory release checklist

The box may be checked only when the repository contains repeatable evidence. A checked
box describes the Community V1 scope; documented post-V1 limitations are not silently
reclassified as delivered features.

- [x] **Distinct roles.** Super Administrator, Administrator, Auditor, Approver, and
  User rights are enforced server-side with explicit permission levels. Evidence:
  `tests/test_rbac.py`, `tests/test_admin_resources.py`, and `docs/permissions.md`.
- [x] **Multiple groups.** A user can belong to several groups and receives only the
  controlled union of active authorizations. Evidence: `tests/test_rbac.py` and
  `tests/test_policy_constraints.py`.
- [x] **Local and federated identities.** Local, LDAP/Active Directory, and OpenID
  Connect identities are modeled and synchronized without plaintext directory secrets.
  Evidence: `tests/test_identity_sources.py`, `tests/test_directory_sync.py`, and
  `tests/test_connector_adapters.py`.
- [x] **Separated inventory.** SSH/RDP equipment, domains, target groups, and privileged
  accounts are distinct resources. Application targets remain outside Community V1.
  Evidence: `tests/test_domains.py` and `tests/test_target_access.py`.
- [x] **Governed secrets.** Secrets are versioned, encrypted by the isolated keyring,
  revealed only after authorization and a mandatory justification, and fully audited.
  Evidence: `tests/test_vault.py`, `tests/test_secret_leases.py`, and
  `tests/test_keyring_migration.py`.
- [x] **Explicit policies.** Policies bind groups, target groups, accounts, protocols,
  schedules, networks, MFA, quotas, and approvals. Evidence:
  `tests/test_policy_constraints.py` and `tests/test_approval_quorum.py`.
- [x] **Approval separation.** Requesters cannot approve their own requests; decisions,
  reasons, quorum, and duration remain immutable. Evidence: `tests/test_approvals.py`
  and `tests/test_approval_quorum.py`.
- [x] **Brokered sessions.** SSH uses an isolated broker, time-limited ticket, encrypted
  trace, and target-side credential injection. RDP provides a governed single-use
  launch and documented traceability boundary. Evidence: `tests/test_gateway.py`,
  `tests/test_session_tickets.py`, `tests/test_rdp.py`, and `docs/rdp.md`. Encrypted
  graphical RDP recording and authoritative Guacamole disconnect reconciliation remain
  explicit post-V1 work.
- [x] **Read-only audit.** Auditors can inspect and export events and sessions without
  secrets or configuration changes. Evidence: `tests/test_audit_integrity.py` and
  `tests/test_console.py`.
- [x] **Operations.** Restore rehearsal, key rotation, health, metrics, backup
  verification, SIEM forwarding, and alerts are documented and tested. Evidence:
  `tests/test_restore_verification.py`, `tests/test_rotation.py`,
  `tests/test_operations_health.py`, and `tests/test_siem.py`.
- [x] **Quality gate.** Migrations are additive, business-core coverage is at least 90%,
  and Django, Ruff, documentation, CodeQL, and critical-CVE gates are configured.
  Evidence: `.github/workflows/ci.yml` and the V1 build report.
- [x] **Fresh install and v0.2 upgrade.** Installers are idempotent and the historical
  v0.2 schema plus encrypted witness data are migrated to the current schema and
  isolated keyring without loss. Evidence: `tests/test_upgrade_v02.py`,
  `scripts/restore-rehearsal.sh`, and `docs/installation.md`.

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
