# PAM-olive V1 Build Report

## Status

- Starting version: 0.2.0
- Target version: 1.0.0
- Current state: V1 architecture in progress, active Docker test deployment on the NAS,
  not yet approved for production
- Modified environments: local repository and isolated `/volume1/docker/pam-olive` stack
- NAS scope: every operation is limited to the explicitly authorized project boundary
  and recorded below

## Functional references

Public administration, audit, and user guides for established PAM solutions were used
as functional references. Retained concepts include role-dependent navigation,
permission profiles, groups, separation of targets and accounts, authorizations,
approvals, session monitoring, and audit history. No proprietary code or branding is
incorporated.

## Initial assessment

Version 0.2 provided Django, PostgreSQL, Redis, Channels, Celery, application-level
encryption, multiple groups, policies, requests, a chained audit log, a personal vault,
local MFA, and a modern console. The main V1 gaps were:

- insufficient permission granularity;
- no structured approver profile or external identities;
- LDAP/OIDC connectors not implemented;
- incomplete domain, target, and account models;
- single-decision approval workflow;
- no short-lived secret leases or orchestrated rotation;
- SSH/RDP brokering and recording not ready;
- incomplete observability, backup, and restore procedures.

## Operations log

### July 13, 2026 — V1 scope

- Reviewed existing models and settings.
- Studied public functional documentation for administration, audit, and user flows.
- Created the V1 scope and permission matrix.
- Formalized the NAS non-modification rule.
- NAS data, Docker services, and users: no operation performed.

### July 13, 2026 — Identities, permissions, and domains

- Expanded capabilities into read, manage, and sensitive-action permissions.
- Added direct delegations with start and end dates.
- Added a dedicated Approver system profile and group.
- Added encrypted LDAP, Active Directory, and OIDC source configuration.
- Added external identities and group mappings.
- Added domains and detailed target and privileged-account types.
- Extended the product console without disclosing connector secrets.
- Verified additive migrations with no destructive deletion or rename.
- Result: 40 tests passed, 93.86% coverage, valid Django checks.
- NAS data, Docker services, and users: no operation performed.

### July 13, 2026 — Federation and approvals

- Added a TLS-capable, paginated LDAP/Active Directory adapter with safe errors.
- Added disabled-by-default Celery synchronization tested through a simulated adapter.
- Added first-login OIDC provisioning with group checks.
- Tracked externally managed memberships while preserving manual assignments.
- Revoked managed memberships when the external group disappears.
- Added configurable quorum, approver groups, and policy-level mandatory ticket references.
- Added immutable decision history and duplicate-decision rejection.
- Result: 51 tests passed, 92.68% coverage, valid Django checks.
- NAS data, Docker services, and users: no operation performed.

### July 13, 2026 — Secret leases and session authorization

- Added 15-to-300-second, single-use secret leases.
- Persisted only token hashes; raw tokens are never stored.
- Centralized policy, approval, and MFA checks before every reveal.
- Added 15-to-120-second session tickets bound to user, account, target, protocol,
  policy, and source address.
- Allowed a valid approval to authorize multiple sessions in its time window, each
  with an independent ticket and audit trail.
- Moved the ticket to the first WebSocket message so it never appears in an HTTP or
  WebSocket URL.
- Exposed session actions only when `start_session` is authorized.
- Marked terminal responses `private`, `no-store`, and `must-revalidate`.
- Enforced fail-closed behavior while the isolated broker was unavailable.
- Verified additive session migrations without table or column removal.
- Result: 60 tests passed, 92.99% coverage, valid style and Django checks.
- NAS data, Docker services, and users: no operation performed.

### July 13, 2026 — Audit integrity and export

- Introduced a strictly sequenced v2 audit log with canonical content and HMAC signatures.
- Serialized concurrent writes using a transactionally locked chain head.
- Preserved v1 events as identified historical entries.
- Validated sequence continuity, links, hashes, signatures, and chain head.
- Added CSV and JSON Lines export limited to 10,000 events and protected by `audit.export`.
- Blocked export with HTTP 409 when tampering is detected.
- Recursively redacted passwords, secrets, keys, cookies, tokens, and tickets and
  neutralized CSV formula injection.
- Added SHA-256 download fingerprints and auditing of exports themselves.
- Added integrity state, filters, and conditional actions to the audit interface.
- Adversarial direct-database tests successfully detected tampering and denied export.
- Result: 64 tests passed, 92.86% coverage, valid style and Django checks.
- NAS data, Docker services, and users: no operation performed.

### July 13, 2026 — Isolated SSH broker and host trust

- Added an SSH host-key registry with SHA-256 fingerprint, approver, justification,
  history, and audited revocation.
- Denied SSH ticket issuance without an active approved host key.
- Added a separate ASGI broker with no PostgreSQL, Redis, vault-key, or audit-key access.
- Added a timestamped HMAC internal protocol and short-lived encrypted connection envelope.
- Secrets are exchanged and consumed broker-side and never sent to the browser.
- Added AsyncSSH connections with mandatory `known_hosts`, supporting passwords and
  private keys in memory.
- Added WebSocket terminal relay for input, output, resizing, and keyboard control.
- Added encrypted stream recording with `0600` permissions, SHA-256 fingerprints, and
  audited sealing; session data is never stored in plain text.
- Added a signed real-time termination channel and safe revocation of unused tickets.
- Fixed a denial-of-service path where an invalid ticket could report closure for a
  session it merely claimed to identify.
- A real loopback SSH test connected with the approved key and rejected a different key.
- Added two-network Compose isolation with Caddy as the only exposed component and a
  read-only, capability-free gateway.
- Vendored and integrity-checked HTMX, with strict CSP and browser headers.
- Result: 79 tests passed, 90.31% coverage, valid style and Django checks.
- NAS data, Docker services, and users: no operation performed.

### July 13, 2026 — Policy constraints and GitHub preparation

- Added optional policy restrictions for credentials and protocols.
- Added validity periods, weekdays, overnight time windows, source CIDRs, and concurrent
  session limits.
- Applied the same policy engine to requests, secret leases, and session tickets.
- Added fail-closed behavior for invalid network configuration and verified proxy source data.
- Completed AGPL-3.0-or-later licensing and retained the vendored HTMX license.
- Reworked README, security policy, contribution guide, notice, and code of conduct to
  accurately describe pre-V1 status.
- Added GitHub CI for PostgreSQL, migrations, 90% minimum coverage, strict documentation,
  image build, and image testing.
- Added CodeQL, Dependabot, and tag-gated GHCR publication with provenance and SBOMs.
- Added issue and pull-request templates that prohibit real secrets and system data.
- Result: 89 tests passed, 91.43% coverage across 2,941 measured statements.
- NAS data, Docker services, and users: no operation performed.

### July 13, 2026 — Operations, rotation, and keyring

- Added idempotent rotation orchestration with configurable connectors, retry behavior,
  encrypted candidate secrets, and promotion only after target success.
- Added Celery scheduling for due rotations and a dedicated history console.
- Added separate liveness, readiness, integrity, and token-protected metrics endpoints.
- Added non-destructive backup using `pg_dump`, encrypted SSH recordings, configuration,
  a SHA-256 manifest, and independent verification without implicit restoration.
- Added a multi-key vault keyring and transactional key rotation command that defaults
  to dry-run and requires explicit confirmation to apply.
- Result: 102 tests passed, 90.67% coverage, valid style, Django, migration, and strict
  documentation checks.
- Native restore rehearsal in an ephemeral Docker stack remained a V1 requirement.
- NAS data, Docker services, and users: no operation performed.

### July 13, 2026 — RDP brokering and dedicated origin

- Validated Apache Guacamole 1.6.0 JSON authentication and browser-token behavior
  against official documentation and source contracts.
- Added a distinct RDP origin, minimal launch broker, ticket-free URLs, and a transition
  page with nonce-based CSP and disabled caching.
- Added compatible HMAC-SHA256/AES-128-CBC JSON authentication with 15-second expiry
  and single-use connections.
- Added NLA, extended NLA, TLS, certificate-fingerprint, keyboard, and resizing settings.
  Permissive certificate and legacy encryption modes are not offered.
- Separated copy and paste permissions, denied both by default, and disabled drives,
  printing, and microphones.
- Added Guacamole 1.6.0, guacd, broker, and proxy services isolated across four internal
  networks. `guacd` exposes no host port and alone reaches target networks.
- Fixed a regression where RDP-specific required fields blocked SSH target creation.
- Result: 113 tests passed, 90.57% coverage, valid style, Django, migration, script,
  YAML, and strict documentation checks.
- Encrypted RDP recording and observed forced termination remained V1 blockers.
- NAS data, Docker services, and users: no operation performed.

### July 14, 2026 — Visual acceptance, restore controls, and checkpoint

- Added a read-only restore-verification command for migrations, optional witness user,
  audit-chain integrity, and decryption of all protected fields.
- Added restore rehearsal into a separate, new PostgreSQL database. It requires explicit
  acknowledgement, restricts the name to ephemeral rehearsal databases, and performs no
  database, volume, or container deletion.
- Tested with a fresh temporary SQLite database, four accounts, and fake data only.
- Validated user flows: login, simplified dashboard, personal vault, target credentials,
  audited password/TOTP reveal, target groups, requests, local account, and MFA enrollment.
- Validated administrator flows: modern console, users, multiple groups, targets, policies,
  approvals, and signed audit. Product administrators were denied `/django-admin/`.
- Validated read-only auditor flows without creation or approval-decision actions.
- Validated exclusive technical administration access for super administrators.
- No browser warnings or JavaScript errors were found during this acceptance pass.
- Result: 115 tests passed, 90.69% coverage, valid style, Django, deployment, migration,
  and strict documentation checks.
- NAS data, Docker services, and users: no operation performed.

### July 14, 2026 — NAS Docker test deployment

- Created a distinct `pam-olive` Compose stack in `/volume1/docker/pam-olive` without
  overwriting the earlier project directory.
- Transferred a clean archive and verified its SHA-256 checksum before extraction.
- Generated a `0600` `.env` locally on the NAS without displaying secrets.
- Published the portal on `0.0.0.0:18081` and RDP origin on `0.0.0.0:18082`.
- Created project-specific Docker volumes and networks without reusing earlier PAM volumes.
- Added the direct `requests` dependency required by Authlib at startup.
- Added Synology DSM compatibility through the sole `NET_BIND_SERVICE` capability for
  Caddy proxies while preserving read-only filesystems, dropped capabilities, and
  `no-new-privileges`.
- Added a public network only to the RDP proxy so DSM Docker could publish the port.
  Broker, Guacamole, and guacd remained compartmentalized.
- Built images, applied migrations, and started eleven services. Every service with a
  health check reported `healthy`.
- Validated login, dashboard, product administration, readiness, and both published ports.
- After explicit owner approval, stopped and removed only the earlier application
  containers and images. Its PostgreSQL and Redis volumes and project directory were retained.
- Odoo, Psono, and BunkerWeb remained active and unchanged.

### July 15, 2026 — Security, policy, and session refinement (v0.3.0)

- Added ten hashed, single-use MFA recovery codes, regeneration, and secure MFA reset.
- Added dynamic TOTP refresh with a 30-second progress bar and non-cacheable responses.
- Added immediate removal of revealed secrets from the rendered page.
- Added reusable `TimeFrame` schedules and independent `SecretRotationPolicy` objects.
- Replaced checkbox walls with compact multi-selection lists.
- Separated LDAP/Active Directory and OpenID Connect administration screens.
- Limited target creation to SSH and RDP equipment in this phase.
- Opened sessions in a new tab and replaced proxy-masked host-key denials with a clear,
  safe corrective page.
- Retained legacy columns for lossless migrations.
- Created a verified pre-deployment backup under the PAM-olive project boundary.
- Result: 120 tests passed with 90.71% application coverage. Ruff, migrations, and the
  isolated Docker suite passed before deployment.
- Deployed the updated stack with healthy web, database, cache, gateway, RDP, worker,
  and proxy services.
- No third-party NAS data, users, containers, images, or volumes were modified.

## Reference validation

Before V1 work started, v0.2 passed 33 tests with 94.37% coverage on the NAS. This is
the historical baseline; each V1 increment must keep migrations non-destructive and
maintain at least 90% business-core coverage.

## Risk register

| Risk | Severity | Control |
| --- | --- | --- |
| Secret exposure in logs | critical | redaction, tests, and opaque secret objects |
| Privilege escalation through combined groups | critical | centralized authorization engine and negative tests |
| Self-approval | high | business constraint and immutable audit |
| Data loss during migration | critical | additive migrations and upgrade testing |
| Web-process compromise enabling SSH access | critical | isolated gateway and ephemeral tickets |
| Session-ticket reuse or disclosure | critical | short, hashed, single-use, context-bound tickets absent from URLs |
| LDAP/OIDC outage | medium | bounded cache, break-glass local accounts, and explicit errors |

## Release decision

The “V1 candidate” label will be added only after every criterion in
`docs/v1-scope.md` has been demonstrated by tests and recorded in this report.
