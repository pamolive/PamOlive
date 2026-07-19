# Changelog

All notable changes are documented here. The project will follow Semantic Versioning
from V1 onward; `0.x` releases may still evolve interfaces and the schema.

## [Unreleased]

### Security

- Target-secret reveals and SSH/RDP session launches now require a local MFA proof
  no older than five minutes, including for sessions created through OIDC.

## [1.0.2] - 2026-07-18

### Added

- Add a shared company and community footer with MOPACY, GitHub, Discord, and LinkedIn links.

## [1.0.1] - 2026-07-18

### Fixed

- The isolated Compose test image now includes the keyring, Redis TLS initializer,
  Compose model, and Guacamole lifecycle sources inspected by the V1 release tests.

## [1.0.0] - 2026-07-18

### Added

- Verified internal TLS for Redis, with a dedicated CA/server-key volume, a client-only
  CA volume, and an idempotent one-shot certificate initializer.
- Per-operation keyring rate limiting with a stricter decryption quota and explicit
  `Retry-After` responses.
- A reproducible v0.2 schema and encrypted-data upgrade test, plus a binary V1 release
  checklist with evidence for every criterion.
- Formal project governance identifying MOPACY (mopacy.eu and mopacy.be) as
  PAM-olive author and steward.
- Structured permission-profile levels and sectioned access authorizations which
  clearly separate console administration from target access.
- SSH terminal selection and full-output copy controls, terminal-aware copy
  shortcuts, and best-effort SSH/RDP session-tab closure after logout.
- Browser SSH terminal based on the vendored xterm.js 6.0.0 emulator, including
  ANSI/VT rendering, UTF-8 byte preservation, resizing, scrollback, and an explicit
  audited multi-line command paste control.
- Local `.txt` download of the one-time MFA recovery codes displayed after enrollment
  or regeneration.
- Idempotent Linux and Windows installers which generate independent Django,
  PostgreSQL, Redis, keyring, gateway, recording, operations, and Guacamole secrets.
- A startup secret gate which refuses blank, short, or known placeholder values.
- A blocking Trivy 0.70.0 CI gate for every final Compose image.
- Isolated FastAPI keyring with a dedicated master-key volume, separate HKDF-derived
  encryption/signing keys, and no published port.
- Transactional legacy-secret and audit-signature migration with mandatory dry-run
  verification and mixed-state retry support.
- Global MFA enforcement with a cache-disabled first-login TOTP enrollment flow.
- Canonical `/mfa/setup/` onboarding, ten hashed one-time recovery codes, and a
  multilingual administration warning when the global MFA requirement is disabled.
- Three-network Compose segmentation (`frontend`, `internal`, and `targets`) with
  a disposable isolation probe enforced by CI.
- Mandatory server-side business justification for every target-secret reveal and
  SSH/RDP session, persisted on leases and sessions and included in signed audit data.
- Server-enforced inactivity and absolute browser-session limits with an
  administration policy screen and expiration audit events.
- SIEM forwarding through HTTPS webhooks or syslog over TLS, with encrypted bearer
  tokens, redaction, retry, and a delivery ledger.

### Changed

- All Python runtime images now use an immutable, critical-CVE-clean Alpine digest.
- PostgreSQL and Guacamole use PAM-olive hardened derivatives of immutable upstream
  images: the PostgreSQL image removes the vulnerable `gosu` binary, while the
  Guacamole image updates Tomcat and retains only the JSON authentication extension
  required by the RDP broker.
- The keyring API now requires an independent Bearer token on every cryptographic
  operation; its unauthenticated endpoint is limited to the internal health probe.
- The source package and runtime identifiers are consistently named `pamolive`;
  legacy product-name references have been removed from published project content.
- Vault encryption, decryption, and audit signing now use the internal keyring API;
  Django no longer receives vault or audit-signing keys through its environment.
- Theme and language preferences now use independent, race-free server updates;
  System, Light, and Dark are explicit choices.
- Light-theme contrast is stronger across navigation, forms, buttons, badges, and
  secret panels.
- Redis now requires authentication and the SSH gateway uses a dedicated egress
  network separated from PostgreSQL, Redis, Celery, and the keyring.
- Fresh Docker installations use the non-debug base settings profile; public TLS
  deployments explicitly opt into the hardened production profile.

### Fixed

- SSH sessions no longer fail before authentication when a persistent recording
  volume was created by an older gateway UID. A network-isolated initializer repairs
  ownership without deleting recordings, and storage failures now have a dedicated
  operator-facing error instead of being reported as SSH transport failures.
- PostgreSQL credential rotation no longer locks the nullable side of an outer join.
- Syslog TLS delivery now explicitly requires TLS 1.2 or newer.
- Anonymous visitors can choose Auto, Light, or Dark directly on the login page;
  the preference is stored locally and remains active after authentication.
- Theme selection now initializes from the persisted preference through a
  CSP-compatible same-origin script on every page load.
- The SSH browser gateway now explicitly requests the one-time authorization ticket,
  removing the WebSocket handshake deadlock before password injection.
- SSH password sessions no longer fail when Django rejects the Docker service name
  used as an internal HTTP Host header.
- Failed gateway WebSockets use an application-valid close code and emit safe,
  actionable broker logs.

## [0.4.0] - 2026-07-15

### Added

- Dark, light, and system appearance preferences persisted per user.
- English, French, and Spanish navigation and core user experience.
- Personal password groups and ownership-protected secret editing.
- Dynamic personal-vault forms for logins, TOTP seeds, payment cards, and notes.
- Live administration dashboard with database/cache health, connected users,
  privileged sessions, authentication failures, approvals, and audit activity.
- Official PAM-olive logo variants for dark and light interfaces.
- SSH trust-on-first-use mode as the default, with strict pre-approval remaining
  available per target.

- Complete MFA lifecycle: single-use recovery codes, regeneration, and reset.
- Dynamic TOTP codes with a countdown and immediate hiding of revealed secrets.
- Reusable time frames attached to access policies.
- Separate rotation policies applicable to credentials and target groups.
- Separate screens for LDAP/AD directories and OpenID Connect providers.
- LDAP, Active Directory, and OIDC identity sources with group mapping.
- Domains, target and account types, and approved/revoked SSH host keys.
- Policy constraints by credential, protocol, schedule, network, and concurrency.
- Approval quorum, approver groups, and immutable decisions.
- Short, source-bound, single-use session tickets and secret leases.
- Isolated SSH gateway, WebSocket terminal, and sealed encrypted recordings.
- Sequenced, signed, verifiable audit log v2 with CSV/JSONL export.
- GitHub readiness: stronger CI, CodeQL, Dependabot, and a GHCR release pipeline.
- Orchestrated credential rotation, health checks, metrics, and verifiable backups.
- Vault keyring with transactional rotation and a safe two-step command.
- RDP brokering through Apache Guacamole 1.6.0 on a dedicated origin, using a
  single-use ticket and policy-controlled security and clipboard settings.

### Changed

- The main navigation now includes an explicit Home entry.
- SSH sessions can use a username and password without a preinstalled client key.
- Target forms clearly expose the SSH host identity policy.

### Fixed

- Session launches open in a new tab, and security denials are explained by
  PAM-olive instead of being hidden behind the proxy error page.
- Authorization forms use compact selection lists instead of walls of checkboxes.
- Target creation is limited to SSH and RDP equipment.
- Explicit declaration of `requests`, an Authlib runtime dependency.
- Synology DSM compatibility for Caddy proxies through the minimal
  `NET_BIND_SERVICE` capability and a public network dedicated to the RDP entry point.

### Security

- First-use SSH host keys are recorded atomically, audited, and reused for all later
  connections; a changed key is denied instead of silently accepted.
- Personal vault edits enforce ownership and re-encrypt the complete secret payload.
- Failed local sign-ins are recorded in the append-only audit chain.
- SSH host identity validation supports strict pre-approval and audited first use.
- HMAC-signed internal gateway API and secrets transported in a Fernet envelope.
- Separate Docker networks and a gateway without direct PostgreSQL access.
- CSP with self-hosted HTMX and application/proxy security headers.
- Audited remote session termination and sealing of the related recording.
- Guacamole JSON authentication expiring after 15 seconds and never sent in a URL.
- `guacd` without a host port, compartmentalized RDP networks, and redirection
  features disabled by default.

## [0.2.0] - 2026-07-13

### Added

- Product roles and granular capabilities for administrators, auditors, and users.
- Multi-group membership with policies linking user groups to target groups.
- Personal encrypted vault entries for logins, TOTP seeds, payment cards, and secure notes.
- Target credential vault with multiple local credentials and optional TOTP per target.
- Local account profile, password change, and TOTP MFA enrollment.
- Product administration console for identities, target groups, credentials, policies,
  approvals, sessions, and audit events.
- Hierarchical, collapsible administration navigation based on established PAM workflows.
- Tests for permission boundaries, MFA, personal vault ownership, and approval separation.

### Security

- Technical Django administration is restricted to super administrators.
- Auditors receive read-only configuration and monitoring access without secret disclosure.
- Administrators cannot approve their own access requests.

## [0.1.0] - 2026-07-13

### Added

- Modular Django foundation for the PAMOLIVE domains.
- PostgreSQL, Redis, Channels, and Celery runtime.
- Encrypted credential service and append-only hash-chained audit events.
- Docker Compose, CI, tests, and MkDocs documentation.

### Changed

- Product identity renamed from PAMOLIVE to PAM-olive.
- Authentication and dashboard interfaces redesigned with an accessible responsive design system.
