# Changelog

All notable changes are documented here. The project will follow Semantic Versioning
from V1 onward; `0.x` releases may still evolve interfaces and the schema.

## [Unreleased]

### Added

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

### Fixed

- Session launches open in a new tab, and security denials are explained by
  PAM-olive instead of being hidden behind the proxy error page.
- Authorization forms use compact selection lists instead of walls of checkboxes.
- Target creation is limited to SSH and RDP equipment.
- Explicit declaration of `requests`, an Authlib runtime dependency.
- Synology DSM compatibility for Caddy proxies through the minimal
  `NET_BIND_SERVICE` capability and a public network dedicated to the RDP entry point.

### Security

- Strict SSH host-key validation with no permissive production mode.
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

- Modular Django foundation for the CBPAM domains.
- PostgreSQL, Redis, Channels, and Celery runtime.
- Encrypted credential service and append-only hash-chained audit events.
- Docker Compose, CI, tests, and MkDocs documentation.

### Changed

- Product identity renamed from CBPAM to PAM-olive.
- Authentication and dashboard interfaces redesigned with an accessible responsive design system.
