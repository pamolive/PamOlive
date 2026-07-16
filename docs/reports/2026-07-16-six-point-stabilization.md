# Six-point stabilization report — 2026-07-16

## Scope

This increment addresses persisted themes, browser SSH password sessions, mandatory
business justification, global MFA, architecture documentation, and reproducible
installation checks. Work on the reference NAS used a separate staging directory and
a separate Docker Compose project. No existing NAS data, account, unrelated Docker
resource, PAM-olive volume, or production container was deleted.

## Delivered controls

### Persisted appearance

Theme initialization now runs from a same-origin external script accepted by the
Content Security Policy. It applies the saved `system`, `light`, or `dark` preference
before the stylesheet paints the page. Language submission no longer alters the
saved theme.

### Browser SSH password sessions

The isolated gateway now sends an explicit `authorization_required` WebSocket state
immediately after accepting the connection. The browser responds once with the
single-use ticket, the internal API consumes it, and the gateway receives an
encrypted credential envelope. Password credentials use AsyncSSH password
authentication; SSH keys remain optional credential types rather than a requirement.

### Mandatory business justification

Every target credential reveal and SSH/RDP session requires 10–1000 characters of
business justification. Authorization is checked first, then the reason is validated
again in the service layer. The normalized reason is stored on `SecretLease` or
`PrivilegedSession` and included in signed audit metadata. Super administrators and
automatically approved policies have no bypass. Personal-vault reveals remain exempt.

### Global MFA

The singleton platform policy enables MFA for every interactive user by default.
Users without a confirmed TOTP device can reach only MFA enrollment and logout.
Enrollment is cache-disabled, generates recovery codes after confirmation, and then
unlocks the application. Confirmed users must provide TOTP or a one-time recovery
code at later logins.

### Installation readiness

Linux and Windows bootstrap scripts now generate the previously missing Redis
password and matching authenticated URL. The installation guide documents fresh
setup, first super-administrator creation, mandatory MFA enrollment, public reverse
proxy requirements, verification, upgrade preparation, and current security limits.
Fresh Docker installations now use the non-debug base settings profile; a public TLS
deployment must explicitly select the hardened production profile.

## Verification evidence

- Python compile check: passed.
- Docker test project: `pam-olive-ci-20260716`, isolated from the active stack.
- Tests: 137 passed.
- Coverage: 90.10%, above the mandatory 90% threshold.
- Migration drift: none.
- Ruff: all checks passed.
- Active deployment: all PAM-olive services running; database, Redis, web, SSH
  gateway, RDP broker, Guacamole, and guacd healthy.
- Live SSH password flow: ticket authorized, password injected in the gateway,
  harmless marker command confirmed, session closed and audited.

## Release assessment

This increment is suitable for a versioned pre-V1 release candidate and for
reproducible community installation. It must not yet be advertised as a
high-assurance Internet-production V1. External KMS/HSM encryption and signing,
firewall/VLAN verification, target-side ephemeral accounts, image digest/CVE release
gates, restore rehearsal, and complete public TLS validation remain explicit release
criteria.
