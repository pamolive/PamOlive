# Evolution Report — Security, Policies, and Sessions

Date: July 15, 2026
Version: 0.3.0

## Objective

This evolution replaces several demonstration behaviors with durable business
features: MFA lifecycle management, dynamic TOTP, reusable authorization schedules,
separate identity sources, rotation policies, and explicit session-denial diagnostics.

## Completed work

- TOTP MFA with ten single-use recovery codes. Only their password hashes are stored.
- Recovery-code regeneration and MFA reset after validating the password and a valid
  second factor.
- Automatic TOTP refresh every 30 seconds, a progress bar, and non-cacheable HTTP responses.
- A hide action that immediately removes the revealed secret from the displayed document.
- An independent `TimeFrame` object for weekdays, hours, and validity windows; one policy
  may combine multiple schedules.
- An independent `SecretRotationPolicy` for frequency, method, generated length, target
  groups, and execution connector.
- Compact administration forms based on multi-selection lists.
- Separate screens for LDAP/Active Directory and OpenID Connect.
- Target creation limited to SSH and RDP equipment in this release.
- Session launch in a new browser tab.
- Session denial displayed in PAM-olive with the expected corrective action.

## 403 response diagnosis

Proxy and Django logs were correlated without changing NAS configuration. The request
reached the application correctly. It was denied because the SSH target had no approved
host key. This check remains enforced because it protects against connecting to an
impostor server. The interface now explains that an administrator must verify and approve
the host key in the console.

## Compatibility and data

Legacy schedule and rotation columns are retained to provide a lossless migration path.
New objects are added through Django migrations. No third-party container, NAS user, or
volume outside the PAM-olive project was modified.

## Validation

- 120 automated tests passed with 90.71% application coverage.
- Ruff completed without errors.
- Django migrations contain no missing changes.
- The isolated Docker test suite passed before deployment to the NAS.

## Next steps before V1

Version 0.3.0 remains an alpha release. Priorities include real LDAP/OIDC connector
validation, remote rotation connectors, complete SSH/RDP journeys across multiple
platforms, hardened TLS exposure, and load testing.
