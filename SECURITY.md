# Security Policy

Security is a product function, not an implied guarantee. PAM-olive is still in a
pre-V1 phase and must not be considered certified or ready for a critical deployment
without an independent review.

## Supported versions

| Version | Security fixes |
| --- | --- |
| Latest prerelease on the main branch | Yes, to the best of the project's ability |
| Older prereleases | No |
| `1.x` | Not released yet |

## Reporting a vulnerability

Never publish a vulnerability, secret, session recording, or personal data in a
public issue.

Prefer **Security → Report a vulnerability** in the GitHub repository to open a
private security advisory. If this feature is not enabled yet, contact the repository
owner through a private channel and request an encrypted channel before sharing details.

A report should contain:

- the affected version or commit;
- the component and prerequisites;
- minimal reproduction steps using fake data;
- the expected impact and, if possible, a suggested fix;
- no keys, internal addresses, or data from a real system.

## Particularly sensitive areas

- bypassing RBAC, policies, approvals, or MFA;
- cross-user vault access or target credential disclosure;
- reuse of a secret lease or session ticket;
- bypassing SSH host-key verification;
- tampering with or silently breaking the audit chain;
- gateway escape, command injection, or database access from a gateway;
- exposure of secrets in URLs, logs, exports, or recordings.

## Deployment expectations

Operators must provide distinct random keys, TLS, a tested backup and restore policy,
key rotation, network restrictions, and monitoring. Examples and CI values are never
production secrets. Read [docs/security.md](docs/security.md) before any deployment.
