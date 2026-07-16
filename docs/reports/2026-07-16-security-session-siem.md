# Security, session and SIEM implementation report — 2026-07-16

## Scope and safety

Work was restricted to `/volume1/docker/pam-olive` and its Compose project. No NAS
user, unrelated container, unrelated image, database volume, Redis volume, recording
volume, or external application was deleted. A source/configuration backup was made
before deployment:

- `backups/pre-security-session-siem-20260715.tar.gz`
- `backups/.env.pre-redis-auth-20260715` (mode `600`)

## Delivered changes

### SSH password authentication

The NAS credential was decrypted only in process memory and independently verified
against `192.168.0.25:2222`. Authentication succeeded. The actual failure was the
gateway's internal HTTP request using Docker hostname `web:8000` as the HTTP `Host`;
Django correctly rejected it because that internal name is not a public allowed host.

The signed internal client now uses `Host: localhost` while connecting to the Docker
service address. The public allowed-host policy therefore remains strict. Password
credentials set `password` and an empty `client_keys` list in AsyncSSH; SSH keys are
used only for credentials explicitly typed as `ssh_key`.

End-to-end production validation created a real single-use ticket, injected the
configured target password inside the gateway, connected to target `nas`, executed
only `true` plus a test marker, and exited. Result:

```json
{"connected": true, "command_confirmed": true, "closed": true, "error": ""}
```

The resulting session is closed with reason `remote_exit`; both `session.opened` and
`session.closed` audit events exist. No password or key was printed or persisted.

### User preferences and light theme

Theme and language changes now use separate CSRF-protected server POST forms and a
safe same-origin redirect. This removes asynchronous request races where a late
response could overwrite a newer preference. Theme choices are System, Light, and
Dark. Changing language does not submit or change the theme. The light palette now
uses stronger text, border, form, badge, navigation, button, and secret-panel
contrast.

### Web-session security policy

A singleton platform policy provides:

- inactivity timeout (default 15 minutes);
- absolute browser-session lifetime (default 480 minutes);
- server-side enforcement on every authenticated request;
- audit event `authentication.session.expired`;
- administrator UI under **System → Session policy**;
- safe `401` behavior for API/HTMX requests and a login explanation for browser
  requests.

The absolute lifetime cannot be shorter than the inactivity limit.

### SIEM integration

The administration console now supports independently configured destinations:

- HTTPS JSON webhook with optional encrypted bearer token;
- RFC 5424-style syslog over TLS with octet-counted framing;
- TLS certificate verification enabled by default;
- asynchronous Celery delivery with exponential retry;
- redaction of metadata keys related to passwords, credentials, secrets, keys,
  cookies, authorization, tickets and tokens;
- delivery ledger with status, time, payload hash, and bounded error detail.

The exported event retains the audit sequence, chain hashes, and signature so the
collector can correlate it with the local immutable chain.

### Redis and network boundaries

Redis now requires a randomly generated 256-bit hexadecimal password. The same
secret is used by Channels, cache, Celery, and health checks without being displayed.
An unauthenticated `PING` returns `NOAUTH Authentication required`. Redis and
PostgreSQL remain on an internal network with no published host ports.

The web/gateway path uses a new internal-only network. The SSH gateway has a separate
target-egress network and no database network. Caddy alone also joins a dedicated
public-ingress network to publish port `18081`; this is required by Docker on the
Synology host. The prior network was not deleted.

These Compose boundaries do not replace a production VLAN and firewall destination
allowlist. TLS is not currently enabled for Redis in this single-host topology;
multi-host deployments must add Redis TLS or a managed private Redis service.

## Verification evidence

- 135 tests passed.
- Coverage: 90.09% (required threshold: 90%).
- Ruff: all checks passed.
- Django migration drift: no changes detected.
- Applied migrations: `accounts.0003_platformsecuritypolicy` and
  `audit.0003_siem`.
- PostgreSQL, Redis, web, SSH gateway, RDP broker, Guacamole and guacd are healthy.
- `http://192.168.0.25:18081/api/health/ready/`: HTTP 200.
- Redis unauthenticated access: rejected.
- SSH password broker test: connected, command confirmed, closed and audited.

## Public URL blocker

Routing through `https://pam.cbovy.be` reaches PAM-olive and returns HTTP 200 when
certificate validation is explicitly bypassed. Normal validation correctly fails:
BunkerWeb currently presents its fallback self-signed certificate for
`www.example.org`, not a certificate for `pam.cbovy.be`. This is outside the
PAM-olive container and must be corrected in BunkerWeb/ACME before the public URL can
be considered secure or production-ready.

## Explicit security limitations before V1

- Superseded by Sprint 1: vault encryption and audit signing now use the isolated
  keyring documented in `2026-07-16-sprint-1-keyring.md`. This remains below
  HSM/KMS-grade protection against full host compromise.
- A pluggable external KMS/HSM backend and external signing service are not yet
  implemented.
- Redis has authentication and network isolation but not internal TLS on this
  single-host deployment.
- Target-side ephemeral-account provisioning is not implemented; JIT applies to
  leases, tickets, approvals and sessions, not creation/deletion of target accounts.
- Docker egress isolation must be complemented by NAS/upstream firewall and VLAN
  rules.
- `guacd` patching, image-digest pinning, vulnerability scanning and an update SLA
  remain release gates.
- Browser tabs that create a ticket but never authorize leave a `created` session
  record until its authorization lifetime elapses. A scheduled cleanup task should
  close these records explicitly.
- The public TLS certificate is invalid as described above.

PAM-olive therefore remains pre-V1. The current build is suitable for continued
controlled demonstration and development, not yet for an Internet-facing production
declaration.
