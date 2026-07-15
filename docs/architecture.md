# Architecture

Each domain is an independent Django application. Views orchestrate inputs, services
implement business rules, and models enforce persistent invariants.

The browser never receives target credentials. A dedicated session gateway retrieves
the secret at the last moment, establishes the connection, and streams only the
terminal or remote display.

## Access flow

1. The user requests access under a policy.
2. The engine checks RBAC, MFA, duration, and time windows.
3. A separate approver accepts or denies the request.
4. A time-limited session is created.
5. The gateway opens the connection without exposing the secret.
6. Events and the recording reference are audited.

## Protocol isolation

SSH is relayed by a dedicated ASGI broker that verifies the host key and encrypts the
trace before writing it. RDP uses Apache Guacamole on a separate origin. A launch
broker consumes the PAM-olive ticket, retrieves the secret through the signed internal
API, and generates Guacamole JSON authentication that expires after 15 seconds.
`guacd` is never published on a host port.

The Docker networks `rdp_launch`, `rdp_auth`, `rdp_frontend`, and `rdp_guacd` separate
the public form, JSON exchange, HTML5 interface, and passive RDP daemon. Only `guacd`
has outbound access to targets. See [RDP](rdp.md) for details.
