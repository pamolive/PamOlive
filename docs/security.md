# Security

- Secrets must never appear in logs, URLs, Celery tasks, or WebSocket messages.
- Secrets are encrypted at rest with a key supplied outside the database.
- Approvals enforce separation of duties.
- Revealing a target secret or launching SSH/RDP requires a local MFA proof no
  older than five minutes by default. `PAMOLIVE_MFA_STEP_UP_MAX_AGE_SECONDS`
  configures this window; OIDC authentication alone does not satisfy the local
  step-up requirement.
- Audit events are immutable and hash-chained.
- Production requires HTTPS, secure cookies, HSTS, and explicit origins.
- The SSH/RDP gateway is a separate, least-privileged component.
- Internal gateway calls use short-lived HMAC signatures bound to the method, path,
  body, and a single-use request ID. Replaying a captured signed request is rejected.
  Gateway termination nonces are stored in shared Redis in the Compose deployment.
  Legacy version 1 acceptance is disabled by default and may only be enabled
  temporarily during the documented rolling upgrade.
- The RDP interface uses a dedicated origin so its `GUAC_AUTH_TOKEN` cannot be
  read from the main PAM-olive origin.
- Guacamole JSON is signed with HMAC-SHA256, encrypted with AES-128-CBC, valid for
  15 seconds, and contains a single-use connection. It is never placed in a URL.
- RDP denies copy, paste, virtual drive, printing, and microphone by default. Copy
  and paste are enabled separately at policy level.
- PAM-olive offers no equivalent to `ignore-cert`: an RDP certificate must be
  validated by a trusted authority or configured FreeRDP fingerprints.
- Identity sources and SIEM outputs always verify their TLS certificates; there is no
  insecure certificate-bypass mode.
  Outbound destinations are resolved and special-use/private addresses are rejected
  unless their CIDR is explicitly listed in `PAMOLIVE_OUTBOUND_ALLOWED_CIDRS`.
- The keyring runs as a non-root UID and requires mutually authenticated TLS in
  addition to its bearer token. Community deployments may retain the local master key
  in the dedicated volume; higher-assurance deployments can select the supported
  Vault Transit backend so the root key never enters the PAM-olive container.

## Sensitive actions and fresh MFA

PAM-olive separates normal navigation from privileged impact. Opening the console,
listing targets, or reading non-secret metadata is not enough to trigger another
MFA challenge. A fresh MFA challenge is required only before actions that reveal,
grant, approve, terminate, export, or change privileged access.

The fresh-MFA window is configured in the platform security policy and can be set
to 2, 5, 10, or 15 minutes. The default is 5 minutes.

Fresh MFA is required before:

- revealing a personal-vault secret or TOTP code;
- revealing a target credential or target TOTP code;
- starting an SSH or RDP privileged session;
- approving or rejecting an access request;
- exporting the signed audit log;
- terminating a privileged session;
- modifying platform configuration, including identity sources, roles, groups,
  targets, policies, SIEM, MFA/session policy, and other administration forms.

Fresh MFA is not required while an SSH or RDP session is already open. The session
ticket is issued only after the fresh-MFA check, then the brokered session can run
without additional MFA prompts until it ends or reaches its policy limits.

This foundation is not a security certification. A threat model, external review,
and penetration tests are required before production use.
