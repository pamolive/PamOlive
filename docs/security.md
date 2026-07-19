# Security

- Secrets must never appear in logs, URLs, Celery tasks, or WebSocket messages.
- Secrets are encrypted at rest with a key supplied outside the database.
- Approvals enforce separation of duties.
- Audit events are immutable and hash-chained.
- Production requires HTTPS, secure cookies, HSTS, and explicit origins.
- The SSH/RDP gateway is a separate, least-privileged component.
- Internal gateway calls use short-lived HMAC signatures bound to the method, path,
  body, and a single-use request ID. Replaying a captured signed request is rejected.
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

This foundation is not a security certification. A threat model, external review,
and penetration tests are required before production use.
