# RDP Brokering with Apache Guacamole

## Status

Governed RDP launch satisfies the Community V1 boundary: access policy, approval,
MFA, single-use authorization, credential injection, and launch auditing are enforced.
The advanced recording and disconnect limitations below are intentionally visible and
remain post-V1 work; Community V1 does not claim full graphical-session forensics.

## Launch flow

1. PAM-olive validates groups, policy, approval, MFA, source, and quota.
2. It creates a hashed, user-bound, single-use session ticket.
3. The browser submits the ticket by `POST` to the dedicated RDP origin. The ticket
   never appears in a URL.
4. The RDP broker calls PAM-olive's internal API with a timestamped HMAC signature.
5. The API consumes the ticket and a single-use secret lease, then returns a Fernet
   envelope to the broker.
6. The broker produces the official `guacamole-auth-json` format: HMAC-SHA256,
   AES-128-CBC, zero IV, Base64, 15-second expiration, and a `singleUse` connection.
7. The broker exchanges this block with Guacamole server-side and sends only the
   Guacamole token to the browser in a `no-store` page with a nonce-based CSP.
8. Guacamole opens the connection through `guacd`. The target secret never passes
   through the browser.

## Docker isolation

| Network | Members | Purpose |
| --- | --- | --- |
| `frontend` | RDP proxy, RDP broker, Guacamole | launch form, HTML5, and WebSocket traffic |
| `internal` | RDP broker, Guacamole, guacd | authorization and Guacamole control traffic |
| `targets` | RDP broker, Guacamole, guacd | outbound connections to approved RDP targets |

`guacd` is a passive daemon with no authentication of its own. It therefore has no
published port. The `targets` network does not contain PostgreSQL, Redis, Celery, or
the keyring, and CI checks this boundary with `scripts/check-isolation.sh`.

## Configuration

Main variables:

```dotenv
PAMOLIVE_RDP_ENABLED=true
PAMOLIVE_RDP_PUBLIC_ORIGIN=https://rdp.pam-olive.example
PAMOLIVE_RDP_HTTP_BIND=127.0.0.1
PAMOLIVE_RDP_HTTP_PORT=8081
PAMOLIVE_GUACAMOLE_JSON_KEY=<32-random-hex-characters>
```

In production, `PAMOLIVE_RDP_PUBLIC_ORIGIN` must be a pathless HTTPS origin distinct
from the main origin. The bootstrap script generates a separate 128-bit JSON key.

For each RDP target:

- select `nla`, `nla-ext`, or `tls`; PAM-olive does not offer legacy `rdp` mode or
  `any` negotiation;
- keep `fr-be-azerty` or select the server's actual keyboard layout;
- enter FreeRDP-format certificate fingerprints when the server chain is not trusted
  by the container;
- never bypass certificate validation. PAM-olive does not generate `ignore-cert`.

Policies deny copying from and pasting into the session by default. These permissions
may be enabled independently. Virtual drives, printing, and microphone remain disabled
in this release.

## Docker verification

Run only in an authorized test environment:

```sh
docker compose config
docker compose build web gateway rdp-broker
docker compose up -d
docker compose ps
docker compose logs --no-log-prefix rdp-broker guacamole guacd rdp-proxy
```

The manual test must use a laboratory Windows target and a known certificate
fingerprint. It must confirm rejection of an invalid fingerprint, single-use ticket
behavior, clipboard restrictions, expiration, and the absence of secrets in logs.

## Documented post-V1 limitations

- administrative RDP termination has not yet been proven to close the active
  Guacamole tunnel;
- Guacamole graphical recording is plain text by default. PAM-olive therefore does
  not enable it until encrypted sealing and verifiable removal of the temporary trace
  are implemented;
- exact session-end tracking must be reconciled with actual Guacamole state rather
  than only PAM authorization expiry.

## Official references

- [Guacamole 1.6.0 JSON authentication](https://guacamole.apache.org/doc/gug/json-auth.html)
- [RDP configuration](https://guacamole.apache.org/doc/gug/configuring-guacamole.html#rdp)
- [Guacamole Docker deployment](https://guacamole.apache.org/doc/gug/guacamole-docker.html)
- [Apache Guacamole releases](https://guacamole.apache.org/releases/)
