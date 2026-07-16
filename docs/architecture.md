# Architecture and trust boundaries

PAM-olive separates the user interface, policy engine, secret storage, protocol
brokers, databases, and external audit destination. Views validate input, service
objects implement authorization, and models enforce persistent invariants.

```text
Browser -- TLS reverse proxy -- Django login + TOTP -- policy / approval engine
                                   |                    |
                                   |                    +-- signed audit chain -- Celery -- external SIEM
                                   |
                     PostgreSQL <--+--> Redis (authenticated, private network)
                         |
                encrypted target credential vault
                         |
             one-time encrypted credential envelope
                  /                              \
       SSH gateway (no DB access)         RDP launch broker
                  |                              |
          injects password/key            Guacamole JSON auth
                  |                              |
             SSH target                     guacd -- RDP target
```

## Target credential vault

Target passwords, private SSH keys, and associated TOTP seeds are stored in the
`vault.Credential` model as opaque ciphertext plus an explicit encryption-key ID.
Encryption and audit signing are performed by the isolated `keyring` service. It
creates `/data/master.key` with mode `0600` and derives separate encryption and
signing keys with HKDF-SHA256. Its dedicated volume is never mounted by another
service and it has no published host port.

PostgreSQL does not receive the plaintext. Decryption happens only after a policy
decision and a short, single-use lease or session ticket. The browser receives the
secret only when a policy explicitly grants the separate reveal capability; normal
SSH and RDP sessions inject it inside the broker and never expose it to the user.

The current Docker edition loads a versioned keyring from environment secrets. This
is encryption at rest, but it is **not equivalent to an HSM**: a complete compromise
of the application host could obtain both ciphertext and runtime keys. Production V1
therefore requires a pluggable external KMS/HSM envelope-encryption backend and a
documented recovery ceremony. Key rotation is already versioned and target password
rotation is policy-driven, but remote account rotation depends on a configured,
tested target connector.

## Authentication and MFA

Local TOTP and one-time recovery codes are enforced by the Django authentication
form for accounts that have a confirmed device. A server-side platform policy is
enabled by default and redirects every interactive user without a confirmed device
to a cache-disabled first-login enrollment page before any application, product
administration, or technical administration route can be opened. Service accounts
do not use browser login and are excluded. The reverse proxy does not implement a
second independent MFA layer. Access policies can additionally require a confirmed
MFA device before a privileged request or session starts.

Browser sessions have two server-side limits: an inactivity timeout and an absolute
lifetime. Both are configurable under **Administration → System → Session policy**.

## Mandatory privileged-action justification

Every target-secret reveal and every SSH or RDP session requires a business reason,
including when the requester is a super administrator or when approval is automatic.
The requirement is validated again in the service layer, persisted on the secret
lease or privileged session, and copied into the signed audit metadata. A browser
cannot bypass it by omitting the form field. Personal-vault access is intentionally
exempt because those records belong only to the authenticated user.

## Credential injection and JIT access

The SSH gateway and RDP broker authenticate to a signed internal API. The API
returns a one-time encrypted credential envelope only after RBAC, policy, approval,
MFA, time-window, source-network, and concurrency checks. Tickets and secret leases
expire automatically. This provides just-in-time session authorization and zero
standing disclosure of the credential to the end user.

Target accounts themselves are currently pre-existing accounts. Creating an
ephemeral account on the target and deleting it afterward is a separate future
connector capability; the current release must not be described as full target-side
zero-standing-privilege provisioning.

## Network isolation

No gateway, `guacd`, PostgreSQL, or Redis port is published. The browser can only
reach the reverse proxies. Internal Docker networks separate browser traffic,
authorization, Redis/PostgreSQL, RDP JSON authentication, Guacamole, and target
egress. The SSH gateway has no database network and uses a dedicated egress network.

Docker network names are not a firewall guarantee. A production deployment must put
broker egress in a dedicated VLAN/subnet and enforce destination/port allowlists on
the NAS or upstream firewall. PAM-olive cannot prove those external firewall rules
from inside its own containers.

## Audit integrity and SIEM

Events form an immutable hash chain and are HMAC-signed by the keyring. Metadata keys that may carry
credentials, tokens, cookies, or tickets are redacted before SIEM export. HTTPS
webhooks and RFC 5424-style syslog over TLS are delivered asynchronously, with a
local delivery ledger and retries.

The default signing key is still supplied to Django at runtime. That detects database
tampering but does not survive a full application-host compromise. High-assurance
deployments must move signing to an external HSM/signing service and send events to
an append-only or WORM SIEM destination whose credentials cannot delete prior data.

## Redis and protocol components

Redis is reachable only on the private backend network and requires a password in
Docker Compose. It carries channel messages, cache entries, Celery messages, and
short-lived coordination data; permanent target credentials are not stored there.
TLS is not enabled inside the single-host Compose topology. Multi-host deployments
must enable Redis TLS (or use a managed private Redis service) in addition to ACLs.

Apache Guacamole and `guacd` are pinned to a specific release and isolated from the
database and public host ports. Image digest pinning, vulnerability scanning, and a
defined patch SLA remain release requirements because pinning a version does not by
itself address future CVEs.

## Vendor access workflow

External suppliers use dedicated user groups and roles. Policies bind those groups
to explicit target groups, time frames, source networks, credential scopes, MFA,
ticket references, approval quorum, duration, and session limits. Requesters cannot
approve their own requests. Membership can expire through temporary assignments;
automatic vendor identity lifecycle provisioning remains connector-specific.
