# Operations

## Redis

Docker Compose requires both `REDIS_PASSWORD` and a matching authenticated
`REDIS_URL`. Redis is private and exposes no host port. Never pass the password on a
command line or commit it to Git. Multi-host deployments must also enable TLS.

## SIEM forwarding

Configure destinations under **Administration → System → SIEM**. HTTPS collectors
must use an `https://` URL; syslog uses TLS (normally port 6514). Certificate
verification is enabled by default and should only be disabled during controlled
diagnostics. Bearer tokens are stored with the vault keyring and are never rendered
back into the form.

Each forwarding attempt is recorded locally. Failed deliveries are retried by Celery
and can be inspected without exposing event secrets.

This page describes the controls available during the pre-V1 phase. Restore
operations remain prohibited on the reference NAS until an isolated rehearsal
and rollback plan have been approved.

## Health

| Endpoint | Authentication | Purpose |
| --- | --- | --- |
| `/api/health/live/` | none | live web process, without dependencies |
| `/api/health/ready/` | none | PostgreSQL and cache are reachable |
| `/api/health/integrity/` | operations Bearer token | complete audit-chain validation |
| `/api/metrics/` | operations Bearer token | aggregated Prometheus metrics |

The token is `CBPAM_OPERATIONS_TOKEN`. It must differ from every vault, audit,
gateway, and recording key. It is never passed to the SSH gateway.

Recommended minimum alerts:

- readiness failing for more than two minutes;
- any audit-integrity failure;
- increasing `pam_olive_rotation_jobs_failed` or
  `pam_olive_rotation_jobs_action_required`;
- a session remaining in `terminating` state;
- PostgreSQL or recording storage above 80% capacity.

## Target credential rotation

Rotation behavior is selected through a `SecretRotationPolicy`. The policy defines
the interval, generation strategy, generated password length, target groups, and an
internal connector key. Connector implementations are loaded through
`CBPAM_ROTATION_BACKENDS`, for example:

```env
CBPAM_ROTATION_BACKENDS={"linux":"my_plugin.backends.LinuxPasswordBackend"}
```

The connector receives the credential, old secret, and generated candidate secret.
PAM-olive encrypts the candidate before the remote call, promotes it only after
success, increments its version, and audits the result. Unexpected exceptions are
redacted. Without a configured connector, the job moves to “action required” and
no network is contacted.

The periodic Celery task looks for due rotations every five minutes. Only one active
job is permitted per credential.

## Migration to the isolated keyring

Back up PostgreSQL and `.env`, then start the keyring while keeping the legacy
`CBPAM_VAULT_*` and `CBPAM_AUDIT_SIGNING_KEY` variables temporarily. Run the
read-only inventory:

```sh
docker compose exec web python manage.py migrate_secrets_to_keyring
```

After reviewing the counts, apply the transactional migration:

```sh
docker compose exec web python manage.py migrate_secrets_to_keyring \
  --apply --confirm MIGRATE-TO-KEYRING
```

The command handles target credentials, TOTP seeds, personal vaults, connectors,
identity sources, MFA, rotation candidates, SIEM tokens, and existing audit
signatures. Verify the audit chain and functional secret access before removing the
legacy variables from `.env`. The mixed-state migration is retryable as long as the
legacy keys remain available.

## Backup

From the project directory on a Docker host:

```sh
sh scripts/backup.sh /path/outside/project/pam-olive-YYYYMMDD-HHMM
```

The script:

1. refuses an existing destination path;
2. produces a custom-format PostgreSQL dump without ownership;
3. copies already encrypted recordings read-only;
4. retains the migration plan and Compose/proxy configuration;
5. seals every file in `SHA256SUMS`.

The `.env` file is deliberately excluded. Keys must be exported and stored separately
in an offline vault with dual control. A backup without keys is intact but cannot be
decrypted; storing a backup with its keys removes security separation.

Non-destructive verification:

```sh
sh scripts/verify-backup.sh /path/to/backup
```

This command recalculates hashes and asks `pg_restore --list` to read the archive
structure. It connects to no destination database and restores nothing.

## Restore

A restore must first be rehearsed on a new isolated stack with empty exercise volumes.
It must demonstrate migrations, login, decryption of a fake secret, audit validation,
and reading a fake recording. No destructive restore script is provided until this
scenario has passed in Docker CI. This remains an explicit V1-candidate blocker.
