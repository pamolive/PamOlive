# Installation and upgrade

This guide targets a fresh single-host Docker Compose installation. It does not
declare that a default single-host deployment meets every high-assurance PAM threat
model; review the architecture limitations before exposing it to the Internet.

## Prerequisites

- Docker Engine with the Compose plugin;
- Git;
- OpenSSL on Linux, or PowerShell on Windows;
- at least 4 GB of available RAM for the complete SSH and RDP stack;
- a DNS name and TLS reverse proxy for public deployment.

## Fresh installation

```sh
git clone https://github.com/pamolive/PamOlive.git
cd PamOlive
make init
docker compose up --build -d
```

On Windows:

```powershell
git clone https://github.com/pamolive/PamOlive.git
Set-Location PamOlive
powershell -ExecutionPolicy Bypass -File scripts/bootstrap.ps1
```

The installer refuses to overwrite an existing `.env`. It generates independent
values for the Django signing key, PostgreSQL and Redis passwords, keyring API
authentication, gateway authentication, session recordings, operations API, and
Guacamole JSON authentication. The vault encryption and audit-signing keys are
generated inside the dedicated keyring volume and never written to `.env`. Keep a
protected offline copy of `.env`; never commit it.

The first Compose start also generates an internal Redis CA and server certificate in
dedicated volumes. Redis listens only with verified TLS. Django, Channels, Celery, and
workers receive the CA certificate read-only; no application container receives the CA
private key or Redis server key.

Create the first technical administrator:

```sh
docker compose exec web python manage.py createsuperuser
```

Open <http://localhost:8000>, sign in, and complete the mandatory TOTP enrollment.
PAM-olive redirects an unenrolled interactive account to `/mfa/setup/` before it
can open any application, secret-reveal, SSH, or RDP endpoint. Confirm a code from
the QR code, then store the ten recovery codes offline: they are displayed once
and each code can be used only once. The enrollment screen can download the displayed
codes as a local text file; PAM-olive does not retain that cleartext file.

## Public reverse proxy

The default listener is `127.0.0.1:8000` and is intentionally not public. Before
using a public name, set at least:

```env
DJANGO_SETTINGS_MODULE=config.settings.production
DJANGO_ALLOWED_HOSTS=pam.example.org
DJANGO_CSRF_TRUSTED_ORIGINS=https://pam.example.org
PAMOLIVE_HTTP_BIND=0.0.0.0
PAMOLIVE_HTTP_PORT=8000
```

Terminate valid TLS at the external reverse proxy, preserve `Host`,
`X-Forwarded-For`, and `X-Forwarded-Proto`, and enable WebSocket forwarding for
`/ws/sessions/`. Do not publish PostgreSQL, Redis, the SSH gateway, Guacamole, or
`guacd` ports. The dedicated RDP origin must also use HTTPS and match
`PAMOLIVE_RDP_PUBLIC_ORIGIN`.

For Internet-facing deployment, add a firewall/VLAN destination allowlist for the
broker egress, external append-only SIEM delivery, tested backups, and a documented
patch process. Docker network names alone are not a firewall boundary.

## Docker and physical network isolation

The Compose stack uses three networks. `frontend` carries reverse-proxy traffic,
`internal` carries application/database/cache/keyring control traffic, and `targets`
carries only broker egress toward SSH/RDP targets. PostgreSQL, Redis, Celery, and
the keyring are attached only to `internal`; Django is attached to `frontend` and
`internal`; SSH/RDP brokers and Guacamole components use `internal` and `targets`,
plus `frontend` only where a reverse proxy must reach them directly.

Verify the runtime boundary after every networking change:

```sh
sh scripts/check-isolation.sh
```

This launches a disposable container attached only to `targets` and fails if it
can reach PostgreSQL or Redis. It does not validate the physical LAN. In production,
put broker egress in a dedicated VLAN and apply a destination allowlist such as:

```text
ALLOW  gateway-vlan  -> approved-ssh-targets  TCP/22
ALLOW  gateway-vlan  -> approved-rdp-targets  TCP/3389
DENY   gateway-vlan  -> management-and-database-subnets  ANY
DENY   gateway-vlan  -> ANY  ANY
```

Use the actual target inventory and declared policy ports; do not copy these example
ports when a target uses a different approved port.

## Verification

```sh
docker compose ps
curl --fail http://127.0.0.1:8000/api/health/ready/
docker compose --profile test run --rm --build test
```

The release gate is 100% passing tests and at least 90% coverage. Also verify an SSH
password session and, if enabled, an RDP session against non-production test targets.
The SSH terminal uses a local xterm.js emulator for ANSI/VT output and exposes an
explicit command-paste box. Pasted input is part of the encrypted session recording
and must be reviewed before it is sent. Operators can select terminal output and copy
it with the visible action, `Ctrl+Shift+C`, or `Ctrl+C` while a selection exists;
without a selection, `Ctrl+C` is still sent to the remote process. A normal SSH close
attempts to close the session tab and keeps a manual close action when the browser
blocks it. The Guacamole extension makes the same best-effort attempt when the RDP
authentication token is removed during logout.

## Upgrade preparation

Never replace an installation without a verified backup and an explicit rollback
point. From the existing checkout:

```sh
sh scripts/backup.sh /path/outside/project/pam-olive-before-upgrade
sh scripts/verify-backup.sh /path/to/pam-olive-before-upgrade
docker compose exec web python manage.py showmigrations --plan
```

Review the release notes and new environment variables before pulling a release.
Run the new image and migrations first in an isolated clone with copied test data.
The project does not provide a destructive automatic rollback. Database rollback is
a restore operation and must be rehearsed separately.

For a v0.2 deployment, retain the legacy vault and audit-signing variables until the
schema migration and keyring migration both succeed. After starting the new keyring and
database in the isolated rehearsal, run:

```sh
docker compose exec web python manage.py migrate --noinput
docker compose exec web python manage.py migrate_secrets_to_keyring
docker compose exec web python manage.py migrate_secrets_to_keyring \
  --apply --confirm MIGRATE-TO-KEYRING
docker compose exec web python manage.py verify_restore
```

Only remove legacy key variables after `verify_restore` validates the complete audit
chain and decrypts every protected field. `tests/test_upgrade_v02.py` reproduces the
historical v0.2 migration graph, seeds encrypted witness data, upgrades to the current
schema, migrates it to the isolated keyring, and proves that identities, inventory,
metadata, and plaintext meaning are preserved.

## Current security boundary

The Community Compose profile creates an isolated keyring service. Its master key is
generated on first start inside the dedicated `keyring_data` volume. No vault
encryption key or audit-signing key is generated in `.env`, and no other service
mounts that volume.

If any of `10.253.0.0/24`, `10.254.0.0/24`, or `10.255.0.0/24` overlaps a Docker,
LAN, or VPN route, set `PAMOLIVE_FRONTEND_SUBNET`, `PAMOLIVE_INTERNAL_SUBNET`, and
`PAMOLIVE_TARGETS_SUBNET` to unused private `/24` networks before first start. This service
boundary does not claim HSM equivalence: a compromised authorised Django process can
still request keyring operations. External KMS/HSM, target-side ephemeral-account
provisioning, and multi-site high availability remain explicit post-V1 work.
