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
sh scripts/bootstrap.sh
```

On Windows:

```powershell
git clone https://github.com/pamolive/PamOlive.git
Set-Location PamOlive
powershell -ExecutionPolicy Bypass -File scripts/bootstrap.ps1
```

The bootstrap refuses to overwrite an existing `.env`. It generates independent
values for the Django signing key, PostgreSQL and Redis passwords, vault encryption,
audit signing, gateway authentication, session recordings, operations API, and
Guacamole JSON authentication. Keep `.env` outside backups and store a protected
offline copy of the keys.

Create the first technical administrator:

```sh
docker compose exec web python manage.py createsuperuser
```

Open <http://localhost:8000>, sign in, and complete the mandatory TOTP enrollment.
The recovery codes are displayed once; store them offline before continuing.

## Public reverse proxy

The default listener is `127.0.0.1:8000` and is intentionally not public. Before
using a public name, set at least:

```env
DJANGO_SETTINGS_MODULE=config.settings.production
DJANGO_ALLOWED_HOSTS=pam.example.org
DJANGO_CSRF_TRUSTED_ORIGINS=https://pam.example.org
CBPAM_HTTP_BIND=0.0.0.0
CBPAM_HTTP_PORT=8000
```

Terminate valid TLS at the external reverse proxy, preserve `Host`,
`X-Forwarded-For`, and `X-Forwarded-Proto`, and enable WebSocket forwarding for
`/ws/sessions/`. Do not publish PostgreSQL, Redis, the SSH gateway, Guacamole, or
`guacd` ports. The dedicated RDP origin must also use HTTPS and match
`CBPAM_RDP_PUBLIC_ORIGIN`.

For Internet-facing deployment, add a firewall/VLAN destination allowlist for the
broker egress, external append-only SIEM delivery, tested backups, and a documented
patch process. Docker network names alone are not a firewall boundary.

## Verification

```sh
docker compose ps
curl --fail http://127.0.0.1:8000/api/health/ready/
docker compose --profile test run --rm --build test
```

The release gate is 100% passing tests and at least 90% coverage. Also verify an SSH
password session and, if enabled, an RDP session against non-production test targets.

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

## Current security boundary

The Community Compose profile creates an isolated keyring service. Its master key is
generated on first start inside the dedicated `keyring_data` volume. No vault
encryption key or audit-signing key is generated in `.env`, and no other service
mounts that volume.

If `10.254.0.0/24` overlaps a Docker, LAN, or VPN route, set
`CBPAM_INTERNAL_SUBNET` to an unused private `/24` before first start. This service
boundary does not claim HSM equivalence: a compromised authorised Django process can
still request keyring operations. External KMS/HSM, target-side ephemeral-account
provisioning, and multi-site high availability remain explicit post-V1 work.
