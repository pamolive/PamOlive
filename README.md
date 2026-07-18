# PAM-olive

PAM-olive is an open-source privileged access management (PAM) platform built
with Django, PostgreSQL, Redis, Celery, an isolated SSH gateway, and Apache
Guacamole for HTML5 RDP brokering.

PAM-olive is authored and stewarded by **MOPACY**, through
**[mopacy.eu](https://mopacy.eu)** and **[mopacy.be](https://mopacy.be)**. Project
governance and release authority are documented in [GOVERNANCE.md](GOVERNANCE.md).

> **Status: Community V1.** The twelve mandatory V1 criteria are backed by
> repeatable repository evidence. Internet-facing deployment still requires the
> documented production configuration, external network controls, backups, and
> an environment-specific security review.

## Current capabilities

- `superadmin`, `administrator`, `auditor`, and `user` system roles, extended
  by granular capabilities;
- membership in multiple groups and temporary assignments;
- configurable LDAP/Active Directory sources and OIDC federation;
- target groups, domains, local accounts, and approved SSH host keys;
- policies by group, target, credential, protocol, network, schedule, and quota;
- quorum approvals, requester/approver separation, and ticket references;
- an encrypted personal vault and target credential vault backed by an isolated keyring;
- globally enforced local TOTP MFA, downloadable one-time recovery codes, and safe
  first-login enrollment;
- mandatory audited business justification for target-secret access and sessions;
- short, single-use secret leases and session tickets;
- SSH sessions using ephemeral tickets, an isolated gateway, encrypted recordings,
  xterm.js ANSI/VT rendering, and explicit audited command paste;
- governed RDP launch using a single-use ticket, dedicated origin, and Apache Guacamole 1.6.0;
- a signed, chained, verifiable, and exportable audit log;
- separate consoles for users, product administration, and Django super administration.

## Architecture

```text
Browser -- Caddy -- Django + TOTP -- policy / approval engine
                         |       \
                         |        +-- signed audit -- Celery -- external SIEM
                         +-- PostgreSQL (ciphertext only)
                         +-- isolated keyring (dedicated master-key volume)
                         +-- authenticated Redis

One-time encrypted envelope -- SSH gateway -- injected password/key -- SSH target
One-time encrypted envelope -- RDP broker -- Guacamole -- guacd -- RDP target
```

The gateway has neither direct PostgreSQL access nor an application `.env` file.
It receives a short-lived encrypted envelope after signed internal validation.
The browser never receives the target secret. RDP brokering uses another origin
to isolate the Guacamole interface's local token.

## Local startup with Docker Compose

Prerequisites: Docker with Compose, GNU Make and OpenSSL on Linux, or PowerShell
on Windows.

```sh
make init
docker compose up --build -d
```

On Windows:

```powershell
powershell -ExecutionPolicy Bypass -File install.ps1
docker compose up --build -d
```

The installer never overwrites an existing `.env`. On first run it generates
independent secrets for Django, PostgreSQL, Redis, keyring authentication, gateway
authentication, recordings, operations, and Guacamole JSON authentication. The web
entrypoint refuses to start with blank, short, or known example values. Vault
encryption and audit-signing keys remain derived inside the isolated keyring and are
never written to `.env`.

Create the first super administrator:

```sh
docker compose exec web python manage.py createsuperuser
```

Open <http://localhost:8000>. The local RDP origin is
<http://localhost:8081>. The interfaces are:

- `/`: user workspace;
- `/admin/`: capability-based product administration;
- `/django-admin/`: technical administration restricted to super administrators.

At first sign-in, every interactive user is redirected to `/mfa/setup/`. The user
must scan the TOTP QR code and confirm a valid code before any application,
target-secret, SSH, or RDP endpoint is available. Ten one-time recovery codes are
then shown exactly once and can be downloaded as a local text file; store them
offline. An administrator can disable the
global requirement under **Administration → System → Session policy**, but the
installation default is enabled and the interface displays a security warning
while it is disabled.

The default listener is restricted to `127.0.0.1`. Local HTTP mode is not an
Internet entry point. Public exposure requires TLS, explicit host names and
origins, a tested backup, and production configuration.

## Network isolation

Compose creates exactly three networks:

- `frontend`: reverse proxies, Django, and the brokers they proxy directly;
- `internal`: Django, PostgreSQL, Redis, Celery, keyring, and broker control traffic;
- `targets`: SSH/RDP gateways and Guacamole components that need target egress.

PostgreSQL, Redis, Celery, and the keyring are never attached to `targets`.
Conversely, a container attached only to `targets` cannot resolve or connect to
PostgreSQL or Redis. CI verifies this boundary with:

```sh
sh scripts/check-isolation.sh
```

Docker segmentation limits accidental reachability on one host; it does not protect
targets from an attacker already present on the same physical LAN. Production
deployments should place gateway egress in a dedicated VLAN. A generic firewall
policy is: allow only the gateway VLAN source addresses to declared target addresses
on declared ports (for example TCP/22 and TCP/3389), deny the gateway VLAN access to
management and database subnets, then deny all other gateway-VLAN egress. Adapt
addresses and ports to the approved target inventory.

## Pinned images and CVE response

All runtime base images and critical Compose images are referenced by immutable
SHA256 digest. GitHub CI builds or pulls every image returned by
`docker compose config --images` and runs Trivy 0.70.0 with a blocking
`CRITICAL` severity gate.

When a CVE affects a pinned image:

1. check the vendor advisory, Docker Hub/registry manifest, and the image project's
   official release notes;
2. select a fixed release and record its multi-platform manifest digest;
3. update the digest in `compose.yml` or the relevant Dockerfile without using
   `latest`;
4. run the full tests, Compose healthchecks, `scripts/check-isolation.sh`, and the
   Trivy gate in a staging project;
5. create and verify a backup, deploy only after review, and record the old/new
   digests in the changelog.

Never suppress a critical result silently. A temporary exception requires a written
risk assessment, compensating controls, an owner, and an expiry date.

## Tests and quality

```sh
docker compose --profile test run --rm --build test
```

The test command fails if a check fails or if `pamolive` coverage drops below 90%.
GitHub CI also checks linting, migrations, PostgreSQL, Docker images, and CodeQL.

For a local Python environment:

```sh
python -m pip install -e ".[dev]"
ruff check .
python manage.py makemigrations --check --dry-run
pytest --cov=pamolive --cov-fail-under=90
```

## Authorization model

A user may belong to multiple groups. A policy links user groups to target groups
and restricts actions, credentials, protocols, source networks, schedules, and
concurrent sessions. Authorization is granted only when every applicable constraint
is satisfied. Auditors may inspect configuration and traces without obtaining secrets.

See [docs/permissions.md](docs/permissions.md) for capability details and
[docs/v1-scope.md](docs/v1-scope.md) for release criteria. Architecture and RDP
brokering limitations are documented in [docs/rdp.md](docs/rdp.md).

The complete fresh-install, reverse-proxy, upgrade, and rollback preparation
workflow is documented in [docs/installation.md](docs/installation.md).

## Documentation and contribution

```sh
mkdocs serve
```

Documentation lives in [`docs/`](docs/). Before contributing, read
[CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and the
[Code of Conduct](CODE_OF_CONDUCT.md).

## License and independence

PAM-olive is licensed under the
[GNU AGPL version 3 or later](LICENSE). It is an independent project. Third-party
names and marks belong to their respective owners. The project implements publicly
documented PAM practices without incorporating proprietary source code.
