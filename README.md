# PAM-olive

PAM-olive is an open-source privileged access management (PAM) platform built
with Django, PostgreSQL, Redis, Celery, an isolated SSH gateway, and Apache
Guacamole for HTML5 RDP brokering.

> **Status: pre-V1.** The functional and security foundation is under active
> development. This release is not yet declared ready for Internet-facing
> production use. The V1 release decision will be explicitly documented,
> tested, and announced.

## Current capabilities

- `superadmin`, `administrator`, `auditor`, and `user` system roles, extended
  by granular capabilities;
- membership in multiple groups and temporary assignments;
- configurable LDAP/Active Directory sources and OIDC federation;
- target groups, domains, local accounts, and approved SSH host keys;
- policies by group, target, credential, protocol, network, schedule, and quota;
- quorum approvals, requester/approver separation, and ticket references;
- an encrypted personal vault and target credential vault backed by an isolated keyring;
- globally enforced local TOTP MFA, recovery codes, and safe first-login enrollment;
- mandatory audited business justification for target-secret access and sessions;
- short, single-use secret leases and session tickets;
- SSH sessions using ephemeral tickets, an isolated gateway, and encrypted recordings;
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

Prerequisites: Docker with Compose, OpenSSL on Linux, or PowerShell on Windows.

```sh
sh scripts/bootstrap.sh
```

On Windows:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/bootstrap.ps1
```

The scripts refuse to overwrite an existing `.env`, generate distinct secrets
for Django, PostgreSQL, Redis, gateway, recordings, operations, and Guacamole JSON
authentication, then build the stack. Vault encryption and audit-signing keys are
derived inside the isolated keyring and never written to `.env`.

Create the first super administrator:

```sh
docker compose exec web python manage.py createsuperuser
```

Open <http://localhost:8000>. The local RDP origin is
<http://localhost:8081>. The interfaces are:

- `/`: user workspace;
- `/admin/`: capability-based product administration;
- `/django-admin/`: technical administration restricted to super administrators.

The default listener is restricted to `127.0.0.1`. Local HTTP mode is not an
Internet entry point. Public exposure requires TLS, explicit host names and
origins, a tested backup, and production configuration.

## Tests and quality

```sh
docker compose --profile test run --rm --build test
```

The test command fails if a check fails or if `cbpam` coverage drops below 90%.
GitHub CI also checks linting, migrations, PostgreSQL, Docker images, and CodeQL.

For a local Python environment:

```sh
python -m pip install -e ".[dev]"
ruff check .
python manage.py makemigrations --check --dry-run
pytest --cov=cbpam --cov-fail-under=90
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
