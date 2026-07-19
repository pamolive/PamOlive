# Contributing to PAM-olive

Thank you for helping build a maintainable open-source PAM. Every change must preserve
privilege separation, traceability, and migration compatibility.

## Before you start

- use an issue for a significant feature or security-model change;
- report vulnerabilities only as described in [SECURITY.md](SECURITY.md);
- never use a secret, internal address, private key, or production data in a test,
  screenshot, or issue;
- follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development environment

With Python 3.12 or later:

```sh
python -m venv .venv
python -m pip install --require-hashes -r requirements-dev.lock
python manage.py migrate
```

With Docker:

```sh
sh scripts/bootstrap.sh
docker compose --profile test run --rm --build test
```

The bootstrap script deliberately refuses to overwrite an existing `.env` file.

## Architecture rules

- models enforce persistent invariants;
- services implement business rules and authorization checks;
- views remain thin and never manipulate secrets directly;
- every model change includes an additive, reviewable migration;
- permissions are tested for both allowed **and** denied cases;
- secrets never travel through URLs, tasks, or logs;
- auditing a sensitive action is part of the same functional change;
- gateway components remain independent from Django and the database.

## Required checks

```sh
ruff check .
python manage.py makemigrations --check --dry-run
python manage.py check
pytest --cov=pamolive --cov-fail-under=90
mkdocs build --strict
```

A change to a model, permission, approval workflow, secret, or session must add
regression tests. Overall coverage must remain at or above 90%.

## Pull requests

A pull request should have one coherent objective and include:

- the problem and solution;
- security and migration impact;
- tests performed;
- related documentation and changelog entry;
- screenshots without sensitive data for interface changes.

Prefer commit messages in the form `type(scope): description`, for example
`feat(policies): enforce source network constraints` or
`fix(gateway): reject a reused session ticket`.

By contributing, you agree that your contribution is distributed under the
project's AGPL-3.0-or-later license.
