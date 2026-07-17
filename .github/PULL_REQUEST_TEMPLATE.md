## Objective

Describe the problem and the proposed solution.

## Security and authorization

- Which access control, secret, audit, or session flow is affected?
- Which denial cases were tested?

## Migrations and compatibility

Describe migrations, backward compatibility, and required operations.

## Validation

- [ ] `ruff check .`
- [ ] `python manage.py makemigrations --check --dry-run`
- [ ] `python manage.py check`
- [ ] `pytest --cov=pamolive --cov-fail-under=90`
- [ ] `mkdocs build --strict`
- [ ] documentation and changelog updated
- [ ] no real data, keys, internal addresses, or sensitive screenshots included
