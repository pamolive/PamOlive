## Objectif

Décrire le problème et la solution proposée.

## Sécurité et autorisations

- Quel contrôle d'accès, secret, audit ou flux de session est touché ?
- Quels cas de refus ont été testés ?

## Migrations et compatibilité

Indiquer les migrations, la compatibilité descendante et les opérations requises.

## Validation

- [ ] `ruff check .`
- [ ] `python manage.py makemigrations --check --dry-run`
- [ ] `python manage.py check`
- [ ] `pytest --cov=cbpam --cov-fail-under=90`
- [ ] `mkdocs build --strict`
- [ ] documentation et changelog mis à jour
- [ ] aucune donnée réelle, clé, adresse interne ou capture sensible incluse
