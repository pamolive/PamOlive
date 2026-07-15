# Contribuer à PAM-olive

Merci de contribuer à un PAM open source maintenable. Toute modification doit préserver
la séparation des privilèges, la traçabilité et la compatibilité des migrations.

## Avant de commencer

- utilisez une issue pour une évolution importante ou une modification du modèle de
  sécurité ;
- signalez les vulnérabilités exclusivement selon [SECURITY.md](SECURITY.md) ;
- n'utilisez jamais de secret, d'adresse interne, de clé privée ou de donnée de
  production dans un test, une capture ou une issue ;
- acceptez le [code de conduite](CODE_OF_CONDUCT.md).

## Environnement de développement

Avec Python 3.12 ou ultérieur :

```sh
python -m venv .venv
python -m pip install -e ".[dev]"
python manage.py migrate
```

Avec Docker :

```sh
sh scripts/bootstrap.sh
docker compose --profile test run --rm --build test
```

Le bootstrap refuse volontairement d'écraser un `.env` existant.

## Règles d'architecture

- les modèles portent les invariants persistants ;
- les services portent les règles métier et les contrôles d'autorisation ;
- les vues restent minces et ne manipulent pas directement les secrets ;
- chaque évolution de modèle possède une migration additive et relisible ;
- les permissions sont testées en cas autorisé **et** refusé ;
- les secrets ne passent ni dans les URLs, ni dans les tâches, ni dans les logs ;
- l'audit d'une action sensible fait partie de la même évolution fonctionnelle ;
- les composants de passerelle restent indépendants de Django et de la base.

## Vérifications obligatoires

```sh
ruff check .
python manage.py makemigrations --check --dry-run
python manage.py check
pytest --cov=cbpam --cov-fail-under=90
mkdocs build --strict
```

Une modification de modèle, permission, workflow d'approbation, secret ou session doit
ajouter des tests de régression. La couverture globale ne peut pas descendre sous 90 %.

## Pull requests

Une pull request doit être limitée à un objectif cohérent et contenir :

- le problème et la solution ;
- l'impact de sécurité et de migration ;
- les tests exécutés ;
- la documentation et l'entrée de changelog associées ;
- des captures sans données sensibles pour une modification d'interface.

Utilisez de préférence des messages de commit de forme `type(scope): description`, par
exemple `feat(policies): enforce source network constraints` ou
`fix(gateway): reject a reused session ticket`.

En contribuant, vous acceptez que votre contribution soit distribuée sous la licence
AGPL-3.0-or-later du projet.
