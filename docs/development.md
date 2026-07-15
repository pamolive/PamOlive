# Développement

Sous Linux, exécuter `sh scripts/bootstrap.sh`. Sous Windows, exécuter
`powershell -ExecutionPolicy Bypass -File scripts/bootstrap.ps1`. Ces scripts
refusent d’écraser un `.env` existant, génèrent les secrets puis démarrent la
stack. Les tests s’exécutent avec `pytest`.

Sur une machine équipée de Docker, la suite isolée s’exécute avec
`docker compose --profile test run --rm test`. Elle utilise SQLite et ne touche
pas à la base de développement. Le service web écoute uniquement sur
`127.0.0.1:8000`; utiliser un tunnel SSH pour y accéder à distance.

Pour un test sur un réseau local de confiance, définir `CBPAM_HTTP_BIND=0.0.0.0`
et `CBPAM_HTTP_PORT=18080`, puis ajouter l’adresse du serveur à
`DJANGO_ALLOWED_HOSTS` et `DJANGO_CSRF_TRUSTED_ORIGINS`. Ce mode HTTP ne doit
pas être publié directement sur Internet.
