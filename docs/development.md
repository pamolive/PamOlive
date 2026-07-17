# Development

On Linux, run `sh scripts/bootstrap.sh`. On Windows, run
`powershell -ExecutionPolicy Bypass -File scripts/bootstrap.ps1`. These scripts
refuse to overwrite an existing `.env`, generate secrets, and start the stack.
Tests run with `pytest`.

On a machine with Docker, run the isolated suite with
`docker compose --profile test run --rm test`. It uses SQLite and does not touch
the development database. The web service listens only on `127.0.0.1:8000`;
use an SSH tunnel for remote access.

For testing on a trusted local network, set `PAMOLIVE_HTTP_BIND=0.0.0.0` and
`PAMOLIVE_HTTP_PORT=18080`, then add the server address to `DJANGO_ALLOWED_HOSTS`
and `DJANGO_CSRF_TRUSTED_ORIGINS`. This HTTP mode must not be exposed directly
to the Internet.
