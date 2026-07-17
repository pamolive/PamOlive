#!/usr/bin/env sh
set -eu

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
  echo "Usage: $0 <backup-directory> <new-rehearsal-database> [expected-username]" >&2
  exit 2
fi

backup="$1"
database="$2"
expected_user="${3:-}"

if [ "${PAMOLIVE_RESTORE_REHEARSAL_ACK:-}" != "ephemeral-ci-only" ]; then
  echo "Refusing restore: set PAMOLIVE_RESTORE_REHEARSAL_ACK=ephemeral-ci-only." >&2
  exit 1
fi
if ! printf '%s' "$database" | grep -Eq '^pamolive_restore_rehearsal_[a-z0-9_]+$'; then
  echo "The destination must be a new database named pamolive_restore_rehearsal_*" >&2
  exit 1
fi
if [ ! -f "$backup/database.dump" ] || [ ! -f "$backup/SHA256SUMS" ]; then
  echo "The backup directory is incomplete." >&2
  exit 1
fi
if [ ! -f .env ] || [ ! -f compose.yml ]; then
  echo "Run this command from the PAM-olive project directory." >&2
  exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required." >&2
  exit 1
fi

sh scripts/verify-backup.sh "$backup"

exists="$(
  docker compose exec -T postgres sh -c \
    'exec psql --username="$POSTGRES_USER" --dbname=postgres --tuples-only --no-align --command "$1"' \
    sh "SELECT 1 FROM pg_database WHERE datname = '${database}';"
)"
if [ "$exists" = "1" ]; then
  echo "Refusing to overwrite existing database: $database" >&2
  exit 1
fi

docker compose exec -T postgres sh -c \
  'exec createdb --username="$POSTGRES_USER" "$1"' sh "$database"

docker compose exec -T postgres sh -c \
  'exec pg_restore --exit-on-error --no-owner --no-acl --username="$POSTGRES_USER" --dbname="$1"' \
  sh "$database" < "$backup/database.dump"

postgres_user="$(docker compose exec -T postgres printenv POSTGRES_USER | tr -d '\r')"
postgres_password="$(docker compose exec -T postgres printenv POSTGRES_PASSWORD | tr -d '\r')"
restore_url="postgresql://${postgres_user}:${postgres_password}@postgres:5432/${database}"

docker compose run --rm -T -e DATABASE_URL="$restore_url" web \
  python manage.py migrate --noinput

if [ -n "$expected_user" ]; then
  docker compose run --rm -T -e DATABASE_URL="$restore_url" web \
    python manage.py verify_restore --expect-user "$expected_user"
else
  docker compose run --rm -T -e DATABASE_URL="$restore_url" web \
    python manage.py verify_restore
fi

echo "Restore rehearsal succeeded in the separate database: $database"
echo "The source database was not modified or removed."
