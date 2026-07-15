#!/usr/bin/env sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <new-backup-directory>" >&2
  exit 2
fi

destination="$1"
if [ -e "$destination" ]; then
  echo "Refusing to overwrite existing path: $destination" >&2
  exit 1
fi
if [ ! -f .env ] || [ ! -f compose.yml ]; then
  echo "Run this command from the PAM-olive directory containing .env and compose.yml." >&2
  exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required." >&2
  exit 1
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  echo "sha256sum is required to seal the backup." >&2
  exit 1
fi

umask 077
mkdir -p "$destination/recordings"

docker compose exec -T postgres sh -c \
  'exec pg_dump --format=custom --no-owner --no-acl --username="$POSTGRES_USER" --dbname="$POSTGRES_DB"' \
  > "$destination/database.dump"

docker compose cp gateway:/recordings/. "$destination/recordings"
docker compose exec -T web python manage.py showmigrations --plan \
  > "$destination/migration-plan.txt"

cp compose.yml "$destination/compose.yml"
cp deploy/Caddyfile "$destination/Caddyfile"

(
  cd "$destination"
  find . -type f ! -name SHA256SUMS -print0 \
    | sort -z \
    | xargs -0 sha256sum > SHA256SUMS
)

echo "Backup created and sealed at $destination"
echo "The .env file was intentionally excluded. Escrow encryption keys separately."
