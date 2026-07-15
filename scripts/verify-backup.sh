#!/usr/bin/env sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <backup-directory>" >&2
  exit 2
fi

backup="$1"
if [ ! -d "$backup" ] || [ ! -f "$backup/SHA256SUMS" ] || [ ! -f "$backup/database.dump" ]; then
  echo "The directory is not a complete PAM-olive backup." >&2
  exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required." >&2
  exit 1
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  echo "sha256sum is required." >&2
  exit 1
fi

(
  cd "$backup"
  sha256sum --check SHA256SUMS
)

docker compose exec -T postgres pg_restore --list < "$backup/database.dump" >/dev/null

echo "Backup hashes and PostgreSQL archive structure are valid."
echo "No database or recording was modified."
