#!/usr/bin/env sh
set -eu

sh ./install.sh
if [ "${PAMOLIVE_BOOTSTRAP_PREPARE_ONLY:-}" = "true" ]; then
  echo "PAM-olive environment prepared without starting Docker."
  exit 0
fi
docker compose up --build -d
echo "PAM-olive is starting at http://localhost:8000"
echo "PAM-olive RDP is starting at http://localhost:8081"
