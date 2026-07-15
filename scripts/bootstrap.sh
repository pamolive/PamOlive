#!/usr/bin/env sh
set -eu

if [ -e .env ]; then
  echo ".env already exists; refusing to overwrite it."
  exit 1
fi

django_key="$(openssl rand -base64 48 | tr -d '\n')"
vault_key="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '\n')"
postgres_password="$(openssl rand -hex 32)"
audit_key="$(openssl rand -hex 32)"
gateway_key="$(openssl rand -hex 32)"
recording_key="$(openssl rand -hex 32)"
operations_token="$(openssl rand -hex 32)"
guacamole_json_key="$(openssl rand -hex 16)"

sed \
  -e "s|change-me-with-at-least-50-random-characters|${django_key}|" \
  -e "s|generate-a-long-random-database-password|${postgres_password}|" \
  -e "s|CBPAM_VAULT_KEY=|CBPAM_VAULT_KEY=${vault_key}|" \
  -e "s|CBPAM_AUDIT_SIGNING_KEY=generate-a-distinct-random-value-of-at-least-32-characters|CBPAM_AUDIT_SIGNING_KEY=${audit_key}|" \
  -e "s|CBPAM_GATEWAY_SHARED_KEY=generate-a-distinct-random-value-of-at-least-32-characters|CBPAM_GATEWAY_SHARED_KEY=${gateway_key}|" \
  -e "s|CBPAM_RECORDING_KEY=generate-a-distinct-random-value-of-at-least-32-characters|CBPAM_RECORDING_KEY=${recording_key}|" \
  -e "s|CBPAM_OPERATIONS_TOKEN=generate-a-distinct-random-value-of-at-least-32-characters|CBPAM_OPERATIONS_TOKEN=${operations_token}|" \
  -e "s|CBPAM_GUACAMOLE_JSON_KEY=generate-a-distinct-32-character-hex-value|CBPAM_GUACAMOLE_JSON_KEY=${guacamole_json_key}|" \
  .env.example > .env

chmod 600 .env
if [ "${CBPAM_BOOTSTRAP_PREPARE_ONLY:-}" = "true" ]; then
  echo "PAM-olive environment prepared without starting Docker."
  exit 0
fi
docker compose up --build -d
echo "PAM-olive is starting at http://localhost:8000"
echo "PAM-olive RDP is starting at http://localhost:8081"
