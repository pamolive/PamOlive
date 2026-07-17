#!/usr/bin/env sh
set -eu

if [ -e .env ]; then
  echo "PAM-olive is already initialized: .env exists and was left unchanged."
  echo "To regenerate intentionally, stop the stack, back up .env, move it aside, then rerun ./install.sh."
  exit 0
fi
if ! grep -Fxq ".env" .gitignore; then
  echo "ERROR: .env must be ignored by Git before secrets can be generated." >&2
  exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
  echo "ERROR: OpenSSL is required to generate installation secrets." >&2
  exit 1
fi

umask 077
temporary=".env.tmp.$$"
trap 'rm -f "$temporary"' EXIT HUP INT TERM

django_key="$(openssl rand -hex 64)"
postgres_password="$(openssl rand -hex 32)"
redis_password="$(openssl rand -hex 32)"
keyring_token="$(openssl rand -hex 48)"
gateway_key="$(openssl rand -hex 48)"
recording_key="$(openssl rand -hex 48)"
operations_token="$(openssl rand -hex 48)"
guacamole_json_key="$(openssl rand -hex 16)"

cat > "$temporary" <<EOF
DJANGO_SETTINGS_MODULE=config.settings.base
DJANGO_SECRET_KEY=${django_key}
DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1
DJANGO_CSRF_TRUSTED_ORIGINS=http://localhost:8000

POSTGRES_DB=pamolive
POSTGRES_USER=pamolive
POSTGRES_PASSWORD=${postgres_password}
DATABASE_URL=postgresql://pamolive:${postgres_password}@postgres:5432/pamolive

REDIS_PASSWORD=${redis_password}
REDIS_URL=redis://:${redis_password}@redis:6379/0

PAMOLIVE_KEYRING_URL=http://keyring:8000
PAMOLIVE_KEYRING_TIMEOUT_SECONDS=3
PAMOLIVE_KEYRING_TOKEN=${keyring_token}
PAMOLIVE_GATEWAY_SHARED_KEY=${gateway_key}
PAMOLIVE_RECORDING_KEY=${recording_key}
PAMOLIVE_OPERATIONS_TOKEN=${operations_token}
PAMOLIVE_GUACAMOLE_JSON_KEY=${guacamole_json_key}

PAMOLIVE_HTTP_BIND=127.0.0.1
PAMOLIVE_HTTP_PORT=8000
PAMOLIVE_RDP_ENABLED=true
PAMOLIVE_RDP_PUBLIC_ORIGIN=http://localhost:8081
PAMOLIVE_RDP_HTTP_BIND=127.0.0.1
PAMOLIVE_RDP_HTTP_PORT=8081
PAMOLIVE_FRONTEND_SUBNET=10.253.0.0/24
PAMOLIVE_INTERNAL_SUBNET=10.254.0.0/24
PAMOLIVE_TARGETS_SUBNET=10.255.0.0/24
PAMOLIVE_ROTATION_BACKENDS={}
EOF

mv "$temporary" .env
trap - EXIT HUP INT TERM
chmod 600 .env
echo "PAM-olive secrets generated in .env (mode 600)."
echo "Start the stack with: docker compose up --build -d"
