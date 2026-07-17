#!/usr/bin/env sh
set -eu

web_container="$(docker compose ps -q web)"
if [ -z "$web_container" ]; then
  echo "ERROR: the PAM-olive web container is not running." >&2
  exit 2
fi

project="$(
  docker inspect \
    --format '{{ index .Config.Labels "com.docker.compose.project" }}' \
    "$web_container"
)"
targets_network="$(
  docker network ls \
    --filter "label=com.docker.compose.project=$project" \
    --filter "label=com.docker.compose.network=targets" \
    --format '{{.Name}}'
)"

if [ -z "$targets_network" ]; then
  echo "ERROR: the Compose targets network was not found for project $project." >&2
  exit 2
fi
if [ "$(printf '%s\n' "$targets_network" | wc -l | tr -d ' ')" -ne 1 ]; then
  echo "ERROR: more than one targets network was found for project $project." >&2
  exit 2
fi

echo "Checking isolation from target-only network: $targets_network"
docker run --rm --network "$targets_network" alpine:3.22 sh -eu -c '
  failure=0
  for endpoint in "postgres 5432" "redis 6379"; do
    set -- $endpoint
    if nc -z -w 2 "$1" "$2" >/dev/null 2>&1; then
      echo "ISOLATION FAILURE: targets can reach $1:$2" >&2
      failure=1
    else
      echo "isolated: $1:$2 is unreachable from targets"
    fi
  done
  exit "$failure"
'
