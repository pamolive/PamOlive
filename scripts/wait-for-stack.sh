#!/usr/bin/env sh
set -eu

timeout="${PAMOLIVE_STACK_WAIT_TIMEOUT:-240}"
interval=2
elapsed=0
one_shot_services="redis-tls-init recordings-init"
long_running_services="keyring postgres redis web gateway rdp-broker guacd guacamole rdp-proxy proxy worker beat"

container_state() {
  service="$1"
  container_id="$(docker compose ps --all -q "$service")"
  if [ -z "$container_id" ]; then
    printf '%s\n' "missing"
    return
  fi
  docker inspect --format '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}|{{.State.ExitCode}}' "$container_id"
}

while [ "$elapsed" -lt "$timeout" ]; do
  ready=true
  summary=""

  for service in $one_shot_services; do
    state="$(container_state "$service")"
    summary="${summary}${service}=${state} "
    case "$state" in
      exited\|\|0) ;;
      exited\|*\|*)
        echo "ERROR: one-shot service failed: ${service} (${state})" >&2
        docker compose logs --no-color --tail=100 "$service" >&2 || true
        exit 1
        ;;
      *) ready=false ;;
    esac
  done

  for service in $long_running_services; do
    state="$(container_state "$service")"
    summary="${summary}${service}=${state} "
    case "$state" in
      running\|healthy\|*|running\|\|*) ;;
      exited\|*\|*)
        echo "ERROR: long-running service exited: ${service} (${state})" >&2
        docker compose logs --no-color --tail=100 "$service" >&2 || true
        exit 1
        ;;
      *) ready=false ;;
    esac
  done

  if [ "$ready" = true ]; then
    echo "PAM-olive stack is ready after ${elapsed}s."
    exit 0
  fi

  sleep "$interval"
  elapsed=$((elapsed + interval))
done

echo "ERROR: PAM-olive stack was not ready after ${timeout}s." >&2
echo "$summary" >&2
docker compose ps >&2 || true
exit 1
