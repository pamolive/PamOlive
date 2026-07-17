#!/bin/sh
set -eu

recording_dir="${PAMOLIVE_RECORDING_DIR:-/recordings}"
runtime_uid="${PAMOLIVE_RECORDING_UID:-10001}"
runtime_gid="${PAMOLIVE_RECORDING_GID:-10001}"

case "${runtime_uid}:${runtime_gid}" in
    *[!0-9:]*|:*|*:) echo "Invalid PAM-olive recording UID/GID" >&2; exit 64 ;;
esac

mkdir -p "$recording_dir"
chown -R "${runtime_uid}:${runtime_gid}" "$recording_dir"
find "$recording_dir" -type d -exec chmod 0700 {} \;
find "$recording_dir" -type f -name '*.pamrec' -exec chmod 0600 {} \;

echo "PAM-olive recording storage is ready for UID ${runtime_uid}:${runtime_gid}."
