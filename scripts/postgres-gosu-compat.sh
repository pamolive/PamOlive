#!/bin/sh
set -eu

if [ "$#" -lt 2 ]; then
    echo "usage: gosu user[:group] command [arguments...]" >&2
    exit 64
fi

identity=$1
shift
user=${identity%%:*}
group=${identity#*:}

if [ "$group" != "$identity" ] && [ "$group" != "$user" ]; then
    echo "PAM-olive postgres wrapper does not support a distinct group" >&2
    exit 64
fi

exec su "$user" -s /bin/sh -c 'exec "$@"' pamolive-gosu "$@"
