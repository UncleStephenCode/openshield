#!/bin/sh
set -eu

log=/run/openshield-init-stub.log

if [ "$#" -eq 1 ] && [ "$1" = --install-fail-closed ]; then
    printf '%s\n' preflight >> "$log"
    exit 0
fi

[ "$#" -eq 0 ] || exit 64
printf '%s\n' run >> "$log"

child=
terminate() {
    trap - TERM INT
    if [ -n "$child" ]; then
        kill "$child" 2>/dev/null || true
        wait "$child" 2>/dev/null || true
    fi
    exit 0
}
trap terminate TERM INT

while :; do
    sleep 30 &
    child=$!
    wait "$child" || true
    child=
done
