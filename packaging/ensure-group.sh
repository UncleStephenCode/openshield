#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

[ "$(id -u)" -eq 0 ] || { printf '%s\n' 'openshield group creation requires uid 0' >&2; exit 1; }

group_exists() {
    if command -v getent >/dev/null 2>&1 && getent group openshield >/dev/null 2>&1; then
        return 0
    fi
    while IFS=: read -r group_name _; do
        [ "$group_name" = openshield ] && return 0
    done < /etc/group
    return 1
}

group_exists && exit 0

if command -v groupadd >/dev/null 2>&1; then
    groupadd --system openshield
elif command -v addgroup >/dev/null 2>&1; then
    addgroup -S openshield 2>/dev/null || addgroup --system openshield
else
    printf '%s\n' 'neither groupadd nor addgroup is available' >&2
    exit 1
fi

group_exists || { printf '%s\n' 'openshield group was not created' >&2; exit 1; }
