#!/bin/sh
set -eu

usage() {
    printf '%s\n' \
        'usage: scripts/test-distro-matrix.sh validate' \
        '       scripts/test-distro-matrix.sh manifests' \
        '       scripts/test-distro-matrix.sh smoke ABSOLUTE_BINARY_DIRECTORY' \
        '       scripts/test-distro-matrix.sh smoke-clean ABSOLUTE_BINARY_DIRECTORY (deprecated alias)'
}

mode=${1:-}
case "$mode" in
    validate|manifests) [ "$#" -eq 1 ] || { usage >&2; exit 2; } ;;
    smoke|smoke-clean) [ "$#" -eq 2 ] || { usage >&2; exit 2; } ;;
    *) usage >&2; exit 2 ;;
esac

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repository_directory=$(CDPATH= cd -- "$script_directory/.." && pwd -P)
matrix="$repository_directory/tests/compat/distros.tsv"
tab=$(printf '\t')
expected_header=$(printf '# id\timage\tfamily\tlibc\tinit\tstatus')
actual_header=$(sed -n '1p' "$matrix")
[ "$actual_header" = "$expected_header" ] || {
    printf '%s\n' 'invalid distribution matrix header' >&2
    exit 1
}
count=0
seen='|'
failed=0

if [ "$mode" = smoke ] || [ "$mode" = smoke-clean ]; then
    binary_directory=$2
    case "$binary_directory" in /*) ;; *) printf '%s\n' 'binary directory must be absolute' >&2; exit 2 ;; esac
    [ -f "$binary_directory/openshield-daemon" ] || { printf '%s\n' 'missing openshield-daemon' >&2; exit 2; }
    [ -f "$binary_directory/openshield-tui" ] || { printf '%s\n' 'missing openshield-tui' >&2; exit 2; }
fi

require_local_docker() {
    command -v docker >/dev/null 2>&1 || {
        printf '%s\n' 'docker is not installed' >&2
        exit 1
    }
    docker_host=$(docker context inspect --format '{{(index .Endpoints "docker").Host}}' 2>/dev/null) || {
        printf '%s\n' 'cannot inspect the active Docker context' >&2
        exit 1
    }
    case "$docker_host" in
        unix:///*) ;;
        *) printf 'refusing non-local Docker endpoint: %s\n' "$docker_host" >&2; exit 1 ;;
    esac
}

case "$mode" in
    manifests|smoke|smoke-clean) require_local_docker ;;
esac
if [ "$mode" = smoke-clean ]; then
    printf '%s\n' \
        'WARN smoke-clean is deprecated; running smoke without deleting images' >&2
fi

while IFS="$tab" read -r identifier image family libc_name init_system lifecycle extra; do
    case "$identifier" in ''|'#'*) continue ;; esac
    [ -z "${extra:-}" ] || { printf 'extra matrix field for %s\n' "$identifier" >&2; exit 1; }
    case "$identifier" in *[!a-z0-9._-]*) printf 'unsafe id: %s\n' "$identifier" >&2; exit 1 ;; esac
    case "$image" in ''|*[!A-Za-z0-9._/:@-]*) printf 'unsafe image: %s\n' "$image" >&2; exit 1 ;; esac
    case "$family:$libc_name:$init_system:$lifecycle" in *[!A-Za-z0-9._:-]*) printf 'unsafe metadata for %s\n' "$identifier" >&2; exit 1 ;; esac
    case "$seen" in *"|$identifier|"*) printf 'duplicate id: %s\n' "$identifier" >&2; exit 1 ;; esac
    seen="${seen}${identifier}|"
    case "$lifecycle" in
        maintained|rolling|legacy|archive|legacy-image) ;;
        *) printf 'invalid lifecycle for %s: %s\n' "$identifier" "$lifecycle" >&2; exit 1 ;;
    esac
    case "$family:$libc_name:$init_system" in
        debian:glibc:systemd | debian:glibc:sysvinit | \
        alpine:musl:openrc | \
        redhat:glibc:systemd | suse:glibc:systemd | \
        arch:glibc:systemd | arch:glibc:openrc | arch:glibc:runit | \
        gentoo:glibc:openrc | gentoo:musl:openrc | \
        void:glibc:runit)
            ;;
        *)
            printf 'invalid family/libc/init mapping for %s: %s/%s/%s\n' \
                "$identifier" "$family" "$libc_name" "$init_system" >&2
            exit 1
            ;;
    esac
    case "$identifier:$image:$family" in
        ubuntu-*:ubuntu:*:debian | debian-*:debian:*:debian | \
        alpine-*:alpine:*:alpine | fedora-*:fedora:*:redhat | \
        rocky-*:rockylinux/rockylinux:*:redhat | alma-*:almalinux:*:redhat | \
        centos-stream-*:quay.io/centos/centos:*:redhat | \
        oracle-*:oraclelinux:*:redhat | \
        opensuse-*:opensuse/*:suse | amazon-linux-*:amazonlinux:*:redhat | \
        arch:archlinux:*:arch | gentoo:gentoo/stage3:*:gentoo | \
        void:voidlinux/voidlinux:*:void | devuan-*:devuan/devuan:*:debian | \
        artix-*:artixlinux/artixlinux:*:arch)
            ;;
        *)
            printf 'invalid id/image/family mapping for %s: %s/%s\n' \
                "$identifier" "$image" "$family" >&2
            exit 1
            ;;
    esac
    case "$identifier:$lifecycle" in
        void:legacy-image | *:maintained | *:rolling | *:legacy | *:archive) ;;
        *) printf 'invalid lifecycle mapping for %s: %s\n' "$identifier" "$lifecycle" >&2; exit 1 ;;
    esac
    count=$((count + 1))

    case "$mode" in
        validate) ;;
        manifests)
            if docker buildx imagetools inspect "$image" >/dev/null 2>&1; then
                printf 'PASS manifest %-24s %s\n' "$identifier" "$image"
            else
                printf 'FAIL manifest %-24s %s\n' "$identifier" "$image" >&2
                failed=$((failed + 1))
            fi
            ;;
        smoke|smoke-clean)
            if docker run --rm --network none --read-only --cap-drop ALL \
                --security-opt no-new-privileges --security-opt label=disable \
                --mount "type=bind,src=$binary_directory,dst=/opt/openshield,readonly" \
                --entrypoint /opt/openshield/openshield-daemon \
                "$image" --version >/dev/null \
                && docker run --rm --network none --read-only --cap-drop ALL \
                    --security-opt no-new-privileges --security-opt label=disable \
                    --mount "type=bind,src=$binary_directory,dst=/opt/openshield,readonly" \
                    --entrypoint /opt/openshield/openshield-tui \
                    "$image" --version >/dev/null; then
                printf 'PASS smoke    %-24s %s\n' "$identifier" "$image"
            else
                printf 'FAIL smoke    %-24s %s\n' "$identifier" "$image" >&2
                failed=$((failed + 1))
            fi
            ;;
    esac
done < "$matrix"

[ "$count" -eq 60 ] || { printf 'expected 60 matrix rows, found %s\n' "$count" >&2; exit 1; }
printf 'matrix rows: %s; failures: %s\n' "$count" "$failed"
[ "$failed" -eq 0 ]
