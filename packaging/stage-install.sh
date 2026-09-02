#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

usage() {
    printf 'usage: %s DESTDIR {systemd|openrc|sysvinit|runit|s6|dinit} ABSOLUTE_BINARY_DIRECTORY\n' "$0" >&2
}

[ "$#" -eq 3 ] || { usage; exit 2; }
requested_destination=$1
init_system=$2
binary_directory=$3

case "$requested_destination" in /*) ;; *) printf '%s\n' 'DESTDIR must be absolute' >&2; exit 2 ;; esac
[ "$requested_destination" != / ] || { printf '%s\n' 'refusing to stage directly into /' >&2; exit 2; }
case "$binary_directory" in /*) ;; *) printf '%s\n' 'binary directory must be absolute' >&2; exit 2 ;; esac
case "$init_system" in systemd|openrc|sysvinit|runit|s6|dinit) ;; *) usage; exit 2 ;; esac

[ -d "$requested_destination" ] || { printf '%s\n' 'DESTDIR must be an existing directory' >&2; exit 2; }

# Reject a symlink in any lexical component before resolving the destination.
# The canonical path used for every later write also removes dependence on the
# caller's spelling of the path. Dot-dot components are rejected because they
# make a security review of the lexical ancestry ambiguous.
path_component=/
remaining_path=${requested_destination#/}
while [ -n "$remaining_path" ]; do
    case "$remaining_path" in
        */*) component=${remaining_path%%/*}; remaining_path=${remaining_path#*/} ;;
        *) component=$remaining_path; remaining_path= ;;
    esac
    [ -n "$component" ] || continue
    case "$component" in
        .) continue ;;
        ..) printf '%s\n' 'DESTDIR must not contain .. components' >&2; exit 2 ;;
    esac
    if [ "$path_component" = / ]; then
        path_component=/$component
    else
        path_component=$path_component/$component
    fi
    [ ! -L "$path_component" ] || {
        printf '%s\n' 'DESTDIR ancestry must not contain a symbolic link' >&2
        exit 2
    }
done

canonical_destination=$(CDPATH= cd -- "$requested_destination" && pwd -P)
[ "$canonical_destination" != / ] || { printf '%s\n' 'DESTDIR resolves to /' >&2; exit 2; }
destination=$canonical_destination

# A canonical path still crosses its parent directories. Accept only parents
# owned by the caller or root and reject writable ancestors, except for a
# root-owned sticky directory such as /tmp. In that exception every child on
# the remaining path is still caller/root-owned, so sticky rename protection
# applies. The caller must serialize staging against its own filesystem edits.
caller_uid=$(id -u)
system_uid=$(stat -c %u /)
ancestor=$destination
while :; do
    [ -d "$ancestor" ] && [ ! -L "$ancestor" ] || {
        printf '%s\n' 'DESTDIR ancestry must contain only directories' >&2
        exit 2
    }
    trusted_owner=$(find "$ancestor" -prune \
        \( -user "$caller_uid" -o -user "$system_uid" \) -print)
    [ -n "$trusted_owner" ] || {
        printf '%s\n' 'DESTDIR ancestry contains a directory owned by another user' >&2
        exit 2
    }
    writable_ancestor=$(find "$ancestor" -prune -type d -perm /022 -print)
    if [ -n "$writable_ancestor" ]; then
        safe_sticky_ancestor=$(find "$ancestor" -prune \
            -user "$system_uid" -perm -1000 -print)
        [ -n "$safe_sticky_ancestor" ] || {
            printf '%s\n' 'DESTDIR ancestry contains an unsafe writable directory' >&2
            exit 2
        }
    fi
    [ "$ancestor" != / ] || break
    ancestor=${ancestor%/*}
    [ -n "$ancestor" ] || ancestor=/
done

# Package staging roots must be prepared by the caller.  Refusing all existing
# links, foreign ownership, writable directories, and multiply-linked regular
# files prevents install(1) from following a pre-existing redirect or
# overwriting a file outside a reused staging tree. This validation is not a
# substitute for excluding concurrent mutation by the trusted caller.
foreign_object=$(find "$destination" ! -user "$caller_uid" -print -quit)
[ -z "$foreign_object" ] || {
    printf '%s\n' 'DESTDIR contains an object owned by another user' >&2
    exit 2
}
writable_directory=$(find "$destination" -type d -perm /022 -print -quit)
[ -z "$writable_directory" ] || {
    printf '%s\n' 'DESTDIR contains a group- or world-writable directory' >&2
    exit 2
}
existing_links=$(find "$destination" -type l -print -quit)
if [ -n "$existing_links" ]; then
    printf '%s\n' 'DESTDIR contains a symbolic link' >&2
    exit 2
fi
multiply_linked_file=$(find "$destination" -type f -links +1 -print -quit)
[ -z "$multiply_linked_file" ] || {
    printf '%s\n' 'DESTDIR contains a multiply-linked regular file' >&2
    exit 2
}

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
[ -f "$binary_directory/openshield-daemon" ] || { printf '%s\n' 'missing daemon binary' >&2; exit 2; }
[ -f "$binary_directory/openshield-tui" ] || { printf '%s\n' 'missing TUI binary' >&2; exit 2; }

install -d -m 0755 "$destination/usr/bin"
install -m 0755 "$binary_directory/openshield-daemon" "$destination/usr/bin/openshield-daemon"
install -m 0755 "$binary_directory/openshield-tui" "$destination/usr/bin/openshield-tui"
install -d -m 0755 "$destination/usr/share/openshield"
install -m 0644 "$script_directory/../LICENSE" "$destination/usr/share/openshield/LICENSE"
install -m 0644 "$script_directory/daemon/openshield.sysusers" \
    "$destination/usr/share/openshield/openshield.sysusers"
install -d -m 0755 "$destination/usr/libexec/openshield"
install -m 0755 "$script_directory/ensure-group.sh" \
    "$destination/usr/libexec/openshield/ensure-group"

case "$init_system" in
    systemd)
        install -d -m 0755 \
            "$destination/usr/lib/systemd/system" \
            "$destination/usr/lib/sysusers.d" \
            "$destination/usr/lib/tmpfiles.d"
        install -m 0644 "$script_directory/daemon/openshield-daemon.service" \
            "$destination/usr/lib/systemd/system/openshield-daemon.service"
        install -m 0644 "$script_directory/daemon/openshield.sysusers" \
            "$destination/usr/lib/sysusers.d/openshield.conf"
        install -m 0644 "$script_directory/daemon/openshield.tmpfiles" \
            "$destination/usr/lib/tmpfiles.d/openshield.conf"
        ;;
    openrc)
        install -d -m 0755 "$destination/etc/init.d"
        install -m 0755 "$script_directory/openrc/openshield" "$destination/etc/init.d/openshield"
        ;;
    sysvinit)
        install -d -m 0755 "$destination/etc/init.d"
        install -m 0755 "$script_directory/sysvinit/openshield" "$destination/etc/init.d/openshield"
        ;;
    runit)
        install -d -m 0755 "$destination/etc/sv/openshield"
        install -m 0755 "$script_directory/runit/openshield/run" "$destination/etc/sv/openshield/run"
        install -m 0755 "$script_directory/runit/openshield/finish" "$destination/etc/sv/openshield/finish"
        install -m 0755 "$script_directory/runit/openshield/check" "$destination/etc/sv/openshield/check"
        ;;
    s6)
        install -d -m 0755 \
            "$destination/etc/s6/sv/openshield" \
            "$destination/etc/s6/sv/openshield/dependencies.d"
        install -m 0755 "$script_directory/s6/openshield/run" "$destination/etc/s6/sv/openshield/run"
        install -m 0755 "$script_directory/s6/openshield/finish" "$destination/etc/s6/sv/openshield/finish"
        install -m 0644 "$script_directory/s6/openshield/type" "$destination/etc/s6/sv/openshield/type"
        install -m 0644 "$script_directory/s6/openshield/timeout-kill" \
            "$destination/etc/s6/sv/openshield/timeout-kill"
        install -m 0644 "$script_directory/s6/openshield/timeout-finish" \
            "$destination/etc/s6/sv/openshield/timeout-finish"
        install -m 0644 "$script_directory/s6/openshield/dependencies.d/mount-filesystems" \
            "$destination/etc/s6/sv/openshield/dependencies.d/mount-filesystems"
        ;;
    dinit)
        install -d -m 0755 "$destination/etc/dinit.d"
        install -m 0644 "$script_directory/dinit/openshield" "$destination/etc/dinit.d/openshield"
        install -m 0644 "$script_directory/dinit/openshield-preflight" \
            "$destination/etc/dinit.d/openshield-preflight"
        install -m 0755 "$script_directory/dinit/dinit-preflight" \
            "$destination/usr/libexec/openshield/dinit-preflight"
        ;;
esac

printf 'staged OpenShield for %s in %s\n' "$init_system" "$destination"
