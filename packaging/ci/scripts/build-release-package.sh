#!/usr/bin/env bash
set -euo pipefail

: "${VERSION:?VERSION is required}"
: "${ARCH:?ARCH is required}"
: "${FAMILY:?FAMILY is required}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
BIN_DIR="$REPO_ROOT/release-bin"
OUT_DIR="$REPO_ROOT/dist"
ROOT_DIR="$REPO_ROOT/.package-root"
CONFIG="$REPO_ROOT/packaging/ci/nfpm.yaml"
RPM_FIREWALL_DEPENDENCY='(nftables or iptables)'
RPM_C_RUNTIME_DEPENDENCY=
RPM_UNWIND_RUNTIME_DEPENDENCY=

[[ -x "$BIN_DIR/openshield-daemon" ]] || { echo "missing $BIN_DIR/openshield-daemon" >&2; exit 2; }
[[ -x "$BIN_DIR/openshield-tui" ]] || { echo "missing $BIN_DIR/openshield-tui" >&2; exit 2; }

rm -rf "$ROOT_DIR" "$OUT_DIR"
mkdir -m 0755 "$ROOT_DIR" "$OUT_DIR"

case "$FAMILY" in
  alpine)
    INIT=openrc
    PACKAGER=apk
    PACKAGE_RELEASE=0
    ;;
  deb)
    INIT=systemd
    PACKAGER=deb
    PACKAGE_RELEASE=1
    ;;
  fedora)
    INIT=systemd
    PACKAGER=rpm
    PACKAGE_RELEASE=1.fc44
    ;;
  el9)
    INIT=systemd
    PACKAGER=rpm
    PACKAGE_RELEASE=1.el9
    ;;
  el10)
    INIT=systemd
    PACKAGER=rpm
    PACKAGE_RELEASE=1.el10
    ;;
  opensuse)
    INIT=systemd
    PACKAGER=rpm
    PACKAGE_RELEASE=1.opensuse16
    ;;
  tumbleweed)
    INIT=systemd
    PACKAGER=rpm
    PACKAGE_RELEASE=1.tumbleweed
    # These GNU binaries are dynamically linked. Unlike rpmbuild, nFPM does
    # not discover their ELF dependencies, so name the official Tumbleweed
    # runtime packages explicitly.
    RPM_C_RUNTIME_DEPENDENCY=glibc
    RPM_UNWIND_RUNTIME_DEPENDENCY=libgcc_s1
    ;;
  arch)
    INIT=systemd
    PACKAGER=archlinux
    PACKAGE_RELEASE=1
    ;;
  *)
    echo "unsupported FAMILY=$FAMILY" >&2
    exit 2
    ;;
esac

"$REPO_ROOT/packaging/stage-install.sh" "$ROOT_DIR" "$INIT" "$BIN_DIR"

export PACKAGE_RELEASE RPM_C_RUNTIME_DEPENDENCY RPM_FIREWALL_DEPENDENCY
export RPM_UNWIND_RUNTIME_DEPENDENCY VERSION ARCH

(cd "$REPO_ROOT" && nfpm package --config "$CONFIG" --packager "$PACKAGER" --target "$OUT_DIR/")

count="$(find "$OUT_DIR" -maxdepth 1 -type f | wc -l)"
[[ "$count" -eq 1 ]] || { echo "expected exactly one package, got $count" >&2; exit 1; }

find "$OUT_DIR" -maxdepth 1 -type f -printf '%f\n'
rm -rf "$ROOT_DIR"
