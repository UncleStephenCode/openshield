#!/usr/bin/env bash
set -euo pipefail

: "${VERSION:?VERSION is required}"
: "${ARCH:?ARCH is required}"
: "${FAMILY:?FAMILY is required}"

version_pattern='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
[[ "$VERSION" =~ $version_pattern ]] || {
  echo 'VERSION must be a semantic version without a v prefix' >&2
  exit 2
}
[[ "$ARCH" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]*$ ]] || {
  echo 'ARCH is not a safe nFPM architecture value' >&2
  exit 2
}

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
BIN_DIR="$REPO_ROOT/release-bin"
OUT_DIR="$REPO_ROOT/dist"
ROOT_DIR="$REPO_ROOT/.package-root"
CONFIG="$REPO_ROOT/packaging/ci/nfpm.yaml"
RPM_FIREWALL_DEPENDENCY='(nftables or iptables)'

[[ -x "$BIN_DIR/openshield-daemon" ]] || { echo "missing $BIN_DIR/openshield-daemon" >&2; exit 2; }
[[ -x "$BIN_DIR/openshield-tui" ]] || { echo "missing $BIN_DIR/openshield-tui" >&2; exit 2; }

rm -rf "$ROOT_DIR" "$OUT_DIR"
mkdir -m 0755 "$ROOT_DIR" "$OUT_DIR"

case "$FAMILY" in
  alpine)
    INIT=openrc
    PACKAGER=apk
    PACKAGE_RELEASE=0
    CONFIG="$REPO_ROOT/packaging/ci/nfpm-apk.yaml"
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

export PACKAGE_RELEASE RPM_FIREWALL_DEPENDENCY VERSION ARCH

(cd "$REPO_ROOT" && nfpm package --config "$CONFIG" --packager "$PACKAGER" --target "$OUT_DIR/")

count="$(find "$OUT_DIR" -maxdepth 1 -type f | wc -l)"
[[ "$count" -eq 1 ]] || { echo "expected exactly one package, got $count" >&2; exit 1; }

find "$OUT_DIR" -maxdepth 1 -type f -printf '%f\n'
rm -rf "$ROOT_DIR"
