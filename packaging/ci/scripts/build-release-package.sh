#!/usr/bin/env bash
set -euo pipefail

: "${VERSION:?VERSION is required}"
: "${ARCH:?ARCH is required}"
: "${FAMILY:?FAMILY is required}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
BIN_DIR="$REPO_ROOT/release-bin"
OUT_DIR="$REPO_ROOT/dist"
ROOT_DIR="$REPO_ROOT/.package-root-${FAMILY}-${ARCH}"
CONFIG="$REPO_ROOT/packaging/ci/nfpm.yaml"

[[ -x "$BIN_DIR/openshield-daemon" ]] || { echo "missing $BIN_DIR/openshield-daemon" >&2; exit 2; }
[[ -x "$BIN_DIR/openshield-tui" ]] || { echo "missing $BIN_DIR/openshield-tui" >&2; exit 2; }

rm -rf "$ROOT_DIR" "$OUT_DIR"
mkdir -m 0755 "$ROOT_DIR" "$OUT_DIR"

case "$FAMILY" in
  alpine)
    INIT=openrc
    PACKAGER=apk
    PACKAGE_RELEASE=0
    POSTINSTALL="$REPO_ROOT/packaging/ci/hooks/postinstall-openrc.sh"
    ;;
  deb)
    INIT=systemd
    PACKAGER=deb
    PACKAGE_RELEASE=1
    POSTINSTALL="$REPO_ROOT/packaging/ci/hooks/postinstall-systemd.sh"
    ;;
  fedora)
    INIT=systemd
    PACKAGER=rpm
    PACKAGE_RELEASE=1.fc44
    POSTINSTALL="$REPO_ROOT/packaging/ci/hooks/postinstall-systemd.sh"
    ;;
  el9)
    INIT=systemd
    PACKAGER=rpm
    PACKAGE_RELEASE=1.el9
    POSTINSTALL="$REPO_ROOT/packaging/ci/hooks/postinstall-systemd.sh"
    ;;
  el10)
    INIT=systemd
    PACKAGER=rpm
    PACKAGE_RELEASE=1.el10
    POSTINSTALL="$REPO_ROOT/packaging/ci/hooks/postinstall-systemd.sh"
    ;;
  opensuse)
    INIT=systemd
    PACKAGER=rpm
    PACKAGE_RELEASE=1.opensuse16
    POSTINSTALL="$REPO_ROOT/packaging/ci/hooks/postinstall-systemd.sh"
    ;;
  arch)
    INIT=systemd
    PACKAGER=archlinux
    PACKAGE_RELEASE=1
    POSTINSTALL="$REPO_ROOT/packaging/ci/hooks/postinstall-systemd.sh"
    ;;
  *)
    echo "unsupported FAMILY=$FAMILY" >&2
    exit 2
    ;;
esac

"$REPO_ROOT/packaging/stage-install.sh" "$ROOT_DIR" "$INIT" "$BIN_DIR"

export PACKAGE_ROOT="$ROOT_DIR"
export PACKAGE_RELEASE POSTINSTALL VERSION ARCH

nfpm package --config "$CONFIG" --packager "$PACKAGER" --target "$OUT_DIR/"

count="$(find "$OUT_DIR" -maxdepth 1 -type f | wc -l)"
[[ "$count" -eq 1 ]] || { echo "expected exactly one package, got $count" >&2; exit 1; }

find "$OUT_DIR" -maxdepth 1 -type f -printf '%f\n'
rm -rf "$ROOT_DIR"
