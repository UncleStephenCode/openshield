#!/usr/bin/env bash
set -euo pipefail

: "${FAMILY:?FAMILY is required}"
: "${IMAGE:?IMAGE is required}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
DIST="$REPO_ROOT/dist"

case "$FAMILY" in
  deb)
    CMD='set -eu
      export DEBIAN_FRONTEND=noninteractive
      apt-get update
      apt-get install -y /packages/*.deb
      openshield-daemon --version
      openshield-tui --version
      test -x /usr/bin/openshield-daemon
      test -x /usr/bin/openshield-tui
      test -f /usr/lib/systemd/system/openshield-daemon.service
      test -f /usr/lib/sysusers.d/openshield.conf
      getent group openshield >/dev/null'
    ;;
  fedora|el9|el10)
    CMD='set -eu
      dnf -y install /packages/*.rpm
      openshield-daemon --version
      openshield-tui --version
      test -x /usr/bin/openshield-daemon
      test -f /usr/lib/systemd/system/openshield-daemon.service
      getent group openshield >/dev/null'
    ;;
  opensuse)
    CMD='set -eu
      zypper --non-interactive install --allow-unsigned-rpm /packages/*.rpm
      openshield-daemon --version
      openshield-tui --version
      test -x /usr/bin/openshield-daemon
      test -f /usr/lib/systemd/system/openshield-daemon.service
      getent group openshield >/dev/null'
    ;;
  alpine)
    CMD='set -eu
      apk add --allow-untrusted /packages/*.apk
      openshield-daemon --version
      openshield-tui --version
      test -x /usr/bin/openshield-daemon
      test -f /etc/init.d/openshield
      getent group openshield >/dev/null'
    ;;
  arch)
    CMD='set -eu
      pacman -Sy --noconfirm
      pacman -U --noconfirm /packages/*.pkg.tar.zst
      openshield-daemon --version
      openshield-tui --version
      test -x /usr/bin/openshield-daemon
      test -f /usr/lib/systemd/system/openshield-daemon.service
      getent group openshield >/dev/null'
    ;;
  *)
    echo "unsupported FAMILY=$FAMILY" >&2
    exit 2
    ;;
esac

docker pull "$IMAGE"
docker run --rm \
  -v "$DIST:/packages:ro" \
  "$IMAGE" \
  /bin/sh -c "$CMD"
