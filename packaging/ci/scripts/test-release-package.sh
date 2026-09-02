#!/usr/bin/env bash
set -euo pipefail

: "${FAMILY:?FAMILY is required}"
: "${IMAGE:?IMAGE is required}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
DIST="$REPO_ROOT/dist"
EXPECTED_RPM_RELEASE=
EXPECT_TUMBLEWEED_RUNTIME=false

RPM_METADATA_ASSERTIONS='set -eu
      set -- /packages/*.rpm
      [ "$#" -eq 1 ] && [ -f "$1" ] || {
        printf "%s\n" "expected exactly one RPM package" >&2
        exit 1
      }
      package=$1
      [ "$(rpm -qp --qf "%{NAME}" "$package")" = openshield ]
      [ "$(rpm -qp --qf "%{RELEASE}" "$package")" = "$EXPECTED_RPM_RELEASE" ]
      package_version=$(rpm -qp --qf "%{VERSION}" "$package")
      package_arch=$(rpm -qp --qf "%{ARCH}" "$package")
      [ -n "$package_version" ] && [ -n "$package_arch" ]
      rpm -qp --requires "$package" | grep -Fqx "(nftables or iptables)"
      rpm -qp --recommends "$package" | grep -Fqx nftables
      if [ "$EXPECT_TUMBLEWEED_RUNTIME" = true ]; then
        rpm -qp --requires "$package" | grep -Fqx glibc
        rpm -qp --requires "$package" | grep -Fqx libgcc_s1
      fi
      for required_path in \
        /usr/bin/openshield-daemon \
        /usr/bin/openshield-tui \
        /usr/lib/systemd/system/openshield-daemon.service \
        /usr/lib/sysusers.d/openshield.conf \
        /usr/lib/tmpfiles.d/openshield.conf; do
        rpm -qpl "$package" | grep -Fqx "$required_path"
      done'

RPM_INSTALL_ASSERTIONS='
      [ "$(rpm -q --qf "%{VERSION}" openshield)" = "$package_version" ]
      [ "$(rpm -q --qf "%{RELEASE}" openshield)" = "$EXPECTED_RPM_RELEASE" ]
      [ "$(rpm -q --qf "%{ARCH}" openshield)" = "$package_arch" ]
      [ "$(openshield-daemon --version)" = "openshield-daemon $package_version" ]
      [ "$(openshield-tui --version)" = "openshield-tui $package_version" ]
      test -x /usr/bin/openshield-daemon
      test -x /usr/bin/openshield-tui
      test -f /usr/lib/systemd/system/openshield-daemon.service
      test -f /usr/lib/sysusers.d/openshield.conf
      test -f /usr/lib/tmpfiles.d/openshield.conf
      getent group openshield >/dev/null'

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
    case "$FAMILY" in
      fedora) EXPECTED_RPM_RELEASE=1.fc44 ;;
      el9) EXPECTED_RPM_RELEASE=1.el9 ;;
      el10) EXPECTED_RPM_RELEASE=1.el10 ;;
    esac
    CMD=$RPM_METADATA_ASSERTIONS'
      dnf -y install /packages/*.rpm
    '$RPM_INSTALL_ASSERTIONS
    ;;
  opensuse)
    EXPECTED_RPM_RELEASE=1.opensuse16
    CMD=$RPM_METADATA_ASSERTIONS'
      zypper --non-interactive install --allow-unsigned-rpm /packages/*.rpm
    '$RPM_INSTALL_ASSERTIONS
    ;;
  tumbleweed)
    EXPECTED_RPM_RELEASE=1.tumbleweed
    EXPECT_TUMBLEWEED_RUNTIME=true
    CMD=$RPM_METADATA_ASSERTIONS'
      zypper --non-interactive install --allow-unsigned-rpm /packages/*.rpm
      rpm -q glibc libgcc_s1 nftables >/dev/null
    '$RPM_INSTALL_ASSERTIONS
    FALLBACK_CMD=$RPM_METADATA_ASSERTIONS'
      zypper --non-interactive install --no-recommends iptables
      rpm -q iptables >/dev/null
      if rpm -q nftables >/dev/null 2>&1 || command -v nft >/dev/null 2>&1; then
        printf "%s\n" "nftables unexpectedly present before fallback installation" >&2
        exit 1
      fi
      zypper --non-interactive install --no-recommends --allow-unsigned-rpm /packages/*.rpm
      rpm -q glibc libgcc_s1 iptables >/dev/null
      if rpm -q nftables >/dev/null 2>&1 || command -v nft >/dev/null 2>&1; then
        printf "%s\n" "nftables recommendation was unexpectedly installed" >&2
        exit 1
      fi
    '$RPM_INSTALL_ASSERTIONS
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
run_package_test() {
  docker run --rm \
    --security-opt label=disable \
    --env "EXPECTED_RPM_RELEASE=$EXPECTED_RPM_RELEASE" \
    --env "EXPECT_TUMBLEWEED_RUNTIME=$EXPECT_TUMBLEWEED_RUNTIME" \
    -v "$DIST:/packages:ro" \
    "$IMAGE" \
    /bin/sh -c "$1"
}

run_package_test "$CMD"
if [[ "$FAMILY" == tumbleweed ]]; then
  run_package_test "$FALLBACK_CMD"
fi
