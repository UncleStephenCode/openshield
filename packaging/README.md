[English](README.md) | [Русский](README.ru.md)

# Packaging and service integration

OpenShield provides package-staging assets for systemd, OpenRC, SysVinit,
runit, s6, and dinit. These files implement the same security lifecycle:

1. create or verify the `openshield` observation group;
2. install kernel `BlockAll` before starting the long-running daemon;
3. start the daemon as root from the fixed `/usr/bin/openshield-daemon` path;
4. install kernel `BlockAll` again after a supervised stop;
5. leave the persisted requested mode unchanged across the shutdown quarantine.

The normal initial persisted mode is `Learning`. The pre-start quarantine is a
temporary kernel policy, not a replacement for that saved mode.

## Staging a package tree

Build release binaries first. Then call the staging helper with an existing,
caller-owned, safely permissioned package root, one supported init-system name,
and the absolute directory containing both binaries:

```console
packaging/stage-install.sh /absolute/package-root systemd /absolute/release-dir
```

Replace `systemd` with `openrc`, `sysvinit`, `runit`, `s6`, or `dinit` as
needed. The helper validates its arguments and refuses `/`, `..` components,
symbolic links in lexical destination components, foreign-owned objects,
group/world-writable directories, and multiply linked regular files anywhere
in the staging tree. It also validates canonical ancestry before every write;
only caller- or system-owned safe parents are accepted, with the conventional
system-owned sticky `/tmp` exception. Filesystem probes stop at the first
rejected object. It never enables or starts a host service. It stages:

- both binaries in `/usr/bin`;
- the license in `/usr/share/openshield`;
- the group helper in `/usr/libexec/openshield`;
- the sysusers and tmpfiles declarations for systemd, or the selected
  non-systemd service files in their conventional directories.

The staging caller is trusted not to change the verified tree concurrently.
Use a fresh, private package root and do not share write access while staging;
the helper is not a defense against a malicious caller racing its own tree.

Install this tree through the target distribution's package manager. Package
maintainer scripts must create the group before the first start. systemd
packages should invoke sysusers and tmpfiles before the first manual start so
the standard root-owned `0600` `/run/xtables.lock` exists. Other packages may invoke the
fixed `/usr/libexec/openshield/ensure-group` helper as root; it is idempotent and
uses only fixed account-management commands.

Do not start the service automatically during an unattended remote package
upgrade unless an inbound management rule and an independently tested recovery
path already exist. Inbound traffic is default-drop even in `Learning`.

## Init-system notes

| Init system | Staged service | Ordering and supervision |
| --- | --- | --- |
| systemd | `/usr/lib/systemd/system/openshield-daemon.service` | `Type=notify`, before and required by enabled `network-pre.target`, restart on failure, pre-start and post-stop quarantine |
| OpenRC | `/etc/init.d/openshield` | requires local mounts, orders before `net`, supervised background PID, pre-start and post-stop quarantine |
| SysVinit | `/etc/init.d/openshield` | LSB metadata, `start-stop-daemon`, PID/executable validation, quarantine around lifecycle |
| runit | `/etc/sv/openshield/` | foreground `run`, readiness `check`, and `finish` quarantine |
| s6 | `/etc/s6/sv/openshield/` | `longrun`, filesystem dependency, foreground `run`, and `finish` quarantine |
| dinit | `/etc/dinit.d/openshield*` | scripted preflight dependency, supervised process, restart delay, stop quarantine |

Service enablement paths and commands vary among distributions. Packages should
use the distribution's native preset/enable policy rather than creating an
unverified generic symlink. None of these service files controls initramfs or a
network path that ignores the init system's declared ordering.

The daemon itself requires effective UID 0. Do not change the service account to
the `openshield` group: that group authorizes read-only monitoring and is not the
daemon's execution identity.

## Verification

Static staging, file-mode, syntax, dependency, and symbolic-link rejection
checks:

```console
scripts/test-init-matrix.sh validate
```

Container parser/supervisor fixtures:

```console
scripts/test-init-matrix.sh manifests
scripts/test-init-matrix.sh containers-clean
```

The container harness checks OpenRC parsing, SysVinit `start-stop-daemon`
semantics, runit and s6 lifecycle/quarantine hooks, dinit service parsing, and
group-helper behavior. Alpine/BusyBox also executes the staging helper against
an isolated package tree. Unsafe ownership, mode, link, and symlink fixtures are
expected to be rejected. systemd is covered by static staging and separate
`systemd-analyze` checks; the tmpfiles declaration was also parsed with a
rooted dry run. The harness does not boot systemd in a container.
Stub daemons are used, so these checks do not exercise a real kernel firewall,
NFQUEUE, boot sequence, or service-manager recovery after a firewall error.

Run the real firewall end-to-end workflow only in its disposable, isolated
Docker network as described in [the compatibility guide](../tests/compat/README.md).

For systemd-specific capability and readiness details, see
[daemon/README.md](daemon/README.md).
