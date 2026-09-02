[English](README.md) | [Русский](README.ru.md)

# systemd daemon packaging

This directory contains the systemd unit, sysusers declaration, and tmpfiles
declaration. The unit is valid for both the preferred nftables backend and the automatic
`iptables`/`ip6tables` fallback.

Install these files through the package manager:

| Source | Destination | Mode |
| --- | --- | ---: |
| `openshield-daemon.service` | `/usr/lib/systemd/system/openshield-daemon.service` | `0644` |
| `openshield.sysusers` | `/usr/lib/sysusers.d/openshield.conf` | `0644` |
| `openshield.tmpfiles` | `/usr/lib/tmpfiles.d/openshield.conf` | `0644` |
| release daemon | `/usr/bin/openshield-daemon` | `0755` |
| release TUI | `/usr/bin/openshield-tui` | `0755` |

Run `systemd-sysusers` and `systemd-tmpfiles --create` before starting the
service. The daemon deliberately refuses partial startup when the required
`openshield` group cannot be resolved.

## RPM firewall and runtime dependencies

Every RPM declares the rich dependency `(nftables or iptables)` and recommends
`nftables`. A normal solver therefore installs the preferred nftables frontend,
while an iptables-only installation remains valid when nftables is unavailable
or recommendations are disabled. At runtime OpenShield still selects nftables
first and uses `iptables`/`ip6tables` only as its fallback.

Every RPM also requires `/usr/bin/systemd-tmpfiles`. The path dependency lets
the distribution select its native provider, including `systemd-mini` where
available, and guarantees that the post-install script can create and relabel
the exact runtime paths before the first manual start.

The Tumbleweed-specific GNU RPMs for `x86_64`, `i586`, `aarch64`, `ppc64le`,
and `s390x` are dynamically linked. They additionally require the official
Tumbleweed `glibc` and `libgcc_s1` runtime packages. These dependencies are not
added to the separate static-musl RPM builds.

## Runtime objects

The service creates or verifies:

- `/run/openshield`, pre-created by tmpfiles as `root:root` and `0755`;
- `/var/lib/openshield`, pre-created by tmpfiles as `root:root` and `0700`;
- `/run/openshield/control.sock`, owned by UID 0 and mode `0600`, for UID-0
  mutation (its group is intentionally irrelevant at that mode);
- `/run/openshield/observe.sock`, `root:openshield` and `0660`, for read-only
  monitoring by root and members of `openshield`;
- `/run/openshield/daemon.lock`, a root-owned regular `0600` singleton lock;
- `/run/xtables.lock`, the standard root-owned `0600` xtables serialization
  lock created by tmpfiles;
- `/var/lib/openshield/state.json`, a root-owned `0600` atomically persisted
  state file.

Unix-socket permissions are only the first check. The daemon also authenticates
control and observation peers with Linux `SO_PEERCRED`, including a bounded,
stable supplementary-group check for observers. Do not relocate the sockets to
a shared temporary directory or weaken ownership checks.

`ProtectSystem=strict` leaves only the two OpenShield directories and the
pre-created `/run/xtables.lock` writable. The file-level exception is required
because both old and new xtables implementations default to that shared lock;
using a private lock would stop OpenShield from serializing with other xtables
processes. The daemon clears the environment of firewall subprocesses, so a
service-level `XTABLES_LOCKFILE` override is intentionally not part of this
contract. The tmpfiles rules adjust and relabel only the two exact directories
and the exact lock path, never their contents recursively. They do not truncate
an existing lock or grant group write access. Packages must apply the
declaration before the first manual service start; at boot the unit is ordered
after and requires
`systemd-tmpfiles-setup.service`.

## Startup and shutdown boundary

`ExecStartPre` invokes the fixed, root-only
`openshield-daemon --install-fail-closed` action. The long-running daemon repeats
the kernel `BlockAll` bootstrap before reading or activating policy. On a fresh
installation it persists `Learning`; an existing saved mode remains unchanged.
The saved policy is activated only after validation and a fail-closed NFQUEUE
consumer are available.

The main process uses `Type=notify` and sends `READY=1` only after the policy,
NFQUEUE consumer, and verified IPC sockets are active. `ExecStopPost` installs
kernel `BlockAll` after the main process releases its singleton lock. Graceful
shutdown inside the daemon also installs this quarantine without changing the
persisted mode.

The unit has `Before=network-pre.target` and, when enabled, its
`RequiredBy=network-pre.target` link makes standard consumers depend on
successful readiness. Merely installing the unit does not create that link.
A network manager, initramfs component, unit, or early packet path that bypasses
`network-pre.target` also bypasses this ordering. Strict whole-boot filtering
requires distribution-specific validation or an initramfs policy.

`Restart=on-failure` repeats the fail-closed pre-start action. Do not delete
`daemon.lock`: each operation opens it with `O_NOFOLLOW|O_CLOEXEC`, verifies its
metadata, and locks the same persistent inode before state or firewall changes.

## Privileges and hardening

The service runs with UID 0 and primary group `root`, and explicitly adds the
supplementary group `openshield`. As the socket owner it may assign that group
to the observation socket without retaining `CAP_CHOWN`. Keeping `Group=root`
and managing the directories with non-recursive tmpfiles rules prevents systemd
from changing preserved runtime locks or persistent state before exec. The
service retains
`CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_SYS_PTRACE`, and `CAP_DAC_READ_SEARCH`. Legacy xtables requires
`CAP_NET_RAW` to open the raw IPv4/IPv6 sockets used for alternate-backend
inspection and fallback operation. The last two capabilities are needed to
associate a queued socket inode with protected `/proc/<pid>` metadata across
local UIDs. The syscall filter denies direct inspection calls including `ptrace`, `process_vm_*`,
`kcmp`, `pidfd_getfd`, and `open_by_handle_at`.

This is attack-surface reduction, not complete isolation. After daemon
compromise, retained capabilities can still permit access to process memory and
files through other system calls or procfs magic links. Review the
[threat model](../../docs/THREAT_MODEL.md) before deployment.

## SELinux and AppArmor

The package does not select an `SELinuxContext=` or `AppArmorProfile=` and never
disables either LSM. tmpfiles creates the runtime directory, state directory,
and shared xtables lock as `root:root`, then restores those three exact paths to
the contexts defined by the installed SELinux file-context database. The
non-recursive `z` rules do not relabel their contents.

This is compatibility with the distribution's standard policy, not a bundled
confinement policy for OpenShield. A locally supplied SELinux domain or AppArmor
profile must explicitly cover the daemon's documented files, procfs attribution,
socket families, capabilities, and fixed nftables/xtables executables. Diagnose
policy failures while enforcement remains enabled:

```console
systemctl show openshield-daemon.service -p Group -p SupplementaryGroups
ls -ldZ /run/openshield /var/lib/openshield /run/xtables.lock
sudo ausearch -m AVC,USER_AVC -ts boot
sudo journalctl -k -b --grep='apparmor="DENIED"'
```

On SELinux systems, `matchpathcon -V` can compare an existing path with policy;
`restorecon -v` on the three exact paths above safely reapplies policy-defined
contexts. Do not work around a denial with `setenforce 0`, `aa-complain`, a
blanket allow rule, or unreviewed `audit2allow` output.

## Operational warning

Fresh state is `Learning`, but inbound traffic is default-drop in every mode.
First activation can terminate the only SSH or VPN session. Use a local console
or independent out-of-band access, create a narrowly scoped inbound management
rule, verify a second session, review learned outbound rules, and only then move
to `Enforcing`.

Do not run another privileged firewall manager unless chain ordering, the upper
two packet-mark bits, and OpenShield's low 31 conntrack-mark bits have been
reviewed. Conntrack bit 31 is preserved. OpenShield health monitoring is not a
proof that arbitrary concurrent ruleset edits are safe.
