[English](README.md) | [Русский](README.ru.md)

# Daemon packaging

Install `openshield-daemon` as `/usr/bin/openshield-daemon` and the unit as
`/usr/lib/systemd/system/openshield-daemon.service`.

The service deliberately runs as root and retains `CAP_NET_ADMIN`,
`CAP_SYS_PTRACE`, and `CAP_DAC_READ_SEARCH`. The latter two capabilities let the
daemon bind queued socket inodes to protected `/proc/<pid>` identity metadata
across local UIDs. The syscall filter still denies `ptrace`,
`process_vm_readv`, `process_vm_writev`, `kcmp`, `pidfd_getfd`, and
`open_by_handle_at`, but these capabilities materially increase the impact of a
daemon compromise and must not be treated as complete privilege separation.
In particular, the filter does not prevent a compromised process with
`CAP_SYS_PTRACE` from opening `/proc/<pid>/mem` and using ordinary read/write
syscalls. `CAP_DAC_READ_SEARCH` can also bypass read/search permissions for
files visible in the service mount namespace.

The service creates:

- `/run/openshield/control.sock` (`0600`) for root-only mutations;
- `/run/openshield/observe.sock` (`0666`) for sanitized, read-only status/events;
- `/run/openshield/daemon.lock` (root-owned regular `0600`) for the singleton
  daemon and startup-policy transaction;
- `/var/lib/openshield/state.json` (`0600`) for atomically persisted state.

Do not relocate either socket to a shared temporary directory and do not weaken
the runtime-directory ownership checks in the daemon.

The first start installs `BlockAll` before opening either socket. Start it only
from a local console or with independent out-of-band access, then use
`sudo openshield-tui` to add rules or enter Learning mode. Stopping the service
leaves the kernel-resident policy active; see the
[top-level README](../../README.md) for the explicit fixed-table removal
procedure.

The unit's `ExecStartPre` invokes the root-only, non-configurable
`openshield-daemon --install-fail-closed` action. The main daemon then sends the
systemd `READY=1` notification only after it has applied validated state, bound
the fixed fail-closed NFQUEUE 1337 consumer, and bound both verified sockets.
The queue has no nftables `bypass` flag; if it cannot be bound, startup fails
with `BlockAll` still active. Do not change the unit back to `Type=simple`, or
network startup will no longer wait for that readiness boundary.

The `[Install]` section includes `RequiredBy=network-pre.target`. Running
`systemctl enable openshield-daemon` creates that requirement; together with
`Before=network-pre.target`, a standard consumer of the target cannot proceed
through it unless OpenShield starts successfully. Merely copying the unit file
without enabling it does not create the dependency.

This still does not cover a network manager, unit, initramfs, or early packet
path that bypasses `network-pre.target`. Strict whole-boot protection requires
tested distribution-specific integration or initramfs enforcement.

`Restart=on-failure` may retry a failed main process, but every attempt repeats
the fail-closed pre-start action and cannot report readiness until the persisted
policy, NFQUEUE consumer, and IPC endpoints are active.

Both `ExecStartPre` and the long-running daemon acquire the same nonblocking
singleton lock before nftables access. A manual `--install-fail-closed` while
the daemon is active therefore exits without replacing live policy. Do not
delete `daemon.lock` while either operation may be running: the daemon keeps the
file in place when releasing `flock` so all future processes lock the same inode.
The packaged unit likewise preserves its runtime directory across stops; `/run`
still clears it naturally on reboot.

Do not run a second firewall manager that flushes the complete nftables ruleset.
OpenShield attempts to repair detected table loss, but competing privileged
services are an unsupported configuration.
