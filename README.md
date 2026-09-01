[English](README.md) | [Русский](README.ru.md)

# OpenShield

OpenShield is a local, application-aware Linux host firewall written in Rust.
It consists of a privileged daemon and a terminal user interface (TUI). The
daemon prefers nftables and automatically falls back to a complete
`iptables`/`ip6tables` tool set when the fixed, trusted `nft` executable or the
running kernel cannot validate an nftables policy.

OpenShield is a focused Rust port of the OpenSnitch security model, not a
line-by-line replacement. It does not load the original Python/Go plugins,
execute configuration-selected programs, or accept the legacy rule format. The
audit and port started from the local `../opensnitch` revision
`a1353848ba1b660320e90cefea782c3fba272c00` (2026-07-27). The copied `LICENSE`
has the same SHA-256 digest as that revision.

The workspace uses Rust 1.98.0, edition 2024, and forbids `unsafe` Rust in
workspace code.

## Policy modes

| Mode | Local input | Local output | Forwarding |
| --- | --- | --- | --- |
| `BlockAll` | drop | drop | drop |
| `Learning` | default-drop; explicit inbound allows and replies bound to a current authorized outbound flow only | matching rules are allowed; otherwise supported traffic is allowed only after fail-closed application attribution and becomes an exact learned rule | return to the pre-existing firewall policy |
| `Enforcing` | default-drop; explicit inbound allows and replies bound to a current authorized outbound flow only | default-drop; enabled manual and learned allow rules only | return to the pre-existing firewall policy |

A machine with no state file gets a persisted `Learning` policy. This does not
create a fail-open startup window: every daemon start first installs a temporary
kernel `BlockAll` quarantine. The saved policy is activated only after it has
been validated, the NFQUEUE consumer is ready, and all required local
prerequisites are available. An existing saved mode is preserved.

Graceful shutdown installs kernel `BlockAll` again without overwriting the saved
mode. Service-manager pre-start and post-stop hooks provide the same quarantine
around daemon failures. A forced kill or kernel/backend failure cannot provide a
universal persistence guarantee; operational recovery must therefore use a
local console or independent out-of-band access.

Learning applies only to supported outbound TCP, UDP, ICMP echo, and ICMPv6
echo traffic. Missing, ambiguous, oversized, unsupported, or timed-out process
attribution is denied. Inbound traffic is never learned automatically.
Automatic insertion stops when the state already contains 7,500 learned rules,
512 learned rules for one filesystem UID, or 256 for one filesystem UID and full
executable file-version identity. These are admission budgets, not validation
invariants for a legacy or root-edited state. The 10,000-rule total normally
leaves 2,500 count slots for root-created rules, although root can still fill the
total manually. Budgets use the numeric filesystem UID, so distinct subordinate
UIDs count independently and can distribute activity until the global budget.
Traffic that reaches a learning quota is allowed
for that Learning decision but is not persisted and is therefore denied in
Enforcing unless another rule matches. The separate 8 MiB state limit still
applies. Reaching that byte limit or a recoverable save failure discards the
current batch and pauses automatic persistence until a successful root mutation
or daemon restart; otherwise eligible, successfully attributed `Learning`
packets remain allowed but create no new rules while persistence is paused. An
immutable current-policy admission index also keeps exact-known and saturated
observations out of the 512-item persistence queue; only a new candidate consumes
a queue slot.

## Application-bound outbound rules

An application selector always includes a canonical executable path and a
persisted file-version identity: device, inode, size, and change time in seconds
and nanoseconds. Optional selectors constrain the filesystem UID, the exact
unified-cgroup-v2 path, and an exact or prefix command line. The command line is
represented as a JSON array of strings, so token boundaries and empty arguments
are preserved. Every supplied application and network field is combined with
logical AND.

For a root-created rule, the daemon must resolve the path in its own mount
namespace. It repeatedly canonicalizes and opens a regular file, fills an omitted
version pin, and rejects a supplied stale pin or an unresolvable path. The TUI
therefore sends no pin for a new or changed path and carries the complete old pin
when the path is unchanged, so a concurrent executable replacement rejects the
edit instead of silently authorizing new code. A learned rule pins the observed
canonical path, complete file version, filesystem UID, exact tokenized argv,
and, when available, the single unified-cgroup-v2 path. On cgroup v1 the cgroup
field is absent while the other fields remain enforced.

Exact argv can contain credentials, tokens, or other secrets. Learning persists
it in the root-owned `0600` `/var/lib/openshield/state.json`; non-root observation
redacts application selectors. Protect the state file and its backups. A change
to argv or the unified cgroup path intentionally stops the learned selector from
matching and requires a separate rule or a reviewed root edit. Treat Learning as
a controlled capture window and review learned rules before Enforcing.

The daemon attributes a queued packet from the kernel-reported UID and network
tuple, requires one unambiguous socket inode and process owner, and performs
bounded repeated checks of `/proc` metadata. It enumerates descriptor tables
only for tasks whose filesystem UID equals the kernel socket UID, groups matching
holders by process, and denies on incomplete candidate scans, multiple process
owners, changing identity, or exhausted bounds. NFQUEUE number 1337 has no
fail-open bypass flag. TCP authorization is tied to a persisted 30-bit policy
generation that increases by one and is not reused before exhaustion; UDP and
ICMP are re-attributed for every otherwise-unmatched outbound packet.

These selectors identify observed process metadata, not all code executing in
the process. The version pin detects ordinary in-place rewrites through size or
change-time differences, but dynamic loaders, interpreters, scripts, plugins,
JIT code, mount-namespace aliases, descriptor transfer, and post-queue `exec`
remain explicit trust boundaries. This mechanism is not cryptographic software
attestation. Older serialized two-field device/inode application pins are rejected
rather than silently upgraded; network-only state remains compatible. Review and
recreate affected rules from a protected console.
See the [threat model](docs/THREAT_MODEL.md) before relying on application rules
as a security boundary.

Rules are allow-only. A broad network-only rule is evaluated before an
application rule and can authorize the same traffic without process matching.
Avoid overlapping broad rules when application identity must be mandatory.

## Local access control

The daemon exposes no TCP management endpoint. It creates two Unix sockets in
the root-owned `/run/openshield` directory:

| Path | Owner and mode | Authorization |
| --- | --- | --- |
| `/run/openshield/control.sock` | `root:root`, `0600` | mode and rule mutations; Linux `SO_PEERCRED` must report UID 0 |
| `/run/openshield/observe.sock` | `root:openshield`, `0660` | read-only status, rules, events, and counters; peer must be root or a member of `openshield` |

Observation is not public. The daemon authenticates the peer with
`SO_PEERCRED`; for a supplementary-group match it reads the peer's bounded procfs
credentials twice and verifies a stable process start time. Filesystem mode
alone is not treated as authorization. Non-root observers receive redacted
application selectors and redacted names for application rules. Mutation
requests are rejected on the observation socket regardless of the client.
Authorization occurs when the Unix connection is accepted; a group member can
pass an already-connected socket fd to another process. Treat group membership
and processes running in those sessions as part of the monitoring trust boundary.

The package must create the system group before starting the daemon. To grant a
user read-only monitoring access, add that user to `openshield` with the
distribution's account-management tool, then start a new login session so the
supplementary group is present. Group membership does not grant rule or mode
changes.

The IPC protocol uses typed, length-bounded JSON frames, absolute I/O deadlines,
bounded worker and subscription queues, rate limits, server-side pagination,
and optimistic policy revisions. A stale mutation returns `Conflict`; the TUI
reloads state and never retries an unconfirmed change automatically.

## Building

Build as an unprivileged user with the pinned lock file:

```console
cargo build --release --locked
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all --check
cargo audit --file Cargo.lock
cargo deny check
```

Application attribution requires Linux procfs plus kernel conntrack and NFQUEUE
support. A cgroup-path selector additionally requires a unified cgroup v2
identity. On v1-only systems, executable path, full file-version identity,
filesystem-UID, and argv matching remain available, while an explicit
cgroup-path selector fails closed.
Network-only rules remain usable when attribution is unavailable. A usable installation also needs one
of these backend sets:

- a fixed, root-owned `nft` executable and kernel nftables support; or
- complete, fixed, root-owned IPv4 and IPv6 `iptables`, `*-restore`, and
  `*-save` bundles.

Executables are selected only from compiled absolute-path allowlists, checked
for safe metadata, invoked with typed arguments and a cleared environment, and
never passed through a shell.

## Installation and init systems

OpenShield includes service definitions for systemd, OpenRC, SysVinit, runit,
s6, and dinit. `packaging/stage-install.sh` stages a package tree for exactly one
of these init systems; by design it refuses to install directly into `/`.
Package maintainers should use it with a fresh `DESTDIR`, install the staged
files through their package manager, and run the platform-specific enablement
step described in [packaging/README.md](packaging/README.md).

For a manual systemd installation, install both binaries, the unit, and the
sysusers and tmpfiles declarations. Create the group and the shared xtables lock
before starting the service:

```console
sudo install -o root -g root -m 0755 target/release/openshield-daemon /usr/bin/openshield-daemon
sudo install -o root -g root -m 0755 target/release/openshield-tui /usr/bin/openshield-tui
sudo install -o root -g root -m 0644 packaging/daemon/openshield-daemon.service /usr/lib/systemd/system/openshield-daemon.service
sudo install -o root -g root -m 0644 packaging/daemon/openshield.sysusers /usr/lib/sysusers.d/openshield.conf
sudo install -o root -g root -m 0644 packaging/daemon/openshield.tmpfiles /usr/lib/tmpfiles.d/openshield.conf
sudo systemd-sysusers /usr/lib/sysusers.d/openshield.conf
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/openshield.conf
sudo systemctl daemon-reload
```

### Safe first activation on a remote server

> **Warning:** `Learning` still denies all new inbound traffic unless an
> explicit inbound allow rule matches. Starting OpenShield over the only SSH or
> VPN path can immediately lock out the operator.

Use a local console or independently tested out-of-band management for the
first activation. Start the daemon, open the root TUI from that console, and
create a narrowly scoped inbound rule for the administration protocol, source
network, local port, and interface. Verify the rule from a second session before
depending on remote access. Keep Learning enabled only for a controlled window,
review and narrow every learned outbound rule, then switch to `Enforcing` and
verify required DNS, time synchronization, package mirrors, monitoring, backup,
and application traffic.

```console
sudo systemctl enable --now openshield-daemon.service
sudo openshield-tui
```

A monitoring user with a fresh `openshield` group session can then run:

```console
openshield-tui
```

Do not manually flush or edit OpenShield-owned backend objects. Do not run a
second privileged firewall manager unless its hook ordering, chain ownership,
upper-two packet-mark use, and low-31 conntrack-mark use have been reviewed for
compatibility. Recovery and
removal are administrative firewall changes and should be performed from a
console using a distribution-specific, tested rollback procedure.

## Backend behavior and coexistence

nftables is preferred. It uses the dedicated `inet openshield` table and
validates a complete replacement before an atomic nftables transaction.

The compatibility backend creates only `OPENSHIELD_*` chains and places
dispatch jumps first in the built-in IPv4 and IPv6 INPUT, OUTPUT, and FORWARD
chains. It uses `iptables-restore`/`ip6tables-restore` with `--noflush`; it does
not flush a system table or change a built-in chain policy. Because xtables has
no transaction spanning both address families, policy replacement first places
both families in `BlockAll`, then applies IPv4 and IPv6. A transition can cause
a temporary denial, but is designed not to create a cross-family allow window.

In `Learning` and `Enforcing`, the OpenShield forwarding chain returns to the
existing firewall rather than accepting forwarded traffic itself. Consequently
the system's pre-existing forwarding policy remains authoritative. In
`BlockAll`, OpenShield drops forwarded traffic before delegating it.

OpenShield reserves the upper two packet-mark bits and preserves the lower 30.
For application authorization it reserves the low 31 conntrack-mark bits and
preserves bit 31. A firewall, VPN, QoS, or CONNMARK writer using the reserved
bits can invalidate either policy. The daemon's
health checks are backend-specific but do not establish safe coexistence with
arbitrary privileged ruleset editors.

## Compatibility evidence

Compatibility claims are intentionally scoped:

- final Rust 1.98.0 workspace verification passed formatting, locked
  all-target checks, clippy with warnings denied, and all 247 tests: 55 core,
  129 daemon, 11 protocol, and 52 TUI tests. These are component tests, not a
  live-firewall end-to-end result;
- both final static-PIE musl binaries completed a no-network, read-only,
  capability-free `--version` smoke test in all 60 container image rows in
  `tests/compat/distros.tsv`;
- all six service layouts passed static validation; dedicated container
  supervisor checks passed for OpenRC, SysVinit, runit, s6, and dinit, while
  systemd is checked separately rather than booted as PID 1 in that matrix;
- `cargo check --workspace --all-targets --locked` passed for 21 stable Rust
  Linux targets covering x86, x86_64/amd64, ARMv5/6/7 (soft- and hard-float
  variants where Rust provides them), arm64/aarch64, and RISC-V 64 with the
  listed GNU or musl environments;
- the two RISC-V 32 targets are Rust Tier 3 and were skipped because stable
  rustup does not ship their standard libraries; they require an explicitly
  separate nightly `build-std` workflow;
- non-native `cargo check` proves source-level compilation, not operation on
  physical hardware. arm64 execution was not available on the test host because
  no binfmt/QEMU handler was installed.

The 60-image smoke matrix does not boot each image's init system and does not
exercise its kernel, firewall backend, NFQUEUE, package manager, or upgrade
path. Archive and rolling images are compatibility probes, not supported-life
guarantees. See [tests/compat/README.md](tests/compat/README.md) for exact rows,
commands, and interpretation.

The final Rust 1.98.0 Debian Bookworm release binaries passed the isolated
`tests/e2e/server-learning-enforcing.sh` workflow separately with nftables and
iptables. Both runs covered Learning, UDP/TCP Enforcing, an explicit inbound
allow, and restart. They ran in disposable namespaces on a local Unix-socket
Docker engine; they neither tested nor modified the host firewall and are not
production certification.

## TUI localization

The TUI embeds 31 separate JSON resources with 183 messages each: the original
20 locales plus 11 additions. Each non-English resource is loaded as a complete
map without merging or falling back to English. Tests verify exact key,
placeholder, and newline parity for every compiled resource; no non-English
value is exactly equal to its English counterpart. An all-pairs regression also
rejects bulk reuse of substantive messages across languages. The complete
maintained list, inventory of missing and removed resources, and native-review
status are documented in
[`crates/openshield-tui/locales/README.md`](crates/openshield-tui/locales/README.md).
Select a locale explicitly with, for example:

```console
openshield-tui --locale ru
```

Without `--locale`, the TUI checks `LC_ALL`, `LC_MESSAGES`, `LANGUAGE`, and
`LANG`, then falls back to English only when no supported locale is selected.
Locale identifiers are bounded and never used as filesystem paths. Automated
structure and copy-detection tests do not constitute linguistic certification
or replace review by native technical translators. No native technical review
is recorded for the 11 additions. Six proposed resources (`os`, `inh`, `bua`,
`xal`, `ady`, and `kjh`) were removed after forensic comparison found large
cross-language copied blocks; they remain unsupported pending replacement and
native technical review.

## Important limits

- New inbound traffic is default-deny in every mode; IPv6 operation can require
  explicit, interface- and network-scoped ICMPv6 permissions.
- The filter covers host IPv4/IPv6, not Ethernet/ARP or direct frame injection
  by an already privileged `AF_PACKET`/`CAP_NET_RAW` process.
- Learning is a bounded operator-controlled trust window, not a verdict that a
  local executable or remote endpoint is benign.
- The packaged daemon retains `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`, and
  `CAP_DAC_READ_SEARCH` for firewall and cross-UID procfs attribution. The
  systemd syscall filter reduces attack surface but is not process-memory or
  filesystem isolation after daemon compromise.
- The workspace, matrices, and audit reduce known risk; they do not prove the
  absence of vulnerabilities or certify every Linux distribution, kernel,
  architecture, boot path, or hardware implementation.

See the [architecture](docs/ARCHITECTURE.md),
[threat model](docs/THREAT_MODEL.md),
[security audit](docs/SECURITY_AUDIT.md),
[security policy](SECURITY.md), and
[packaging guide](packaging/README.md).
