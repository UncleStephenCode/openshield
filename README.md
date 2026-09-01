[English](README.md) | [Русский](README.ru.md)

# OpenShield

OpenShield is a secure Linux host firewall written in Rust, with a privileged
daemon and a terminal interface. It is a new, minimal port of the OpenSnitch
core: it implements the required modes, network-level rules, and local
observation, including outbound rules bound to an application identity. It does
not retain compatibility with the former project's Python/Go plugins, task
executors, or legacy rule format.

The project builds with Rust 1.98.0 (edition 2024). Filtering is performed in
the kernel through a dedicated nftables `inet openshield` table. Initial
application decisions use one fixed, bounded NFQUEUE without a bypass flag;
shell execution, loadable plugins, and configuration-selected executables are
not used.

## Port provenance

The audit and port are based on the local `../opensnitch` checkout from
<https://github.com/evilsocket/opensnitch.git>, commit
`a1353848ba1b660320e90cefea782c3fba272c00` dated 2026-07-27. OpenShield is a
new, minimal Rust implementation of the required network model, not a
line-by-line translation. The `LICENSE` file has the same SHA-256 digest as the
file in that source revision.

## Modes

- `BlockAll` blocks local inbound, outbound, and forwarded IP traffic. The local
  Unix control sockets remain available.
- `Learning` sends otherwise-unmatched outbound TCP, UDP, ICMP echo, and ICMPv6
  echo traffic through fail-closed application attribution. A successfully
  attributed connection creates an exact application-bound endpoint rule with
  the actual outbound interface. Missing, ambiguous, oversized, unsupported, or
  timed-out attribution is denied. New inbound traffic remains denied except
  where an explicit inbound rule allows it.
- `Enforcing` permits new packets only when an enabled manual or learned rule
  matches. Network-only rules are evaluated in the kernel; application-bound
  outbound rules additionally require a successful process match. Established
  TCP replies can use the current application authorization; UDP/ICMP replies
  require an explicit inbound allow. There is no blanket
  `ct state established accept`.

Forwarding is always blocked: version 0.1 has no API for forwarding allow
rules.

## Outbound application rules

An outbound allow rule can be constrained by an application selector. Its
executable path is mandatory and the persisted rule is always pinned to a
device/inode pair. If the path is visible in the daemon's mount namespace, the
daemon canonicalizes and opens it, fills the pair automatically, and rejects a
conflicting supplied pair. A privileged operator must provide both values for a
path outside that namespace.

Optional constraints are a numeric filesystem UID (`fsuid`, the fourth value on
the procfs `Uid:` line), an exact unified-cgroup-v2 path, and either an exact or
prefix command line. The cgroup identity comes from exactly one procfs
`0::/path` entry; v1 controller entries are ignored. A v1-only host, a missing
v2 identity, or multiple v2 identities deny application attribution. Command
arguments are entered in the
TUI as a JSON string array, preserving token boundaries and empty arguments;
matching starts at `argv[0]`. Every supplied application and network field is
combined with AND. Regular expressions, environment matching, parent-process
selectors, persistent PID rules, MD5/SHA-1, and executable execution are
deliberately unsupported.

These selectors identify observed process metadata, not every piece of code
inside the process. For example, `LD_PRELOAD=/tmp/evil.so /allowed/path` keeps
the same path, device/inode, arguments, filesystem UID, and cgroup while the
loaded library can initiate traffic. Interpreters, plugins, and JIT code have
the same boundary; this is not code attestation.

These values are bounded UTF-8: an application path is at most 4,096 bytes, a
cgroup path 1,024 bytes, and a command selector at most 64 arguments, 1,024
bytes per argument, and 8,192 bytes in total. Control and bidirectional-format
characters and `.`/`..` path components are rejected. An empty JSON string is a
valid argument, but an exact/prefix selector must contain at least one token.

The daemon attributes a queued packet by its kernel-reported UID and
network tuple, requires exactly one socket inode and one owning process, and
then performs bounded, repeated checks of the process start time, socket fd,
executable path, file identity, and UID. Failure at any stage returns DROP. The
owner search enumerates every `/proc/TGID/task/TID/fd` table, regardless of
filesystem UID, and groups holders by TGID. Different TGIDs, a cross-UID holder,
or any incomplete, unavailable, or bounded-out live process/task scan deny
attribution. Sibling holders in one TGID count as one process only when every
holder task has the same executable/file, argv, filesystem UID, and cgroup
identity. A vanished entry is skipped only after procfs confirms it disappeared.
`PermissionDenied` on a TGID-leader fd table is skipped only when two bounded
`stat` reads confirm stable zombie state `Z`; every other error, non-zombie
state, or unconfirmed state is denied.
The queue is fixed at number 1337, has no `bypass` flag, and is bounded
independently from the learning worker, so a missing or overloaded consumer
cannot turn an application rule into a network-wide allow.

After a successful TCP decision, both directions of the established connection
are bound to a persisted, nonzero policy generation. A mode change or rule
mutation that invalidates authorization advances the generation without reuse,
so stale TCP state does not by itself preserve permission. UDP and ICMP are not
cached: every otherwise-unmatched outbound packet is queued and attributed
again, its conntrack mark is cleared, and its reply requires an explicit inbound
allow. This prevents another process from inheriting an authorization by reusing
a surviving UDP five-tuple.

Rules are allow-only. A broader network-only rule can accept traffic before an
application rule is considered; an application selector is not a deny override.
Avoid overlapping generic allows when application identity must be mandatory.

## Privilege separation

The daemon accepts requests only through two fixed Unix sockets:

| Path | Mode | Purpose |
| --- | ---: | --- |
| `/run/openshield/control.sock` | `0600` | mode changes and rule CRUD; additionally checks `SO_PEERCRED uid == 0` |
| `/run/openshield/observe.sock` | `0666` | policy status, rules, events, and counters; available to every local user |

The TUI independently verifies the root ownership of the runtime directory,
socket, and daemon process. An ordinary user receives a read-only interface;
the daemon rejects mutation attempts again regardless of client behavior. Each
mutation also contains the revision of the snapshot on which it is based. If
the policy has already changed, the daemon returns `Conflict` before applying
anything; the TUI reloads the snapshot and never retries the command
automatically.

Before working with nftables or persisted state, the daemon acquires a
nonblocking exclusive lock on `/run/openshield/daemon.lock`. The lock must be a
regular root-owned `0600` file; links are rejected. The
`--install-fail-closed` action uses the same lock, so a manual invocation cannot
overwrite the policy of a running instance.

In version 0.1, observation consists of aggregate ALLOW/DROP/LEARN counters
updated once per second and policy-change events; it is not a per-packet capture.
For application decisions, the daemon reads a bounded packet prefix and bounded
`/proc` identity metadata, including the command-line tokens, but never reads a
process environment. A UID-0 observer receives full rule metadata. For every
other UID the daemon replaces the application selector and even its potentially
identifying rule name with fixed redacted values before serialization. The
public IPC path uses a fixed worker pool and bounded queues: there can be at most
24 active subscriptions globally and two per UID; a slow reader is disconnected
when its 512-event queue fills. For each cursor the server ignores a smaller
client limit, fetches up to 128 rules, and shrinks the page only to fit the 64
KiB frame limit, returning a resumable cursor. The TUI reuses one connection,
while the server permits at most two `Status` requests before strictly advancing
pagination; `Subscribe` is valid only as the first request.

## TUI languages

The TUI ships with separate, compile-time embedded JSON resources under
`crates/openshield-tui/locales/` for 20 locales: English (`en`), Russian (`ru`),
Chinese (`zh`), Spanish (`es`), Hindi (`hi`), Arabic (`ar`), Portuguese (`pt`),
French (`fr`), German (`de`), Japanese (`ja`), Korean (`ko`), Indonesian (`id`),
Turkish (`tr`), Italian (`it`), Polish (`pl`), Ukrainian (`uk`), Dutch (`nl`),
Vietnamese (`vi`), Thai (`th`), and Persian (`fa`). Select one explicitly, for
example:

```console
openshield-tui --locale ru
```

Without `--locale`, the TUI checks `LC_ALL`, `LC_MESSAGES`, `LANGUAGE`, and
`LANG`, in that order, and falls back to English if none selects a supported
locale; `LANGUAGE` may contain a colon-separated preference list, and `C` or
`POSIX` selects the English fallback. An explicit unknown or malformed
`--locale` is an error. Locale identifiers are bounded and parsed without
filesystem access. At startup, the selected embedded resource is validated
against the English message keys and placeholders, while the test suite
validates all resources; the privileged TUI never loads a translation path
supplied through the environment.

## Building and verification

Build the project as an unprivileged user:

```console
cargo build --release --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all --check
cargo audit --file Cargo.lock
cargo deny check
```

Linux, procfs, nftables, kernel NFQUEUE support, and `inet` family tables are
required. The daemon checks a fixed root-owned `nft` at `/usr/sbin/nft`,
`/usr/bin/nft`, or `/sbin/nft` and never invokes it through a shell.

## Installation

> **Warning:** the first start deliberately installs `BlockAll`. It immediately
> interrupts SSH, VPN, DNS, and all other IP traffic. Perform the first start
> only from a local console or with independent out-of-band access.

After building, install only the completed artifacts and the unit file:

```console
sudo install -o root -g root -m 0755 target/release/openshield-daemon /usr/bin/openshield-daemon
sudo install -o root -g root -m 0755 target/release/openshield-tui /usr/bin/openshield-tui
sudo install -o root -g root -m 0644 packaging/daemon/openshield-daemon.service /usr/lib/systemd/system/openshield-daemon.service
sudo systemctl daemon-reload
```

The unit first runs the explicitly documented
`openshield-daemon --install-fail-closed` action, which installs only
`BlockAll`. The main process uses `Type=notify` and sends `READY=1` only after a
validated policy, the fail-closed NFQUEUE consumer, and both IPC sockets are
active. The `[Install]` section contains `RequiredBy=network-pre.target`; after
`systemctl enable openshield-daemon`, this creates a success dependency, while
`Before=network-pre.target` keeps the target behind the readiness boundary. A
standard consumer of `network-pre.target` therefore does not proceed through
that target when the fixed `nft` executable is missing or `ExecStartPre` fails.

This is not a guarantee for all boot-time traffic. Installing the file without
enabling it creates no `RequiredBy` link, and a network manager, unit, initramfs,
or early packet path that bypasses `network-pre.target` also bypasses this
dependency. Strict whole-boot enforcement needs tested distribution-specific
integration or an initramfs policy.

Independently of the unit helper, every daemon start first installs kernel
`BlockAll`, selects a cryptographically random nonzero startup epoch from the
lower 29 bits of the 30-bit flow-generation domain, persists it, and only then
applies the saved policy. The new value differs from the previously persisted
one, invalidating TCP authorization marks from the previous daemon process.

Application attribution requires inspecting protected metadata below `/proc`.
The packaged unit therefore retains `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`, and
`CAP_DAC_READ_SEARCH`, while explicitly denying `ptrace`, `process_vm_readv`,
`process_vm_writev`, `kcmp`, `pidfd_getfd`, and `open_by_handle_at` syscalls.
The normal daemon code does not inspect process memory or environments, but the
syscall list is not memory isolation: after a daemon compromise,
`CAP_SYS_PTRACE` can still authorize opening `/proc/<pid>/mem`, and ordinary
read/write syscalls remain available. `CAP_DAC_READ_SEARCH` can also bypass
read/search permissions for files visible to the service. Procfs magic links
such as `/proc/<pid>/root` may expose another process's mount view despite the
service mount restrictions. These capabilities are therefore a material trust
expansion; see the threat model before enabling application rules.

From a local console, start the daemon and then open the privileged TUI to add
rules or deliberately enable Learning:

```console
sudo systemctl enable --now openshield-daemon.service
sudo openshield-tui
```

For unprivileged live observation:

```console
openshield-tui
```

Do not simultaneously run another manager that executes `flush ruleset` or
modifies `inet openshield`. The daemon detects a missing table, base hook, or
named counter and attempts to restore the current policy. An isolated
`flush chain` leaves the default-drop hook in place and therefore remains
fail-closed, but lost permits may not be noticed until the next policy change or
restart. The monitor does not compare complete rule bodies, so a privileged
targeted edit or additional allow can evade it. Concurrent firewall services
are unsupported.

Stopping the service leaves the last kernel-resident policy active. This
protects the host if userspace crashes. To **deliberately** remove protection,
first stop and disable the service from a local console, then delete only the
table owned by OpenShield:

```console
sudo systemctl disable --now openshield-daemon.service
sudo nft delete table inet openshield
```

If the journal reports `read-only quarantine`, the kernel already has
`BlockAll` installed and the daemon deliberately remains alive, so
`Restart=on-failure` is not triggered: the persisted file may be in an ambiguous
state. From a local console, repair the filesystem and directory permissions
first, stop the service, move
`/var/lib/openshield/state.json` to a root-only backup for analysis, and only
then restart the service. If `state.json` is absent, the daemon safely creates a
new empty `BlockAll` state.

## Rules and limitations

A rule contains a direction, protocol, remote IP/CIDR, port or port range, and
interface. Every field is typed and validated before nftables generation.
Rules are allow-only; no match means DROP.

- For inbound TCP/UDP, the port is the local destination port; for outbound
  TCP/UDP, it is the remote destination port.
- Correct IPv6 connectivity may require explicit inbound ICMPv6 permissions,
  for example for NDP/RA. Version 0.1 does not yet implement ICMP type/code
  selectors, so scope such a rule to a link-local CIDR and interface.
- Counters reset after an atomic policy replacement, such as a mode or manual
  rule change; the TUI must treat a decrease as a reset.
- Enable Learning only for a controlled period and review the rules it creates:
  any attributable local process can deliberately contact many endpoints. The
  daemon limits state to 10,000 rules, queues at most 512 learning observations,
  persists at most 256 in one batch, and enforces an independent exact 8 MiB
  encoded-state quota before nftables application. A manual mutation over the
  quota is rejected; Learning pauses a batch on the quota or a recoverable save
  failure and retains the previous state and active policy. These bounds do not
  decide which application the operator intended to trust.
- Executable pinning currently identifies a file by canonical path and
  device/inode, not by a content digest or mount-namespace identity. Command-line
  and cgroup values are read after the packet is queued and can be changed by the
  process. Treat these selectors as useful constraints, not as cryptographic
  software attestation; see the threat model for the fail-closed race handling
  and remaining limitations.
- Process identity is checked for the first queued packet of an established TCP
  connection, not continuously for every later TCP packet. A later exec,
  credential/cgroup change, or socket-fd transfer may therefore continue that
  connection until it is reconnected or a policy-generation change invalidates
  it. UDP and ICMP are re-attributed per outbound packet. Even before any
  decision, a sender can queue a packet and exec an allowed image while
  retaining the socket; post-hoc procfs attribution may see only the new image.
- OpenShield reserves the upper two packet-mark bits during outbound processing
  and preserves the lower 30 bits, but it exclusively owns the complete
  conntrack mark on application-authorized traffic: it stores the TCP cache and
  clears the mark for UDP/ICMP. Other packet-mark users must avoid the upper
  bits; another firewall, VPN, QoS, or CONNMARK writer on the same conntrack
  entry is unsupported. A privileged earlier CONNMARK rule can potentially
  forge the current value on an established TCP flow and bypass the queue; NEW
  traffic never uses this fast path, but exclusive mark ownership and compatible
  hook ordering are required.
- The `inet` table filters host IPv4/IPv6 traffic but is not an L2 firewall: it
  does not block ARP or direct frame injection by a privileged
  `AF_PACKET`/`CAP_NET_RAW` peer.
- OpenShield does not modify other nftables tables, but a chain owned by another
  product may still additionally block a packet that OpenShield accepts.

For details, see the [architecture](docs/ARCHITECTURE.md),
[threat model](docs/THREAT_MODEL.md), [audit report](docs/SECURITY_AUDIT.md), and
[security policy](SECURITY.md).
