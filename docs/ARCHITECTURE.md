[English](ARCHITECTURE.md) | [Русский](ARCHITECTURE.ru.md)

# OpenShield architecture

OpenShield is a Linux host firewall composed of two Rust binaries:

- `openshield-daemon` is the only component allowed to change the firewall. It owns a
  dedicated `inet openshield` nftables table and persists validated rules.
- `openshield-tui` displays status and events for every local user. Mutating
  controls are enabled only when the daemon authenticates the peer as UID 0.

The daemon never accepts TCP control connections. It exposes two local Unix
sockets below the root-owned `/run/openshield` directory:

| Socket | Mode | Operations |
| --- | ---: | --- |
| `control.sock` | `0600` | change mode; create, update, enable, disable, or delete rules |
| `observe.sock` | `0666` | read a sanitized snapshot and subscribe to bounded events |

Filesystem permissions are defense in depth. Each control connection is also
authenticated with Linux `SO_PEERCRED`; a request is rejected unless the peer's
effective UID is 0. Protocol messages use a length-prefixed JSON frame with a
small fixed maximum size. Slow observers have bounded queues and are dropped,
so they cannot delay packet filtering or policy changes. The observation path
uses 32 fixed workers, a 64-job admission queue, at most 24 live public
subscriptions, and per-UID limits of four connections and two subscriptions. A
single per-UID token bucket (burst 256, refill 64 tokens/second) is charged both
when a connection is accepted and before each `Status`, `RulesPage`, or
`Subscribe` request; exhaustion returns `Conflict` and closes the session. A
session state machine permits `Subscribe` only as the first
request; snapshot sessions permit at most two `Status` requests and, after rule
pagination begins, only a strictly advancing cursor. For each cursor the server
fetches up to its fixed 128-rule maximum, ignoring a smaller client-supplied
limit, and then binary-searches a shorter page only when needed to keep the
encoded frame within 64 KiB. The response carries a resumable cursor, and the
TUI reuses one connection for the complete snapshot. Each event subscriber has
a 512-event queue, large enough for a complete 256-rule learning batch plus
policy/counter headroom while remaining bounded.
Rule pages and events are redacted server-side for every observer whose peer UID
is not 0: application path, device/inode, command line, UID, cgroup, and the
potentially identifying rule name are replaced before serialization.

Before loading state or invoking nftables, every privileged daemon action takes
a nonblocking exclusive `flock` on the verified root-owned regular `0600`
`/run/openshield/daemon.lock`. The main process retains it for its complete
lifetime; `--install-fail-closed` uses the same lock for its transaction. The
lock pathname is opened with `O_NOFOLLOW|O_CLOEXEC`, its inode is never unlinked
by the daemon, and a second instance exits before it can change live policy or
replace IPC sockets. Socket cleanup records the filesystem device/inode created
by each listener and unlinks only that exact object.

Every control mutation carries `expected_revision`, captured when the operator
starts the edit. The engine compares it with current state before cloning,
validation, persistence, or nftables work. A mismatch returns `Conflict` with no
side effects. The TUI then requests a fresh snapshot and requires a new operator
action; it never silently retries a stale full-rule update. A transport timeout
or EOF after sending a command is treated as an unconfirmed outcome because the
daemon may have committed before its acknowledgement was lost. The TUI warns
against retrying and resynchronizes instead of claiming the change failed.

## Application attribution

An application selector is valid only on an outbound rule. The executable path
is mandatory, and every persisted selector must also contain its device/inode
file identity. Optional exact constraints are filesystem UID and cgroup path;
command arguments use token-preserving exact or prefix matching. All configured
network and application fields are ANDed. The daemon never executes the path and
does not support environment, regular-expression, parent-process,
persistent-PID, MD5, or SHA-1 selectors.

The cgroup identity is the path from exactly one unified cgroup v2 procfs entry
`0::/path`. Controller-specific cgroup v1 entries are ignored. Missing or
multiple unified entries, including a v1-only host, deny application attribution
even when a rule does not add an exact cgroup constraint.

This is process-metadata matching, not complete code identity. A dynamically
linked allowed executable can retain every selector field while loading
user-controlled code through `LD_PRELOAD`; interpreters, plugins, and JITs have
the same boundary. Stronger code identity requires an execution-domain control
outside this procfs selector design.

For a privileged manual mutation, the engine canonicalizes and opens a path
visible in its mount namespace before cloning persistent state. It records the
opened file's device/inode and rejects a conflicting supplied identity. A path
outside the daemon's namespace is accepted only with an explicit pair, which is
still compared with the queued process identity. Learned selectors contain the
observed path, device/inode, and filesystem UID.

Otherwise-unmatched application traffic enters the fixed NFQUEUE 1337 without
the nftables `bypass` flag. The kernel supplies a bounded packet prefix, socket
UID, and output-interface index. A single bounded consumer parses only TCP,
UDP, ICMP echo, and ICMPv6 echo, maps the tuple to exactly one procfs socket
inode, requires exactly one process owner, and captures identity with repeated
start-time, fd, executable, file-identity, and UID checks. Ambiguity, unsupported
traffic, malformed metadata, a 250 ms procfs deadline, or any configured bound
causes DROP. The owner search enumerates all `/proc/TGID/task/TID/fd` tables,
regardless of filesystem UID, and groups holders by TGID. Different TGIDs, a
cross-UID holder, an incomplete or unavailable live process/task scan, or
descriptor-bound exhaustion make the whole attribution fail closed. Sibling
holder TIDs in one TGID are accepted as one process only when their captured
executable/file, argv, filesystem-UID, and cgroup enforcement identities are
equal. A vanished procfs entry is skipped only after disappearance is confirmed.
`PermissionDenied` on a TGID leader's fd table is skipped only after two bounded
`stat` reads confirm stable zombie state `Z`; every other error, non-zombie
state, or unconfirmed state fails closed.
Before ACCEPT the current policy is checked again. Learning uses a
separate 512-item queue and persists at most 256 observations per batch.

The nftables output pipeline uses an early sanitization chain, the main policy
chain, and a late authorization chain. OpenShield reserves the upper two bits of
the 32-bit packet mark for its pending/handoff handshake and preserves the lower
30 bits through NFQUEUE, so existing lower-bit `fwmark` policy-routing and QoS
values are not discarded. The NFQUEUE ACCEPT leaves that packet mark unchanged,
and the daemon holds the policy-engine lock from its final generation recheck
through the synchronous verdict send/reinjection. The late chain accepts only
the expected internal domain and clears the reserved packet bits before the
packet leaves the pipeline.

Successful application authorization uses a conntrack cache only for TCP. For
TCP, the late chain writes the complete conntrack mark as an OpenShield domain
plus the current persisted, nonzero 30-bit policy generation. The original and
reply directions of an established TCP connection must carry that exact current
value. A mode change or rule mutation that can invalidate authorization advances
the generation without reuse, so an old conntrack entry alone does not keep the
connection authorized. The fast path also requires `ct state established`, so a
pre-set mark on NEW traffic cannot skip the application queue.

Application-bound UDP, ICMP echo, and ICMPv6 echo use no conntrack
authorization cache. Every otherwise-unmatched outbound packet is queued and
attributed again, and the late chain clears its complete conntrack mark after a
successful decision. This prevents a different process from inheriting an old
authorization by reusing a UDP five-tuple while its conntrack entry survives.
Replies to application-authorized UDP/ICMP traffic receive no implicit reverse
allow and therefore require an explicit matching inbound allow rule.

Generation exhaustion rejects mutations that need a new value; transition to
`BlockAll` remains available.

This means packet-mark interoperability and conntrack-mark interoperability are
different: the lower 30 packet-mark bits are preserved, but OpenShield uses all
32 conntrack-mark bits for application-authorized traffic. It stores the TCP
authorization value and clears the mark for UDP/ICMP. Another firewall, VPN,
QoS, or CONNMARK scheme using that conntrack mark can overwrite or be overwritten
by OpenShield and is not a supported combination. Other components must also
leave the upper two packet-mark bits unused. A privileged earlier CONNMARK rule
can still forge the current value on an already-established TCP flow, so
exclusive ownership and compatible hook ordering are security requirements,
not only compatibility advice.

Application rules are still allow rules, not negative overrides. A broader
network-only rule is emitted before the queue and can accept the same traffic
without application attribution. Operators must avoid such overlap when the
application identity is intended to be mandatory.

## Modes

`BlockAll`

: Input, output, and forward hooks use a drop policy. No local or forwarded IP
  traffic is permitted. Local Unix-socket control remains available.

`Learning`

: Otherwise-unmatched outbound TCP, UDP, ICMP echo, and ICMPv6 echo connections
  are accepted only after successful fail-closed application attribution. The
  daemon persists validated application-, protocol-, endpoint-, and
  interface-specific outbound allow rules. Unsupported or unattributable
  traffic is denied, not converted into a broad rule. New inbound connections
  remain default-deny; only explicit inbound rules can allow them.

`Enforcing`

: New inbound and outbound connections are default-deny. Enabled network-only
  rules are enforced directly by nftables; an application-bound outbound rule
  additionally requires the NFQUEUE identity match. There is no blanket
  established-flow exception, and related traffic requires an explicit rule.

The forward hook is always default-drop. Version 0.1 deliberately has no API for
forwarding exceptions.

Mode changes and rule changes are compiled into a complete policy, checked with
`nft --check`, and then applied as one nftables transaction. The dedicated table
is added, deleted, and recreated inside that atomic batch, which removes stale
objects without a visible unfiltered interval. The previous policy is retained
on validation or application failure. Runtime counters reset on a successful
replacement. State is stored using a same-directory temporary file, `fsync`,
and atomic rename; unsafe ownership, permissions, file types, and symbolic links
are rejected. A semantic 8 MiB encoded-state quota is checked before backend
application, independently of the 10,000-rule count limit. Rule ordering is
revision-based. If UTC moves backwards, rule
update timestamps are clamped to their prior value so clock correction cannot
make otherwise valid privileged mutations unavailable.

The monitor reads lightweight nftables table/chain/counter metadata once per
second rather than serializing every compiled rule. Application learning is fed
by the separate bounded NFQUEUE worker described above. Deduplication uses one
linear-time index, and one batch persists at most 256 new rules. Ten thousand
rules and 8 MiB are independent absolute state limits. If Learning reaches the
byte quota, it pauses that batch. After a save error it rereads authoritative
state: an exact previous snapshot is left untouched and learning pauses without
another write; a candidate or unknown result is rolled back. Only an ambiguous
result together with failed rollback escalates to `BlockAll`. This keeps health
and learning work bounded while still detecting a missing table, hook,
default-drop policy, or named counter.
The lightweight observation does not compare complete rule bodies; a privileged
targeted edit or additional allow can evade it.

## Trust boundaries

The daemon trusts the Linux kernel, nftables, the fixed system `nft` executable,
and UID 0. It does not load plugins, scripts, downloaded policy, eBPF objects, or
configuration-selected executables. User-provided values become nftables syntax
only after parsing into typed IP networks, ports, protocols, directions, and a
strictly validated interface name. Application values remain typed identity
data and are never interpreted as commands.

The packaged process retains `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`, and
`CAP_DAC_READ_SEARCH` so procfs access checks permit identity inspection across
local UIDs. Its syscall filter explicitly denies `ptrace`, `process_vm_readv`,
`process_vm_writev`, `kcmp`, `pidfd_getfd`, and `open_by_handle_at`, and it does
not normally read process memory or environments. This deny list is not memory
isolation: `CAP_SYS_PTRACE` can authorize a compromised daemon to open
`/proc/<pid>/mem`, after which ordinary read/write syscalls remain available.
Together with `CAP_DAC_READ_SEARCH`, procfs magic links such as
`/proc/<pid>/root` can also expose another process's mount view despite service
mount restrictions. The retained capabilities therefore materially expand the
impact of a daemon compromise and are inside the trusted computing base.

The observation API intentionally reveals firewall mode, rules, aggregate
one-second counters, and learned network endpoints to every local user, as
required. For a non-root observer, all application metadata and identifying rule
names are redacted by the daemon. UID 0 can read the full rule, including
bounded command-line selectors. Runtime attribution reads bounded procfs
identity metadata and a bounded queued-packet prefix, but never the process
environment; version 0.1 does not provide a per-packet capture feed.

## Failure policy

Network-only decisions stay in nftables. Initial application decisions use the
fixed bounded NFQUEUE, deliberately without queue bypass. A missing, overloaded,
or failed consumer therefore denies queued traffic instead of allowing it; a
terminal queue error asks the engine to install emergency `BlockAll` and stops
the daemon. A crashed or overloaded TUI has no effect on either path.

On every daemon start, the engine first installs kernel `BlockAll`, then loads
state, chooses a cryptographically random nonzero startup epoch from the lower
29 bits of the 30-bit flow-generation domain, and persists the new generation
before applying the saved policy. The value is forced to differ from the
previously persisted generation, so conntrack authorization marks from the
previous daemon process are invalid. This startup quarantine also applies when
the daemon is invoked directly without the packaged `ExecStartPre` helper.

Missing state is initialized as `BlockAll`. Invalid or unsafe existing state
causes the daemon to install `BlockAll`, keep IPC sockets closed, and exit with
failure. Automatic restart attempts continue to fail closed and cannot reach
readiness until the operator repairs the state. If runtime nftables objects
disappear, the monitor attempts to reinstall the current validated snapshot;
failure escalates to emergency `BlockAll`. The emergency state keeps the last
validated rules as policy data while its mode provides no accept path. If that
state is persisted, the daemon asks the service manager for a restart. If
persistence itself fails, it deliberately stays alive in a poisoned read-only
quarantine with kernel `BlockAll` active; automatically restarting could
otherwise load an ambiguous permissive file.

The packaged systemd unit also installs `BlockAll` in `ExecStartPre`. Its main
process uses `Type=notify` and sends `READY=1` only after the persisted policy is
active, the fail-closed NFQUEUE consumer is bound, and the fixed IPC sockets have
been verified. Its `[Install]` section contains
`RequiredBy=network-pre.target`; after `systemctl enable openshield-daemon`, that
success dependency combines with `Before=network-pre.target` so a standard
consumer cannot proceed through the target unless the daemon reaches readiness.

This boundary applies only after the unit is enabled and only to consumers that
honour `network-pre.target`. A network manager, unit, initramfs, or early packet
path that bypasses the target also bypasses the dependency. Strict whole-boot
enforcement therefore requires tested distribution-specific integration or an
initramfs policy.
