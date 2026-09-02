[English](ARCHITECTURE.md) | [Русский](ARCHITECTURE.ru.md)

# OpenShield architecture

OpenShield is a Linux host firewall composed of two Rust binaries:

- `openshield-daemon` is the only component allowed to change the firewall. It
  owns either a dedicated `inet openshield` nftables table or the reserved
  `OPENSHIELD_*` iptables/ip6tables chains, and persists validated rules.
- `openshield-tui` displays status and events only to root or members of the
  `openshield` system group. Mutating controls are enabled only when the daemon
  authenticates the peer as UID 0.

The daemon never accepts TCP control connections. It exposes two local Unix
sockets below the root-owned `/run/openshield` directory:

| Socket | Mode | Operations |
| --- | ---: | --- |
| `control.sock` | UID 0, `0600` | change mode; create, update, enable, disable, or delete rules |
| `observe.sock` | `root:openshield`, `0660` | read a sanitized snapshot and subscribe to bounded events |

Filesystem permissions are defense in depth. Every connection is authenticated
with Linux `SO_PEERCRED`. Control is rejected unless the peer UID is 0.
Observation requires UID 0, a primary `openshield` GID, or a stable
supplementary-group match. For the latter, the daemon reads bounded procfs
credentials twice and verifies the process start time and effective credentials
against `SO_PEERCRED`; ambiguity denies access. Protocol messages use a
length-prefixed JSON frame with a
small fixed maximum size. Slow observers have bounded queues and are dropped,
so they cannot delay packet filtering or policy changes. The observation path
uses 32 fixed workers, a 64-job admission queue, at most 24 live observation
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
Rule pages and events are redacted server-side for every authorized observer
whose peer UID is not 0: application path, file-version identity, command line,
UID, cgroup, and the potentially identifying rule name are replaced before
serialization. Group membership grants no control-plane authority.
Authorization applies when the Unix connection is accepted; Unix fd passing can
delegate an already-connected observation stream, so group access is not a
non-delegable confidentiality boundary.

Before loading state or invoking a firewall backend, every privileged daemon action takes
a nonblocking exclusive `flock` on the verified root-owned regular `0600`
`/run/openshield/daemon.lock`. The main process retains it for its complete
lifetime; `--install-fail-closed` uses the same lock for its transaction. The
lock pathname is opened with `O_NOFOLLOW|O_CLOEXEC`, its inode is never unlinked
by the daemon, and a second instance exits before it can change live policy or
replace IPC sockets. Socket cleanup records the filesystem device/inode created
by each listener and unlinks only that exact object.

Every control mutation carries `expected_revision`, captured when the operator
starts the edit. The engine compares it with current state before cloning,
validation, persistence, or backend work. A mismatch returns `Conflict` with no
side effects. The TUI then requests a fresh snapshot and requires a new operator
action; it never silently retries a stale full-rule update. A transport timeout
or EOF after sending a command is treated as an unconfirmed outcome because the
daemon may have committed before its acknowledgement was lost. The TUI warns
against retrying and resynchronizes instead of claiming the change failed.

## Application attribution

An application selector is valid only on an outbound rule. The executable path
is mandatory, and every persisted selector must also contain its file-version
identity: device, inode, size, and ctime seconds and nanoseconds. Optional exact
constraints are filesystem UID and cgroup path; command arguments use
token-preserving exact or prefix matching. All configured network and application
fields are ANDed. The daemon never executes the path and does not support
environment, regular-expression, parent-process, persistent-PID, MD5, or SHA-1
selectors.

On a cgroup v2 host, the cgroup identity is the path from exactly one unified
procfs entry `0::/path`; missing or multiple unified entries deny attribution.
On a v1-only host, the resolver validates the bounded controller memberships but
returns an empty cgroup identity. Executable path, full file-version identity,
filesystem-UID, and argv attribution therefore remains available, while a rule
that explicitly requires a cgroup path fails closed. A cgroup-path selector
requires unified cgroup v2; application attribution as a whole does not.

This is process-metadata matching, not complete code identity. A dynamically
linked allowed executable can retain every selector field while loading
user-controlled code through `LD_PRELOAD`; interpreters, plugins, and JITs have
the same boundary. Stronger code identity requires an execution-domain control
outside this procfs selector design.

For a privileged manual mutation, the engine must resolve the path inside its own
mount namespace. It canonicalizes the path, opens the canonical target read-only
with `O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK`, requires a regular file, then repeats the
canonicalization and open while retaining both handles and performs a final path
check. The canonical path and all five file-version fields must remain stable.
The daemon fills an omitted pin and rejects a conflicting supplied pin; an
unresolvable path is rejected even when the client supplies an identity. Learned
selectors contain the observed path, complete file version, filesystem UID,
exact tokenized argv, and the single unified-cgroup-v2 path when one is
available. On a v1-only host the learned cgroup field is absent.
The TUI omits a pin for a new or changed path so the daemon can derive it; an edit
that preserves the path carries the old complete pin for stale-version rejection.
Serialized application rules that contain only the older device/inode pair fail
closed and must be reviewed and recreated; network-only state is unaffected.

Otherwise-unmatched application traffic enters the fixed NFQUEUE 1337 without
a fail-open queue-bypass flag. The kernel supplies a bounded packet prefix, socket
UID, and output-interface index. A single bounded consumer parses only TCP,
UDP, ICMP echo, and ICMPv6 echo, maps the tuple to exactly one procfs socket
inode, requires exactly one process owner, and captures identity with repeated
start-time, fd, executable path, complete file-version, UID, argv, and cgroup
checks. Ambiguity, unsupported traffic, malformed metadata, a 250 ms procfs
deadline, or any configured bound causes DROP. After an attribution attempt has
resolved one socket inode, its owner search performs a fresh bounded enumeration
of external PID/TID entries, reads each task's filesystem UID, and scans
`/proc/TGID/task/TID/fd` only when that UID equals the kernel socket UID. It does
not retain a process identity or authorization result across packets. Matching
holders are grouped by TGID. The absence of a matching-UID holder, different
matching TGIDs, an incomplete or unavailable live process/task scan, or candidate
descriptor-bound exhaustion makes the attribution fail closed. Sibling holder
TIDs in one TGID are accepted as one process only when their captured executable
path/file version, argv, filesystem-UID, and cgroup enforcement identities are
equal.

The daemon's own TGID is handled separately because its standard Rust threads
share one descriptor table. When its filesystem UID equals the kernel socket UID,
the resolver performs a bounded check of `/proc/<self>/fd` immediately before
external-owner enumeration and another after that enumeration completes. These
are two shared-table checks on a completed owner scan instead of one scan per
daemon thread. Finding the target socket or failing either inspection fails
closed, and the daemon's per-thread fd paths are never accepted as application
owners.
This optimization is valid only while daemon threads retain the standard shared
file table and do not receive file descriptors from another process or change
filesystem UID independently; introducing `unshare(CLONE_FILES)`/
`CLOSE_RANGE_UNSHARE`, cross-process descriptor receipt, or per-thread
filesystem-UID changes requires re-auditing and, if the invariant no longer
holds, redesigning it.
The normal cross-UID exclusion applies when the UIDs differ. For an external
owner, the descriptor number found for one task is tried first for later
matching-UID tasks in the same scan. Only an exact target-symlink match followed
by a repeated filesystem-UID check is accepted; any mismatch or read error falls
back to that task's complete bounded fd-table scan. This local hint is not
retained across packets. The exact fd path found by the ownership scan is
likewise only a performance hint:
runtime capture revalidates its symlink before reading identity metadata, falls
back to a bounded rescan of that same task's fd table when the hint vanished or
no longer names the target, and rechecks the selected symlink after identity
capture. A revalidation or fallback error fails closed. A vanished procfs entry
is skipped only after disappearance is confirmed.
`PermissionDenied` on a TGID leader's fd table is skipped only after two bounded
`stat` reads confirm stable zombie state `Z`; every other error, non-zombie
state, or unconfirmed state fails closed.
For runtime capture, `/proc/TID/exe` is opened and its complete file version is
compared with a second path/open snapshot together with the remaining process
metadata. Before issuing a successful backend-specific verdict, the engine
rechecks only the current mode and generation under its lock. Its immutable
`Arc<ApplicationDecisionPolicy>` packet-policy
cache contains only enabled application rules in `Enforcing` and is empty in
`Learning` and `BlockAll`; it is rebuilt after a successful policy or learning
commit. The per-packet snapshot acquisition is therefore an O(1) `Arc` clone
instead of a clone of the complete state. The cache indexes rules by the complete
executable file version. A lookup scans only the policy-ordered candidate vector
for that exact version rather than all application rules. A root-edited or legacy
state can still place many rules under one pin, so candidate matching is linear
within that bucket. Learning uses a separate 512-item queue and persists at most
256 observations per batch. This is a rule-index cache, not a process-identity or
authorization-result cache. Apart from the established-TCP conntrack-generation
fast path described below, every queued packet still receives fresh attribution.

Both backend compilers implement an early mark-sanitization step, the main
policy path, and a late authorization path. OpenShield reserves the upper two bits of
the 32-bit packet mark for its pending/handoff handshake and preserves the lower
30 bits through NFQUEUE, so existing lower-bit `fwmark` policy-routing and QoS
values are not discarded. On nftables, an `NF_ACCEPT` verdict leaves the pending
mark unchanged and processing continues into the later authorization base chain.
On iptables, `NF_ACCEPT` would terminate the filter hook, so the daemon returns
`NF_REPEAT` with an authenticated handoff mark; the first rule on the repeated
OpenShield OUTPUT path consumes that domain and transfers control to the
protocol-specific authorization chain. The daemon holds the policy-engine lock
from its final mode/generation recheck through verdict delivery and reinjection.
The netlink verdict socket is nonblocking: send-buffer exhaustion fails the
operation and triggers emergency quarantine instead of blocking every control
operation while the engine lock is held. Both backend paths clear the reserved
packet bits before the packet leaves the pipeline.

Successful application authorization writes an OpenShield domain plus the
current persisted, nonzero 30-bit policy generation into the low 31 conntrack
mark bits while preserving bit 31. TCP uses those low bits as a cache: the
original and reply directions of an established connection must carry that
exact current value. A mode change or rule mutation that can invalidate
authorization advances the generation without reuse, so an old conntrack entry
alone does not keep the connection authorized. The fast path also requires
`ct state established`, so a pre-set mark on NEW traffic cannot skip the
application queue.

Application-bound UDP, ICMP echo, and ICMPv6 echo do not use the mark as an
outbound cache. Before every original packet, the policy clears OpenShield's low
31 conntrack bits while preserving bit 31, then queues and attributes the packet
again. Successful authorization refreshes the current low-31-bit generation so
the matching reply can be accepted. This prevents another process from
inheriting an outbound authorization by reusing a UDP five-tuple while retaining
the unrelated high conntrack bit.

The persisted 30-bit generation advances monotonically by one and is never
reused before exhaustion. Exhaustion rejects mutations that need a new value;
transition to `BlockAll` remains available.

Packet-mark and conntrack-mark interoperability therefore differ. OpenShield
reserves the upper two packet-mark bits and preserves the lower 30. In the
conntrack mark it reserves the low 31 bits and preserves bit 31. Another
firewall, VPN, QoS, or CONNMARK scheme using those low conntrack bits can
overwrite or be overwritten by OpenShield and is not a supported combination;
coexistence is possible only for the preserved high bit after hook ordering has
been reviewed. Other components must also leave the upper two packet-mark bits
unused. A privileged earlier CONNMARK rule can still forge the current low-31-bit
value on an already-established TCP flow, so exclusive ownership of those bits
and compatible hook ordering are security requirements, not only compatibility
advice.

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
  interface-specific outbound allow rules. The application selector pins the
  observed path/version, filesystem UID, exact argv, and available unified-v2
  cgroup path. Unsupported or unattributable
  traffic is denied, not converted into a broad rule. New inbound connections
  remain default-deny; only explicit inbound rules can allow them.

`Enforcing`

: New inbound and outbound connections are default-deny. Enabled network-only
  rules are enforced directly by the selected backend; an application-bound outbound rule
  additionally requires the NFQUEUE identity match. There is no blanket
  established-flow exception, and related traffic requires an explicit rule.

In `BlockAll`, the forward path drops before delegation. In `Learning` and
`Enforcing`, OpenShield returns forwarded traffic to the pre-existing firewall
policy; it neither accepts forwarded traffic nor provides forwarding-rule CRUD.

Mode and rule changes are compiled into a complete backend policy. The preferred
nftables path checks it with `nft --check`, then replaces the dedicated table in
one atomic transaction. The compatibility path uses fixed, validated
`iptables`/`ip6tables` command, restore, and save bundles. It owns only
`OPENSHIELD_*` chains, installs first-position dispatch jumps in the built-in
INPUT, OUTPUT, and FORWARD chains, and uses restore with `--noflush`. Because
xtables cannot atomically update IPv4 and IPv6 together, both families enter
`BlockAll` before the two validated family transactions; a replacement can
temporarily deny traffic but must not create a cross-family authorization
window. An apply or verification failure escalates back to emergency `BlockAll`.
Runtime counters reset on a successful replacement. State is stored in the
root-owned `0600` `/var/lib/openshield/state.json` using a same-directory
temporary file, `fsync`, and atomic rename; unsafe ownership, permissions, file
types, and symbolic links are rejected. Exact argv in learned selectors can
contain secrets, so this file and its backups are confidential; non-root
observation redacts application selectors. A semantic 8 MiB encoded-state quota is checked before backend
application, independently of the 10,000-rule total count limit. Automatic
insertion stops when the state already contains 7,500 learned rules, normally
leaving 2,500 count slots for privileged manual rules; this admission budget is
not a validation invariant for root-edited or legacy state. Root can still fill
the total limit through manual mutations. Rule ordering is
revision-based. If UTC moves backwards, rule
update timestamps are clamped to their prior value so clock correction cannot
make otherwise valid privileged mutations unavailable.

The monitor reads bounded backend-specific chain and counter state once per
second rather than serializing every compiled rule. The iptables path compares
the complete OpenShield-owned rules with the last verified transaction;
the nftables path verifies the owned table, base hooks, default-drop policies,
and named counters. Application learning is fed
by the separate bounded NFQUEUE worker described above. Deduplication builds one
O(N) index for the batch, and one batch persists at most 256 new rules. Automatic
insertion also stops at 512 learned rules per filesystem UID and 256 per pair of
filesystem UID and full executable file-version identity. These are admission
budgets, not absolute state invariants. They use the numeric filesystem UID;
distinct subordinate UIDs count independently and can distribute learning until
the global budget is reached. The engine keeps a second immutable
`ApplicationLearningAdmissionIndex` and rebuilds it together with the packet
policy at startup and after every successful normal, learning, or emergency state
replacement. After mandatory race-checked procfs attribution, it rechecks poison
state, mode, generation, index revision, and persistence status under the engine
lock. The index recognizes exact learned outbound keys and the total, global
learned, per-filesystem-UID, and per-UID/file-version counts. Exact-known,
saturated, and persistence-paused observations are allowed by the active
`Learning` decision without entering the 512-item queue; only a potential new
candidate is enqueued, and queue full/disconnect remains fail-closed. The worker
also coalesces exact duplicates in each bounded 256-observation drain. This keeps
known or necessarily discarded observations from consuming queue capacity, but
does not avoid their procfs attribution. A saturated endpoint has no new rule
persisted, so the same traffic is denied after a switch to Enforcing unless
another rule matches. Ten thousand total rules
and 8 MiB are independent absolute state limits. Reaching the byte quota or a
recoverable save failure discards the current batch and pauses all further
automatic learning in that daemon process until a successful privileged policy
mutation or a restart; the active `Learning` traffic behavior remains in force.
An argv or unified-v2 cgroup change creates a distinct candidate rather than
widening an existing learned selector. Operators must therefore conduct Learning
in a controlled window and review its exact selectors before Enforcing.
After a save error the daemon rereads authoritative state: an exact previous
snapshot is left untouched, while a candidate or unknown result is rolled back.
Only an ambiguous result together with failed rollback escalates to `BlockAll`. This keeps health
and learning work bounded. The nftables lightweight observation does not compare
complete rule bodies; a privileged targeted edit or additional allow can evade
it. The iptables comparison is stricter for owned chains, but no monitor makes
arbitrary concurrent privileged firewall editors a supported configuration.

## Trust boundaries

The daemon trusts the Linux kernel, UID 0, and the selected fixed system backend
executables. nftables is preferred only after a kernel validation probe. The
fallback requires complete trusted IPv4 and IPv6 xtables bundles. Executable
paths come from compiled allowlists, are metadata-checked, and are invoked with a
cleared environment and typed arguments, never a shell. The daemon does not load
plugins, scripts, downloaded policy, eBPF objects, or configuration-selected
executables. User-provided values become firewall syntax only after parsing into
typed IP networks, ports, protocols, directions, and a strictly validated
interface name. Application values remain typed identity data and are never
interpreted as commands.

The packaged systemd process retains `CAP_NET_ADMIN`, `CAP_NET_RAW`,
`CAP_SYS_PTRACE`, and `CAP_DAC_READ_SEARCH`. It keeps primary group `root` and
explicitly adds `openshield` as a supplementary group. As the socket owner it
assigns that group to a new observation socket without `CAP_CHOWN`. Legacy
xtables needs `CAP_NET_RAW` to open the
raw IPv4/IPv6 sockets used for alternate-backend inspection and fallback;
the last two capabilities let procfs access checks permit identity inspection
across local UIDs. Its syscall filter explicitly denies `ptrace`, `process_vm_readv`,
`process_vm_writev`, `kcmp`, `pidfd_getfd`, and `open_by_handle_at`, and it does
not normally read process memory or environments. This deny list is not memory
isolation: `CAP_SYS_PTRACE` can authorize a compromised daemon to open
`/proc/<pid>/mem`, after which ordinary read/write syscalls remain available.
Together with `CAP_DAC_READ_SEARCH`, procfs magic links such as
`/proc/<pid>/root` can also expose another process's mount view despite service
mount restrictions. The retained capabilities therefore materially expand the
impact of a daemon compromise and are inside the trusted computing base.

The observation API reveals firewall mode, rules, aggregate one-second counters,
and learned network endpoints only to root and members of `openshield`. For an
authorized non-root observer, all application metadata and identifying rule
names are redacted by the daemon. UID 0 can read the full rule, including
bounded command-line selectors. Runtime attribution reads bounded procfs
identity metadata and a bounded queued-packet prefix, but never the process
environment; version 0.1 does not provide a per-packet capture feed.

## Failure policy

Network-only decisions stay in the selected kernel backend. Initial application decisions use the
fixed bounded NFQUEUE, deliberately without queue bypass. A missing, overloaded,
or failed consumer therefore denies queued traffic instead of allowing it; a
terminal queue error asks the engine to install emergency `BlockAll` and stops
the daemon. A crashed or overloaded TUI has no effect on either path.

On every daemon start, the engine first installs kernel `BlockAll`, then loads
state, increments the persisted nonzero 30-bit flow generation by exactly one,
and persists it before applying the requested policy. The monotonic counter is
not reused before exhaustion, so conntrack authorization marks from every
earlier daemon process are invalid. Exhaustion retains `BlockAll` and fails
startup instead of wrapping. This startup quarantine also applies when the
daemon is invoked directly without the packaged `ExecStartPre` helper.

Missing state is initialized and persisted as `Learning`, while kernel
`BlockAll` remains active until that new policy can be activated. Invalid or
unsafe existing state causes the daemon to retain `BlockAll`, keep IPC sockets
closed, and exit with failure. Automatic restart attempts continue to fail
closed and cannot reach readiness until the operator repairs the state. If
runtime backend objects disappear or differ from verified invariants, the
monitor attempts to reinstall the current validated snapshot;
failure escalates to emergency `BlockAll`. The emergency state keeps the last
validated rules as policy data while its mode provides no accept path. If that
state is persisted, the daemon asks the service manager for a restart. If
persistence itself fails, it deliberately stays alive in a poisoned read-only
quarantine with kernel `BlockAll` active; automatically restarting could
otherwise load an ambiguous permissive file.

Graceful daemon shutdown installs kernel `BlockAll` without persisting a mode
change. The systemd, OpenRC, SysVinit, runit, s6, and dinit integrations provide
corresponding pre-start and post-stop quarantine hooks. Their ordering is a
service-manager boundary, not proof of coverage for initramfs or early traffic.

The packaged systemd unit also installs `BlockAll` in `ExecStartPre` and
`ExecStopPost`. Its main
process uses `Type=notify` and sends `READY=1` only after the persisted policy is
active, the fail-closed NFQUEUE consumer is bound, and the fixed IPC sockets have
been verified. It requires `systemd-tmpfiles-setup.service`; the package's
tmpfiles rules create root-owned runtime/state directories and the standard
`0600` `/run/xtables.lock`, then relabel those exact paths without recursively
touching their contents. The unit grants write access only to those paths
instead of all of `/run` or `/var/lib`.
Its `[Install]` section contains
`RequiredBy=network-pre.target`; after `systemctl enable openshield-daemon`, that
success dependency combines with `Before=network-pre.target` so a standard
consumer cannot proceed through the target unless the daemon reaches readiness.

This boundary applies only after the unit is enabled and only to consumers that
honour `network-pre.target`. A network manager, unit, initramfs, or early packet
path that bypasses the target also bypasses the dependency. Strict whole-boot
enforcement therefore requires tested distribution-specific integration or an
initramfs policy.
