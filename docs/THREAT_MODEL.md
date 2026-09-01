[English](THREAT_MODEL.md) | [Русский](THREAT_MODEL.ru.md)

# Threat model

## Security objectives

1. A non-root local user cannot change firewall mode or rules.
2. A malformed, slow, or flooding observer cannot stop enforcement or consume
   unbounded memory, threads, or event queues.
3. Policy input cannot select commands, plugins, or executable code. An
   application path is identity data only and is never executed.
4. Failed parsing, persistence, identity attribution, or nftables updates
   preserve or strengthen the last known policy; they must not silently allow
   traffic.
5. New inbound traffic is denied unless an enabled inbound rule matches.
6. In enforcing mode, new outbound traffic is denied unless all fields of an
   enabled outbound rule match, including its application selector when present.
7. Missing, ambiguous, stale, unsupported, or over-limit application identity
   information results in DROP, not a network-wide fallback allow.
8. A non-root observer cannot obtain executable paths, device/inode identities,
   command arguments, UID or cgroup selectors, or identifying names of
   application-bound rules through the observation protocol.
9. Forwarded traffic is denied in every mode until a separately authenticated
   forwarding-rule design exists.

## Attacker model

The design assumes an attacker may:

- run arbitrary processes as any unprivileged local UID;
- choose command arguments and move a process within cgroups available to that
  user;
- inherit, duplicate, or pass socket descriptors and deliberately create
  ambiguous ownership;
- create many connections or processes to exhaust bounded attribution and
  learning capacity;
- create files and sockets in world-writable directories and modify files the
  attacker owns;
- connect repeatedly to the observation socket and send malformed frames;
- control remote endpoints and packet contents;
- supply every editable rule field through the TUI or protocol.

A compromised kernel, compromised UID 0, or a malicious replacement for the
root-owned system `nft` binary is outside this boundary. Such an attacker already
has authority equivalent to the firewall daemon. Compromise of the daemon itself
is addressed as a high-impact residual risk because its retained capabilities
are broader than nftables administration alone.

## Controls inherited from the OpenSnitch audit

- Sockets are under a verified root-owned directory, never predictable paths in
  `/tmp`; control also checks `SO_PEERCRED`.
- There is no unauthenticated TCP/gRPC management endpoint and no TLS fail-open
  mode.
- The protocol has bounded frames, connection limits, absolute request
  deadlines, and bounded subscriber queues. Observation uses 32 fixed workers,
  a 64-job queue, at most 24 public subscriptions (two per UID), and at most four
  connections per UID. One per-UID bucket has a 256-token burst, refills at 64
  tokens/s, and is charged both on connection acceptance and before each
  `Status`, `RulesPage`, or `Subscribe`; exhaustion closes the session. The
  connection state machine permits `Subscribe` only first,
  bounds pre-pagination `Status` requests to two, and then accepts only strictly
  advancing rule cursors. The server ignores smaller client limits, fetches up
  to 128 rules per cursor, and byte-shrinks only to fit the 64 KiB frame bound,
  returning a resumable cursor. A subscriber is disconnected if its bounded
  512-event queue fills.
- The daemon never accepts arbitrary task paths, logger paths, eBPF module paths,
  shell commands, or downloadable plugins. A validated application path is a
  bounded selector and is never invoked.
- Rule identifiers are UUIDs; display names are never filesystem paths.
- Persistence rejects symbolic links and uses fixed root-owned locations.
- Normal daemon code does not read process environments or process memory.
  Before serializing a response for a non-root observer, the daemon replaces the
  complete application selector and its potentially identifying rule name with
  fixed redacted values.
- Network-only decisions remain in default-drop nftables chains. Initial
  application decisions use the fixed NFQUEUE 1337 with no `bypass` flag, a
  maximum kernel queue length of 256 packets, and a 512-byte copy range.
- The queue consumer accepts only successfully parsed TCP, UDP, ICMP echo, and
  ICMPv6 echo traffic. It maps the kernel UID and network tuple to exactly one
  socket inode and one owner, then repeats process start-time, socket-fd,
  executable path, device/inode, command-line, cgroup, and filesystem-UID checks.
  It enumerates all `/proc/TGID/task/TID/fd` tables and groups holders by TGID.
  Different TGIDs, a cross-UID holder, an incomplete or unavailable live
  process/task scan, or descriptor-bound exhaustion produce DROP. Sibling
  holder TIDs in one TGID count as one process only if their captured
  executable/file, argv, filesystem-UID, and cgroup identities agree. A vanished
  entry is skipped only after procfs confirms disappearance. `PermissionDenied`
  on a TGID-leader fd table is skipped only after two bounded `stat` reads
  confirm stable zombie state `Z`; every other error, non-zombie state, or
  unconfirmed state produces DROP. Any remaining failure, ambiguity, configured
  bound, or 250 ms procfs deadline also produces
  DROP. The policy generation is rechecked under the engine lock, which remains
  held through the synchronous ACCEPT verdict and packet reinjection.
- The upper two packet-mark bits form an internal pending/handoff domain and are
  stripped from untrusted outbound marks; the lower 30 packet bits survive the
  complete NFQUEUE path. Successful established-TCP authorization writes a
  persisted, nonzero, non-reused 30-bit policy generation into the conntrack
  mark, binding both TCP directions and invalidating older connections after
  restrictive policy changes. UDP/ICMP uses no cache: every otherwise-unmatched
  outbound packet is re-attributed and its conntrack mark is cleared.
- A persisted application selector requires a canonical-looking absolute
  executable path and device/inode pair; a path visible to the daemon is
  canonicalized before persistence. Exact filesystem UID, exact unified-cgroup-v2
  path, and tokenized exact or prefix command-line constraints are optional;
  every supplied network and application field is combined with AND. Process
  cgroup identity comes from exactly one `0::/path` entry; v1 controller entries
  are ignored, while missing or multiple unified entries produce DROP.
- Stateful TCP reverse traffic is tied to the selectors of a live allow rule; an
  old conntrack entry alone is not an authorization in enforcing mode.
  Application-authorized UDP/ICMP replies require an independent inbound allow.
- Learned authorizations retain the observed application identity, protocol,
  endpoint, and outbound interface, so a VPN or link-local endpoint does not
  silently become allowed for another program or on every interface.
- Application learning uses a separate bounded 512-item queue, persists no more
  than 256 observations per batch, and cannot grow state beyond either 10,000
  rules or an exact 8 MiB encoded-state quota. Reaching the byte quota or a
  recoverable save failure pauses that learning batch and retains the previous
  state and active policy.
- Every daemon start first installs kernel `BlockAll`, chooses a cryptographically
  random nonzero startup epoch from the lower 29 bits of the 30-bit generation
  domain, persists it, and only then applies the saved policy. The new value is
  forced to differ from the previously persisted generation, invalidating TCP
  authorization marks from the previous daemon process.
- The packaged unit installs `BlockAll` before its main process and reports
  systemd readiness only after the selected policy, fail-closed queue consumer,
  and IPC endpoints are active. Once enabled, its
  `RequiredBy=network-pre.target` installation dependency and
  `Before=network-pre.target` ordering make standard consumers depend on that
  successful readiness; the scope limitation is recorded below.
- A verified root-owned `0600` singleton lock is acquired before any state or
  nftables mutation, including `--install-fail-closed`; stale socket cleanup is
  bound to the device/inode created by that daemon instance.
- Every root control mutation is conditional on its source snapshot revision.
  Concurrent or stale edits fail with `Conflict` before side effects, and the
  TUI resynchronizes without automatically replaying the rejected intent.
- A lost acknowledgement is not reported as a failed mutation: the TUI treats
  transport errors as ambiguous, warns against retrying, and reloads state.
- UTC rollback cannot invalidate a rule update: revisions define ordering and
  persisted `updated_at` values are kept monotonic.
- The packaged unit limits the daemon to `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`, and
  `CAP_DAC_READ_SEARCH`; its syscall filter denies `ptrace`,
  `process_vm_readv`, `process_vm_writev`, `kcmp`, `pidfd_getfd`, and
  `open_by_handle_at`.

## Residual risks

- The packaged `RequiredBy=network-pre.target` relationship is created by
  `systemctl enable`; merely installing the unit does not activate it. A network
  manager, unit, initramfs, or early packet path that bypasses
  `network-pre.target` also bypasses this dependency and may send traffic
  without OpenShield. Strict whole-boot enforcement requires tested
  distribution-specific integration or an initramfs policy.
- Every local user can see the deliberately public network observation feed.
  Application selectors and identifying application-rule names are redacted,
  but mode, network rules, endpoints, events, and aggregate counters may still
  be sensitive. Such systems should restrict the observation socket to a
  dedicated group rather than mode `0666`.
- Procfs attribution is a bounded, repeated post-hoc consistency check, not an
  atomic kernel record of the process generation that initiated an operation.
  In particular, a process can enqueue a packet and then exec an allowed image
  while retaining the socket; the resolver may observe only the post-exec image
  and authorize an operation initiated before exec. Repeated reads detect
  changes during the scan but cannot reconstruct sender/exec history. UDP
  `SO_REUSEPORT` groups and wildcard/specific binds under the same UID can also
  change the actual sender while tuple and UID observations remain compatible.
  The implementation does not provide an atomic sender record or cryptographic
  process attestation.
- An executable is identified by canonical path plus device/inode. The selector
  contains neither a content digest nor a mount-namespace identity, so in-place
  content changes and namespace/path aliasing are not distinguished. Script
  execution may identify the interpreter rather than the script the operator had
  in mind. Protect application files with root ownership and non-writable parent
  directories, and review rules after software updates.
- These fields identify observed process metadata, not all code executing inside
  that process. For example, `LD_PRELOAD=/tmp/evil.so /allowed/path` preserves
  the executable path, device/inode, argv, filesystem UID, and cgroup while a
  constructor can perform network I/O. Interpreters, plugins, and JIT-generated
  code have the same boundary; hashing only the main executable would not fix
  it. Strong code identity requires a trusted launcher/cgroup with
  user-controlled loaders disabled, or an LSM/IMA/eBPF execution domain.
- Command-line and cgroup values are mutable process metadata collected after a
  packet enters the queue. Repeated reads detect observed changes, but they do
  not make those values immutable. The UID selector is the numeric filesystem
  UID, not a real/effective/saved-UID tuple.
- Unified cgroup v2 is required for application attribution even when the rule
  omits a cgroup selector. A v1-only host therefore denies application-bound
  traffic; this is a fail-closed compatibility/availability limit, not a
  network-only-rule failure.
- At initial attribution, discovered stable shared, inherited, or
  `SCM_RIGHTS`-passed descriptors, including cross-UID ownership, are denied.
  The procfs view remains post-hoc and can race with the sender at send time;
  kernel-LSM sender attribution is not implemented. This preserves
  confidentiality at the cost of availability without claiming an atomic
  sender identity.
- Process identity is resolved for the first queued packet of an established TCP
  connection rather than every subsequent TCP packet. A later exec,
  filesystem-UID/cgroup change, or descriptor transfer can continue that
  connection until reconnection or a policy-generation change. UDP/ICMP is
  re-attributed for every outbound packet, but neither path is kernel
  exec-lifecycle enforcement.
- One bounded NFQUEUE consumer performs procfs work that is worst-case
  proportional to tasks times their per-task descriptor tables. Process/thread/fd floods,
  queue pressure, or the 250 ms deadline can therefore deny legitimate traffic.
  This is an availability/denial-of-service risk, not a fail-open path. Because
  an incomplete live process/task scan denies the whole decision, one oversized
  or inaccessible task descriptor table can affect all application attribution.
  An inaccessible non-zombie leader/task, a state that cannot be confirmed as a
  stable zombie, or an error other than `PermissionDenied` has the same
  fail-closed availability effect.
- `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH` are retained so the hardened service
  can inspect another UID's protected procfs metadata. Denying `ptrace` and
  `process_vm_*` does not provide memory isolation: a compromised daemon can use
  `CAP_SYS_PTRACE` to open `/proc/<pid>/mem` and then use ordinary read/write
  syscalls. `CAP_DAC_READ_SEARCH` can also bypass read/search permissions for
  files visible inside the service mount namespace, including system secrets;
  following `/proc/<pid>/root` and related procfs magic links may additionally
  reach a target process's mount view despite the service's mount hardening. The
  daemon therefore retains broader readable-procfs and filesystem access.
- Application rules are allow rules, not deny overrides. A broader matching
  network-only rule is evaluated before the application queue and can authorize
  the same traffic without application identity. Operators must avoid such
  overlap when application binding is intended to be mandatory.
- OpenShield temporarily reserves the upper two packet-mark bits and preserves
  the lower 30, but uses all 32 conntrack-mark bits for application-authorized
  traffic: it stores a TCP domain/generation and clears the mark for UDP/ICMP.
  Other packet-mark users must avoid those upper bits. Coexistence with another
  firewall, VPN, QoS, or CONNMARK writer on the same conntrack entry is
  unsupported and may break either policy. More seriously, a privileged earlier
  chain that copies an attacker-controlled `SO_MARK` into the conntrack mark
  before OpenShield's sanitizer can create the current domain/generation value
  and bypass the TCP application queue for an established flow. OpenShield
  requires exclusive conntrack-mark ownership and compatible hook ordering. An
  external asynchronous queue between its priority-0 policy chain and
  priority-1 late chain also breaks the engine-lock/reinjection timing
  assumption.
- A root user can intentionally install rules that cut off remote administration.
  The TUI requires confirmation for `BlockAll`, but root remains authoritative.
- nftables rules owned by other products may still drop traffic that OpenShield
  accepts. OpenShield never flushes tables it does not own.
- The fixed `nft` path is checked as a root-owned, non-symlink regular executable
  before later path-based spawns. A privileged package update or root process can
  replace it between validation and execution. This low-risk path TOCTOU is
  inside the already trusted UID-0/package-management boundary.
- Learning creates application-and-endpoint rules, not trust in remote content.
  A learned server or local executable can later become malicious, so learned
  entries should be reviewed. Any attributable local process can deliberately
  contact many endpoints and consume the bounded learning queue, 10,000-rule
  capacity, or 8 MiB state quota during a Learning window. The limits preserve
  memory/disk bounds but can cause learning to pause.
- Competing privileged firewall managers can delete OpenShield's table. The
  daemon attempts to repair detected loss, but they should not be run
  concurrently.
- A privileged `flush chain` leaves the base chain's default-drop policy in
  place, so it cannot create a fail-open path, but lightweight health checks do
  not reconstruct missing allow rules until a later policy apply or restart.
- Health monitoring checks table, base-chain, policy, and named-counter metadata,
  not complete rule bodies. A privileged targeted edit or additional allow rule
  can therefore evade detection. Such a `CAP_NET_ADMIN` peer is outside the
  unprivileged threat boundary and must not run concurrently.
- Strict inbound filtering can block required ICMPv6 neighbour/router discovery.
  Version 0.1 has no ICMP type/code selector; operators must scope explicit
  ICMPv6 allows by link-local network and interface where possible. Application
  attribution supports only echo requests for ICMP/ICMPv6.
- The `inet` table covers host IPv4/IPv6, not layer-2 ARP or direct frame
  injection by a privileged `AF_PACKET`/`CAP_NET_RAW` peer. OpenShield 0.1 is
  not an L2 firewall.
- If both a state transaction and emergency-state persistence fail, the daemon
  keeps kernel `BlockAll` active and enters read-only quarantine instead of
  restarting from an ambiguous file. Recovery then requires a local root
  operator to repair storage and deliberately replace or move aside the state
  file before restarting.
