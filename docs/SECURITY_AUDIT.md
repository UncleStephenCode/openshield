[English](SECURITY_AUDIT.md) | [Русский](SECURITY_AUDIT.ru.md)

# Security audit status

Review snapshot: 2026-09-02, OpenShield 0.1.14, Rust stable 1.98.0.

This document records the controls found in the current tree, the evidence that
has actually been collected, and the remaining security boundaries. It is not a
formal certification and does not claim that the software is free of defects.
The normative boundary is defined by the
[threat model](THREAT_MODEL.md) and [architecture](ARCHITECTURE.md).

## Implemented controls

### Local authorization and bounded IPC

- Policy mutation is available only through `/run/openshield/control.sock`.
  The socket is `root:root` `0600`, and the daemon additionally requires Linux
  `SO_PEERCRED` UID 0. Filesystem permissions are therefore not the sole
  authorization check.
- Read-only observation uses `/run/openshield/observe.sock`, owned by
  `root:openshield` with mode `0660`. The daemon accepts root, a peer whose
  primary GID is `openshield`, or a peer whose bounded, stable procfs credential
  check confirms supplementary membership. Credentials must remain consistent
  with `SO_PEERCRED`. Monitoring is not available to an arbitrary local user.
- A non-root observer receives a redacted snapshot: application selectors and
  identifying application-rule names are replaced before serialization.
  Network rules, endpoints, events, mode, and aggregate counters remain visible
  to authorized group members.
- IPC messages are strictly typed and reject unknown fields. Frames, clients,
  worker queues, subscriptions, event queues, pagination, reads, writes, and
  per-UID work rates are bounded. Slow or malformed observers are disconnected
  without blocking the policy engine.
- Every privileged mutation includes an expected revision. A stale request is
  rejected before state, backend, or event side effects. A lost reply is treated
  by the TUI as an unconfirmed outcome followed by a snapshot refresh, not as a
  safe invitation to repeat the mutation.

### Policy construction and firewall backends

- Workspace code forbids unsafe Rust. Policy data cannot select a shell command,
  plugin, downloaded policy, eBPF object, or executable to run. An application
  path is a bounded identity selector only.
- Backend selection is deterministic. A trusted and usable nftables executable
  is preferred. The daemon selects the iptables/ip6tables compatibility backend
  only if the nftables capability probe fails, and fails startup if neither
  complete backend is safe to use.
- Backend programs are selected from fixed absolute allowlists and must be
  root-owned, safely permissioned, regular executable files. Commands run with a
  cleared environment, fixed working directory, bounded input/output, and
  deadlines.
- The nftables compiler emits validated syntax and checks it before an atomic
  transaction. It owns only `table inet openshield` and verifies its ownership
  sentinel before replacement.
- The compatibility compiler emits complete IPv4 and IPv6 restore programs. It
  uses `--noflush`, owns only `OPENSHIELD_*` chains, verifies ownership and full
  installed rule bodies, and keeps its dispatch jumps first in the relevant
  built-in chains. It refuses ambiguous coexistence with old OpenShield
  artifacts in nftables or another xtables implementation.
- An installed legacy userspace frontend whose kernel protocol is unavailable
  is treated as an empty alternate xtables world only after both `filter` and
  `mangle` inspections return the exact bounded `ENOPROTOOPT` diagnostic with
  an empty stdout. Mixed results, permission failures, timeouts, malformed or
  oversized output, and every other error remain fail-closed.
- xtables has no transaction that spans IPv4 and IPv6. OpenShield therefore
  validates both programs and puts both families into `BlockAll` before applying
  either requested policy. Failure can cause temporary denial but must not
  create a cross-family authorization window; verification failure triggers an
  emergency `BlockAll` attempt.
- New local inbound traffic is default-deny and requires an explicit enabled
  inbound allow. Outbound behavior follows the selected mode. `BlockAll` also
  drops forwarded traffic; `Learning` and `Enforcing` return forwarded traffic
  to the pre-existing firewall policy instead of granting it or managing
  forwarding rules.
- NFQUEUE 1337 is installed without a fail-open bypass. Kernel queue length,
  packet copy length, procfs work, and attribution time are bounded. Parse,
  ownership, identity, ambiguity, or terminal queue failures deny traffic or
  request emergency `BlockAll`.
- The engine rechecks mode and generation under its lock through verdict
  delivery and reinjection. nftables uses `NF_ACCEPT` followed by its later
  authorization base chain; iptables uses `NF_REPEAT` with an authenticated
  `NFQA_MARK` handoff consumed by the first repeated OpenShield OUTPUT rule.
  Verdict delivery is nonblocking, and a terminal send error requests emergency
  `BlockAll` instead of indefinitely retaining the policy lock.

### Application identity and learning

- An outbound persisted application selector requires a canonical absolute
  executable path plus its complete file-version tuple: device, inode, size,
  and ctime seconds and nanoseconds. Optional filesystem UID, tokenized exact or
  prefix argv, cgroup path, and all network fields are combined with logical AND.
  The selected path is never executed.
- For a manual create/update, the daemon resolves the path in its own mount
  namespace, performs repeated canonicalization and read-only regular-file opens
  with `O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK`, and requires the canonical path and all
  five version fields to remain stable. It fills an omitted pin and rejects a
  stale supplied pin. Older two-field persisted application identities are
  rejected rather than silently repinned; network-only state is unaffected.
- Attribution maps the queued packet tuple and kernel UID to one socket inode
  and one stable process identity. It scans bounded fd tables only for tasks
  whose filesystem UID equals the kernel socket UID, groups matching holders by
  TGID, and rechecks process start time, executable path and full file version,
  argv, cgroup, UID, and socket ownership. No matching-UID holder, multiple
  matching TGIDs, incomplete scans, unstable identities, or exhausted bounds are
  denied.
- On cgroup v2, exactly one unified `0::/path` entry supplies the cgroup
  identity. On a v1-only host, bounded controller memberships are validated but
  no cgroup identity is returned. Executable path, full file version, filesystem
  UID, and argv attribution still work; an explicit cgroup-path selector fails
  closed.
- Authorized established TCP traffic is tied to the current nonzero policy
  generation. Policy-invalidating changes increment that generation by one. UDP and ICMP
  are attributed per otherwise-unmatched outbound packet; successful attribution
  refreshes the current generation for its reply, while unsolicited inbound
  traffic still needs an explicit allow.
- `Learning` creates only successfully attributed, exact
  application/protocol/endpoint/interface permits. A bounded learning queue,
  batch limit, and deduplication bound work. Automatic insertion stops when
  existing learned counts reach 7,500 globally, 512 per filesystem UID, or 256
  per pair of filesystem UID and complete executable file version. These are
  admission budgets, not validation invariants for legacy or root-edited state;
  distinct subordinate UIDs count separately. The total limit remains 10,000
  rules, normally reserving 2,500 count slots for privileged manual rules; the
  independent 8 MiB semantic-state limit also applies. Unsupported protocols do not become broad
  `Any` rules. A revision-checked immutable index classifies each successfully
  attributed observation before queue admission. Exact-known, saturated, and
  persistence-paused observations keep the current Learning allow without
  entering the queue; only a potential new candidate consumes a slot, and the
  worker coalesces exact duplicates in each bounded drain. A policy/cache mismatch
  or full/disconnected queue for a candidate fails closed. At a learning quota,
  no permit is persisted for Enforcing.

### State, startup, shutdown, and packaging

- State storage is bounded and root-owned, rejects links and unsafe metadata,
  and uses a same-directory temporary file, `fsync`, and atomic rename.
  Ambiguous persistence or rollback outcomes escalate to kernel `BlockAll` or a
  read-only recovery state.
- A direct daemon start acquires a root-owned singleton lock, discovers a
  trusted backend, and installs bootstrap `BlockAll` before inspecting state or
  constructing the fallible runtime. If no state exists, the first requested
  state persisted by the daemon is `Learning`. The bootstrap policy is
  temporary and does not overwrite that requested mode.
- Startup increments the persisted nonzero 30-bit policy generation by exactly
  one before the requested policy is activated. Values are not reused before
  exhaustion; exhaustion retains `BlockAll` and fails startup rather than
  wrapping. Readiness is announced only after the policy, fail-closed queue
  consumer, and verified IPC sockets are active.
- Graceful daemon shutdown and packaged post-stop hooks reinstall kernel
  `BlockAll` without replacing the saved requested mode.
- Service definitions are provided for systemd, OpenRC, SysVinit, runit, s6, and
  dinit. They install pre-start and post-stop quarantine around the supervised
  daemon. This ordering does not cover initramfs or packet paths that bypass the
  chosen init system.
- `packaging/stage-install.sh` stages into an existing package root and refuses
  `/`, `..`, lexical symlink components, foreign-owned objects,
  group/world-writable directories, and multiply linked regular files. Before
  every write it validates canonical ancestry as caller- or system-owned and
  safely permissioned, with the conventional system-owned sticky `/tmp`
  exception. Its probes stop at the first rejected object. It never enables or
  starts a service on the host.
- The systemd service retains `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`, and
  `CAP_DAC_READ_SEARCH` and denies several process-memory syscalls. A tmpfiles
  rule creates the standard root-owned `0600` `/run/xtables.lock`; the unit
  requires tmpfiles setup and makes only that shared lock, rather than all of
  `/run`, additionally writable. This preserves serialization with other
  xtables processes. The unit reduces attack surface but is not a sandbox
  against a compromised daemon.

## Verification evidence

The evidence layers below are intentionally separate. Passing one layer does not
establish the properties of another.

- Final Rust 1.98.0 verification passed `cargo fmt --all -- --check`, locked
  workspace all-target checks, workspace all-target clippy with warnings denied,
  and all 247 workspace tests: 55 core, 129 daemon, 11 protocol, and 52 TUI.
  This includes automatic-learning budgets, version pinning, fsuid-prefilter,
  and immutable policy-index cases. Daemon tests used mock backends and temporary
  Unix sockets and did not touch the host firewall. These are component results,
  not a live-firewall result.
- `cargo-audit` checked the current 152-dependency lock graph against 1,235
  advisories from the RustSec database revision dated 2026-09-01 and reported no
  applicable advisory. The offline cargo-deny advisories, bans, licenses, and
  sources checks passed; only the two explicitly allowed duplicate-version
  warnings for `hashbrown` and `syn` remained.
- Both final static-PIE musl binaries completed a no-network, read-only,
  capability-free `--version` smoke test in all 60 rows of
  `tests/compat/distros.tsv`. This establishes startup compatibility of those
  artifacts with the selected container userspaces, not firewall operation or
  certification of 60 distributions.
- `cargo check --workspace --all-targets --locked` completed for all 21 Linux
  targets whose standard libraries were available from stable Rust 1.98.0. The
  two recorded RISC-V 32 targets are Tier 3 and were skipped because stable
  rustup does not provide their standard libraries; a separately reviewed
  nightly `build-std` workflow would be required.
- The cross-target jobs were compilation checks, not links or hardware runs.
  In particular, arm64 execution was unavailable on the test host because it
  had no binfmt/QEMU handler.
- Static staging checks covered all six init layouts. Isolated container
  parser/supervisor fixtures passed for OpenRC, SysVinit, runit, s6, and dinit,
  including lifecycle quarantine and group creation. systemd is staged and
  analyzed separately rather than booted as PID 1 in that container matrix. The
  staged unit with target stubs passed `systemd-analyze verify`; offline
  `systemd-analyze security --offline=yes --threshold=100` passed with exposure
  2.6 (`OK`).
  Alpine/BusyBox also executed the staging helper, and unsafe staging-tree
  fixtures, including symlink and writable-parent cases, were rejected. A
  rooted tmpfiles dry run parsed the shared-lock declaration. These are
  static/unit-fixture results, not a systemd boot or packet-filtering run.
- The TUI suite covers all 31 locale resources with 183 messages each and
  verifies exact key, placeholder, and newline parity. No non-English value is
  exactly equal to its English counterpart. A second regression checks every
  unordered locale pair and, after excluding placeholders and common protocol
  or product identifiers, permits at most 24 nontrivial short exact matches and
  four substantive exact matches per pair. Twelve proposed resources with 29
  to 119 Russian copies were removed rather than presented as complete
  translations. A later forensic comparison also removed `os`, `inh`, `bua`,
  `xal`, `ady`, and `kjh` after finding large cross-language copied blocks. The
  TUI all-target clippy run with warnings denied and package formatting check
  also passed. These mechanical checks detect structural and bulk-copy errors;
  they are not linguistic certification or a substitute for native technical
  review.
- `tests/e2e/server-learning-enforcing.sh` defines separate disposable nftables
  and iptables workflows for observation authorization, Learning, application
  attribution, Enforcing, coexistence, inbound allow, shutdown quarantine, and
  restart. Final Rust 1.98.0 Debian Bookworm release runs passed for both
  backends and printed:

  ```text
  PASS server Learning -> UDP/TCP Enforcing -> inbound allow -> restart (nftables)
  PASS server Learning -> UDP/TCP Enforcing -> inbound allow -> restart (iptables)
  ```

  These were local, isolated Docker network/container-namespace tests. They did
  not exercise or modify the host firewall and are not production certification.

Commands and exact interpretation are documented in
[the compatibility guide](../tests/compat/README.md).

## Residual findings and deliberate limits

### Deployment and availability

- Enabling a packaged service does not prove whole-boot enforcement. initramfs,
  early network consumers, custom service ordering, or network paths outside the
  declared init dependency can transmit before OpenShield is active.
- The staging helper trusts its caller not to modify the verified package tree
  concurrently. A malicious owner racing its own tree remains outside that
  helper's boundary; package builds should use a fresh private root with no
  concurrent writers.
- A fresh requested mode is `Learning`, but inbound traffic is still
  default-deny. On a remote server, first activation can cut off administration.
  Use a local console or tested out-of-band path, create and verify the inbound
  management allow first, and keep a recovery procedure ready before enabling
  the service.
- Learning is an operator-controlled trust window. Any successfully attributed
  local process can create exact application-and-endpoint rules and consume its
  per-application or per-UID quota. Multiple UIDs/applications can still consume
  the 7,500 learned-rule capacity or the independent 8 MiB state budget and
  pause further learning. Reaching the byte limit or a recoverable save failure
  discards the current batch and pauses automatic learning until a successful
  privileged mutation or daemon restart, while the active Learning traffic
  policy remains. The 2,500-slot manual count reserve does not reserve bytes.
  Learned rules require review before Enforcing.
- An authorized root operator can still fill the 10,000-rule total with manual
  mutations. Root is inside the administrative trust boundary, but this remains
  an operational availability limit.
- Procfs attribution and one bounded NFQUEUE consumer can be forced into
  fail-closed denial by process, thread, fd, or queue pressure. This is a
  material availability/DoS risk, not a fail-open path. In particular, the
  current scan rejects more than 4,096 descriptors in a task whose filesystem
  UID matches the socket UID, or more than 131,072 proc/task entries globally.
  Unrelated-UID fd tables are skipped, but global process/task pressure and
  matching-UID fd pressure can still deny application attribution. Immutable
  cached packet policy removes the previous per-packet full-state clone and
  indexes enabled rules by complete executable file version. A lookup scans only
  the policy-ordered bucket for the observed version. Matching within that bucket
  remains linear, and a legacy or root-edited state can concentrate many rules
  under one pin despite the 256-rule automatic-insertion budget.
  The Learning admission index prevents already-known, saturated, or paused
  observations from filling the persistence queue, but classification follows
  mandatory procfs attribution. New eligible candidates can still fill the
  queue and fail closed; all classes retain the procfs availability cost.
  Nonblocking verdict delivery prevents an indefinite policy-lock stall, but
  sustained netlink send pressure can request emergency `BlockAll`; this is an
  intentional fail-closed availability tradeoff.
- Forced termination, kernel failure, or power loss can bypass graceful
  post-stop code. Pre-start hooks and the early in-process bootstrap reduce, but
  cannot eliminate, that deployment boundary.

### Identity and privilege

- Procfs attribution is a repeated post-event consistency check, not an atomic
  kernel sender/exec record. An exec or descriptor transfer concurrent with
  packet processing can expose only the later observable identity. UDP
  `SO_REUSEPORT` and related ownership patterns have the same non-atomic
  boundary.
- Executable identity is path plus device, inode, size, and ctime seconds and
  nanoseconds. Ordinary in-place rewrites change size or ctime and stop matching,
  but the tuple is not a content digest or mount-namespace identity. Metadata
  reuse, privileged/raw-filesystem manipulation, namespace aliases,
  interpreters, injected libraries, plugins, and JIT code remain outside full
  code attestation.
- argv and cgroup are mutable metadata. On cgroup v1, application attribution
  remains available, but exact cgroup-path selectors cannot match.
- Stable shared, inherited, or `SCM_RIGHTS`-passed descriptors are denied when
  they create ambiguity among matching-UID TGIDs, but procfs fallback is not
  proof of which process performed the actual send. A cross-UID recipient is
  skipped before fd inspection; without an original matching-UID holder the
  decision fails closed, but with that holder still present the recipient is
  invisible and the original holder can be attributed. After an established TCP flow is authorized,
  identity is not recaptured for every packet; a later exec or fd transfer can
  retain the connection until reconnection or policy-generation change.
- `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH` materially expand the impact of a
  daemon compromise. The syscall deny list does not prevent ordinary I/O to a
  successfully opened `/proc/pid/mem` or every traversal through procfs magic
  links.
- Application selectors constrain allow rules; they are not deny overrides. A
  broader matching network-only allow can authorize the same flow first.

### Coexistence and protocol scope

- OpenShield reserves the upper two packet-mark bits and preserves the lower 30.
  It reserves the low 31 conntrack bits for application authorization and
  preserves bit 31. Other firewalls, VPNs, QoS, or CONNMARK users of the
  reserved bits can conflict. A privileged earlier mark writer or an
  asynchronous queue placed between OpenShield hooks can invalidate the
  reinjection assumptions.
- Other firewall rules may still drop traffic that OpenShield returns or
  accepts. Conversely, a privileged ruleset editor can bypass or damage
  OpenShield. Run no competing manager without reviewing hook order, marks, and
  chain ownership.
- nftables health checks validate owned table/base-chain metadata and counters,
  not the complete rule body. The iptables backend compares full owned rule
  bodies, but its first-position dispatch can be displaced by another
  privileged editor. Neither check is protection from UID 0 or `CAP_NET_ADMIN`.
- The fixed backend executable is checked before it is later run by path. A
  privileged package update can replace it in that interval. This TOCTOU remains
  inside the trusted UID-0/package-manager boundary.
- iptables cannot update IPv4 and IPv6 atomically together. The deliberate
  cross-family `BlockAll` quarantine can temporarily deny valid traffic during a
  policy update.
- Authorized members of `openshield` can see sensitive network endpoints,
  events, rules, mode, and counters even though application identity fields are
  redacted for non-root. Group membership must be treated as a monitoring
  privilege. Authorization occurs when the Unix connection is accepted; an
  authorized process can relay that already-connected socket fd to another
  process, so group access is not a non-delegable confidentiality boundary.
- ICMP type/code selectors are not implemented, and application attribution
  supports only ICMP/ICMPv6 echo. Required ICMPv6 permits should be narrowed by
  network and interface.
- OpenShield filters host IPv4/IPv6 traffic. It is not an L2/ARP firewall and
  does not constrain a process that already has `CAP_NET_RAW` from direct
  `AF_PACKET` injection.

### Compatibility and localization

- Static `--version` smoke tests share the host kernel and do not exercise libc
  integration, init boot, firewall tools, NFQUEUE, package upgrades, or real
  traffic. Archived and rolling images are probes, not supported-lifecycle
  guarantees.
- Cross-compilation checks do not establish runtime behavior on every x86, ARM,
  AArch64, or RISC-V machine. No claim of support for all architectures or every
  ABI is made.
- The 31 locale resources have mechanical schema coverage, but translations,
  especially for languages with limited technical-review resources, still need
  review by native technical speakers. No native technical review is recorded
  for the 11 additions. Six proposed cross-language fallback resources (`os`,
  `inh`, `bua`, `xal`, `ady`, and `kjh`) remain unsupported pending replacement
  and native review. The set is broad but not exhaustive.

If state persistence and emergency recovery both become ambiguous, OpenShield
keeps or attempts kernel `BlockAll` and enters a read-only recovery posture.
Only a local root operator with an independent console should repair or
deliberately replace the state before restart.
