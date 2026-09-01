[English](SECURITY_AUDIT.md) | [Русский](SECURITY_AUDIT.ru.md)

# Security audit status

Audit snapshot: 2026-09-01, OpenShield 0.1.0, Rust 1.98.0.

## Closed findings

- Management is local-only. Mutations use a root-owned `0600` Unix socket and
  require Linux `SO_PEERCRED` UID 0. The public `0666` socket is read-only;
  before serialization for a non-root peer, the daemon replaces the complete
  application selector and potentially identifying rule name with fixed
  redacted values.
- IPC JSON is strictly typed, rejects unknown fields, is limited to 64 KiB, and
  has bounded clients, queues, pagination, absolute read deadlines, and absolute
  write deadlines. The public path uses a fixed 32-worker/64-job pool, per-UID
  connection/subscription admission limits, at most 24 public subscriptions,
  and 512 events per subscriber. One per-UID bucket (burst 256, refill 64
  tokens/second) is charged both on connection acceptance and before every
  `Status`, `RulesPage`, or `Subscribe`; exhaustion returns `Conflict` and closes
  the session. Its session FSM
  allows `Subscribe` only first, at most two pre-pagination `Status` requests,
  and then only a strictly advancing rule cursor. The server ignores a smaller
  client limit, fetches up to 128 rules per cursor, and byte-shrinks only to fit
  below 64 KiB, with a resumable cursor; the TUI uses a single persistent
  snapshot connection. Slow readers are disconnected without blocking policy
  work.
- The workspace forbids unsafe Rust. The daemon invokes no shell, loads no
  plugins or eBPF objects, and downloads no policy. Executable paths are accepted
  only as bounded, typed application identity selectors and are never executed.
- nftables input is generated only from validated types and is checked before one
  atomic apply. A reported apply error is treated as an ambiguous outcome: the
  previous snapshot is explicitly reinstalled, or the engine escalates to
  emergency `BlockAll`.
- Input, output, and forward base chains are default-drop. Enforcing mode has no
  blanket established-flow authorization; reverse traffic remains bound to the
  selectors of a currently enabled rule.
- An application selector is outbound-only, requires an executable path and
  persisted device/inode pair, and combines every supplied network and process
  field with AND. The daemon canonicalizes and pins a path visible in its mount
  namespace; an external path requires an explicit pair. Command arguments retain
  token boundaries and support exact or prefix matching. Environment, regex,
  parent-process, persistent PID, MD5, and SHA-1 selectors are not accepted.
- Process cgroup identity comes from exactly one unified v2 procfs entry
  `0::/path`; v1 controller entries are ignored. Missing or multiple unified
  entries deny application attribution, including on a v1-only host.
- Otherwise-unmatched application traffic uses the fixed NFQUEUE 1337 without
  the nftables `bypass` flag. The kernel queue is capped at 256 packets and the
  copied prefix at 512 bytes. The consumer parses TCP, UDP, ICMP echo, and ICMPv6
  echo only, applies a 250 ms procfs deadline and fixed scan bounds, requires a
  unique socket inode and process owner, repeats identity checks, and rechecks
  policy before ACCEPT. It enumerates every `/proc/TGID/task/TID/fd` table and
  groups holders by TGID. Different TGIDs, a cross-UID holder, an incomplete or
  unavailable live process/task scan, or descriptor-bound exhaustion deny
  attribution. Sibling holder TIDs in one TGID count as one owner only when the
  captured executable/file, argv, filesystem-UID, and cgroup identities agree
  across every holder. A vanished entry is skipped only after procfs confirms
  disappearance. An
  `PermissionDenied` error on a TGID-leader fd table is skipped only after two
  bounded `stat` reads confirm stable zombie state `Z`; every other error,
  non-zombie state, or unconfirmed state denies. Failure or ambiguity returns
  DROP; a terminal queue failure requests emergency `BlockAll` and daemon
  shutdown.
- The final policy-generation check and synchronous NFQUEUE ACCEPT/reinjection
  occur under one engine lock. Two reserved packet-mark bits carry only the
  internal pending/handoff state while the lower 30 bits are preserved. A
  successful established-TCP decision binds both TCP directions to a persisted,
  nonzero, non-reused 30-bit policy generation; invalidating changes advance it.
  UDP/ICMP decisions are not cached: every otherwise-unmatched outbound packet
  is re-attributed, its conntrack mark is cleared, and replies need an explicit
  inbound allow. This prevents authorization inheritance through a surviving
  reused UDP five-tuple.
- Learning persists only successfully attributed, exact
  application/protocol/endpoint/interface permits. A separate 512-item queue,
  batches of at most 256 observations, indexed deduplication, and the 10,000-rule
  ceiling bound its resource use. An independent exact 8 MiB semantic-state
  quota is checked before backend application. Reaching that quota pauses the
  batch. After a save error the daemon rereads authoritative state: an exact
  previous snapshot is left untouched; a candidate or unknown result is rolled
  back. Only an ambiguous result plus failed rollback escalates to `BlockAll`.
  Unknown L4 protocols and unsupported ICMP messages are never converted into
  an `Any` rule.
- State I/O is bounded and root-owned, rejects links and unsafe metadata, and
  uses a same-directory temporary file, `fsync`, and atomic rename.
- Every daemon start installs kernel `BlockAll`, selects a cryptographically
  random nonzero startup epoch from the lower 29 bits of the 30-bit generation
  domain, persists it, and only then applies saved policy. The value is forced
  to differ from the previous persisted generation, invalidating prior-process
  TCP authorization marks.
- The packaged unit installs `BlockAll` in `ExecStartPre` and uses
  `Type=notify`; `READY=1` is sent only after policy activation, the fail-closed
  NFQUEUE consumer, and verified IPC sockets are active. Once enabled,
  `RequiredBy=network-pre.target` plus `Before=network-pre.target` makes standard
  consumers depend on successful readiness.
- Main startup and `--install-fail-closed` share a root-owned `0600`,
  `O_NOFOLLOW|O_CLOEXEC`, nonblocking singleton lock acquired before state or
  nftables mutation. Socket teardown requires the originally recorded filesystem
  device/inode, so an old guard cannot unlink a replacement socket.
- Privileged control messages require an `expected_revision`. A stale request
  returns `Conflict` before cloning or mutating state, persistence, backend
  application, or event publication. The TUI captures the revision when an
  editing intent opens, forces a snapshot resync on conflict, and never retries
  automatically.
- TUI transport timeout/EOF is reported as an unconfirmed outcome, never as a
  definite failure: an acknowledgement can be lost after commit. The operator
  is told not to retry, and a snapshot resync is forced.
- Health polling uses bounded table/chain/counter metadata instead of serializing
  every compiled rule each second. Application learning is handled by the
  separate bounded NFQUEUE worker rather than unbounded event harvesting.
- NFQUEUE verdict sequence numbers wrap while skipping zero instead of
  terminating after `2^32` verdicts. Emergency `BlockAll` persistence retains
  the last validated rules as data while its mode has no accept path.
- Rule mutations keep `updated_at` monotonic across wall-clock rollback, so an
  NTP correction cannot turn timestamp validation into a control-plane outage.
- The systemd unit retains only `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`, and
  `CAP_DAC_READ_SEARCH`. Its syscall filter explicitly denies `ptrace`,
  `process_vm_readv`, `process_vm_writev`, `kcmp`, `pidfd_getfd`, and
  `open_by_handle_at`; normal daemon code does not inspect process memory or
  environments. This is syscall-surface reduction, not memory isolation, as
  recorded below.

## Verification evidence

Evidence for the final source and for its immediate pre-hardening predecessor is
separated below. The following current-source checks used Rust 1.98.0:

- `cargo test --workspace --locked --offline`: 182/182 tests passed (core 39,
  daemon 90, protocol 11, TUI 42; no documentation tests).
- Host `cargo clippy --workspace --all-targets -- -D warnings`: passed.
- Release workspace build: passed.
- `cargo-audit` 0.22.2 checked 152 dependencies against advisory-database
  commit `72f8b23` dated 2026-09-01: zero findings.
- `cargo-deny` 0.20.2 passed advisories, bans, licenses, and sources. It reported
  only duplicate-version warnings for `hashbrown` 0.16/0.17 and `syn` 2/3.
- Offline `systemd-analyze security` reported exposure 2.3 (`OK`) for the
  packaged service.
- A post-fix smoke run used a binary built from the final source in the official
  `rust:1.98.0-bookworm` image. Fresh startup installed `BlockAll`; Learning
  allowed `curl` to a separate HTTP container and persisted `/usr/bin/curl`
  with device/inode and filesystem UID; Enforcing still returned HTTP 200 for
  `curl`, while `python3` to the same endpoint timed out with exit 1. The daemon
  log contained no attribution error.

Immediately before the final per-task, stable-zombie, and unified-cgroup-v2
resolver hardening, an isolated extended nftables/NFQUEUE end-to-end run passed
Learning with `curl`, Enforcing, exact-argv denial after an argument change,
  preservation of the
  lower 30 `SO_MARK` bits, rejection of a forged reserved-mark bypass,
  `BlockAll`, fail-closed behavior after queue death, startup-generation
  rotation, denial of delivery when a second application reused the same UDP
  five-tuple, and inbound denial followed by an explicit allow yielding HTTP
  200.

The final-source tests and smoke run cover the changed resolver; the extended
matrix is supporting evidence from the immediate predecessor, not a claim that
every matrix case was rerun after those last changes. None of these results is a
proof that the residual boundaries below are absent.

## Residual findings and deliberate limits

- The packaged `RequiredBy=network-pre.target` relationship exists only after
  `systemctl enable`; merely installing the unit does not activate it. A network
  manager, unit, initramfs, or early packet path that bypasses
  `network-pre.target` also bypasses the dependency and may send traffic without
  OpenShield. Strict whole-boot enforcement requires tested
  distribution-specific integration or an initramfs policy.
- Procfs attribution is post-hoc and race-checked, not an atomic kernel exec or
  send event. A sender can queue a packet and then exec an allowed image while
  retaining the socket, so the resolver may authorize the post-exec identity
  for an operation initiated before exec. Repeated reads do not reconstruct that
  history. UDP `SO_REUSEPORT` groups and wildcard/specific binds under one UID
  can also change the actual sender while tuple and UID observations remain
  compatible. This is neither an atomic sender record nor cryptographic process
  attestation.
- Executable identity is canonical path plus device/inode, without a content
  digest or mount-namespace identity. In-place file changes, namespace aliases,
  and interpreter-versus-script identity remain operator-visible limitations.
- Selector fields identify process metadata, not all code executing inside the
  process. `LD_PRELOAD=/tmp/evil.so /allowed/path` preserves path, device/inode,
  argv, filesystem UID, and cgroup while library initialization can perform
  network I/O. Interpreters, plugins, and JIT code share this boundary, and a
  main-executable hash alone would not fix it. Strong code identity needs a
  trusted launcher/cgroup with user-controlled loaders disabled or an
  LSM/IMA/eBPF execution domain.
- Command-line and cgroup metadata can change; the repeated reads detect observed
  changes but do not make them immutable. The UID selector is filesystem UID,
  not a complete real/effective/saved/fs UID identity.
- Application attribution requires unified cgroup v2 even without a cgroup
  selector. A v1-only host therefore denies application-bound traffic; this is
  a fail-closed compatibility/availability limit, while network-only rules can
  still be used.
- At initial attribution, stable shared or `SCM_RIGHTS`-passed descriptors that
  are discovered, including cross-UID owners, are denied. This post-hoc scan is
  still not an atomic sender-at-send event: ownership can race with observation,
  and no BPF/LSM sender-generation attribution is implemented.
- Identity is not recaptured for every packet after an established TCP
  connection is authorized. A later exec, filesystem-UID/cgroup change, or
  inherited/`SCM_RIGHTS` fd transfer can keep using it until reconnection or a
  policy-generation change. UDP/ICMP is re-attributed per outbound packet.
- One bounded NFQUEUE consumer performs procfs scanning with worst-case work
  proportional to tasks times their per-task fd tables. Process/thread/fd floods, queue
  pressure, or the attribution deadline can therefore deny legitimate traffic.
  Because any incomplete live process/task scan denies the whole decision, a
  single oversized or inaccessible task descriptor table can contribute to this
  global application-attribution availability/DoS risk. An inaccessible
  non-zombie leader/task, a state that cannot be confirmed as a stable zombie,
  or an access error other than `PermissionDenied` has the same fail-closed
  availability effect.
- Cross-UID procfs attribution requires `CAP_SYS_PTRACE` and
  `CAP_DAC_READ_SEARCH` in the packaged daemon. The syscall deny list blocks
  `ptrace` and `process_vm_*`, but a compromised daemon can still use
  `CAP_SYS_PTRACE` to open `/proc/<pid>/mem` and ordinary read/write syscalls.
  `CAP_DAC_READ_SEARCH` also permits read/search DAC bypass for files visible in
  the service mount namespace, potentially including system secrets. Procfs
  magic links such as `/proc/<pid>/root` may expose a target process's mount view
  despite service mount restrictions. This is materially broader access than
  `CAP_NET_ADMIN` alone.
- Application selectors constrain allow rules; they are not negative overrides.
  A matching network-only allow is evaluated first and can authorize the same
  traffic without application attribution.
- The lower 30 packet-mark bits are preserved, but OpenShield reserves the upper
  two and exclusively uses all 32 conntrack-mark bits for application-authorized
  traffic: a TCP cache value or a cleared UDP/ICMP mark. Another firewall, VPN,
  QoS, or CONNMARK writer using that conntrack entry is an unsupported conflict.
  A privileged earlier CONNMARK rule that copies attacker-controlled `SO_MARK`
  before OpenShield sanitizes it can synthesize the current domain/generation
  and bypass the application queue for established TCP. An external asynchronous
  queue inserted between OpenShield's priority-0 policy and priority-1 late
  chain also breaks the engine-lock/reinjection timing assumption. Exclusive
  mark ownership and compatible hook ordering are required.
- Observation is aggregate and intentionally visible to every local user.
  Process/application metadata is redacted for non-root peers, but network rule
  and endpoint metadata remains public under the default `0666` mode.
- Learning is an operator-controlled trust window. Any successfully attributed
  local process can cause application-and-endpoint rules to be learned and can
  consume the bounded queue, 10,000-rule quota, or 8 MiB state quota; reaching a
  quota pauses further learning.
- ICMP type/code selectors are not implemented; required ICMPv6 rules must be
  scoped by network and interface. Per-application attribution accepts only ICMP
  and ICMPv6 echo requests.
- Filtering is implemented by an `inet` IPv4/IPv6 table. It is not an L2/ARP
  firewall and does not constrain direct `AF_PACKET` injection by a peer that
  already has `CAP_NET_RAW`.
- The fixed `nft` path is metadata-checked as a root-owned non-symlink regular
  executable, then later spawned by path. A privileged package update or root
  process can replace it between validation and execution. This low-risk TOCTOU
  remains inside the already trusted UID-0/package-management boundary.
- A compromised kernel, UID 0, other privileged firewall manager, or trusted
  system `nft` executable is outside the threat boundary. A privileged targeted
  rule edit or additional allow can evade monitoring because health checks do
  not compare complete rule bodies. Flushing an OpenShield chain
  remains fail-closed because its base policy is drop, but may remove valid
  permits until the next policy apply or restart.

See [the threat model](THREAT_MODEL.md) and [architecture](ARCHITECTURE.md) for
the normative security boundary.
