[English](README.md) | [Русский](README.ru.md)

# OpenShield host-firewall performance tests

This directory contains a reproducible, safety-gated performance harness for
OpenShield's actual host-firewall data paths. It is not a generic bandwidth
benchmark. The primary outputs are the highest sustainable packet rate,
connection rate, and concurrency point, together with latency and resource
overhead relative to a paired run without OpenShield.

The harness never changes the host firewall. It requires a local Unix-socket
Docker engine and builds a disposable three-container topology:

- the DUT contains the exact supplied `openshield-daemon`, the local workload
  process, and either nftables or the iptables/ip6tables fallback;
- an unprivileged, capability-free pressure peer runs the opposite workload
  endpoint;
- a second capability-free peer and a separate internal network provide the
  controlled-overload canary path; on the same canary veth, each transport has
  an application-bound target for the wrong-executable probe and a distinct
  network-only liveness endpoint;
- the DUT and pressure peer use a dedicated internal Docker network, so all
  measured traffic crosses real veth interfaces and separate network
  namespaces rather than loopback;
- only the DUT receives `NET_ADMIN`, `NET_RAW`, `SYS_PTRACE`, and
  `DAC_READ_SEARCH`, and those capabilities exist only inside its namespace.

Every TCP/UDP client, server, and executable-identity probe runs as the fixed
non-root numeric identity `65532:65532` in all three containers, without
supplementary groups or added capabilities. The daemon, control helper, and
metric collectors remain root because their firewall and `/proc` duties require
it. A root supervisor installs each phase JSON in a non-writable directory as
`root:root` mode `0644`, so a generator can read but cannot replace or rewrite
its input. Its assigned private writable location is a mode `0700` home/tmp
directory on the container's disposable `/tmp` tmpfs.

The DUT creates the daemon's real `/var/lib/openshield` state directory on the
container's writable overlay rather than substituting a `tmpfs` or mock state
store. `state.json`, its atomic rename and `fsync` path, flow generation, and
learned rules therefore survive the exit of every phase client and subsequent
daemon control transactions within that backend topology. The writable layer
is destroyed with the disposable DUT, so this is real persistence for one
isolated backend run, not state carried between independent harness
invocations.

TCP clients use ordinary nonblocking sockets and complete HTTP/1.1 or bounded
framed request/response exchanges. UDP clients use persistent ordinary UDP
sockets. The harness does not inject handcrafted TCP packets. Consequently the
kernel exercises TCP state, conntrack, NFQUEUE, socket ownership, and `/proc`
process attribution in the same shape as the production daemon.

UDP completion does not rely on an ordering guarantee that UDP does not
provide. Every flow carries an explicit sequence. The server tracks a bounded
reordering window and acknowledges that flow's drain frame only after it has
consumed the exact contiguous sequence prefix preceding the frame. A gap,
duplicate/crossing sequence, exceeded bound, missing acknowledgement, or
client/server count mismatch invalidates and fails the point.

## Paths under test

Every applicable profile has a paired baseline followed by these policy cases:

| Case | Expected OpenShield path |
| --- | --- |
| `baseline` | Same container image and veth topology, daemon not started |
| `network_only` | Exact network allow is evaluated in the kernel before NFQUEUE; queue sequence delta must be zero (or the explicitly configured tiny noise bound) |
| `application_tcp` | The first packet of every new TCP connection is attributed through NFQUEUE; established traffic must use the current conntrack generation fast-path |
| `application_udp` | Every otherwise-unmatched outbound datagram clears the reusable conntrack generation and is attributed again |

`network_only` runs in both `Enforcing` and `Learning`. Application cases run
with a privileged manual executable rule in `Enforcing` and as real learned
rules in `Learning`. The `known_endpoint` learning variant keeps the client's
argv stable while changing only the owner-controlled JSON configuration file.
The optional `discovery_churn` variant deliberately changes that argv path at
every phase and load point to measure repeated first-seen learning.

Inbound profiles are network-only because OpenShield intentionally forbids
application selectors on inbound rules. The included HTTP profiles model an
NGINX-like service with short and persistent HTTP/1.1 connections and a
deterministic weighted response-size mixture. Outbound TCP and UDP profiles run
the generator on the DUT and therefore exercise OpenShield's unique
application-aware path. UDP includes long-lived large-datagram streams and a
many-flow 128--512-byte high-PPS profile.

Each load point executes warm-up, one or more ramp steps, repeated steady-state
windows, and a burst. `production-like.json` sets
`capacity_certification=true`; a capacity-qualified maximum requires three
passing steady windows and, when `require_burst_capacity=true`, the matching
passing burst at the same load level. The much shorter `ci-smoke.json` sets
`capacity_certification=false`: it verifies path selection, reporting, and
fail-closed safety, but can never publish a capacity-qualified point.
The release smoke retains every backend, mode, policy path, and workload
profile, but uses one half-load ramp and three one-second steady windows. Its
bounded rates target hundreds of operations in every steady window, reducing
the single-digit-sample instability of the earlier sub-second profile. All
three repetitions must pass independently.

Every phase launches a fresh client process with a fresh initial socket set;
TCP connections are deliberately not carried from warm-up into ramp, steady,
or burst. The server stays alive for the whole load point. A keep-alive client
performs multiple real request/response operations on each connection inside
the same phase, so that phase independently exercises one first-packet
NFQUEUE/process-attribution decision followed by established TCP traffic on the
conntrack-generation fast-path. The harness never infers fast-path behavior
from a connection created in an earlier phase.

For a given backend, profile, load level, and phase, the baseline and every
OpenShield policy case use the same offered configuration and the same
deterministic trace seed; policy is intentionally absent from seed derivation.
Conntrack is flushed before each load point for baseline and protected cases.
The pair is executed sequentially in the same disposable topology, so it
controls workload identity but cannot remove time-varying host or CI noise.

## Running safely

Build the daemon first as an unprivileged user. Give the harness an absolute,
non-symlink path to an exact mode-`0755` binary and a new absolute report
directory:

```console
cargo build --release --locked --bin openshield-daemon
python3 tests/perf/run.py \
  --config tests/perf/config/production-like.json \
  --daemon "$PWD/target/release/openshield-daemon" \
  --output-dir /tmp/openshield-perf-result
```

The command pulls the SHA-256-pinned images declared by the profile and installs
runtime tools inside the temporary DUT before disconnecting its provisioning
network. Do not run the harness with a remote Docker context: it refuses every
context except `unix:///...`. The CI wrapper generates a fresh 128-bit token
and gives every current-run container and network its exact label. On normal
exit, `TERM`, `INT`, or hard timeout it selects by that label and re-inspects
each immutable Docker ID before deletion. It never prunes Docker or deletes by
a shared name prefix, so other jobs' resources are outside the cleanup scope.
No `sudo`, host `nft`, or host `iptables` invocation is used.

The release-only bounded gate is:

```console
OPENSHIELD_DAEMON="$PWD/target/release/openshield-daemon" \
  tests/perf/ci-smoke.sh /tmp/openshield-perf-ci
```

The wrapper has a 900-second hard process-group timeout and validates the
report schema, file types, permissions, and size bounds. It runs on the single
openSUSE Tumbleweed `linux/amd64` release stand after all functional firewall
E2E jobs.

The host orchestrator re-executes as `python3 -I -B -S` before importing any
workspace-resolvable module. `environment.py` is opened without following
symlinks and compiled directly from source; the later harness manifest must
match the exact bytes that were loaded. Containers do not receive the repository
tree. They receive a generated read-only `runtime-bundle/` containing only the
seven allowlisted runtime sources and a canonical SHA-256 manifest. A separate,
manifest-pinned launcher keeps every process argument within the daemon's
attribution bounds (at most 64 arguments and 1024 bytes per argument). Every
Python entrypoint runs with `-I -B -S`, verifies that manifest, hashes every component,
and rejects symlinks, writable entries, missing files, extras, and bytecode
before executing the selected source. The bundle and its manifest are retained
with the report so CI can independently repeat the verification.

Each backend result records bounded environment evidence: the resolved Docker
image ID, exact `x86_64` machine, parsed openSUSE Tumbleweed `/etc/os-release`,
`uname`, the SHA-256 of the repository's
`repo-oss` `repomd.xml`, and the exact sorted unique RPM
`name|epoch|version|release|arch` inventory. The nftables and iptables runs must
use the same image ID, OS identity, machine/kernel, and repository metadata.
Their RPM manifests are retained separately and are not required to be identical:
the only permitted nftables-only names are the pinned dependency closure
`nftables`, `libnftables1`, `libjansson4`, and `libedit0`; the iptables-only
delta must be empty. A changed dependency closure therefore fails closed until
the pinned stand and allowlist are deliberately reviewed together. Missing or
malformed evidence, any other package delta, or a mismatch in the shared
identity fields invalidates the run. The container image reference and
image ID are content-addressed, but provisioning currently uses the signed live
Tumbleweed repository. Recording its metadata makes the selected package set
auditable; it does not make that set immutable or reproduce it in a later run.

## Configuration

Both checked-in files use `openshield.perf.config.v1`. Unknown keys, duplicate
JSON keys, non-finite numbers, unsafe names, duplicate ports, unpinned images,
and values outside fixed resource bounds are rejected before Docker is used.
The estimated total workload duration must also fit
`max_total_workload_seconds`.

The following values are intended to be replaced with measured production
p50/p95/p99 distributions later:

- `load_levels` and phase duration/scales;
- TCP `concurrency`, `cps`, approximate wire `pps`, bidirectional application
  `mbps`, keep-alive ratio, request size, weighted `response_mix`, and weighted
  persistent-connection lifetime `connection_lifetime_ms_mix`;
- UDP flow count, approximate IP `pps`, bidirectional application `mbps`,
  request/response sizes, sampled-reply cadence, socket buffer, and MTU model;
- all latency, loss, saturation, daemon CPU/RSS, NFQUEUE, and path-shape gates;
- the single deterministic `seed` used to derive a separate seed for every
  backend, scenario, load point, and phase.

TCP and UDP `pps` are pacing targets from a documented packet-cost estimate;
they are not reported as observed PPS. Actual RX/TX PPS and Mbps always come
from DUT and peer interface counters. Application operations/s and bytes/s are
reported separately. CPS is counted from successful real TCP connects, and
concurrency is a thread-safe peak and time-weighted live-flow gauge.

`connection_lifetime_ms_mix` uses the exact
`MILLISECONDS:WEIGHT,...` syntax. Lifetimes must be unique integers from 50 to
3,600,000 ms. A seed-isolated deterministic choice is made whenever a
persistent socket is connected; after its deadline the client closes it and
opens a new real TCP socket between completed exchanges. This preserves normal
TCP and conntrack semantics and never interrupts a request in flight. `short`
mode still creates one connection per exchange and therefore validates but
otherwise ignores this field.

## Measurements and validity

Every phase records:

- actual DUT and peer RX/TX packets and bytes, converted to PPS and Mbps;
- application operation rate, actual TCP CPS, current/peak/mean flows, response
  latency p50/p95/p99, and separate TCP connect p50/p95/p99 latency;
- errors, sampled UDP reply loss, kernel TCP retransmits, conntrack count, and
  interface drops/errors;
- `openshield-daemon` CPU as a percentage of one core and mean/peak RSS;
- host-wide NET_RX/NET_TX softirq deltas;
- NFQUEUE 1337 depth, wrap-safe packet-sequence delta, and exact kernel/user
  drop deltas from `/proc/net/netfilter/nfnetlink_queue`;
- process-lifetime monotonic deltas from the typed
  `status.data.nfqueue` counters: `queue_overflow`, `attribution_timeout`,
  `terminal_queue_error`, and `denied`; these status deltas are authoritative
  for daemon-observed NFQUEUE conditions in the release gate (one overflow
  event can represent an unknown number of kernel-denied packets);
- rate-limited daemon queue/attribution log diagnostics, explicitly labelled
  as diagnostic lower bounds and never used as authoritative pass evidence;
- daemon mode and any transition to quarantine/`BlockAll`.

Validity and pass/fail are separate. Missing or excessive generator CPU,
excessive scheduler lag, saturated or unmeasurable server CPU, rejected
connections, and server protocol/internal errors invalidate the affected
window. A baseline that misses its offered target also becomes invalid and
invalidates every paired OpenShield window. A per-phase peer CPU sample over
its configured ceiling is another invalidation signal. These points are marked
as unreliable, excluded from maximum-sustainable calculations, and are never
reported as an OpenShield regression or capacity result.

The same rule applies to the controlled-overload generator, pressure peer, and
canary: missing or excessive process/resource measurements, socket-queue
errors, workload/protocol errors, or NIC drops/errors invalidate the overload
proof. A blocked probe cannot be credited to a dead or saturated peer.

A valid steady window passes capacity only when it attains the configured
fraction of offered application operations and remains within the configured
error, sampled UDP reply-loss, TCP retransmit, p99 latency, daemon CPU/RSS,
interface drop/error, and NFQUEUE drop/error bounds. Path safety independently
requires NFQUEUE sequence deltas of zero for network-only, approximately one
per new application TCP connection with a low keep-alive per-operation ratio,
and approximately one per application UDP datagram. Every required steady
window must pass. Every burst must remain valid and fail-closed; when
`require_burst_capacity` is true, it must pass the capacity bounds as well.
Explicit wrong-executable fail-open behavior is tested separately by the
independent canary during controlled NFQUEUE overload, so the paired burst
workloads remain equivalent.

In its steady and burst windows, the release `ci-smoke.json` gate allows at
most a 10% paired reduction in throughput or DUT PPS and at most a 10% paired
increase in request p50/p95/p99, TCP connect p50/p95/p99, or DUT-cgroup CPU.
`production-like.json` tightens each relative limit to 5%. Burst additionally
remains a mandatory capacity and fail-closed safety test. Every ordinary window
still requires zero application loss/errors, TCP retransmits, NIC drops/errors,
and NFQUEUE drops/errors. The only intentional exception is
the separately reported controlled-overload proof: there NFQUEUE drops prove
that saturation actually occurred, while every canary probe must still
demonstrate fail-closed behavior without one successful round trip.

If the daemon enters `BlockAll`, the event is retained in the result and the
harness independently inspects the active nftables or IPv4/IPv6 xtables chains.
A reported quarantine without a canonical kernel drop policy is a hard safety
failure. A verified quarantine is fail-closed but still fails the requested
capacity point.

## Controlled NFQUEUE overload gate

The separate `overload` configuration is a destructive stress test of the
disposable namespace, not a capacity point. For each backend it installs an
exact outbound application rule in `Enforcing`, flushes conntrack, and runs both
real short-connection TCP and real UDP workloads. The pressure client first
validates its configuration and sockets, emits an explicit ready event, and
waits at a start barrier. Only then does the harness stop the authenticated
daemon process with `SIGSTOP`, release the client, and poll direct NFQUEUE
snapshots through an enlarged but fixed saturation window. This sequencing
cannot mistake client startup latency for queue resistance. A `finally` path
attempts authenticated `SIGCONT` before an error can leave this section;
disposable-container teardown is the outer fallback.

Saturation is valid only when the measured sum of kernel and userspace NFQUEUE
drops reaches `minimum_nfqueue_drops`; merely offering a large load is not
proof. The independent canary uses the same transport and veth for two distinct
endpoints. Its network-only liveness exchange must succeed immediately before
and immediately after every application-bound wrong-executable probe, while the
probe itself must time out in the strictly validated blocked form without one
successful round trip. Thus a probe cannot appear blocked because the canary
server, socket path, veth, or transport failed. After resume, the daemon must
either remain in `Enforcing` and complete the configured allowed recovery
operations without errors, or enter a `BlockAll` quarantine. A reported
quarantine is accepted only when canonical kernel snapshots and daemon status
bracket real TCP and UDP probes to endpoints proven reachable before overload;
both probes must time out while real loopback round trips inside the canary
container succeed immediately before and after each negative probe. This
out-of-band check proves peer health without traversing the DUT firewall. IPv6
is recorded explicitly as unavailable in the current IPv4-only topology rather
than being claimed as tested. Synchronized metrics,
proven saturation, paired liveness observations, blocked probes, clean
generator/peer/canary evidence, and one of those two fail-closed outcomes are
all mandatory. TCP connection/concurrency, UDP datagram/flow counts, readiness
and saturation deadlines, stall and workload durations, probe count/timeout,
recovery work, and the minimum drop evidence are bounded configuration fields.
Overload results are reported separately and never contribute to
maximum-sustainable PPS, CPS, or concurrency.

The overload TCP payload inherits the validated lifetime distribution but
forces `short` mode, so queue pressure remains an explicit new-connection test
and is not reduced by keep-alive lifetime choices.

## Reports and interpretation

Every run atomically creates owner-only files:

- `report.json`: complete structured configuration identity, the SHA-256
  manifest of every executable harness/workload source, backend gates,
  environment evidence, phase measurements, safety evidence, paired baselines,
  and sustainable points;
- `report.csv`: one flat row per phase for analysis and plotting;
- `overload.csv`: one flat safety-evidence row per backend and TCP/UDP
  controlled-overload proof;
- `report.md`: short outcome, failed/invalid windows, and sustainable-point table;
- `raw/`: bounded per-phase input and evidence useful for diagnosis.
- `runtime-bundle/`: the exact source-only allowlist mounted into containers,
  plus its canonical manifest; no `.pyc` or unlisted import candidate is allowed.

Relative throughput and p50/p95/p99 latency overhead are paired by backend,
profile, load level, and phase. A maximum is called capacity-qualified only
when `capacity_certification=true`, at least three steady-state repetitions at
that load point all remain valid, sustainable, and fail-closed, and every
configured mandatory burst gate for that point passes as well. With
`capacity_certification=false`, passing steady windows remain useful diagnostic
candidate points but `capacity_qualified` is always false.

Container/veth results are appropriate for regression and architecture-path
validation. They are not a NIC line-rate claim. Offloads can make interface
packet counters differ from physical-wire packets. `/proc/softirqs` is global
to the host kernel rather than a container or network namespace, and therefore
includes Docker and unrelated host activity; its deltas are interpreted only
against the paired baseline on a quiet runner and never as daemon-attributed
CPU. Docker scheduling adds further noise, and a shared CI runner is not a
controlled benchmark host. In addition, a signed live Tumbleweed repository is
mutable between runs even though each run records its exact metadata and RPM
inventory. Publication-grade numbers require a prebuilt performance image
pinned by digest, a dedicated runner with reserved CPUs and recorded
offload/IRQ/kernel settings, a non-saturating external peer, enough independent
repetitions, and retained JSON evidence. No full performance run or numerical
claim is considered successful without that evidence.
