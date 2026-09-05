[English](SECURITY.md) | [Русский](SECURITY.ru.md)

# Security policy

Please report suspected vulnerabilities privately to the repository owner before
opening a public issue. Include the affected revision, threat prerequisites, a
minimal reproducer, and the observed impact. Do not include live credentials or
data from systems you do not own.

The supported branch is `main`. Security fixes should add a regression test and,
where relevant, a threat-model update.

Control is local and root-only. Read-only monitoring is limited to root and
members of the `openshield` system group; membership grants access to network
rules, endpoints, events, mode, and counters and must be treated as a security
privilege. nftables is preferred, with a validated iptables/ip6tables fallback.

OpenShield deliberately treats all protocol input as untrusted, including input
from a local root client. The project forbids unsafe Rust in workspace code and
rejects shell execution, configuration-selected executables, unbounded IPC
frames, and NFQUEUE bypass. Executable paths in outbound rules are bounded,
typed identity selectors; the daemon never executes them.

Since OpenShield 0.1.31, the daemon reports its policy mode, selected firewall
backend, and dynamically recomputed active-policy path classification as separate `StatusV2`
fields. This classification is not kernel-capability attestation or fallback
negotiation for an unchanged policy. `KernelNative` means nftables/iptables policy evaluation, not an eBPF
application data plane. This release does not add `CAP_BPF`, a kernel module,
boot-parameter changes, or MOK enrollment. If mandatory NFQUEUE setup fails,
the daemon retains bootstrap `BlockAll` and exits; it never substitutes a
weaker network-only policy or enables queue bypass.
The only automatic startup backend fallback is from nftables to the complete
iptables/ip6tables bundle when nftables cannot be validated.
When the running daemon has entered read-only fail-closed quarantine,
`StatusV2` uses the distinct `EmergencyBlockAll` reason and the TUI presents it
as an emergency; it is not confused with an operator-selected `BlockAll`.

Since v0.1.32, OpenShield amortizes procfs owner enumeration across at most 32
already-ready NFQUEUE packets without weakening attribution. `SOCK_DIAG` stays
per packet; two bounded owner snapshots bracket capture; reuse is confined to
one batch; mandatory process identity must reach consensus; and one absolute
250 ms deadline covers the whole batch, while one global owner-record cap covers
all targets in each snapshot. Typed
timeouts remain auditable, and every ambiguity or exhausted bound denies rather
than bypasses filtering. nftables runtime observation now obtains tables,
chains, and counters from one fixed process while retaining the same checks,
one-second cadence, and fail-closed repair policy.

The operational boundary, fail-closed assumptions, and the material risks of
the daemon's retained procfs-inspection capabilities are documented in the
[threat model](docs/THREAT_MODEL.md).
The current audit evidence and unresolved limitations are listed separately in
[the security audit](docs/SECURITY_AUDIT.md).
