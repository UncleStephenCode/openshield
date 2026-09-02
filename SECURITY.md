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

The operational boundary, fail-closed assumptions, and the material risks of
the daemon's retained procfs-inspection capabilities are documented in the
[threat model](docs/THREAT_MODEL.md).
The current audit evidence and unresolved limitations are listed separately in
[the security audit](docs/SECURITY_AUDIT.md).
