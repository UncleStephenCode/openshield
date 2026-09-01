[English](SECURITY.md) | [Русский](SECURITY.ru.md)

# Security policy

Please report suspected vulnerabilities privately to the repository owner before
opening a public issue. Include the affected revision, threat prerequisites, a
minimal reproducer, and the observed impact. Do not include live credentials or
data from systems you do not own.

The supported branch is `main`. Security fixes should add a regression test and,
where relevant, a threat-model update.

OpenShield deliberately treats all protocol input as untrusted, including input
from a local root client. The project forbids unsafe Rust in workspace code and
rejects shell execution, configuration-selected executables, unbounded IPC
frames, and NFQUEUE bypass. Executable paths in outbound rules are bounded,
typed identity selectors; the daemon never executes them.

The operational boundary, fail-closed assumptions, and the material risks of
the daemon's retained procfs-inspection capabilities are documented in the
[threat model](docs/THREAT_MODEL.md).
