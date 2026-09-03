[English](README-CI.md) | [Русский](README-CI.ru.md)

# OpenShield CI and releases

The authoritative release-CI documentation is
[`.github/README-CI.md`](.github/README-CI.md). The workflow itself is
`.github/workflows/release.yml`, and its machine-readable support contract is
`packaging/ci/release-matrix.json`.

The release graph is fail-closed:

```text
Validation
    -> Quality Gate
    -> 43 family/architecture binary builds
    -> 43 family/architecture package builds
    -> 37 distribution/platform installations for 19 package variants
    -> pinned init-system container tests
    -> 74 firewall E2E jobs
    -> sealed release candidate and evidence
    -> publication
```

The runtime matrix contains 37 pinned distribution/platform rows: 16 `amd64`,
15 `arm64`, and 6 `386`. Every row executes both the nftables-preference and
iptables-only fallback scenarios. `amd64` and `arm64` use native GitHub-hosted
runners; `linux/386` uses the x86-64 kernel's direct 32-bit compatibility path.

All 43 binary and 43 package targets are still built. The other 24 package
variants for ARMv5/6/7, PowerPC64LE, RISC-V 64, and IBM Z are build-only:
they account for 49 of the 86 declared distribution/platform mappings. Their
Cross/QEMU lanes provide ELF and capability-free `--version` smoke evidence,
but no package-install or firewall-runtime evidence. Publication of one of
these artifacts is not a runtime-support or native-hardware claim.

Each runtime-tested package is linked to its installation and firewall evidence
by asset name and SHA-256; build-only packages carry build and asset-integrity
evidence instead. Before making any publication API request, the write-capable
job independently verifies the tag, source revision, matrix hash, complete
asset inventory, file sizes, digests, and `SHA256SUMS`.

GitHub's ZIP artifact transport normalizes regular files to mode `0644`.
Release Evidence therefore treats the downloaded raw ELF files as byte-level
transport copies and requires that mode explicitly. The publishable `tar.xz`
remains the authority for executable metadata: it must contain exactly the
daemon and TUI as regular `0755` members whose sizes and SHA-256 contents match
the transport copies. Package assembly restores `0755` explicitly.

To create a release, set `[workspace.package].version` in `Cargo.toml`, commit
the complete change, and create the matching `vX.Y.Z` tag on that commit. A
numeric `X.Y.Z` tag without the mandatory `v` prefix reaches Validation only,
where it fails with an explicit diagnostic; it can never reach compilation or
publication. Recovery of an already published release is allowed only through
the explicit `workflow_dispatch` repair option; existing assets with different
bytes are never overwritten.
