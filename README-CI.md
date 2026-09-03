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
    -> 86 distribution/platform installations
    -> pinned init-system container tests
    -> 172 firewall E2E jobs
    -> sealed release candidate and evidence
    -> publication
```

Every one of the 86 pinned distribution/platform rows executes both the
nftables-preference and iptables-only fallback scenarios. `amd64` and `arm64`
use native GitHub-hosted runners, `linux/386` uses the x86 compatibility path,
and the remaining ARM, PowerPC, RISC-V, and IBM Z rows use a SHA-256-pinned
Cross/QEMU path. Emulated evidence is labelled as such and is not represented
as native-hardware certification.

Every published package is linked to its installation and firewall evidence by
asset name and SHA-256. Before making any publication API request, the
write-capable job independently verifies the tag, source revision, matrix hash,
complete asset inventory, file sizes, digests, and `SHA256SUMS`.

To create a release, set `[workspace.package].version` in `Cargo.toml`, commit
the complete change, and create the matching `vX.Y.Z` tag on that commit. A
numeric `X.Y.Z` tag without the mandatory `v` prefix reaches Validation only,
where it fails with an explicit diagnostic; it can never reach compilation or
publication. Recovery of an already published release is allowed only through
the explicit `workflow_dispatch` repair option; existing assets with different
bytes are never overwritten.
