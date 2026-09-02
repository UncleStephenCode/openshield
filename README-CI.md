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
    -> 7 binary builds
    -> 18 package builds
    -> 34 distribution/platform installations
    -> pinned init-system container tests
    -> 59 firewall E2E jobs
    -> sealed release candidate and evidence
    -> publication
```

The 59 firewall jobs comprise 32 nftables scenarios and 27 iptables fallback
scenarios. Tumbleweed i586 executes both scenarios through the x86 runner's
`linux/386` compatibility mode. Tumbleweed ppc64le and s390x are explicitly
recorded as QEMU package smoke only and are not represented as full firewall or
native-hardware certification.

Every published package is linked to its installation and firewall evidence by
asset name and SHA-256. Before making any publication API request, the
write-capable job independently verifies the tag, source revision, matrix hash,
complete asset inventory, file sizes, digests, and `SHA256SUMS`.

To create a release, set `[workspace.package].version` in `Cargo.toml`, commit
the complete change, and create the matching `vX.Y.Z` tag. Recovery of an
already published release is allowed only through the explicit
`workflow_dispatch` repair option; existing assets with different bytes are
never overwritten.
