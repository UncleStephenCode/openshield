[English](README-CI.md) | [Русский](README-CI.ru.md)

# Release CI architecture

The release workflow treats validation, compilation, packaging, installation,
runtime verification, and publication as separate trust boundaries. A later
stage may consume only artifacts and evidence produced by its declared
predecessors.

## Release dependency graph

```text
Validation
    -> Quality Gate
    -> Binaries
    -> Packages
    -> Install Matrix
    -> Container Tests
    -> Firewall E2E
    -> Release Evidence
    -> Publish
```

The stages have the following responsibilities:

1. **Validation** binds the requested tag to the checked-out source revision,
   checks the workspace version, validates the release-matrix schema and unique
   row identifiers, and verifies that every referenced image is pinned by
   digest and contains the declared OCI platform.
2. **Quality Gate** runs the repository-wide formatting, lint, locked test, and
   static packaging checks before any release binary is accepted.
3. **Binaries** uses one matrix job to compile the daemon and TUI for every
   package-family/architecture pair. Each artifact carries its target identity,
   is checked as an ELF file, and is smoke-run in a pinned image of that family
   before it can be packaged.
4. **Packages** produces the DEB, RPM, APK, and Arch artifacts from those exact
   binaries. Identical family/architecture packages are built once and reused
   by all applicable distribution rows.
5. **Install Matrix** installs 19 runtime-tested package variants with the
   native package manager in 37 authoritative distribution/platform rows. The
   other 24 package variants are explicitly build-only and do not acquire
   installation evidence.
6. **Container Tests** exercises the pinned OpenRC, SysVinit, runit, s6, and
   dinit parser/supervisor fixtures after every package-install row succeeds.
7. **Firewall E2E** runs the complete Learning-to-Enforcing policy scenario
   twice for each of the 37 runtime-tested distribution/platform rows: once with
   nftables preferred and once in an iptables-only fallback environment (74
   jobs in total).
8. **Release Evidence** collects the source revision, matrix revision, image and
   platform identities, artifact hashes, the 37 package-install results, the 74
   backend-test results, and the expected inventory of all 43 binary archives
   and 43 packages. Evidence completeness is checked against the authoritative
   matrix rather than inferred from whichever jobs happened to finish.
9. **Publish** is reachable only when every required evidence record and release
   asset is present and consistent. Publication remains resumable, but an
   existing asset is never silently replaced with different bytes.

Validation and the Quality Gate therefore precede every release compilation;
package installation and firewall testing consume packages produced during the
same run, not binaries rebuilt inside test jobs. This runtime gate applies only
to package variants explicitly selected by the matrix.

Release tags use the canonical `vX.Y.Z` form and must point to the commit that
contains the same workspace version. Semver-like `X.Y.Z` tags without `v` are
included in the workflow trigger only so Validation can report the naming
error; all build, packaging, testing, and publication jobs remain unreachable.

Compilation runs on a native hosted runner or inside a digest-pinned Cross
toolchain container. It is intentionally not bootstrapped from each target
distribution's mutable package repository. The resulting static binary is then
executed in a pinned image of its package family. For the runtime-tested subset,
the exact package is also installed and tested in every declared distribution
image.

## Authoritative release matrix

[`packaging/ci/release-matrix.json`](../packaging/ci/release-matrix.json) is the
authoritative machine-readable list of release validation rows. It contains 43
binary/package family/architecture build targets, 86 declared
distribution/platform mappings, and a 37-row runtime submatrix covering 19
package variants:

| Distribution rows | Built package targets | Package-install and firewall E2E targets |
| --- | --- | --- |
| Debian 12 | `386`, `amd64`, ARMv7, `arm64`, `ppc64le` | `386`, `amd64`, `arm64` |
| Debian 13 | `386`, `amd64`, ARMv5, ARMv7, `arm64`, `ppc64le`, `riscv64`, `s390x` | `386`, `amd64`, `arm64` |
| Ubuntu 22.04, 24.04, and 26.04 | `amd64`, ARMv7, `arm64`, `ppc64le`, `riscv64`, `s390x` | `amd64`, `arm64` |
| Fedora 43 and 44 | `amd64`, `arm64`, `ppc64le`, `s390x` | `amd64`, `arm64` |
| Rocky Linux 9 / 10 | `amd64`, `arm64`, `ppc64le`, `s390x`; Rocky 10 also `riscv64` | `amd64`, `arm64` |
| AlmaLinux 9 / 10 | `amd64`, `arm64`, `ppc64le`, `s390x`; AlmaLinux 10 also `386` | `amd64`, `arm64`; AlmaLinux 10 also `386` |
| openSUSE Leap 16.0 | `amd64`, `arm64`, `ppc64le`, `s390x` | `amd64`, `arm64` |
| openSUSE Tumbleweed | `386`, `amd64`, ARMv6, ARMv7, `arm64`, `ppc64le`, `riscv64`, `s390x` | `386`, `amd64`, `arm64` |
| Alpine 3.23 and 3.24 | the same eight targets as Tumbleweed | `386`, `amd64`, `arm64` |
| Arch Linux | `amd64` | `amd64` |

The matrix is the release contract. All 43 binary archives and 43 packages are
built, but only the 37 selected distribution/platform rows acquire package
installation and firewall evidence. A package family is shared across
compatible image versions: for example, one runtime-tested DEB per architecture
is installed independently in every selected Debian and Ubuntu userspace that
publishes that architecture. The remaining 24 package variants account for 49
declared distribution/platform mappings; they are published as build-only
artifacts and carry no runtime-support claim.

This release matrix must not be confused with
[`tests/compat/distros.tsv`](../tests/compat/distros.tsv). The latter contains
60 maintained, rolling, legacy, and archived images used for broad portability
research. Its static-musl `--version` smoke tests do not install a package,
start an init system, initialize NFQUEUE, or exercise a firewall policy. A row
in that research matrix is not a release-support declaration.

## Architecture evidence

- `amd64` jobs execute natively on an x86-64 runner.
- `arm64` jobs execute natively on an AArch64 runner.
- `linux/386` packages execute through the x86-64 kernel's direct 32-bit
  compatibility path; this is not a test on a physical 32-bit processor.
- ARMv5, ARMv6, ARMv7, PowerPC64LE, RISC-V 64 and IBM Z builds use
  SHA-256-pinned Cross toolchain images and a pinned QEMU `binfmt_misc` handler
  only for target-image binary `--version` smoke tests. Their packages are not
  installed and their firewall is not exercised in release CI.

For QEMU binary-smoke rows, the workflow registers only the required
`binfmt_misc` handler by directly running the SHA-256-pinned `tonistiigi/binfmt`
image on the ephemeral runner. It does not depend on a third-party setup action.
The registration container is necessarily privileged and is explicitly refused
on self-hosted runners. Registration is followed immediately by checks of the
enabled handler, fix-binary flag and interpreter, then by a network-isolated,
capability-free probe in the pinned foreign-platform image. Any mismatch fails
the binary build job before its artifact is accepted.

QEMU success is retained only in the binary-build job log as emulated
binary-smoke evidence; it is not a runtime record in `RELEASE-EVIDENCE.json`. It
cannot certify package installation, firewall or NFQUEUE behavior, application
attribution, CPU-specific behavior, physical hardware, boot firmware, or a
distribution kernel. Those architectures require trusted native runners or
full-system hardware/VM test systems before runtime support can be claimed.

All Docker containers share the runner's Linux kernel. Even a native container
therefore validates the selected userspace, package manager, command-line
firewall tools, and isolated network namespace—not the kernel shipped by that
distribution or its complete boot sequence. Standard package-test containers
also do not boot systemd as PID 1.

## Firewall backend coverage

Each of the 37 runtime rows runs the complete Learning-to-Enforcing E2E
separately with nftables and with an iptables-only fallback installation: 37
jobs per backend, 74 in total. DEB and RPM use an explicit package-manager
alternative dependency. APK and Arch do not force-install one backend, because
those formats cannot express the same portable alternative; the installation
tests verify the package and dependency layout, while the separate firewall E2E
jobs prove that either backend can satisfy the runtime contract.

In an nftables scenario both frontends are installed and the daemon must still
select nftables. In an iptables scenario `nft` is absent, the complete IPv4 and
IPv6 xtables tool set must be available, and the daemon must select
`iptables/ip6tables`. This proves preference and fallback rather than merely
forcing a backend label.

## Pinned inputs and release evidence

Actions, downloaded build tools, Cross/QEMU environments, release-matrix
images, the E2E server, and all init fixtures are pinned to immutable revisions
or SHA-256 digests. A release-matrix image must
use `name@sha256:digest`; CI also checks that its manifest index contains the
row's explicit `linux/<architecture>` platform. The platform is always passed
to Docker so the daemon does not silently select the runner architecture.

Image pinning makes the base filesystem reproducible. Package repositories
consulted during installation can still change, so each of the 37 runtime rows
records the image digest, requested platform, execution mode, installed
OpenShield asset name and SHA-256, and both backend outcomes. Build-only
packages have no installation or backend record. The init gate records its
pinned images and script SHA-256. A successful manifest lookup alone is never
release evidence.

For openSUSE rows, CI refreshes only the required GPG-checked OSS repository
before provisioning. A libzypp status `4` during refresh is retried at most
three times with bounded backoff; every other status and every installation
transaction fails immediately. Installation disables implicit refresh, so a
partial repository update cannot be misreported as missing dependencies.

The evidence stage fails closed for missing, duplicate, unexpected, or
contradictory rows and assets. `SHA256SUMS` covers all published packages and
binary archives. Publication depends on that verified inventory and cannot run
directly after only the build or package stages.
