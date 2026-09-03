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
5. **Install Matrix** installs the selected package with the native package
   manager in every authoritative distribution/platform row. An artifact being
   built is not sufficient: every declared row must report a successful
   installation.
6. **Container Tests** exercises the pinned OpenRC, SysVinit, runit, s6, and
   dinit parser/supervisor fixtures after every package-install row succeeds.
7. **Firewall E2E** runs the complete Learning-to-Enforcing policy scenario
   twice for every distribution/platform row: once with nftables preferred and
   once in an iptables-only fallback environment (172 jobs in total).
8. **Release Evidence** collects the source revision, matrix revision, image and
   platform identities, artifact hashes, package-install results, backend-test
   results, and the expected release-asset inventory. Evidence completeness is
   checked against the authoritative matrix rather than inferred from whichever
   jobs happened to finish.
9. **Publish** is reachable only when every required evidence record and release
   asset is present and consistent. Publication remains resumable, but an
   existing asset is never silently replaced with different bytes.

Validation and the Quality Gate therefore precede every release compilation;
package installation and firewall testing consume packages produced during the
same run, not binaries rebuilt inside test jobs.

Release tags use the canonical `vX.Y.Z` form and must point to the commit that
contains the same workspace version. Semver-like `X.Y.Z` tags without `v` are
included in the workflow trigger only so Validation can report the naming
error; all build, packaging, testing, and publication jobs remain unreachable.

Compilation runs on a native hosted runner or inside a digest-pinned Cross
toolchain container. It is intentionally not bootstrapped from each target
distribution's mutable package repository. The resulting static binary is then
executed in a pinned image of its package family, and the exact package is
installed and tested in every declared distribution image.

## Authoritative release matrix

[`packaging/ci/release-matrix.json`](../packaging/ci/release-matrix.json) is the
authoritative machine-readable list of release validation rows. It contains 43
binary/package family/architecture pairs and 86 distribution/userspace and
OCI-platform pairs:

| Distribution rows | Validated package platforms |
| --- | --- |
| Debian 12 | `linux/386`, `linux/amd64`, `linux/arm/v7`, `linux/arm64`, `linux/ppc64le` |
| Debian 13 | `linux/386`, `linux/amd64`, `linux/arm/v5`, `linux/arm/v7`, `linux/arm64`, `linux/ppc64le`, `linux/riscv64`, `linux/s390x` |
| Ubuntu 22.04, 24.04, and 26.04 | `linux/amd64`, `linux/arm/v7`, `linux/arm64`, `linux/ppc64le`, `linux/riscv64`, `linux/s390x` |
| Fedora 43 and 44 | `linux/amd64`, `linux/arm64`, `linux/ppc64le`, `linux/s390x` |
| Rocky Linux 9 / 10 | four architectures above; Rocky 10 additionally `linux/riscv64` |
| AlmaLinux 9 / 10 | four architectures above; AlmaLinux 10 additionally `linux/386` |
| openSUSE Leap 16.0 | `linux/amd64`, `linux/arm64`, `linux/ppc64le`, `linux/s390x` |
| openSUSE Tumbleweed | `linux/386`, `linux/amd64`, `linux/arm/v6`, `linux/arm/v7`, `linux/arm64`, `linux/ppc64le`, `linux/riscv64`, `linux/s390x` |
| Alpine 3.23 and 3.24 | the same eight OCI platforms as Tumbleweed |
| Arch Linux | `linux/amd64` |

The matrix is the release contract. Every platform published by the pinned
image indexes is represented when a stable Rust target and a matching package
architecture exist. A package family is still shared across compatible image
versions: for example, one DEB per architecture is tested independently in
every selected Debian and Ubuntu userspace that publishes that architecture.

This 86-row list must not be confused with
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
  SHA-256-pinned Cross toolchain images and execute their package and firewall
  jobs through a pinned QEMU `binfmt_misc` handler.

For QEMU rows, the workflow registers only the required
`binfmt_misc` handler by directly running the SHA-256-pinned `tonistiigi/binfmt`
image on the ephemeral runner. It does not depend on a third-party setup action.
The registration container is necessarily privileged and is explicitly refused
on self-hosted runners. Registration is followed immediately by checks of the
enabled handler, fix-binary flag and interpreter, then by a network-isolated,
capability-free probe in the pinned foreign-platform image. Any mismatch fails
the job before the package artifact is downloaded or tested.

QEMU success is explicitly recorded as emulated evidence. It cannot certify
CPU-specific behavior, physical hardware, boot firmware, a distribution kernel,
or procfs application attribution under native execution. Full production
certification requires trusted native runners or hardware/VM test systems and a
separate evidence level.

User-mode QEMU normally obscures the original executable behind its interpreter
in `/proc/<pid>/exe`. To preserve the application-attribution assertions instead
of skipping them, emulated firewall jobs mount a separately built static native
TCP/UDP test client into the target container. The target OpenShield daemon,
package-manager userspace and firewall tools remain the declared foreign
architecture; the client gives procfs a stable, distinct executable identity
for the learned-rule and cross-application denial checks.

All Docker containers share the runner's Linux kernel. Even a native container
therefore validates the selected userspace, package manager, command-line
firewall tools, and isolated network namespace—not the kernel shipped by that
distribution or its complete boot sequence. Standard package-test containers
also do not boot systemd as PID 1.

## Firewall backend coverage

Every row runs the complete Learning-to-Enforcing E2E separately with nftables
and with an iptables-only fallback installation. DEB and RPM use an explicit
package-manager alternative dependency. APK and Arch do not force-install one
backend, because those formats cannot express the same portable alternative;
the installation tests verify the package and dependency layout, while the
separate firewall E2E jobs prove that either backend can satisfy the runtime
contract.

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
consulted during installation can still change, so evidence records the image
digest, requested platform, execution mode, installed OpenShield asset name and
SHA-256, backend, and test outcome. The init gate records its pinned images and
script SHA-256. A successful manifest lookup alone is never release evidence.

The evidence stage fails closed for missing, duplicate, unexpected, or
contradictory rows and assets. `SHA256SUMS` covers all published packages and
binary archives. Publication depends on that verified inventory and cannot run
directly after only the build or package stages.
