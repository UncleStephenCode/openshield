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
3. **Binaries** compiles the daemon and TUI once for every required release
   target. Each artifact carries its target identity and is checked as an ELF
   file before it can be packaged.
4. **Packages** produces the DEB, RPM, APK, and Arch artifacts from those exact
   binaries. Identical family/architecture packages are built once and reused
   by all applicable distribution rows.
5. **Install Matrix** installs the selected package with the native package
   manager in every authoritative distribution/platform row. An artifact being
   built is not sufficient: every declared row must report a successful
   installation.
6. **Container Tests** exercises the pinned OpenRC, SysVinit, runit, s6, and
   dinit parser/supervisor fixtures after every package-install row succeeds.
7. **Firewall E2E** runs the complete Learning-to-Enforcing policy scenario for
   every backend assigned to a matrix row: 32 nftables jobs and 27 iptables
   fallback jobs.
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

## Authoritative release matrix

[`packaging/ci/release-matrix.json`](../packaging/ci/release-matrix.json) is the
authoritative machine-readable list of release validation rows. It contains 34
distribution/userspace and OCI-platform pairs:

| Distribution rows | Validated package platforms |
| --- | --- |
| Debian 12 and 13 | `linux/amd64`, `linux/arm64` |
| Ubuntu 22.04, 24.04, and 26.04 | `linux/amd64`, `linux/arm64` |
| Fedora 43 and 44 | `linux/amd64`, `linux/arm64` |
| Rocky Linux 9 and 10 | `linux/amd64`, `linux/arm64` |
| AlmaLinux 9 and 10 | `linux/amd64`, `linux/arm64` |
| openSUSE Leap 16.0 | `linux/amd64`, `linux/arm64` |
| openSUSE Tumbleweed | `linux/amd64`, `linux/386` (i586), `linux/arm64`, `linux/ppc64le`, `linux/s390x` |
| Alpine 3.23 and 3.24 | `linux/amd64`, `linux/arm64` |
| Arch Linux | `linux/amd64` |

The matrix row, not the existence of a compiler target or an image manifest,
defines release scope. An OCI image may publish additional platforms for which
OpenShield does not currently publish a matching package. Conversely, a
package family may be shared by several rows: for example, one DEB per
architecture is tested separately in each selected Debian and Ubuntu
userspace.

This 34-row list must not be confused with
[`tests/compat/distros.tsv`](../tests/compat/distros.tsv). The latter contains
60 maintained, rolling, legacy, and archived images used for broad portability
research. Its static-musl `--version` smoke tests do not install a package,
start an init system, initialize NFQUEUE, or exercise a firewall policy. A row
in that research matrix is not a release-support declaration.

## Architecture evidence

- `amd64` jobs execute natively on an x86-64 runner.
- `arm64` jobs execute natively on an AArch64 runner.
- The Tumbleweed i586 package is installed through the x86 runner's direct
  `linux/386` compatibility path. Its cross-built binary also receives a
  capability-free `qemu-runner` smoke check. The installed package then runs
  the full nftables and iptables E2E directly through `linux/386`; this is not
  a test on a physical i586 processor.
- Tumbleweed `ppc64le` and `s390x` jobs use pinned QEMU/Cross environments for
  ELF validation, package installation, and capability-free execution smoke.
  Those jobs do not claim native execution or full firewall E2E.

For the two QEMU package-install rows, the workflow registers only the required
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
certification for `ppc64le` or `s390x` requires trusted native runners or
hardware/VM test systems and a separate evidence level.

All Docker containers share the runner's Linux kernel. Even a native container
therefore validates the selected userspace, package manager, command-line
firewall tools, and isolated network namespace—not the kernel shipped by that
distribution or its complete boot sequence. Standard package-test containers
also do not boot systemd as PID 1.

## Firewall backend coverage

The backend contract follows package dependencies:

- DEB and RPM rows marked `full` (`amd64`, `arm64`, and Tumbleweed i586) run the complete Learning-to-Enforcing E2E
  separately with nftables and with an iptables-only fallback installation;
- APK and Arch rows run the complete nftables E2E because their released
  package metadata requires nftables rather than declaring iptables as an
  alternative dependency;
- Tumbleweed `ppc64le` and `s390x` are limited to package and QEMU execution
  smoke and are not reported as full firewall-backend passes.

In an nftables scenario both frontends are installed and the daemon must still
select nftables. In an iptables scenario `nft` is absent, the complete IPv4 and
IPv6 xtables tool set must be available, and the daemon must select
`iptables/ip6tables`. This proves preference and fallback rather than merely
forcing a backend label.

Extending APK or Arch coverage to iptables requires changing and reviewing the
package dependency contract first; a CI-only installation of undeclared tools
would not prove that the released package supports an iptables-only host.

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
