[English](README.md) | [Русский](README.ru.md)

# Linux compatibility matrices

The compatibility suite separates four different kinds of evidence. A pass in
one layer must not be interpreted as a pass in another.

| Layer | What it establishes | What it does not establish |
| --- | --- | --- |
| image manifest | a named container image was available from its registry at the time of the check | binary compatibility or runtime support |
| static musl smoke | both binaries can start and print `--version` in the image's userspace | init boot, libc integration, firewall tools, kernel features, NFQUEUE, or policy correctness |
| cross-target `cargo check` | the workspace type-checks for an installed Rust target standard library | linking, execution, hardware behavior, kernel ABI, or packaging |
| init parser/supervisor fixture | staged files, selected parsers, lifecycle hooks, and group helper behave in isolated fixtures | a real boot or real firewall policy |

The real Learning-to-Enforcing firewall workflow is a separate end-to-end test.

## Distribution image matrix

`distros.tsv` contains exactly 60 rows across Debian/Ubuntu, Alpine, Fedora,
Rocky, AlmaLinux, CentOS Stream, Oracle Linux, openSUSE, Amazon Linux, Arch,
Gentoo, Void, Devuan, and Artix. Rows intentionally include maintained,
rolling, legacy, and archived releases spanning approximately the preceding ten
years. The lifecycle column describes the image row; it is not a project support
commitment.

Validate matrix syntax and row count without Docker:

```console
scripts/test-distro-matrix.sh validate
```

Check registry manifests:

```console
scripts/test-distro-matrix.sh manifests
```

Run a smoke matrix using a directory that contains statically linked musl
`openshield-daemon` and `openshield-tui` binaries:

```console
scripts/test-distro-matrix.sh smoke /absolute/musl/release-directory
```

`smoke` requires a local Unix-socket Docker endpoint, disables networking in
each test container, mounts binaries read-only, makes the root filesystem
read-only, drops all capabilities, and enables `no-new-privileges`. It does not
remove images, which avoids racing with other local Docker users. `smoke-clean`
remains as a deprecated, non-destructive alias for `smoke`. The completed matrix
run against the final static-PIE artifacts reported `matrix rows: 60; failures:
0`; both binaries completed `--version` in every row.

This result primarily demonstrates portability of the chosen static musl
artifacts across those container userspaces. Containers share the host kernel,
and `--version` deliberately does not initialize procfs attribution or either
firewall backend. It is not certification of 60 complete distributions.

## Rust target matrix

`targets.tsv` contains 23 built-in Linux target names. Validate the file with:

```console
scripts/check-target-matrix.sh validate
```

In a Rust 1.98.0 environment with rustup, install missing stable target
components and type-check them with:

```console
scripts/check-target-matrix.sh check --install
```

The harness runs cross-target checks with one Cargo job to bound peak memory and
make the matrix deterministic on constrained builders.

The completed stable run checked 21/21 available targets without failures:

| Architecture family | Covered variants |
| --- | --- |
| x86 | i586 and i686; GNU and musl where listed |
| x86_64 / amd64 | GNU and musl |
| ARM | ARMv5, ARMv6, and ARMv7; soft-float and hard-float variants where the Rust target provides them; GNU and musl as listed |
| arm64 / aarch64 | GNU and musl |
| RISC-V 64 | `riscv64gc` GNU/musl and `riscv64a23` GNU |

`riscv32gc-unknown-linux-gnu` and
`riscv32gc-unknown-linux-musl` are recorded as Rust Tier 3. Stable rustup does
not provide their standard libraries, so the stable matrix skips them. Building
them requires a separately reviewed nightly `build-std` workflow; they are not
claimed as stable release targets.

The non-native jobs were compilation checks only. No blanket runtime claim is
made for x86, ARM, arm64, or RISC-V hardware. In particular, arm64 execution
could not be run on the test host because it had no binfmt/QEMU handler.
Architecture aliases do not create additional targets: AMD64 means x86_64, and
ARM64 means AArch64. `aarch` alone is not a Rust Linux target name.

## Init-system matrix

Run source/layout checks without Docker:

```console
scripts/test-init-matrix.sh validate
```

Run the isolated parser and supervisor fixtures:

```console
scripts/test-init-matrix.sh manifests
scripts/test-init-matrix.sh containers-clean
```

The completed checks covered staging layouts for all six supported init systems,
OpenRC parsing, SysVinit PID/executable semantics, runit and s6 supervised
start/finish quarantine, s6 dependency compilation, dinit parsing, and both
BusyBox `addgroup` and shadow `groupadd` group creation. systemd is statically
staged and checked separately: the unit with target stubs passed
`systemd-analyze verify`, and offline
`systemd-analyze security --offline=yes --threshold=100` passed with exposure
2.6 (`OK`). The tmpfiles declaration for the shared xtables lock also passed a
rooted dry run. This matrix does not boot systemd in a container or as PID 1.

The lifecycle fixtures mount a stub daemon. Their successful result does not
mean a backend was selected or that real packets were filtered.

## Real firewall end-to-end workflow

`../e2e/server-learning-enforcing.sh` creates a disposable Docker network with a
client and HTTP server. It is designed to verify, separately for each backend:

- selection of the requested nftables or iptables backend;
- initial persisted `Learning` mode after startup quarantine;
- observation access for `openshield` and denial for an outsider;
- denial of control to a non-root group member;
- learning an application-bound `/usr/bin/curl` rule;
- continued curl access and denial of another executable in `Enforcing`;
- coexistence with a downstream firewall DROP;
- inbound denial followed by an explicit inbound allow;
- graceful-shutdown kernel `BlockAll` without replacing persisted `Enforcing`;
- restart into the persisted mode.

Build daemon binaries compatible with the Debian Bookworm test container, then
run each backend explicitly:

```console
tests/e2e/server-learning-enforcing.sh nftables /absolute/bookworm/release-directory
tests/e2e/server-learning-enforcing.sh iptables /absolute/bookworm/release-directory
```

The workflow installs packages in the disposable client container and therefore
needs registry/package-network access. Firewall capabilities are granted only
inside that container; the script does not apply rules on the host. Before
creating resources, it reads the active endpoint with `docker context inspect`
and refuses every endpoint whose URI is not `unix:///*`.

The final Rust 1.98.0 Debian Bookworm release binaries passed both backend runs:

```text
PASS server Learning -> UDP/TCP Enforcing -> inbound allow -> restart (nftables)
PASS server Learning -> UDP/TCP Enforcing -> inbound allow -> restart (iptables)
```

These results cover the scripted behavior inside disposable network and
container namespaces on a local Unix-socket Docker engine. They did not test or
modify the host firewall and do not certify production kernels, deployments,
upgrades, or competing firewall configurations.
