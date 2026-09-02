# OpenShield GitHub CI/release files

Copy the contents of this archive into the root of the OpenShield repository.
The archive is additive: it does not replace the existing `packaging/` assets;
it relies on the project's existing `packaging/stage-install.sh`, init files and
compatibility scripts.

## What it adds

- `.github/workflows/ci.yml`: PR/main Rust and packaging validation.
- `.github/workflows/release.yml`: tag-driven amd64 + arm64 static-musl builds,
  native package generation, install smoke tests, firewall E2E, checksums and a
  GitHub Release.
- `packaging/ci/nfpm.yaml`: common nFPM package definition.
- `packaging/ci/scripts/build-release-package.sh`: builds DEB/RPM/APK/Arch packages.
- `packaging/ci/scripts/test-release-package.sh`: installs packages in distribution containers.
- `packaging/ci/hooks/*`: safe post-install hooks; they create runtime prerequisites
  but deliberately do not enable or start OpenShield.

## Release matrix

Binaries:
- amd64: `x86_64-unknown-linux-musl`
- arm64: `aarch64-unknown-linux-musl`

Packages:
- DEB: amd64, arm64
- Fedora RPM: amd64, arm64
- EL9 RPM: amd64, arm64
- EL10 RPM: amd64, arm64
- openSUSE RPM: amd64, arm64
- Alpine APK: amd64, arm64
- Arch package: amd64

Install smoke tests currently run on amd64 containers for Debian 12/13,
Ubuntu 22.04/24.04/26.04, Fedora 43/44, Rocky/Alma 9 and 10,
openSUSE Leap 16.0, Alpine 3.23/3.24 and Arch Linux.

## First test

1. Merge the files into `main` and make sure the ordinary CI passes.
2. Ensure `[workspace.package].version` in `Cargo.toml` is the desired version.
3. Create and push the matching tag, for example:

   git tag -a v0.1.14 -m 'OpenShield v0.1.14'
   git push origin v0.1.14

The release workflow refuses a tag whose version differs from Cargo.toml.

Publishing is resumable. If the tag already has a GitHub Release, the workflow
keeps matching assets, uploads only missing files, and refuses to delete or
replace a file whose size or SHA-256 digest differs from the current build. A
draft is published only after the complete remote asset set has been verified.
A run triggered by creation of a tag automatically completes an existing
matching release. Tag updates and force-pushes are not authorized to repair a
published release. To recover an older tag through `workflow_dispatch`, run it
from a revision containing this workflow, pass that tag as the `tag` input, and
explicitly enable `repair_existing_release`. Re-running an older failed job uses
its original workflow revision and does not pick up later workflow fixes.

## Important

The workflow uses GitHub-hosted `ubuntu-24.04-arm` for native arm64 builds.
If that runner label is not available for the repository/account, change the
arm64 row in `.github/workflows/release.yml` to an available ARM64 runner or a
self-hosted ARM64 runner.
