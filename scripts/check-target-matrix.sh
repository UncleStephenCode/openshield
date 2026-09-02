#!/bin/sh
set -eu

usage() {
    printf '%s\n' \
        'usage: scripts/check-target-matrix.sh validate' \
        '       scripts/check-target-matrix.sh check [--install]'
}

mode=${1:-}
install_missing=false
case "$mode:${2:-}" in
    validate:) ;;
    check:) ;;
    check:--install) install_missing=true ;;
    *) usage >&2; exit 2 ;;
esac

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repository_directory=$(CDPATH= cd -- "$script_directory/.." && pwd -P)
matrix="$repository_directory/tests/compat/targets.tsv"
tab=$(printf '\t')
expected_header=$(printf '# target\tarchitecture\tlibc\trust-tier\texecution')
actual_header=$(sed -n '1p' "$matrix")
[ "$actual_header" = "$expected_header" ] || {
    printf '%s\n' 'invalid target matrix header' >&2
    exit 1
}
count=0
checked=0
skipped=0
failed=0
seen='|'

if [ "$mode" = check ]; then
    command -v rustc >/dev/null 2>&1 || {
        printf '%s\n' 'rustc is required for target validation in check mode' >&2
        exit 1
    }
    rust_targets=$(rustc --print target-list)
fi

while IFS="$tab" read -r target architecture libc_name tier execution extra; do
    case "$target" in ''|'#'*) continue ;; esac
    [ -z "${extra:-}" ] || { printf 'extra matrix field for %s\n' "$target" >&2; exit 1; }
    case "$target:$architecture:$libc_name:$tier:$execution" in
        *[!A-Za-z0-9._:-]*) printf 'unsafe target metadata: %s\n' "$target" >&2; exit 1 ;;
    esac
    case "$seen" in
        *"|$target|"*) printf 'duplicate target: %s\n' "$target" >&2; exit 1 ;;
    esac
    seen="${seen}${target}|"
    case "$target:$architecture:$libc_name:$tier:$execution" in
        i586-unknown-linux-gnu:x86:glibc:2:qemu-or-hardware | \
        i586-unknown-linux-musl:x86:musl:2:qemu-or-hardware | \
        i686-unknown-linux-gnu:x86:glibc:1:qemu-or-hardware | \
        i686-unknown-linux-musl:x86:musl:2:qemu-or-hardware | \
        x86_64-unknown-linux-gnu:x86_64-amd64:glibc:1:native | \
        x86_64-unknown-linux-musl:x86_64-amd64:musl:2:native | \
        armv5te-unknown-linux-gnueabi:armv5:glibc:2:qemu-or-hardware | \
        armv5te-unknown-linux-musleabi:armv5:musl:2:qemu-or-hardware | \
        arm-unknown-linux-gnueabi:armv6:glibc:2:qemu-or-hardware | \
        arm-unknown-linux-gnueabihf:armv6-hardfloat:glibc:2:qemu-or-hardware | \
        arm-unknown-linux-musleabi:armv6:musl:2:qemu-or-hardware | \
        arm-unknown-linux-musleabihf:armv6-hardfloat:musl:2:qemu-or-hardware | \
        armv7-unknown-linux-gnueabi:armv7:glibc:2:qemu-or-hardware | \
        armv7-unknown-linux-gnueabihf:armv7-hardfloat:glibc:2:qemu-or-hardware | \
        armv7-unknown-linux-musleabi:armv7:musl:2:qemu-or-hardware | \
        armv7-unknown-linux-musleabihf:armv7-hardfloat:musl:2:qemu-or-hardware | \
        aarch64-unknown-linux-gnu:arm64-aarch64:glibc:1:qemu-or-hardware | \
        aarch64-unknown-linux-musl:arm64-aarch64:musl:2:qemu-or-hardware | \
        powerpc64le-unknown-linux-gnu:powerpc64le:glibc:2:qemu-or-hardware | \
        s390x-unknown-linux-gnu:s390x:glibc:2:qemu-or-hardware | \
        riscv64gc-unknown-linux-gnu:riscv64-gc:glibc:2:qemu-or-hardware | \
        riscv64gc-unknown-linux-musl:riscv64-gc:musl:2:qemu-or-hardware | \
        riscv64a23-unknown-linux-gnu:riscv64-a23:glibc:2:qemu-or-hardware | \
        riscv32gc-unknown-linux-gnu:riscv32-gc:glibc:3:build-std-nightly-required | \
        riscv32gc-unknown-linux-musl:riscv32-gc:musl:3:build-std-nightly-required)
            ;;
        *)
            printf 'invalid target metadata mapping: %s\n' "$target" >&2
            exit 1
            ;;
    esac
    count=$((count + 1))
    [ "$mode" = validate ] && continue

    printf '%s\n' "$rust_targets" | grep -Fqx "$target" || {
        printf 'target is not built into this rustc: %s\n' "$target" >&2
        exit 1
    }

    if [ "$tier" = 3 ]; then
        printf 'SKIP %-42s stable rustup std unavailable (%s)\n' "$target" "$execution"
        skipped=$((skipped + 1))
        continue
    fi
    if ! rustup target list --installed | grep -Fqx "$target"; then
        if [ "$install_missing" = true ]; then
            rustup target add "$target"
        else
            printf 'SKIP %-42s target component not installed\n' "$target"
            skipped=$((skipped + 1))
            continue
        fi
    fi
    # Keep rustc memory pressure deterministic across the 32/64-bit matrix.
    # Parallel crate builds have triggered a reproducible compiler ICE in
    # rustc 1.98.0 under constrained CI, while the same source succeeds in a
    # single job.
    if cargo check --workspace --all-targets --locked --jobs 1 --target "$target"; then
        printf 'PASS %-42s\n' "$target"
        checked=$((checked + 1))
    else
        printf 'FAIL %-42s\n' "$target" >&2
        failed=$((failed + 1))
    fi
done < "$matrix"

[ "$count" -eq 25 ] || { printf 'expected 25 matrix rows, found %s\n' "$count" >&2; exit 1; }
printf 'targets: %s; checked: %s; skipped: %s; failures: %s\n' "$count" "$checked" "$skipped" "$failed"
[ "$failed" -eq 0 ]
