#!/usr/bin/env bash
set -euo pipefail

usage() {
    printf 'usage: %s ARCH PLATFORM PINNED_PROBE_IMAGE\n' "$0" >&2
}

[[ "$#" -eq 3 ]] || { usage; exit 2; }
: "${BINFMT_IMAGE:?BINFMT_IMAGE is required}"

emulated_arch=$1
emulated_platform=$2
probe_image=$3

[[ "${RUNNER_ENVIRONMENT:-}" == github-hosted \
    && "${RUNNER_OS:-}" == Linux \
    && "${RUNNER_ARCH:-}" == X64 ]] || {
    printf '%s\n' \
        'privileged binfmt registration is restricted to an ephemeral GitHub-hosted Linux X64 runner' >&2
    exit 1
}

case "$emulated_arch:$emulated_platform" in
    armv5:linux/arm/v5|armv6:linux/arm/v6|armv7:linux/arm/v7)
        binfmt_arch=arm
        qemu_arch=arm
        uname_family=arm
        ;;
    arm64:linux/arm64)
        binfmt_arch=arm64
        qemu_arch=aarch64
        uname_family=arm64
        ;;
    ppc64le:linux/ppc64le)
        binfmt_arch=ppc64le
        qemu_arch=ppc64le
        uname_family=ppc64le
        ;;
    riscv64:linux/riscv64)
        binfmt_arch=riscv64
        qemu_arch=riscv64
        uname_family=riscv64
        ;;
    s390x:linux/s390x)
        binfmt_arch=s390x
        qemu_arch=s390x
        uname_family=s390x
        ;;
    *)
        printf 'unsupported emulated architecture/platform pair: %s / %s\n' \
            "$emulated_arch" "$emulated_platform" >&2
        exit 2
        ;;
esac

image_pattern='^[a-z0-9]+([._-][a-z0-9]+)*(:[0-9]+)?(/[a-z0-9]+([._-][a-z0-9]+)*)*(:[A-Za-z0-9_][A-Za-z0-9._-]{0,127})?@sha256:[0-9a-f]{64}$'
for image in "$BINFMT_IMAGE" "$probe_image"; do
    [[ "$image" =~ $image_pattern ]] || {
        printf 'container image is not pinned by SHA-256: %s\n' "$image" >&2
        exit 1
    }
done

for command in awk docker grep tee; do
    command -v "$command" >/dev/null || {
        printf 'required command is missing: %s\n' "$command" >&2
        exit 1
    }
done

if [[ -n ${DOCKER_HOST:-} && -z ${DOCKER_CONTEXT:-} ]]; then
    docker_host=$DOCKER_HOST
else
    docker_host=$(docker context inspect \
        --format '{{(index .Endpoints "docker").Host}}' 2>/dev/null) || {
        printf '%s\n' 'cannot inspect the active Docker context' >&2
        exit 1
    }
fi
[[ "$docker_host" =~ ^unix:///[A-Za-z0-9._/-]+$ ]] || {
    printf 'refusing non-local Docker endpoint: %s\n' "$docker_host" >&2
    exit 1
}
[[ "${RUNNER_TEMP:-}" =~ ^/[A-Za-z0-9._/-]+$ ]] || {
    printf 'unsafe RUNNER_TEMP path: %s\n' "${RUNNER_TEMP:-}" >&2
    exit 1
}

docker pull --platform linux/amd64 "$BINFMT_IMAGE" >/dev/null
install_log="$RUNNER_TEMP/openshield-binfmt-$emulated_arch.log"
[[ ! -e "$install_log" && ! -L "$install_log" ]] || {
    printf 'refusing an existing binfmt log path: %s\n' "$install_log" >&2
    exit 1
}
if ! docker run --rm --privileged --network none \
    --platform linux/amd64 --pull never \
    "$BINFMT_IMAGE" --install "$binfmt_arch" 2>&1 | tee "$install_log"; then
    printf 'the pinned binfmt installer failed for %s\n' "$emulated_arch" >&2
    exit 1
fi
grep -Fqx "installing: $binfmt_arch OK" "$install_log" || {
    printf 'the pinned binfmt image did not register %s\n' "$binfmt_arch" >&2
    exit 1
}

handler="/proc/sys/fs/binfmt_misc/qemu-$qemu_arch"
[[ -r "$handler" ]] || {
    printf 'QEMU/binfmt handler was not registered: %s\n' "$handler" >&2
    exit 1
}
grep -qx enabled "$handler" || {
    printf 'QEMU/binfmt handler is not enabled: %s\n' "$handler" >&2
    exit 1
}
handler_flags=$(awk '$1 == "flags:" { print $2; exit }' "$handler")
[[ "$handler_flags" == *F* ]] || {
    printf 'QEMU/binfmt handler lacks the fix-binary flag: %s\n' "$handler_flags" >&2
    exit 1
}
handler_interpreter=$(awk '$1 == "interpreter" { print $2; exit }' "$handler")
[[ "$handler_interpreter" == "/usr/bin/qemu-$qemu_arch" ]] || {
    printf 'unexpected QEMU/binfmt interpreter: %s\n' "$handler_interpreter" >&2
    exit 1
}

docker pull --platform "$emulated_platform" "$probe_image" >/dev/null
actual_arch=$(docker run --rm --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges --security-opt label=disable \
    --platform "$emulated_platform" --pull never \
    --entrypoint /bin/sh "$probe_image" -eu -c 'uname -m')
case "$uname_family:$actual_arch" in
    arm:arm|arm:armv5*|arm:armv6*|arm:armv7*|arm:armv8*|\
    arm64:aarch64|arm64:arm64|ppc64le:ppc64le|riscv64:riscv64|s390x:s390x)
        ;;
    *)
        printf 'QEMU/binfmt probe reported %s for %s\n' \
            "$actual_arch" "$emulated_arch" >&2
        exit 1
        ;;
esac
