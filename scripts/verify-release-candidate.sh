#!/bin/bash
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

fail() {
    printf 'verify-release-candidate: %s\n' "$*" >&2
    exit 1
}

[[ "$#" -eq 5 ]] || fail \
    'usage: verify-release-candidate.sh DIRECTORY VERSION TAG SOURCE_SHA MATRIX'

candidate=$1
version=$2
tag=$3
source_sha=$4
matrix=$5

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.+][0-9A-Za-z.-]+)?$ ]] \
    || fail 'unsafe version'
[[ "$tag" == "v$version" ]] || fail 'tag/version mismatch'
[[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] || fail 'unsafe source SHA'
[[ -d "$candidate" && ! -L "$candidate" ]] || fail 'unsafe candidate directory'
[[ -f "$matrix" && ! -L "$matrix" ]] || fail 'unsafe release matrix'
[[ -f "$candidate/RELEASE-EVIDENCE.json" && ! -L "$candidate/RELEASE-EVIDENCE.json" ]] \
    || fail 'missing release evidence'
[[ -f "$candidate/SHA256SUMS" && ! -L "$candidate/SHA256SUMS" ]] \
    || fail 'missing checksums'
command -v jq >/dev/null || fail 'jq is required'
script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repository_directory=$(CDPATH= cd -- "$script_directory/.." && pwd -P)

temporary_directory=$(mktemp -d /tmp/openshield-candidate-verify.XXXXXX)
cleanup() {
    case "$temporary_directory" in
        /tmp/openshield-candidate-verify.*) rm -rf -- "$temporary_directory" ;;
        *) printf 'refusing unsafe temporary cleanup: %s\n' "$temporary_directory" >&2 ;;
    esac
}
trap cleanup EXIT

unexpected=$(find "$candidate" -mindepth 1 -maxdepth 1 ! -type f -print -quit)
[[ -z "$unexpected" ]] || fail 'candidate contains a non-regular entry'
while IFS= read -r -d '' release_file; do
    [[ ! -L "$release_file" && $(stat -c '%h' -- "$release_file") == 1 ]] \
        || fail "unsafe release file: $release_file"
done < <(find "$candidate" -mindepth 1 -maxdepth 1 -type f -print0)

expected_assets=$(jq -er '(.binaries | length) + (.packages | length)' "$matrix")
[[ "$expected_assets" =~ ^[0-9]+$ ]] || fail 'invalid matrix asset count'
actual_files=$(find "$candidate" -mindepth 1 -maxdepth 1 -type f | wc -l)
[[ "$actual_files" -eq $((expected_assets + 2)) ]] || fail 'release file count mismatch'

declare -A checksum_names=()
while IFS= read -r checksum_line || [[ -n "$checksum_line" ]]; do
    [[ "$checksum_line" =~ ^([0-9a-f]{64})\ \ ([A-Za-z0-9][A-Za-z0-9._+~-]*)$ ]] \
        || fail 'unsafe checksum-manifest entry'
    checksum_name=${BASH_REMATCH[2]}
    [[ -z "${checksum_names[$checksum_name]+present}" ]] \
        || fail "duplicate checksum entry: $checksum_name"
    checksum_names[$checksum_name]=1
    printf '%s\n' "$checksum_name" >> "$temporary_directory/checksum-assets"
done < "$candidate/SHA256SUMS"
[[ "${#checksum_names[@]}" -eq $((expected_assets + 1)) ]] \
    || fail 'checksum-manifest entry count mismatch'
LC_ALL=C sort -o "$temporary_directory/checksum-assets" \
    "$temporary_directory/checksum-assets"
find "$candidate" -mindepth 1 -maxdepth 1 -type f ! -name SHA256SUMS \
    -printf '%f\n' | LC_ALL=C sort > "$temporary_directory/checksum-expected"
cmp -s "$temporary_directory/checksum-assets" "$temporary_directory/checksum-expected" \
    || fail 'checksum manifest does not cover the exact candidate inventory'
(cd "$candidate" && sha256sum --check --strict SHA256SUMS)

evidence=$candidate/RELEASE-EVIDENCE.json
matrix_sha256=$(sha256sum -- "$matrix")
matrix_sha256=${matrix_sha256%% *}
init_script_sha256=$(sha256sum -- "$repository_directory/scripts/test-init-matrix.sh")
init_script_sha256=${init_script_sha256%% *}
jq -e \
    --argjson expected_assets "$expected_assets" \
    --arg matrix_sha256 "$matrix_sha256" \
    --arg source_sha "$source_sha" \
    --arg tag "$tag" \
    --arg version "$version" '
      (keys == ["assets", "firewall_e2e_results", "init_system_result",
        "matrix_sha256", "package_install_results", "schema_version",
        "source_sha", "tag", "version"])
      and .schema_version == 1
      and .tag == $tag
      and .version == $version
      and .source_sha == $source_sha
      and .matrix_sha256 == $matrix_sha256
      and (.assets | length == $expected_assets)
      and (.assets | map(.name) | unique | length == $expected_assets)
      and all(.assets[];
        (.name | test("^[A-Za-z0-9][A-Za-z0-9._+~-]*$"))
        and (.sha256 | test("^[0-9a-f]{64}$"))
        and (.size | type == "number" and . > 0)
        and (.kind == "binary" or .kind == "package")
        and (.matrix_id | test("^[a-z0-9]+(-[a-z0-9]+)*$")))
    ' "$evidence" >/dev/null || fail 'release evidence identity or schema mismatch'

jq -S '[.binaries[] | {kind: "binary", matrix_id: .id}]
    + [.packages[] | {kind: "package", matrix_id: .id}] | sort_by(.kind, .matrix_id)' \
    "$matrix" > "$temporary_directory/expected-identities.json"
jq -S '[.assets[] | {kind, matrix_id}] | sort_by(.kind, .matrix_id)' \
    "$evidence" > "$temporary_directory/actual-identities.json"
cmp -s "$temporary_directory/expected-identities.json" \
    "$temporary_directory/actual-identities.json" \
    || fail 'release asset matrix identities differ'

find "$candidate" -mindepth 1 -maxdepth 1 -type f \
    ! -name RELEASE-EVIDENCE.json ! -name SHA256SUMS -printf '%f\n' \
    | LC_ALL=C sort > "$temporary_directory/actual-assets"
jq -r '.assets[].name' "$evidence" | LC_ALL=C sort \
    > "$temporary_directory/evidence-assets"
cmp -s "$temporary_directory/actual-assets" "$temporary_directory/evidence-assets" \
    || fail 'release asset inventory differs from evidence'

while IFS=$'\t' read -r name expected_sha256 expected_size; do
    [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._+~-]*$ ]] || fail 'unsafe asset name'
    asset=$candidate/$name
    [[ -f "$asset" && ! -L "$asset" ]] || fail "missing asset: $name"
    actual_size=$(stat -c '%s' -- "$asset")
    actual_sha256=$(sha256sum -- "$asset")
    actual_sha256=${actual_sha256%% *}
    [[ "$actual_size" == "$expected_size" && "$actual_sha256" == "$expected_sha256" ]] \
        || fail "asset digest or size mismatch: $name"
done < <(jq -r '.assets[] | [.name, .sha256, (.size | tostring)] | @tsv' "$evidence")

jq -S --arg source_sha "$source_sha" --arg version "$version" \
    --slurpfile evidence "$evidence" '
      def execution_mode($arch):
        if ($arch == "386" or $arch == "i586") then "x86-compat"
        elif ($arch == "amd64" or $arch == "arm64") then "native"
        else "qemu-user"
        end;
      ($evidence[0].assets
        | map(select(.kind == "package"))
        | INDEX(.matrix_id)) as $assets
      | [.platforms[] as $row
        | $assets[$row.package] as $asset
        | {schema_version: 1, type: "package-install", id: $row.id,
           package: $row.package, image: $row.image, platform: $row.platform,
           execution_mode: execution_mode($row.arch),
           package_asset: $asset.name, package_sha256: $asset.sha256,
           version: $version, source_sha: $source_sha}]
      | sort_by(.id)
    ' "$matrix" > "$temporary_directory/expected-install-evidence.json"
jq -S '.package_install_results | sort_by(.id)' "$evidence" \
    > "$temporary_directory/actual-install-evidence.json"
cmp -s "$temporary_directory/expected-install-evidence.json" \
    "$temporary_directory/actual-install-evidence.json" \
    || fail 'package-install evidence is incomplete or contradictory'

jq -S --arg source_sha "$source_sha" --arg version "$version" \
    --slurpfile evidence "$evidence" '
      def execution_mode($arch):
        if ($arch == "386" or $arch == "i586") then "x86-compat"
        elif ($arch == "amd64" or $arch == "arm64") then "native"
        else "qemu-user"
        end;
      ($evidence[0].assets
        | map(select(.kind == "package"))
        | INDEX(.matrix_id)) as $assets
      | [.platforms[] as $row
        | (if $row.firewall_test == "full" then ["nftables", "iptables"]
           elif $row.firewall_test == "nft" then ["nftables"]
           elif $row.firewall_test == "emulated" then []
           else error("unknown firewall policy")
           end)[] as $backend
        | $assets[$row.package] as $asset
        | {schema_version: 1, type: "firewall-e2e",
           id: ($row.id + "-" + $backend), backend: $backend,
           package: $row.package, image: $row.image, platform: $row.platform,
           execution_mode: execution_mode($row.arch),
           package_asset: $asset.name, package_sha256: $asset.sha256,
           version: $version, source_sha: $source_sha}]
      | sort_by(.id)
    ' "$matrix" > "$temporary_directory/expected-firewall-evidence.json"
jq -S '.firewall_e2e_results | sort_by(.id)' "$evidence" \
    > "$temporary_directory/actual-firewall-evidence.json"
cmp -s "$temporary_directory/expected-firewall-evidence.json" \
    "$temporary_directory/actual-firewall-evidence.json" \
    || fail 'firewall evidence is incomplete or contradictory'

"$repository_directory/scripts/test-init-matrix.sh" images \
    | jq -Rsc '
      split("\n")
      | map(select(length > 0) | split("\t"))
      | if length == 6 and all(.[]; length == 3)
        then map({id: .[0], image: .[1], platform: .[2]})
        else error("invalid init image inventory")
        end
    ' > "$temporary_directory/init-images.json"
jq -e '
      length == 6
      and (map(.id) | unique | length == 6)
      and all(.[];
        (.id | test("^[a-z0-9]+(-[a-z0-9]+)*$"))
        and (.image | test("^[A-Za-z0-9._/-]+:[A-Za-z0-9_.-]+@sha256:[0-9a-f]{64}$"))
        and .platform == "linux/amd64")
    ' "$temporary_directory/init-images.json" >/dev/null \
    || fail 'unsafe init image inventory'
jq -S -n \
    --arg id init-systems \
    --arg script_sha256 "$init_script_sha256" \
    --arg source_sha "$source_sha" \
    --arg version "$version" \
    --slurpfile images "$temporary_directory/init-images.json" \
    '{schema_version: 1, type: "init-systems", id: $id,
      images: $images[0], script_sha256: $script_sha256,
      version: $version, source_sha: $source_sha}' \
    > "$temporary_directory/expected-init-evidence.json"
jq -S '.init_system_result' "$evidence" \
    > "$temporary_directory/actual-init-evidence.json"
cmp -s "$temporary_directory/expected-init-evidence.json" \
    "$temporary_directory/actual-init-evidence.json" \
    || fail 'init-system evidence is incomplete or contradictory'

printf 'release candidate verified: %s assets, tag %s, source %s\n' \
    "$expected_assets" "$tag" "$source_sha"
