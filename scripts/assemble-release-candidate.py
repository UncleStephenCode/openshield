#!/usr/bin/env python3
"""Assemble a fail-closed release asset set from CI artifacts and evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import stat
import tarfile
from typing import Any


SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~-]*$")
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
PINNED_IMAGE = re.compile(
    r"^[A-Za-z0-9._/-]+:[A-Za-z0-9_.-]+@sha256:[0-9a-f]{64}$"
)
INIT_IMAGES = {
    "alpine-openrc": "alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce",
    "devuan-sysvinit": "devuan/devuan:daedalus@sha256:878e7d497ed8bb3333e85186cc9b8b89ed19270e13f770ea784b1cfbef695a00",
    "void-runit": "voidlinux/voidlinux:latest@sha256:26ba972f0c06beadcec4796ec3037e0bec32af4d255edb68a528bd98304c74f4",
    "artix-openrc": "artixlinux/artixlinux:base-openrc@sha256:09d7ca64ca40db4ffa8f8e97f7bdac8969f9f4a8f791e42d82a6b2377d40ce71",
    "artix-s6": "artixlinux/artixlinux:base-s6@sha256:e563ae1357cf6cd7c6df858b795db8ddf23ffa6ab1888739b91a33da189cf82b",
    "artix-dinit": "artixlinux/artixlinux:base-dinit@sha256:234cf62105d8a5a10caebb9b62dadc271d33eccc9fd41399453e20004a8e319a",
}


class CandidateError(RuntimeError):
    pass


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CandidateError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    raise CandidateError(f"non-finite JSON number is forbidden: {value}")


def load_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as stream:
            return json.load(
                stream,
                object_pairs_hook=unique_object,
                parse_constant=reject_constant,
            )
    except (OSError, json.JSONDecodeError) as error:
        raise CandidateError(f"cannot read JSON {path}: {error}") from error


def regular_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise CandidateError(f"cannot inspect {path}: {error}") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size <= 0:
        raise CandidateError(f"unsafe or empty artifact: {path}")


def directory_entries(path: Path) -> list[Path]:
    try:
        metadata = path.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
            raise CandidateError(f"unsafe artifact directory: {path}")
        return sorted(path.iterdir(), key=lambda item: item.name)
    except OSError as error:
        raise CandidateError(f"cannot inspect artifact directory {path}: {error}") from error


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def copy_asset(source: Path, output: Path, seen: set[str]) -> dict[str, Any]:
    regular_file(source)
    name = source.name
    if not SAFE_NAME.fullmatch(name):
        raise CandidateError(f"unsafe release asset name: {name}")
    if name in seen:
        raise CandidateError(f"duplicate release asset name: {name}")
    seen.add(name)
    destination = output / name
    with source.open("rb") as input_stream, destination.open("xb") as output_stream:
        shutil.copyfileobj(input_stream, output_stream, length=1024 * 1024)
    os.chmod(destination, 0o644)
    return {"name": name, "sha256": digest(destination), "size": destination.stat().st_size}


def verify_archive(path: Path, binaries: dict[str, Path]) -> None:
    expected = {"openshield-daemon", "openshield-tui"}
    try:
        with tarfile.open(path, mode="r:xz") as archive:
            members = archive.getmembers()
    except (OSError, tarfile.TarError) as error:
        raise CandidateError(f"invalid binary archive {path}: {error}") from error
    names = {member.name for member in members}
    if names != expected or len(members) != len(expected):
        raise CandidateError(f"unexpected members in binary archive {path.name}")
    for member in members:
        binary = binaries[member.name]
        if (
            not member.isfile()
            or member.issym()
            or member.islnk()
            or member.size != binary.stat().st_size
            or member.mode & 0o7777 != 0o755
        ):
            raise CandidateError(f"unsafe member in binary archive {path.name}: {member.name}")
        try:
            with tarfile.open(path, mode="r:xz") as archive:
                extracted = archive.extractfile(member.name)
                if extracted is None:
                    raise CandidateError(
                        f"cannot read binary member in {path.name}: {member.name}"
                    )
                member_hasher = hashlib.sha256()
                for block in iter(lambda: extracted.read(1024 * 1024), b""):
                    member_hasher.update(block)
        except (OSError, tarfile.TarError) as error:
            raise CandidateError(f"cannot verify binary member in {path.name}") from error
        if member_hasher.hexdigest() != digest(binary):
            raise CandidateError(
                f"archive member differs from verified binary: {path.name}/{member.name}"
            )


def execution_mode(arch: str) -> str:
    if arch in {"386", "i586"}:
        return "x86-compat"
    if arch in {"amd64", "arm64"}:
        return "native"
    return "qemu-user"


def expected_evidence(matrix: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    installs = {row["id"]: row for row in matrix["platforms"]}
    firewall: dict[str, dict[str, Any]] = {}
    for row in matrix["platforms"]:
        modes = row["firewall_test"]
        backends: tuple[str, ...]
        if modes == "full":
            backends = ("nftables", "iptables")
        elif modes == "nft":
            backends = ("nftables",)
        elif modes == "emulated":
            backends = ()
        else:
            raise CandidateError(f"unknown firewall_test mode in {row['id']}: {modes}")
        for backend in backends:
            evidence_id = f"{row['id']}-{backend}"
            firewall[evidence_id] = {**row, "backend": backend}
    return installs, firewall


def validate_evidence_record(
    record: Any,
    expected_type: str,
    expected_id: str,
    expected: dict[str, Any],
    version: str,
    source_sha: str,
    package_asset: dict[str, Any],
) -> None:
    required = {
        "schema_version",
        "type",
        "id",
        "package",
        "image",
        "platform",
        "execution_mode",
        "package_asset",
        "package_sha256",
        "version",
        "source_sha",
    }
    if expected_type == "firewall-e2e":
        required.add("backend")
    if not isinstance(record, dict) or set(record) != required:
        raise CandidateError(f"invalid evidence schema: {expected_id}")
    if record["schema_version"] != 1 or record["type"] != expected_type or record["id"] != expected_id:
        raise CandidateError(f"evidence identity mismatch: {expected_id}")
    comparisons = {
        "package": expected["package"],
        "image": expected["image"],
        "platform": expected["platform"],
        "execution_mode": execution_mode(expected["arch"]),
        "package_asset": package_asset["name"],
        "package_sha256": package_asset["sha256"],
        "version": version,
        "source_sha": source_sha,
    }
    if expected_type == "firewall-e2e":
        comparisons["backend"] = expected["backend"]
    for key, value in comparisons.items():
        if record[key] != value:
            raise CandidateError(f"evidence {expected_id} has unexpected {key}")


def collect_evidence(
    evidence_root: Path,
    matrix: dict[str, Any],
    version: str,
    source_sha: str,
    package_assets: dict[str, dict[str, Any]],
    init_script: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    expected_installs, expected_firewall = expected_evidence(matrix)
    entries = directory_entries(evidence_root)
    actual_names = {entry.name for entry in entries}
    expected_names = {f"install-{item}.json" for item in expected_installs}
    expected_names.update(f"firewall-{item}.json" for item in expected_firewall)
    expected_names.add("init-systems.json")
    if actual_names != expected_names:
        missing = sorted(expected_names - actual_names)
        unexpected = sorted(actual_names - expected_names)
        raise CandidateError(f"evidence inventory mismatch; missing={missing}, unexpected={unexpected}")

    install_records: list[dict[str, Any]] = []
    for evidence_id, expected in sorted(expected_installs.items()):
        path = evidence_root / f"install-{evidence_id}.json"
        regular_file(path)
        record = load_json(path)
        validate_evidence_record(
            record,
            "package-install",
            evidence_id,
            expected,
            version,
            source_sha,
            package_assets[expected["package"]],
        )
        install_records.append(record)

    firewall_records: list[dict[str, Any]] = []
    for evidence_id, expected in sorted(expected_firewall.items()):
        path = evidence_root / f"firewall-{evidence_id}.json"
        regular_file(path)
        record = load_json(path)
        validate_evidence_record(
            record,
            "firewall-e2e",
            evidence_id,
            expected,
            version,
            source_sha,
            package_assets[expected["package"]],
        )
        firewall_records.append(record)

    init_path = evidence_root / "init-systems.json"
    regular_file(init_path)
    init_record = load_json(init_path)
    init_keys = {
        "schema_version",
        "type",
        "id",
        "images",
        "script_sha256",
        "version",
        "source_sha",
    }
    if not isinstance(init_record, dict) or set(init_record) != init_keys:
        raise CandidateError("invalid init-system evidence schema")
    if (
        init_record["schema_version"] != 1
        or init_record["type"] != "init-systems"
        or init_record["id"] != "init-systems"
        or init_record["version"] != version
        or init_record["source_sha"] != source_sha
        or init_record["script_sha256"] != digest(init_script)
    ):
        raise CandidateError("init-system evidence identity mismatch")
    images = init_record["images"]
    if not isinstance(images, list) or len(images) != len(INIT_IMAGES):
        raise CandidateError("invalid init-system image inventory")
    actual_images: dict[str, str] = {}
    for image in images:
        if not isinstance(image, dict) or set(image) != {"id", "image", "platform"}:
            raise CandidateError("invalid init-system image record")
        if (
            not isinstance(image["id"], str)
            or not isinstance(image["image"], str)
            or not PINNED_IMAGE.fullmatch(image["image"])
            or image["platform"] != "linux/amd64"
            or image["id"] in actual_images
        ):
            raise CandidateError("unsafe init-system image record")
        actual_images[image["id"]] = image["image"]
    if actual_images != INIT_IMAGES:
        raise CandidateError("unexpected init-system image inventory")
    return install_records, firewall_records, init_record


def assemble(arguments: argparse.Namespace) -> None:
    version = arguments.version
    tag = arguments.tag
    source_sha = arguments.source_sha
    if not SEMVER.fullmatch(version) or tag != f"v{version}" or not SHA.fullmatch(source_sha):
        raise CandidateError("invalid version, tag, or source SHA")

    matrix_path = arguments.matrix.resolve(strict=True)
    repository_root = Path(__file__).resolve().parent.parent
    canonical_matrix = (repository_root / "packaging" / "ci" / "release-matrix.json").resolve(
        strict=True
    )
    if matrix_path != canonical_matrix:
        raise CandidateError("only the authoritative release matrix is accepted")
    artifact_root = arguments.artifacts.resolve(strict=True)
    validator = runpy.run_path(
        str(repository_root / "scripts" / "release-matrix.py"),
        run_name="openshield_release_matrix_validator",
    )
    try:
        matrix = validator["load_and_validate"]()
    except validator["MatrixError"] as error:
        raise CandidateError(f"invalid authoritative release matrix: {error}") from error

    output = arguments.output
    if output.exists() or output.is_symlink():
        try:
            output_metadata = output.lstat()
        except OSError as error:
            raise CandidateError(f"cannot inspect output directory {output}: {error}") from error
        if (
            not stat.S_ISDIR(output_metadata.st_mode)
            or output.is_symlink()
            or any(output.iterdir())
        ):
            raise CandidateError(f"output directory is not empty: {output}")
    else:
        output.mkdir(mode=0o755, parents=False)
    output = output.resolve(strict=True)

    seen: set[str] = set()
    asset_records: list[dict[str, Any]] = []
    package_assets: dict[str, dict[str, Any]] = {}
    binary_root = artifact_root / "binaries"
    for row in sorted(matrix["binaries"], key=lambda item: item["id"]):
        directory = binary_root / row["artifact_name"]
        archive_name = row["archive_template"].replace("{version}", version)
        expected_names = {"openshield-daemon", "openshield-tui", archive_name}
        entries = directory_entries(directory)
        if {entry.name for entry in entries} != expected_names:
            raise CandidateError(f"binary artifact inventory mismatch: {row['id']}")
        for entry in entries:
            regular_file(entry)
        binaries = {name: directory / name for name in ("openshield-daemon", "openshield-tui")}
        for binary in binaries.values():
            if stat.S_IMODE(binary.stat().st_mode) != 0o755:
                raise CandidateError(f"release binary is not mode 0755: {binary}")
        archive = directory / archive_name
        verify_archive(archive, binaries)
        record = copy_asset(archive, output, seen)
        record.update({"kind": "binary", "matrix_id": row["id"]})
        asset_records.append(record)

    package_root = artifact_root / "packages"
    extensions = {
        "deb": ".deb",
        "fedora": ".rpm",
        "el9": ".rpm",
        "el10": ".rpm",
        "opensuse": ".rpm",
        "tumbleweed": ".rpm",
        "alpine": ".apk",
        "arch": ".pkg.tar.zst",
    }
    for row in sorted(matrix["packages"], key=lambda item: item["id"]):
        entries = directory_entries(package_root / row["artifact_name"])
        if len(entries) != 1:
            raise CandidateError(f"expected one package artifact: {row['id']}")
        package = entries[0]
        if not package.name.endswith(extensions[row["family"]]):
            raise CandidateError(f"wrong package format for {row['id']}: {package.name}")
        record = copy_asset(package, output, seen)
        record.update({"kind": "package", "matrix_id": row["id"]})
        asset_records.append(record)
        package_assets[row["id"]] = record

    init_script = matrix_path.parents[2] / "scripts" / "test-init-matrix.sh"
    regular_file(init_script)
    install_records, firewall_records, init_record = collect_evidence(
        artifact_root / "evidence",
        matrix,
        version,
        source_sha,
        package_assets,
        init_script,
    )
    evidence = {
        "schema_version": 1,
        "tag": tag,
        "version": version,
        "source_sha": source_sha,
        "matrix_sha256": digest(matrix_path),
        "assets": sorted(asset_records, key=lambda item: item["name"]),
        "package_install_results": install_records,
        "firewall_e2e_results": firewall_records,
        "init_system_result": init_record,
    }
    evidence_path = output / "RELEASE-EVIDENCE.json"
    with evidence_path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(evidence, stream, ensure_ascii=True, indent=2, sort_keys=True)
        stream.write("\n")
    os.chmod(evidence_path, 0o644)
    seen.add(evidence_path.name)

    checksum_entries = sorted(
        (path for path in output.iterdir() if path.name != "SHA256SUMS"), key=lambda item: item.name
    )
    checksum_path = output / "SHA256SUMS"
    with checksum_path.open("x", encoding="ascii", newline="\n") as stream:
        for path in checksum_entries:
            regular_file(path)
            stream.write(f"{digest(path)}  {path.name}\n")
    os.chmod(checksum_path, 0o644)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--matrix", required=True, type=Path)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source-sha", required=True)
    return parser.parse_args()


def main() -> int:
    try:
        assemble(parse_args())
    except (CandidateError, KeyError, TypeError, ValueError) as error:
        print(f"assemble-release-candidate: {error}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
