#!/usr/bin/env python3
"""Validate and emit the authoritative OpenShield release matrices."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, NoReturn


MATRIX_PATH = (
    Path(__file__).resolve().parent.parent / "packaging" / "ci" / "release-matrix.json"
)
MAX_MATRIX_BYTES = 1024 * 1024
EXPECTED_COUNTS = {"binaries": 7, "packages": 18, "platforms": 34}

ROOT_KEYS = frozenset({"schema_version", "binaries", "packages", "platforms"})
BINARY_KEYS = frozenset(
    {
        "id",
        "kind",
        "arch",
        "runner",
        "target",
        "cross",
        "native",
        "elf_class",
        "elf_endian",
        "elf_machine",
        "artifact_name",
        "archive_template",
        "smoke_image",
        "smoke_runner",
        "smoke_arch",
    }
)
PACKAGE_KEYS = frozenset(
    {
        "id",
        "family",
        "arch",
        "binary_id",
        "binary_artifact_name",
        "artifact_name",
        "expected_package_arch",
        "expected_elf_machine",
    }
)
PLATFORM_KEYS = frozenset(
    {
        "id",
        "name",
        "family",
        "arch",
        "package",
        "image",
        "platform",
        "runner",
        "expected_package_arch",
        "firewall_test",
    }
)

ID_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 .+()/_-]*\Z")
ARTIFACT_RE = re.compile(r"(?:binary|package)-[a-z0-9]+(?:-[a-z0-9]+)*\Z")
TARGET_RE = re.compile(r"[a-z0-9_]+(?:-[a-z0-9_]+)+\Z")
ARCHIVE_RE = re.compile(
    r"openshield-\{version\}-linux(?:-tumbleweed)?-"
    r"(?:amd64|i586|arm64|ppc64le|s390x)\.tar\.xz\Z"
)
IMAGE_RE = re.compile(
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*"
    r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
    r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?"
    r"@sha256:[0-9a-f]{64}\Z"
)
ABSOLUTE_COMMAND_RE = re.compile(r"/[A-Za-z0-9._/-]+\Z")

BINARY_TARGETS = {
    ("generic", "amd64"): "x86_64-unknown-linux-musl",
    ("generic", "arm64"): "aarch64-unknown-linux-musl",
    ("tumbleweed", "amd64"): "x86_64-unknown-linux-gnu",
    ("tumbleweed", "i586"): "i586-unknown-linux-gnu",
    ("tumbleweed", "arm64"): "aarch64-unknown-linux-gnu",
    ("tumbleweed", "ppc64le"): "powerpc64le-unknown-linux-gnu",
    ("tumbleweed", "s390x"): "s390x-unknown-linux-gnu",
}
ARCH_DETAILS = {
    "amd64": {
        "platform": "linux/amd64",
        "runner": "ubuntu-24.04",
        "elf_class": "ELF64",
        "elf_endian": "little endian",
        "elf_machine": "Advanced Micro Devices X86-64",
    },
    "i586": {
        "platform": "linux/386",
        "runner": "ubuntu-24.04",
        "elf_class": "ELF32",
        "elf_endian": "little endian",
        "elf_machine": "Intel 80386",
    },
    "arm64": {
        "platform": "linux/arm64",
        "runner": "ubuntu-24.04-arm",
        "elf_class": "ELF64",
        "elf_endian": "little endian",
        "elf_machine": "AArch64",
    },
    "ppc64le": {
        "platform": "linux/ppc64le",
        "runner": "ubuntu-24.04",
        "elf_class": "ELF64",
        "elf_endian": "little endian",
        "elf_machine": "PowerPC64",
    },
    "s390x": {
        "platform": "linux/s390x",
        "runner": "ubuntu-24.04",
        "elf_class": "ELF64",
        "elf_endian": "big endian",
        "elf_machine": "IBM S/390",
    },
}
CROSS_SMOKE = {
    "i586": ("/qemu-runner", "i586"),
    "ppc64le": ("/linux-runner", "powerpc64le"),
    "s390x": ("/linux-runner", "s390x"),
}
# i586 binaries receive an additional QEMU smoke check during cross-build, but
# installed linux/386 packages execute directly on the x86-64 runner.  Only
# architectures that need user-mode emulation for their package are excluded
# from privileged firewall E2E.
EMULATED_FIREWALL_ARCHES = {"ppc64le", "s390x"}

GENERIC_PACKAGE_FAMILIES = (
    "deb",
    "fedora",
    "el9",
    "el10",
    "opensuse",
    "alpine",
)
PACKAGE_COMBINATIONS = {
    *(
        (family, arch)
        for family in GENERIC_PACKAGE_FAMILIES
        for arch in ("amd64", "arm64")
    ),
    ("arch", "amd64"),
    *(
        ("tumbleweed", arch)
        for arch in ("amd64", "i586", "arm64", "ppc64le", "s390x")
    ),
}


def package_architecture(family: str, arch: str) -> str:
    if family == "deb":
        return arch
    if arch == "amd64":
        return "x86_64"
    if arch == "arm64":
        return "aarch64"
    return arch


EXPECTED_IMAGE_PLATFORMS = {
    **{
        image: (family, ("amd64", "arm64"))
        for image, family in (
            ("debian:12", "deb"),
            ("debian:13", "deb"),
            ("ubuntu:22.04", "deb"),
            ("ubuntu:24.04", "deb"),
            ("ubuntu:26.04", "deb"),
            ("fedora:43", "fedora"),
            ("fedora:44", "fedora"),
            ("rockylinux/rockylinux:9", "el9"),
            ("rockylinux/rockylinux:10", "el10"),
            ("almalinux:9", "el9"),
            ("almalinux:10", "el10"),
            ("opensuse/leap:16.0", "opensuse"),
            ("alpine:3.23", "alpine"),
            ("alpine:3.24", "alpine"),
        )
    },
    "opensuse/tumbleweed": (
        "tumbleweed",
        ("amd64", "i586", "arm64", "ppc64le", "s390x"),
    ),
    "archlinux:base": ("arch", ("amd64",)),
}


class MatrixError(ValueError):
    """A deterministic release-matrix validation error."""


def reject_constant(value: str) -> NoReturn:
    raise MatrixError(f"non-finite JSON number is forbidden: {value}")


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MatrixError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def exact_keys(value: Any, expected: frozenset[str], where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise MatrixError(f"{where} must be an object")
    actual = frozenset(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        details = []
        if missing:
            details.append(f"missing={','.join(missing)}")
        if unknown:
            details.append(f"unknown={','.join(unknown)}")
        raise MatrixError(f"{where} has invalid keys ({'; '.join(details)})")
    return value


def string(value: Any, pattern: re.Pattern[str], where: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise MatrixError(f"{where} has an invalid value")
    return value


def member(value: Any, allowed: set[str] | frozenset[str], where: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise MatrixError(f"{where} must be one of: {', '.join(sorted(allowed))}")
    return value


def boolean(value: Any, where: str) -> bool:
    if type(value) is not bool:
        raise MatrixError(f"{where} must be a boolean")
    return value


def unique_rows(rows: list[dict[str, Any]], field: str, where: str) -> None:
    seen: set[str] = set()
    for index, row in enumerate(rows):
        value = row[field]
        if value in seen:
            raise MatrixError(f"duplicate {where} {field}: {value} (row {index})")
        seen.add(value)


def image_parts(image: str) -> tuple[str, str]:
    name, digest = image.rsplit("@sha256:", 1)
    return name, digest


def validate_binaries(rows: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(rows, list) or len(rows) != EXPECTED_COUNTS["binaries"]:
        raise MatrixError(f"binaries must contain exactly {EXPECTED_COUNTS['binaries']} rows")

    result: list[dict[str, Any]] = []
    combinations: set[tuple[str, str]] = set()
    for index, raw in enumerate(rows):
        where = f"binaries[{index}]"
        row = exact_keys(raw, BINARY_KEYS, where)
        identifier = string(row["id"], ID_RE, f"{where}.id")
        kind = member(row["kind"], {"generic", "tumbleweed"}, f"{where}.kind")
        arch = member(row["arch"], set(ARCH_DETAILS), f"{where}.arch")
        combination = (kind, arch)
        if combination not in BINARY_TARGETS:
            raise MatrixError(f"{where} has unsupported kind/arch: {kind}/{arch}")
        combinations.add(combination)

        expected_id = f"{kind}-{arch}"
        if identifier != expected_id:
            raise MatrixError(f"{where}.id must be {expected_id}")
        target = string(row["target"], TARGET_RE, f"{where}.target")
        if target != BINARY_TARGETS[combination]:
            raise MatrixError(f"{where}.target does not match {kind}/{arch}")

        details = ARCH_DETAILS[arch]
        for field in ("runner", "elf_class", "elf_endian", "elf_machine"):
            if row[field] != details[field]:
                raise MatrixError(f"{where}.{field} does not match architecture {arch}")

        cross = boolean(row["cross"], f"{where}.cross")
        native = boolean(row["native"], f"{where}.native")
        expected_cross = arch in CROSS_SMOKE
        if cross != expected_cross or native == cross:
            raise MatrixError(f"{where} has inconsistent cross/native flags")

        expected_artifact = "binary-" + ("" if kind == "generic" else "tumbleweed-") + arch
        artifact = string(row["artifact_name"], ARTIFACT_RE, f"{where}.artifact_name")
        if artifact != expected_artifact:
            raise MatrixError(f"{where}.artifact_name must be {expected_artifact}")

        archive = string(row["archive_template"], ARCHIVE_RE, f"{where}.archive_template")
        expected_archive = "openshield-{version}-linux-"
        if kind == "tumbleweed":
            expected_archive += "tumbleweed-"
        expected_archive += f"{arch}.tar.xz"
        if archive != expected_archive:
            raise MatrixError(f"{where}.archive_template must be {expected_archive}")

        if cross:
            smoke_image = string(row["smoke_image"], IMAGE_RE, f"{where}.smoke_image")
            smoke_runner = string(
                row["smoke_runner"], ABSOLUTE_COMMAND_RE, f"{where}.smoke_runner"
            )
            smoke_arch = string(row["smoke_arch"], ID_RE, f"{where}.smoke_arch")
            expected_runner, expected_smoke_arch = CROSS_SMOKE[arch]
            if smoke_runner != expected_runner or smoke_arch != expected_smoke_arch:
                raise MatrixError(f"{where} has incorrect cross smoke parameters")
            smoke_repository, _ = image_parts(smoke_image)
            if smoke_repository != f"ghcr.io/cross-rs/{target}":
                raise MatrixError(f"{where}.smoke_image does not match its Rust target")
        elif any(row[field] is not None for field in ("smoke_image", "smoke_runner", "smoke_arch")):
            raise MatrixError(f"{where} must not define smoke parameters for a native build")

        result.append(row)

    if combinations != set(BINARY_TARGETS):
        raise MatrixError("binaries do not cover the required kind/architecture combinations")
    unique_rows(result, "id", "binary")
    unique_rows(result, "artifact_name", "binary")
    unique_rows(result, "archive_template", "binary")
    return {row["id"]: row for row in result}


def validate_packages(
    rows: Any, binaries: dict[str, dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    if not isinstance(rows, list) or len(rows) != EXPECTED_COUNTS["packages"]:
        raise MatrixError(f"packages must contain exactly {EXPECTED_COUNTS['packages']} rows")

    result: list[dict[str, Any]] = []
    combinations: set[tuple[str, str]] = set()
    for index, raw in enumerate(rows):
        where = f"packages[{index}]"
        row = exact_keys(raw, PACKAGE_KEYS, where)
        identifier = string(row["id"], ID_RE, f"{where}.id")
        family = member(
            row["family"],
            set(GENERIC_PACKAGE_FAMILIES) | {"arch", "tumbleweed"},
            f"{where}.family",
        )
        arch = member(row["arch"], set(ARCH_DETAILS), f"{where}.arch")
        combination = (family, arch)
        if combination not in PACKAGE_COMBINATIONS:
            raise MatrixError(f"{where} has unsupported family/arch: {family}/{arch}")
        combinations.add(combination)
        if identifier != f"{family}-{arch}":
            raise MatrixError(f"{where}.id must be {family}-{arch}")

        binary_id = string(row["binary_id"], ID_RE, f"{where}.binary_id")
        if binary_id not in binaries:
            raise MatrixError(f"{where}.binary_id references an unknown binary")
        binary = binaries[binary_id]
        expected_binary_id = (
            f"tumbleweed-{arch}" if family == "tumbleweed" else f"generic-{arch}"
        )
        if binary_id != expected_binary_id or binary["arch"] != arch:
            raise MatrixError(f"{where}.binary_id does not match its package architecture")

        binary_artifact = string(
            row["binary_artifact_name"], ARTIFACT_RE, f"{where}.binary_artifact_name"
        )
        if binary_artifact != binary["artifact_name"]:
            raise MatrixError(f"{where}.binary_artifact_name does not match binary_id")
        artifact = string(row["artifact_name"], ARTIFACT_RE, f"{where}.artifact_name")
        if artifact != f"package-{family}-{arch}":
            raise MatrixError(f"{where}.artifact_name does not match family/arch")

        expected_package_arch = package_architecture(family, arch)
        if row["expected_package_arch"] != expected_package_arch:
            raise MatrixError(
                f"{where}.expected_package_arch must be {expected_package_arch}"
            )
        if row["expected_elf_machine"] != binary["elf_machine"]:
            raise MatrixError(f"{where}.expected_elf_machine does not match binary_id")
        result.append(row)

    if combinations != PACKAGE_COMBINATIONS:
        raise MatrixError("packages do not cover the required family/architecture combinations")
    unique_rows(result, "id", "package")
    unique_rows(result, "artifact_name", "package")
    return {row["id"]: row for row in result}


def validate_platforms(
    rows: Any, packages: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    if not isinstance(rows, list) or len(rows) != EXPECTED_COUNTS["platforms"]:
        raise MatrixError(f"platforms must contain exactly {EXPECTED_COUNTS['platforms']} rows")

    result: list[dict[str, Any]] = []
    image_platforms: set[tuple[str, str]] = set()
    image_digests: dict[str, str] = {}
    referenced_packages: set[str] = set()
    for index, raw in enumerate(rows):
        where = f"platforms[{index}]"
        row = exact_keys(raw, PLATFORM_KEYS, where)
        identifier = string(row["id"], ID_RE, f"{where}.id")
        name = string(row["name"], NAME_RE, f"{where}.name")
        family = member(
            row["family"],
            set(GENERIC_PACKAGE_FAMILIES) | {"arch", "tumbleweed"},
            f"{where}.family",
        )
        arch = member(row["arch"], set(ARCH_DETAILS), f"{where}.arch")
        if not identifier.endswith(f"-{arch}") or not name.endswith(f" / {arch}"):
            raise MatrixError(f"{where} id/name must identify architecture {arch}")

        package_id = string(row["package"], ID_RE, f"{where}.package")
        if package_id not in packages:
            raise MatrixError(f"{where}.package references an unknown package")
        package = packages[package_id]
        referenced_packages.add(package_id)
        if package["family"] != family or package["arch"] != arch:
            raise MatrixError(f"{where}.package does not match platform family/arch")

        image = string(row["image"], IMAGE_RE, f"{where}.image")
        image_name, digest = image_parts(image)
        expected_image = EXPECTED_IMAGE_PLATFORMS.get(image_name)
        if expected_image is None:
            raise MatrixError(f"{where}.image is not in the supported release image set")
        expected_family, expected_arches = expected_image
        if family != expected_family or arch not in expected_arches:
            raise MatrixError(f"{where}.image does not support the declared family/arch row")
        previous_digest = image_digests.setdefault(image_name, digest)
        if previous_digest != digest:
            raise MatrixError(f"platform image {image_name} uses more than one digest")

        expected_platform = ARCH_DETAILS[arch]["platform"]
        if row["platform"] != expected_platform:
            raise MatrixError(f"{where}.platform must be {expected_platform}")
        if row["runner"] != ARCH_DETAILS[arch]["runner"]:
            raise MatrixError(f"{where}.runner does not match architecture {arch}")
        if row["expected_package_arch"] != package["expected_package_arch"]:
            raise MatrixError(f"{where}.expected_package_arch does not match its package")

        firewall_test = member(
            row["firewall_test"], {"full", "nft", "emulated"}, f"{where}.firewall_test"
        )
        expected_firewall_test = "full"
        if family in {"alpine", "arch"}:
            expected_firewall_test = "nft"
        elif arch in EMULATED_FIREWALL_ARCHES:
            expected_firewall_test = "emulated"
        if firewall_test != expected_firewall_test:
            raise MatrixError(
                f"{where}.firewall_test must be {expected_firewall_test} for {family}/{arch}"
            )

        image_platform = (image_name, expected_platform)
        if image_platform in image_platforms:
            raise MatrixError(f"duplicate image/platform row: {image_name}/{expected_platform}")
        image_platforms.add(image_platform)
        result.append(row)

    expected_image_platforms = {
        (image, ARCH_DETAILS[arch]["platform"])
        for image, (_, arches) in EXPECTED_IMAGE_PLATFORMS.items()
        for arch in arches
    }
    if image_platforms != expected_image_platforms:
        raise MatrixError("platforms do not cover the required pinned image/platform set")
    if referenced_packages != set(packages):
        missing = sorted(set(packages) - referenced_packages)
        raise MatrixError(f"packages without an installation platform: {', '.join(missing)}")
    unique_rows(result, "id", "platform")
    unique_rows(result, "name", "platform")
    return result


def load_and_validate() -> dict[str, Any]:
    try:
        stat = MATRIX_PATH.stat()
        if not MATRIX_PATH.is_file() or stat.st_size <= 0 or stat.st_size > MAX_MATRIX_BYTES:
            raise MatrixError("release matrix must be a non-empty regular file below 1 MiB")
        raw = MATRIX_PATH.read_text(encoding="utf-8")
        document = json.loads(
            raw,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise MatrixError(f"cannot read release matrix: {error}") from error

    root = exact_keys(document, ROOT_KEYS, "root")
    if type(root["schema_version"]) is not int or root["schema_version"] != 1:
        raise MatrixError("schema_version must be integer 1")
    binaries = validate_binaries(root["binaries"])
    packages = validate_packages(root["packages"], binaries)
    platforms = validate_platforms(root["platforms"], packages)
    return {
        "schema_version": 1,
        "binaries": list(binaries.values()),
        "packages": list(packages.values()),
        "platforms": platforms,
    }


def enrich_platform(
    platform: dict[str, Any], packages: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    package = packages[platform["package"]]
    enriched = dict(platform)
    enriched["package_artifact_name"] = package["artifact_name"]
    enriched["expected_elf_machine"] = package["expected_elf_machine"]
    if platform["arch"] in EMULATED_FIREWALL_ARCHES:
        enriched["execution_mode"] = "qemu-user"
    elif platform["arch"] == "i586":
        enriched["execution_mode"] = "x86-compat"
    else:
        enriched["execution_mode"] = "native"
    return enriched


def emitted_rows(document: dict[str, Any], matrix: str) -> list[dict[str, Any]]:
    if matrix == "binaries":
        return document["binaries"]
    if matrix == "packages":
        return document["packages"]

    packages = {row["id"]: row for row in document["packages"]}
    platforms = [enrich_platform(row, packages) for row in document["platforms"]]
    if matrix == "platforms":
        return platforms

    firewall: list[dict[str, Any]] = []
    for platform in platforms:
        policy = platform["firewall_test"]
        if policy == "emulated":
            continue
        backends = ("nftables", "iptables") if policy == "full" else ("nftables",)
        for backend in backends:
            row = dict(platform)
            row["backend"] = backend
            row["evidence_id"] = f"{platform['id']}-{backend}"
            firewall.append(row)
    unique_rows(firewall, "evidence_id", "firewall evidence")
    return firewall


def parser() -> argparse.ArgumentParser:
    argument_parser = argparse.ArgumentParser(
        description="Validate or emit the OpenShield release matrix"
    )
    commands = argument_parser.add_subparsers(dest="command", required=True)
    commands.add_parser("validate", help="validate the authoritative JSON matrix")
    matrix_parser = commands.add_parser("matrix", help="emit a compact GitHub matrix")
    matrix_parser.add_argument(
        "matrix",
        choices=("binaries", "packages", "platforms", "firewall"),
    )
    return argument_parser


def main() -> int:
    arguments = parser().parse_args()
    try:
        document = load_and_validate()
        if arguments.command == "validate":
            firewall_count = len(emitted_rows(document, "firewall"))
            print(
                "release matrix validated: "
                f"{len(document['binaries'])} binaries, "
                f"{len(document['packages'])} packages, "
                f"{len(document['platforms'])} platforms, "
                f"{firewall_count} firewall jobs"
            )
        else:
            json.dump(
                {"include": emitted_rows(document, arguments.matrix)},
                sys.stdout,
                ensure_ascii=True,
                separators=(",", ":"),
            )
            sys.stdout.write("\n")
    except (MatrixError, KeyError) as error:
        print(f"release-matrix.py: error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
