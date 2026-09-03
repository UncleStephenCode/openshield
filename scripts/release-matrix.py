#!/usr/bin/env python3
"""Validate and emit the authoritative OpenShield release matrices."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any, NoReturn


MATRIX_PATH = (
    Path(__file__).resolve().parent.parent / "packaging" / "ci" / "release-matrix.json"
)
CROSS_PATH = Path(__file__).resolve().parent.parent / "Cross.toml"
MAX_MATRIX_BYTES = 1024 * 1024
MAX_CROSS_BYTES = 64 * 1024
EXPECTED_COUNTS = {"binaries": 43, "packages": 43, "platforms": 86}

ROOT_KEYS = frozenset(
    {"schema_version", "runtime_test_arches", "binaries", "packages", "platforms"}
)
BINARY_KEYS = frozenset(
    {
        "id",
        "family",
        "arch",
        "platform",
        "runner",
        "target",
        "cross",
        "native",
        "crt_static",
        "execution_mode",
        "elf_class",
        "elf_endian",
        "elf_machine",
        "artifact_name",
        "archive_template",
        "smoke_image",
        "smoke_platform",
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
        "nfpm_arch",
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
    r"openshield-\{version\}-linux-[a-z0-9]+(?:-[a-z0-9]+)*\.tar\.xz\Z"
)
IMAGE_RE = re.compile(
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*"
    r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
    r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?"
    r"@sha256:[0-9a-f]{64}\Z"
)
CROSS_IMAGE_RE = re.compile(
    r"ghcr\.io/cross-rs/"
    r"(?P<target>[a-z0-9_]+(?:-[a-z0-9_]+)+)"
    r"@sha256:[0-9a-f]{64}\Z"
)
BINARY_TARGETS = {
    "amd64": "x86_64-unknown-linux-musl",
    "arm64": "aarch64-unknown-linux-musl",
    "386": "i586-unknown-linux-musl",
    "armv5": "armv5te-unknown-linux-musleabi",
    "armv6": "arm-unknown-linux-musleabihf",
    "armv7": "armv7-unknown-linux-musleabihf",
    "ppc64le": "powerpc64le-unknown-linux-gnu",
    "riscv64": "riscv64gc-unknown-linux-gnu",
    "s390x": "s390x-unknown-linux-gnu",
}
ARCH_DETAILS = {
    "amd64": {
        "platform": "linux/amd64",
        "runner": "ubuntu-24.04",
        "elf_class": "ELF64",
        "elf_endian": "little endian",
        "elf_machine": "Advanced Micro Devices X86-64",
    },
    "386": {
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
    "armv5": {
        "platform": "linux/arm/v5",
        "runner": "ubuntu-24.04",
        "elf_class": "ELF32",
        "elf_endian": "little endian",
        "elf_machine": "ARM",
    },
    "armv6": {
        "platform": "linux/arm/v6",
        "runner": "ubuntu-24.04",
        "elf_class": "ELF32",
        "elf_endian": "little endian",
        "elf_machine": "ARM",
    },
    "armv7": {
        "platform": "linux/arm/v7",
        "runner": "ubuntu-24.04",
        "elf_class": "ELF32",
        "elf_endian": "little endian",
        "elf_machine": "ARM",
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
    "riscv64": {
        "platform": "linux/riscv64",
        "runner": "ubuntu-24.04",
        "elf_class": "ELF64",
        "elf_endian": "little endian",
        "elf_machine": "RISC-V",
    },
}
FAMILY_ARCHES = {
    "deb": ("amd64", "armv5", "armv7", "arm64", "386", "ppc64le", "riscv64", "s390x"),
    "fedora": ("amd64", "arm64", "ppc64le", "s390x"),
    "el9": ("amd64", "arm64", "ppc64le", "s390x"),
    "el10": ("amd64", "arm64", "ppc64le", "s390x", "riscv64", "386"),
    "opensuse": ("amd64", "arm64", "ppc64le", "s390x"),
    "tumbleweed": ("amd64", "arm64", "ppc64le", "s390x", "386", "armv6", "armv7", "riscv64"),
    "alpine": ("amd64", "arm64", "ppc64le", "s390x", "386", "armv6", "armv7", "riscv64"),
    "arch": ("amd64",),
}
PACKAGE_FAMILIES = frozenset(FAMILY_ARCHES)
PACKAGE_COMBINATIONS = {
    (family, arch) for family, arches in FAMILY_ARCHES.items() for arch in arches
}
CROSS_ARCHES = frozenset(set(ARCH_DETAILS) - {"amd64", "arm64"})
CRT_STATIC_ARCHES = frozenset({"ppc64le", "riscv64", "s390x"})
EXPECTED_RUNTIME_TEST_ARCHES = ("amd64", "arm64", "386")


def execution_mode(arch: str) -> str:
    if arch in {"amd64", "arm64"}:
        return "native"
    if arch == "386":
        return "x86-compat"
    return "qemu-user"


def nfpm_architecture(family: str, arch: str) -> str:
    if family == "el10" and arch == "386":
        return "i686"
    if family == "tumbleweed" and arch == "386":
        return "i586"
    return {
        "amd64": "amd64",
        "arm64": "arm64",
        "386": "386",
        "armv5": "arm5",
        "armv6": "arm6",
        "armv7": "arm7",
        "ppc64le": "ppc64le",
        "riscv64": "riscv64",
        "s390x": "s390x",
    }[arch]


def package_architecture(family: str, arch: str) -> str:
    if family == "deb":
        return {
            "amd64": "amd64",
            "arm64": "arm64",
            "386": "i386",
            "armv5": "armel",
            "armv7": "armhf",
            "ppc64le": "ppc64el",
            "riscv64": "riscv64",
            "s390x": "s390x",
        }[arch]
    if family == "alpine":
        return {
            "amd64": "x86_64",
            "arm64": "aarch64",
            "386": "x86",
            "armv6": "armhf",
            "armv7": "armv7",
            "ppc64le": "ppc64le",
            "riscv64": "riscv64",
            "s390x": "s390x",
        }[arch]
    if family == "arch":
        return "x86_64"
    if arch == "amd64":
        return "x86_64"
    if arch == "arm64":
        return "aarch64"
    if arch == "386":
        return "i686" if family == "el10" else "i586"
    if arch == "armv6":
        return "armv6hl"
    if arch == "armv7":
        return "armv7hl"
    return arch


# Ordered from the oldest/first supported image to the newest.  This order is
# also the authoritative choice for each binary's target-distribution smoke run.
IMAGE_SPECS = (
    (
        "debian:12",
        "deb",
        "debian-12",
        "Debian 12",
        ("amd64", "armv7", "arm64", "386", "ppc64le"),
    ),
    (
        "debian:13",
        "deb",
        "debian-13",
        "Debian 13",
        ("amd64", "armv5", "armv7", "arm64", "386", "ppc64le", "riscv64", "s390x"),
    ),
    (
        "ubuntu:22.04",
        "deb",
        "ubuntu-22-04",
        "Ubuntu 22.04",
        ("amd64", "armv7", "arm64", "ppc64le", "riscv64", "s390x"),
    ),
    (
        "ubuntu:24.04",
        "deb",
        "ubuntu-24-04",
        "Ubuntu 24.04",
        ("amd64", "armv7", "arm64", "ppc64le", "riscv64", "s390x"),
    ),
    (
        "ubuntu:26.04",
        "deb",
        "ubuntu-26-04",
        "Ubuntu 26.04",
        ("amd64", "armv7", "arm64", "ppc64le", "riscv64", "s390x"),
    ),
    (
        "fedora:43",
        "fedora",
        "fedora-43",
        "Fedora 43",
        ("amd64", "arm64", "ppc64le", "s390x"),
    ),
    (
        "fedora:44",
        "fedora",
        "fedora-44",
        "Fedora 44",
        ("amd64", "arm64", "ppc64le", "s390x"),
    ),
    (
        "rockylinux/rockylinux:9",
        "el9",
        "rocky-9",
        "Rocky Linux 9",
        ("amd64", "arm64", "ppc64le", "s390x"),
    ),
    (
        "rockylinux/rockylinux:10",
        "el10",
        "rocky-10",
        "Rocky Linux 10",
        ("amd64", "arm64", "ppc64le", "s390x", "riscv64"),
    ),
    (
        "almalinux:9",
        "el9",
        "alma-9",
        "AlmaLinux 9",
        ("amd64", "arm64", "ppc64le", "s390x"),
    ),
    (
        "almalinux:10",
        "el10",
        "alma-10",
        "AlmaLinux 10",
        ("amd64", "arm64", "386", "ppc64le", "s390x"),
    ),
    (
        "opensuse/leap:16.0",
        "opensuse",
        "opensuse-leap-16",
        "openSUSE Leap 16.0",
        ("amd64", "arm64", "ppc64le", "s390x"),
    ),
    (
        "opensuse/tumbleweed",
        "tumbleweed",
        "opensuse-tumbleweed",
        "openSUSE Tumbleweed 20260830",
        ("amd64", "arm64", "386", "armv6", "armv7", "ppc64le", "riscv64", "s390x"),
    ),
    (
        "alpine:3.23",
        "alpine",
        "alpine-3-23",
        "Alpine 3.23",
        ("amd64", "arm64", "386", "armv6", "armv7", "ppc64le", "riscv64", "s390x"),
    ),
    (
        "alpine:3.24",
        "alpine",
        "alpine-3-24",
        "Alpine 3.24",
        ("amd64", "arm64", "386", "armv6", "armv7", "ppc64le", "riscv64", "s390x"),
    ),
    ("archlinux:base", "arch", "arch-linux", "Arch Linux", ("amd64",)),
)
EXPECTED_IMAGE_PLATFORMS = {
    image: (family, arches) for image, family, _, _, arches in IMAGE_SPECS
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
        family = member(row["family"], PACKAGE_FAMILIES, f"{where}.family")
        arch = member(row["arch"], set(ARCH_DETAILS), f"{where}.arch")
        combination = (family, arch)
        if combination not in PACKAGE_COMBINATIONS:
            raise MatrixError(f"{where} has unsupported family/arch: {family}/{arch}")
        combinations.add(combination)

        expected_id = f"{family}-{arch}"
        if identifier != expected_id:
            raise MatrixError(f"{where}.id must be {expected_id}")
        target = string(row["target"], TARGET_RE, f"{where}.target")
        if target != BINARY_TARGETS[arch]:
            raise MatrixError(f"{where}.target does not match architecture {arch}")

        details = ARCH_DETAILS[arch]
        for field in ("platform", "runner", "elf_class", "elf_endian", "elf_machine"):
            if row[field] != details[field]:
                raise MatrixError(f"{where}.{field} does not match architecture {arch}")

        cross = boolean(row["cross"], f"{where}.cross")
        native = boolean(row["native"], f"{where}.native")
        crt_static = boolean(row["crt_static"], f"{where}.crt_static")
        expected_cross = arch in CROSS_ARCHES
        if cross != expected_cross or native != (not expected_cross):
            raise MatrixError(f"{where} has inconsistent cross/native flags")
        if crt_static != (arch in CRT_STATIC_ARCHES):
            raise MatrixError(f"{where}.crt_static does not match architecture {arch}")
        expected_mode = execution_mode(arch)
        if row["execution_mode"] != expected_mode:
            raise MatrixError(f"{where}.execution_mode must be {expected_mode}")

        expected_artifact = f"binary-{family}-{arch}"
        artifact = string(row["artifact_name"], ARTIFACT_RE, f"{where}.artifact_name")
        if artifact != expected_artifact:
            raise MatrixError(f"{where}.artifact_name must be {expected_artifact}")

        archive = string(row["archive_template"], ARCHIVE_RE, f"{where}.archive_template")
        expected_archive = f"openshield-{{version}}-linux-{family}-{arch}.tar.xz"
        if archive != expected_archive:
            raise MatrixError(f"{where}.archive_template must be {expected_archive}")

        string(row["smoke_image"], IMAGE_RE, f"{where}.smoke_image")
        if row["smoke_platform"] != details["platform"]:
            raise MatrixError(f"{where}.smoke_platform must be {details['platform']}")

        result.append(row)

    if combinations != PACKAGE_COMBINATIONS:
        raise MatrixError("binaries do not cover the required family/architecture combinations")
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
        family = member(row["family"], PACKAGE_FAMILIES, f"{where}.family")
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
        expected_binary_id = f"{family}-{arch}"
        if (
            binary_id != expected_binary_id
            or binary["family"] != family
            or binary["arch"] != arch
        ):
            raise MatrixError(f"{where}.binary_id does not match its package architecture")

        binary_artifact = string(
            row["binary_artifact_name"], ARTIFACT_RE, f"{where}.binary_artifact_name"
        )
        if binary_artifact != binary["artifact_name"]:
            raise MatrixError(f"{where}.binary_artifact_name does not match binary_id")
        artifact = string(row["artifact_name"], ARTIFACT_RE, f"{where}.artifact_name")
        if artifact != f"package-{family}-{arch}":
            raise MatrixError(f"{where}.artifact_name does not match family/arch")

        expected_nfpm_arch = nfpm_architecture(family, arch)
        if row["nfpm_arch"] != expected_nfpm_arch:
            raise MatrixError(f"{where}.nfpm_arch must be {expected_nfpm_arch}")
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
        family = member(row["family"], PACKAGE_FAMILIES, f"{where}.family")
        arch = member(row["arch"], set(ARCH_DETAILS), f"{where}.arch")
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

        matching_specs = [
            (prefix, label)
            for spec_image, spec_family, prefix, label, spec_arches in IMAGE_SPECS
            if spec_image == image_name
            and spec_family == family
            and arch in spec_arches
        ]
        if len(matching_specs) != 1:
            raise MatrixError(f"{where}.image has an ambiguous platform specification")
        prefix, label = matching_specs[0]
        expected_id = f"{prefix}-{arch}"
        expected_name = f"{label} / {arch}"
        if identifier != expected_id or name != expected_name:
            raise MatrixError(
                f"{where} id/name must be {expected_id!r}/{expected_name!r}"
            )
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

        expected_firewall_test = (
            "full" if arch in EXPECTED_RUNTIME_TEST_ARCHES else "build-only"
        )
        if row["firewall_test"] != expected_firewall_test:
            raise MatrixError(
                f"{where}.firewall_test must be {expected_firewall_test} for {arch}"
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


def validate_runtime_test_arches(value: Any) -> list[str]:
    if not isinstance(value, list) or tuple(value) != EXPECTED_RUNTIME_TEST_ARCHES:
        raise MatrixError(
            "runtime_test_arches must be exactly: "
            + ", ".join(EXPECTED_RUNTIME_TEST_ARCHES)
        )
    return list(value)


def validate_smoke_links(
    binaries: dict[str, dict[str, Any]], platforms: list[dict[str, Any]]
) -> None:
    platform_rows = {
        (image_parts(row["image"])[0], row["arch"]): row for row in platforms
    }
    for identifier, binary in binaries.items():
        family = binary["family"]
        arch = binary["arch"]
        oldest_image = next(
            image
            for image, spec_family, _, _, arches in IMAGE_SPECS
            if spec_family == family and arch in arches
        )
        smoke_platform = platform_rows[(oldest_image, arch)]
        if binary["smoke_image"] != smoke_platform["image"]:
            raise MatrixError(
                f"binary {identifier} must smoke-test in {smoke_platform['image']}"
            )
        if binary["smoke_platform"] != smoke_platform["platform"]:
            raise MatrixError(
                f"binary {identifier} smoke platform does not match its target image"
            )


def validate_cross_config() -> None:
    """Require every cross compiler image to be explicit and digest-pinned."""

    try:
        stat = CROSS_PATH.stat()
        if not CROSS_PATH.is_file() or stat.st_size <= 0 or stat.st_size > MAX_CROSS_BYTES:
            raise MatrixError("Cross.toml must be a non-empty regular file below 64 KiB")
        document = tomllib.loads(CROSS_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise MatrixError(f"cannot read Cross.toml: {error}") from error

    root = exact_keys(document, frozenset({"target"}), "Cross.toml root")
    targets = root["target"]
    if not isinstance(targets, dict) or not targets:
        raise MatrixError("Cross.toml.target must be a non-empty table")

    required_targets = {BINARY_TARGETS[arch] for arch in CROSS_ARCHES}
    missing = sorted(required_targets - set(targets))
    if missing:
        raise MatrixError(
            "Cross.toml is missing release cross targets: " + ", ".join(missing)
        )

    for target, raw in targets.items():
        string(target, TARGET_RE, f"Cross.toml.target.{target}")
        config = exact_keys(
            raw,
            frozenset({"image"}),
            f"Cross.toml.target.{target}",
        )
        image = config["image"]
        match = CROSS_IMAGE_RE.fullmatch(image) if isinstance(image, str) else None
        if match is None:
            raise MatrixError(
                f"Cross.toml.target.{target}.image must be a digest-pinned cross-rs image"
            )
        if match.group("target") != target:
            raise MatrixError(
                f"Cross.toml.target.{target}.image does not match its target"
            )


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
    runtime_test_arches = validate_runtime_test_arches(root["runtime_test_arches"])
    binaries = validate_binaries(root["binaries"])
    packages = validate_packages(root["packages"], binaries)
    platforms = validate_platforms(root["platforms"], packages)
    validate_smoke_links(binaries, platforms)
    validate_cross_config()
    return {
        "schema_version": 1,
        "runtime_test_arches": runtime_test_arches,
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
    enriched["execution_mode"] = execution_mode(platform["arch"])
    return enriched


def emitted_rows(document: dict[str, Any], matrix: str) -> list[dict[str, Any]]:
    if matrix == "binaries":
        return document["binaries"]
    if matrix == "packages":
        return document["packages"]

    packages = {row["id"]: row for row in document["packages"]}
    platforms = [enrich_platform(row, packages) for row in document["platforms"]]
    runtime_test_arches = frozenset(document["runtime_test_arches"])
    runtime_platforms = [
        row for row in platforms if row["arch"] in runtime_test_arches
    ]
    if matrix == "platforms":
        return runtime_platforms

    firewall: list[dict[str, Any]] = []
    for platform in runtime_platforms:
        for backend in ("nftables", "iptables"):
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
            runtime_platform_count = len(emitted_rows(document, "platforms"))
            firewall_count = len(emitted_rows(document, "firewall"))
            print(
                "release matrix validated: "
                f"{len(document['binaries'])} binaries, "
                f"{len(document['packages'])} packages, "
                f"{len(document['platforms'])} declared platforms, "
                f"{runtime_platform_count} package-install jobs, "
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
