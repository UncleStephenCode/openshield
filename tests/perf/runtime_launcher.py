#!/usr/bin/env python3
"""Verify and dispatch one source-only performance-harness entrypoint."""

import hashlib
import json
import os
import runpy
import stat
import sys


RUNTIME_ROOT = "/opt/openshield-perf"
MANIFEST_NAME = ".manifest.json"
MANIFEST_SCHEMA = "openshield.perf.runtime-bundle.v1"
MANIFEST_DIGEST_ENV = "OPENSHIELD_PERF_RUNTIME_MANIFEST_SHA256"
VERIFY_ONLY = "--verify-only"
MAX_MANIFEST_BYTES = 65_536
MAX_COMPONENT_BYTES = 4 * 1024 * 1024
ENTRYPOINTS = [
    "control.py",
    "metrics.py",
    "workloads/tcp.py",
    "workloads/udp.py",
]
EXPECTED_COMPONENTS = [
    ("tests/perf/runtime_launcher.py", "runtime_launcher.py"),
    ("tests/perf/control.py", "control.py"),
    ("tests/perf/metrics.py", "metrics.py"),
    ("tests/perf/workloads/common.py", "workloads/common.py"),
    ("tests/perf/workloads/identity_probe.c", "workloads/identity_probe.c"),
    ("tests/perf/workloads/tcp.py", "workloads/tcp.py"),
    ("tests/perf/workloads/udp.py", "workloads/udp.py"),
]


def _read_bounded_regular(path, maximum):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o022
            or not 0 < metadata.st_size <= maximum
        ):
            raise SystemExit("runtime component is not a bounded read-only regular file")
        payload = bytearray()
        while chunk := os.read(descriptor, min(1024 * 1024, maximum + 1)):
            payload.extend(chunk)
            if len(payload) > maximum:
                raise SystemExit("runtime component exceeds its byte bound")
        metadata_after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)
        != (
            metadata_after.st_dev,
            metadata_after.st_ino,
            metadata_after.st_size,
            metadata_after.st_mtime_ns,
        )
        or len(payload) != metadata.st_size
    ):
        raise SystemExit("runtime component changed while being verified")
    return bytes(payload), metadata


def main(runtime_root=RUNTIME_ROOT):
    """Verify the exact bundle rooted at *runtime_root*, then dispatch argv[1]."""

    expected_digest = os.environ.get(MANIFEST_DIGEST_ENV, "")
    if (
        len(expected_digest) != 64
        or any(character not in "0123456789abcdef" for character in expected_digest)
        or not sys.flags.isolated
        or not sys.dont_write_bytecode
        or not sys.flags.no_site
    ):
        raise SystemExit("runtime Python isolation evidence is unavailable")
    root_metadata = os.lstat(runtime_root)
    if not stat.S_ISDIR(root_metadata.st_mode) or root_metadata.st_mode & 0o022:
        raise SystemExit("runtime bundle root is unsafe")
    manifest_payload, _ = _read_bounded_regular(
        os.path.join(runtime_root, MANIFEST_NAME), MAX_MANIFEST_BYTES
    )
    if hashlib.sha256(manifest_payload).hexdigest() != expected_digest:
        raise SystemExit("runtime manifest digest mismatch")
    try:
        manifest = json.loads(manifest_payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SystemExit("runtime manifest is malformed") from error
    expected_sources = [source for source, _ in EXPECTED_COMPONENTS]
    expected_paths = [path for _, path in EXPECTED_COMPONENTS]
    components = manifest.get("components") if isinstance(manifest, dict) else None
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema") != MANIFEST_SCHEMA
        or manifest.get("container_root") != RUNTIME_ROOT
        or manifest.get("python_flags") != ["-I", "-B", "-S"]
        or manifest.get("source_only") is not True
        or manifest.get("entrypoints") != ENTRYPOINTS
    ):
        raise SystemExit("runtime manifest policy mismatch")
    if (
        not isinstance(components, list)
        or [
            component.get("path") if isinstance(component, dict) else None
            for component in components
        ]
        != expected_paths
        or [
            component.get("source_path") if isinstance(component, dict) else None
            for component in components
        ]
        != expected_sources
        or any(
            not isinstance(component, dict)
            or set(component) != {"path", "source_path", "size", "sha256"}
            for component in components
        )
    ):
        raise SystemExit("runtime component allowlist mismatch")

    observed_files = set()
    observed_directories = set()
    for current, directories, files in os.walk(
        runtime_root, topdown=True, followlinks=False
    ):
        relative_directory = os.path.relpath(current, runtime_root)
        relative_directory = "" if relative_directory == "." else relative_directory
        observed_directories.add(relative_directory)
        for name in directories:
            metadata = os.lstat(os.path.join(current, name))
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o022:
                raise SystemExit("runtime bundle contains an unsafe directory")
        for name in files:
            path = os.path.join(current, name)
            metadata = os.lstat(path)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o022:
                raise SystemExit("runtime bundle contains an unsafe file")
            observed_files.add(os.path.relpath(path, runtime_root))
    if observed_directories != {"", "workloads"} or observed_files != set(
        expected_paths
    ) | {MANIFEST_NAME}:
        raise SystemExit("runtime bundle contains missing or extra filesystem entries")

    for component in components:
        size = component.get("size")
        digest = component.get("sha256")
        if (
            not isinstance(size, int)
            or not 0 < size <= MAX_COMPONENT_BYTES
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise SystemExit("runtime component metadata is invalid")
        payload, metadata = _read_bounded_regular(
            os.path.join(runtime_root, component["path"]), MAX_COMPONENT_BYTES
        )
        if metadata.st_size != size or hashlib.sha256(payload).hexdigest() != digest:
            raise SystemExit("runtime component digest mismatch")

    if len(sys.argv) < 2:
        raise SystemExit("runtime entrypoint is missing")
    entrypoint = sys.argv[1]
    if entrypoint == VERIFY_ONLY:
        print(json.dumps({"schema": manifest["schema"], "verified": True}, sort_keys=True))
        return 0
    if entrypoint not in ENTRYPOINTS:
        raise SystemExit("runtime entrypoint is not allowlisted")
    sys.path.insert(0, os.path.join(runtime_root, "workloads"))
    sys.argv = [os.path.join(runtime_root, entrypoint), *sys.argv[2:]]
    runpy.run_path(sys.argv[0], run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
