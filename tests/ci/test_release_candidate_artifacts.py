#!/usr/bin/env python3
"""Regression tests for binary artifacts crossing GitHub's ZIP transport."""

from __future__ import annotations

import io
import os
from pathlib import Path
import runpy
import tarfile
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
ASSEMBLER = runpy.run_path(str(REPOSITORY_ROOT / "scripts" / "assemble-release-candidate.py"))
CandidateError = ASSEMBLER["CandidateError"]
verify_binary_artifact = ASSEMBLER["verify_binary_artifact"]


class BinaryArtifactTests(unittest.TestCase):
    archive_name = "openshield-test-linux-amd64.tar.xz"
    payloads = {
        "openshield-daemon": b"daemon-elf-payload",
        "openshield-tui": b"tui-elf-payload",
    }

    def make_artifact(
        self,
        root: Path,
        *,
        raw_mode: int = 0o644,
        member_mode: int = 0o755,
        mismatch: str | None = None,
        extra_member: bool = False,
    ) -> Path:
        for name, payload in self.payloads.items():
            path = root / name
            path.write_bytes(payload)
            os.chmod(path, raw_mode)

        archive_path = root / self.archive_name
        with tarfile.open(archive_path, mode="w:xz") as archive:
            for name, payload in self.payloads.items():
                archived_payload = (
                    bytes([payload[0] ^ 1]) + payload[1:] if mismatch == name else payload
                )
                member = tarfile.TarInfo(name)
                member.mode = member_mode
                member.size = len(archived_payload)
                archive.addfile(member, io.BytesIO(archived_payload))
            if extra_member:
                member = tarfile.TarInfo("unexpected")
                member.mode = 0o755
                member.size = 1
                archive.addfile(member, io.BytesIO(b"x"))
        os.chmod(archive_path, 0o644)
        return archive_path

    def test_accepts_github_transport_mode_with_preserved_tar_modes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            archive = self.make_artifact(root)
            self.assertEqual(
                verify_binary_artifact(root, self.archive_name, "test-amd64"),
                archive,
            )

    def test_rejects_unexpected_transport_modes(self) -> None:
        for raw_mode in (0o600, 0o664, 0o666, 0o755, 0o4755):
            with self.subTest(raw_mode=oct(raw_mode)):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    root = Path(temporary_directory)
                    self.make_artifact(root, raw_mode=raw_mode)
                    with self.assertRaisesRegex(
                        CandidateError, "transport binary has unexpected mode"
                    ):
                        verify_binary_artifact(root, self.archive_name, "test-amd64")

    def test_rejects_non_executable_archive_members(self) -> None:
        for member_mode in (0o644, 0o754, 0o775, 0o4755):
            with self.subTest(member_mode=oct(member_mode)):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    root = Path(temporary_directory)
                    self.make_artifact(root, member_mode=member_mode)
                    with self.assertRaisesRegex(CandidateError, "unsafe member"):
                        verify_binary_artifact(root, self.archive_name, "test-amd64")

    def test_rejects_archive_and_raw_byte_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self.make_artifact(root, mismatch="openshield-daemon")
            with self.assertRaisesRegex(CandidateError, "differs from verified binary"):
                verify_binary_artifact(root, self.archive_name, "test-amd64")

    def test_rejects_extra_archive_member(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self.make_artifact(root, extra_member=True)
            with self.assertRaisesRegex(CandidateError, "unexpected members"):
                verify_binary_artifact(root, self.archive_name, "test-amd64")


if __name__ == "__main__":
    unittest.main()
