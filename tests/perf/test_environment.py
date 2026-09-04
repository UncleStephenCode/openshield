#!/usr/bin/env python3
"""Unit tests for bounded, shell-free environment evidence parsing."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).with_name("environment.py")
SPECIFICATION = importlib.util.spec_from_file_location(
    "openshield_perf_environment", MODULE_PATH
)
if SPECIFICATION is None or SPECIFICATION.loader is None:
    raise RuntimeError(f"cannot load {MODULE_PATH}")
environment = importlib.util.module_from_spec(SPECIFICATION)
SPECIFICATION.loader.exec_module(environment)


class OsReleaseTests(unittest.TestCase):
    def test_parses_without_shell_evaluation_and_sorts_keys(self) -> None:
        document = (
            "# generated distribution identity\n"
            'NAME="openSUSE Tumbleweed"\n'
            "ID=opensuse-tumbleweed\n"
            "VERSION_ID='20260903'\n"
            'PRETTY_NAME="openSUSE \\"Tumbleweed\\" \\$stable"\n'
            "LOCALIZED_NAME='openSUSE Тамблвид'\n"
        )
        parsed = environment.parse_os_release(document.encode("utf-8"))
        self.assertEqual(list(parsed), sorted(parsed))
        self.assertEqual(parsed["ID"], "opensuse-tumbleweed")
        self.assertEqual(parsed["NAME"], "openSUSE Tumbleweed")
        self.assertEqual(parsed["PRETTY_NAME"], 'openSUSE "Tumbleweed" $stable')
        self.assertEqual(parsed["LOCALIZED_NAME"], "openSUSE Тамблвид")

    def test_rejects_ambiguous_or_executable_shell_syntax(self) -> None:
        invalid_documents = (
            "ID=opensuse\nID=tumbleweed\n",
            "ID=$(id)\n",
            "ID=`id`\n",
            "export ID=opensuse\n",
            " ID=opensuse\n",
            "ID=opensuse trailing\n",
            "ID=opensuse\nEXTRA=value;command\n",
            'ID="unterminated\n',
            'ID="open$suse"\n',
            "NAME=opensuse\n",
            "id=opensuse\n",
            "ID=opensuse\r\n",
            "ID=open\x00suse\n",
            "ID=open\u202esuse\n",
        )
        for document in invalid_documents:
            with self.subTest(document=repr(document)):
                with self.assertRaises(environment.EnvironmentEvidenceError):
                    environment.parse_os_release(document)

    def test_os_release_input_is_bounded_before_splitting(self) -> None:
        oversized = b"ID=opensuse\n" + b"A" * environment.MAX_OS_RELEASE_BYTES
        with self.assertRaisesRegex(
            environment.EnvironmentEvidenceError, "byte bound"
        ):
            environment.parse_os_release(oversized)

    def test_os_release_rejects_duplicate_and_excessive_lines(self) -> None:
        with mock.patch.object(environment, "MAX_OS_RELEASE_LINES", 2):
            with self.assertRaisesRegex(
                environment.EnvironmentEvidenceError, "line count"
            ):
                environment.parse_os_release("ID=opensuse\nA=a\nB=b\n")


class ScalarEvidenceTests(unittest.TestCase):
    def test_validates_canonical_docker_image_id(self) -> None:
        identifier = "sha256:" + "ab" * 32
        self.assertEqual(
            environment.validate_docker_image_id((identifier + "\n").encode()),
            identifier,
        )
        for invalid in (
            "ab" * 32,
            "sha256:" + "AB" * 32,
            " sha256:" + "ab" * 32,
            "sha256:" + "ab" * 31,
            "sha512:" + "ab" * 32,
            "sha256:" + "ab" * 32 + " extra",
        ):
            with self.subTest(identifier=invalid):
                with self.assertRaises(environment.EnvironmentEvidenceError):
                    environment.validate_docker_image_id(invalid)

    def test_validates_bounded_single_line_linux_uname(self) -> None:
        value = "Linux perf-dut 6.17.0 x86_64 GNU/Linux"
        self.assertEqual(environment.validate_uname(value + "\n"), value)
        padded_date = (
            "Linux 7.1.6-1-default #1 SMP PREEMPT_DYNAMIC "
            "Mon Aug  3 10:04:30 UTC 2026 x86_64"
        )
        self.assertEqual(environment.validate_uname(padded_date), padded_date)
        for invalid in (
            "",
            "FreeBSD peer 15.0 amd64",
            "Linux  peer 6.17.0",
            "Linux peer\t6.17.0",
            "Linux peer\n6.17.0",
            " Linux peer 6.17.0",
            "Linux peer 6.17.0 x86_64 ",
            "Linux peer 6.17.0 x86_64 suffix",
            "Linux peer \x006.17.0",
            "Linux peer " + "x" * environment.MAX_UNAME_BYTES,
        ):
            with self.subTest(uname=repr(invalid[:80])):
                with self.assertRaises(environment.EnvironmentEvidenceError):
                    environment.validate_uname(invalid)

    def test_validates_machine_architecture_as_one_bounded_token(self) -> None:
        self.assertEqual(environment.validate_machine("x86_64\n"), "x86_64")
        for invalid in ("", "x86 64", "x86_64\narm64", "../x86_64", "x" * 65):
            with self.subTest(machine=repr(invalid)):
                with self.assertRaises(environment.EnvironmentEvidenceError):
                    environment.validate_machine(invalid)

    def test_validates_plain_lowercase_repomd_sha256(self) -> None:
        digest = "0123456789abcdef" * 4
        self.assertEqual(environment.validate_sha256_digest(digest + "\n"), digest)
        for invalid in (
            "sha256:" + digest,
            digest.upper(),
            digest[:-1],
            digest + "  repomd.xml",
            digest + "\n" + digest,
            "g" * 64,
        ):
            with self.subTest(digest=repr(invalid[:80])):
                with self.assertRaises(environment.EnvironmentEvidenceError):
                    environment.validate_sha256_digest(invalid)


class RpmInventoryTests(unittest.TestCase):
    def test_parses_normalizes_and_sorts_unique_nevra_records(self) -> None:
        document = (
            "zlib|0|1.3.1|2.1|x86_64\n"
            "bash|000|5.2.37|1.1|x86_64\n"
            "gpg-pubkey|0|39db7c82|66c5d91a|(none)\n"
            "kernel-default|0|6.17.0~rc1|1.1|x86_64\n"
        )
        self.assertEqual(
            environment.parse_rpm_nevra_records(document),
            (
                "bash|0|5.2.37|1.1|x86_64",
                "gpg-pubkey|0|39db7c82|66c5d91a|(none)",
                "kernel-default|0|6.17.0~rc1|1.1|x86_64",
                "zlib|0|1.3.1|2.1|x86_64",
            ),
        )

    def test_rejects_duplicates_after_epoch_normalization(self) -> None:
        document = (
            "bash|0|5.2.37|1.1|x86_64\n"
            "bash|00|5.2.37|1.1|x86_64\n"
        )
        with self.assertRaisesRegex(
            environment.EnvironmentEvidenceError, "duplicates"
        ):
            environment.parse_rpm_nevra_records(document)

    def test_rejects_malformed_or_unsafe_rpm_fields(self) -> None:
        invalid_records = (
            "bash|0|5.2|1.1\n",
            "ba|sh|0|5.2|1.1|x86_64\n",
            "bash||5.2|1.1|x86_64\n",
            "bash|-1|5.2|1.1|x86_64\n",
            "bash|18446744073709551616|5.2|1.1|x86_64\n",
            "bash|0|%{VERSION}|1.1|x86_64\n",
            "bash|0|5.2|%{RELEASE}|x86_64\n",
            "bash|0|5.2|1.1|x86 64\n",
            "bash|0|5.2|1.1|(none)\n",
            "gpg-pubkey|0|1|1|(NONE)\n",
            "пакет|0|1|1|noarch\n",
            "\n",
        )
        for record in invalid_records:
            with self.subTest(record=repr(record)):
                with self.assertRaises(environment.EnvironmentEvidenceError):
                    environment.parse_rpm_nevra_records(record)

    def test_inventory_record_count_and_line_length_are_bounded(self) -> None:
        with mock.patch.object(environment, "MAX_RPM_RECORDS", 1):
            with self.assertRaisesRegex(
                environment.EnvironmentEvidenceError, "record count"
            ):
                environment.parse_rpm_nevra_records(
                    "a|0|1|1|noarch\nb|0|1|1|noarch\n"
                )
        oversized_name = "a" * (environment.MAX_RPM_NAME_BYTES + 1)
        with self.assertRaisesRegex(
            environment.EnvironmentEvidenceError, "invalid name"
        ):
            environment.parse_rpm_nevra_records(
                f"{oversized_name}|0|1|1|noarch\n"
            )


if __name__ == "__main__":
    unittest.main()
