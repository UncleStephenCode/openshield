#!/usr/bin/env python3
"""Pure, bounded parsers for reproducible performance-environment evidence."""

from __future__ import annotations

import re
from typing import Final


MAX_OS_RELEASE_BYTES: Final = 64 * 1024
MAX_OS_RELEASE_LINES: Final = 256
MAX_OS_RELEASE_KEY_BYTES: Final = 64
MAX_OS_RELEASE_VALUE_BYTES: Final = 8 * 1024
MAX_UNAME_BYTES: Final = 4 * 1024
MAX_MACHINE_BYTES: Final = 64
MAX_RPM_INVENTORY_BYTES: Final = 16 * 1024 * 1024
MAX_RPM_RECORDS: Final = 100_000
MAX_RPM_LINE_BYTES: Final = 4 * 1024
MAX_RPM_NAME_BYTES: Final = 255
MAX_RPM_VERSION_BYTES: Final = 1_024
MAX_RPM_RELEASE_BYTES: Final = 1_024
MAX_RPM_ARCH_BYTES: Final = 64

_OS_RELEASE_KEY = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_OS_RELEASE_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_OS_RELEASE_UNQUOTED_VALUE = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._+:/@%~,-]*\Z"
)
_DOCKER_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SHA256_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_MACHINE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_+-]{0,63}\Z")
_RPM_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9+._-]*\Z")
_RPM_VERSION_RELEASE = re.compile(r"[A-Za-z0-9][A-Za-z0-9+._~^-]*\Z")
_RPM_ARCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9_+-]*\Z")


class EnvironmentEvidenceError(ValueError):
    """Raised when external environment evidence is missing or ambiguous."""


def _bounded_text(raw: bytes | str, maximum_bytes: int, description: str) -> str:
    if isinstance(raw, bytes):
        if len(raw) > maximum_bytes:
            raise EnvironmentEvidenceError(f"{description} exceeds its byte bound")
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise EnvironmentEvidenceError(
                f"{description} is not valid UTF-8"
            ) from error
    elif isinstance(raw, str):
        try:
            encoded = raw.encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            raise EnvironmentEvidenceError(
                f"{description} is not valid Unicode text"
            ) from error
        if len(encoded) > maximum_bytes:
            raise EnvironmentEvidenceError(f"{description} exceeds its byte bound")
        text = raw
    else:
        raise EnvironmentEvidenceError(f"{description} must be bytes or text")
    for character in text:
        codepoint = ord(character)
        if codepoint == 0 or codepoint == 0x7F:
            raise EnvironmentEvidenceError(
                f"{description} contains a forbidden control character"
            )
        if codepoint < 0x20 and character not in "\t\r\n":
            raise EnvironmentEvidenceError(
                f"{description} contains a forbidden control character"
            )
        if character not in "\t\r\n" and not character.isprintable():
            raise EnvironmentEvidenceError(
                f"{description} contains non-printable Unicode text"
            )
    return text


def _one_line(raw: bytes | str, maximum_bytes: int, description: str) -> str:
    text = _bounded_text(raw, maximum_bytes, description)
    if text.endswith("\r\n"):
        text = text[:-2]
    elif text.endswith("\n"):
        text = text[:-1]
    if not text or "\n" in text or "\r" in text:
        raise EnvironmentEvidenceError(f"{description} must be exactly one line")
    if text != text.strip() or "\t" in text:
        raise EnvironmentEvidenceError(
            f"{description} has ambiguous surrounding or tab whitespace"
        )
    return text


def _parse_os_release_value(value: str, line_number: int) -> str:
    if not value:
        return ""
    if value[0] in "\"'":
        quote = value[0]
        if len(value) < 2 or value[-1] != quote:
            raise EnvironmentEvidenceError(
                f"os-release line {line_number} has an unterminated quoted value"
            )
        body = value[1:-1]
        if quote == "'":
            if "'" in body:
                raise EnvironmentEvidenceError(
                    f"os-release line {line_number} has ambiguous quoting"
                )
            parsed = body
        else:
            output: list[str] = []
            index = 0
            while index < len(body):
                character = body[index]
                if character in "\"$`":
                    raise EnvironmentEvidenceError(
                        f"os-release line {line_number} has an unescaped shell special"
                    )
                if character != "\\":
                    output.append(character)
                    index += 1
                    continue
                index += 1
                if index >= len(body) or body[index] not in "\\\"$`'":
                    raise EnvironmentEvidenceError(
                        f"os-release line {line_number} has an invalid escape"
                    )
                output.append(body[index])
                index += 1
            parsed = "".join(output)
    else:
        if _OS_RELEASE_UNQUOTED_VALUE.fullmatch(value) is None:
            raise EnvironmentEvidenceError(
                f"os-release line {line_number} has unsafe unquoted syntax"
            )
        parsed = value
    if len(parsed.encode("utf-8")) > MAX_OS_RELEASE_VALUE_BYTES:
        raise EnvironmentEvidenceError(
            f"os-release line {line_number} value exceeds its byte bound"
        )
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in parsed):
        raise EnvironmentEvidenceError(
            f"os-release line {line_number} value contains a control character"
        )
    return parsed


def parse_os_release(raw: bytes | str) -> dict[str, str]:
    """Parse os-release assignments without evaluating any shell syntax."""

    text = _bounded_text(raw, MAX_OS_RELEASE_BYTES, "os-release evidence")
    if "\r" in text:
        raise EnvironmentEvidenceError("os-release evidence contains carriage returns")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if not lines or len(lines) > MAX_OS_RELEASE_LINES:
        raise EnvironmentEvidenceError("os-release has an invalid line count")
    values: dict[str, str] = {}
    for line_number, line in enumerate(lines, start=1):
        if not line or line.startswith("#"):
            continue
        if line != line.strip() or "=" not in line:
            raise EnvironmentEvidenceError(
                f"os-release line {line_number} is not a canonical assignment"
            )
        key, value = line.split("=", 1)
        if (
            len(key.encode("ascii", errors="ignore")) > MAX_OS_RELEASE_KEY_BYTES
            or _OS_RELEASE_KEY.fullmatch(key) is None
        ):
            raise EnvironmentEvidenceError(
                f"os-release line {line_number} has an invalid key"
            )
        if key in values:
            raise EnvironmentEvidenceError(f"os-release key {key} is duplicated")
        values[key] = _parse_os_release_value(value, line_number)
    distribution_id = values.get("ID")
    if distribution_id is None or _OS_RELEASE_ID.fullmatch(distribution_id) is None:
        raise EnvironmentEvidenceError("os-release ID is missing or invalid")
    return {key: values[key] for key in sorted(values)}


def validate_docker_image_id(raw: bytes | str) -> str:
    """Return one canonical Docker content-addressed image identifier."""

    value = _one_line(raw, 72, "Docker image ID")
    if _DOCKER_IMAGE_ID.fullmatch(value) is None:
        raise EnvironmentEvidenceError(
            "Docker image ID must be lowercase sha256:<64 hex digits>"
        )
    return value


def validate_uname(raw: bytes | str) -> str:
    """Validate bounded single-line Linux uname output for verbatim evidence."""

    value = _one_line(raw, MAX_UNAME_BYTES, "uname evidence")
    # Kernel version strings legitimately contain repeated ASCII spaces, for
    # example the space-padded day in "Mon Aug  3".  Preserve those bytes in
    # the evidence while excluding controls, Unicode whitespace and ambiguous
    # leading/trailing padding.
    if any(not (" " <= character <= "~") for character in value):
        raise EnvironmentEvidenceError("uname evidence contains non-ASCII text")
    fields = value.split()
    if (
        value != value.strip(" ")
        or len(fields) < 4
        or fields[0] != "Linux"
    ):
        raise EnvironmentEvidenceError("uname evidence is not canonical Linux output")
    return value


def validate_machine(raw: bytes | str) -> str:
    """Validate a canonical single-token `uname -m` value."""

    value = _one_line(raw, MAX_MACHINE_BYTES, "machine architecture evidence")
    if _MACHINE.fullmatch(value) is None:
        raise EnvironmentEvidenceError("machine architecture evidence is invalid")
    return value


def parse_rpm_nevra_records(raw: bytes | str) -> tuple[str, ...]:
    """Validate, uniquely identify, and sort `name|epoch|version|release|arch`."""

    text = _bounded_text(raw, MAX_RPM_INVENTORY_BYTES, "RPM inventory")
    if "\r" in text:
        raise EnvironmentEvidenceError("RPM inventory contains carriage returns")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if not lines or len(lines) > MAX_RPM_RECORDS:
        raise EnvironmentEvidenceError("RPM inventory has an invalid record count")
    records: set[str] = set()
    for line_number, line in enumerate(lines, start=1):
        try:
            line_bytes = line.encode("ascii", errors="strict")
        except UnicodeEncodeError as error:
            raise EnvironmentEvidenceError(
                f"RPM record {line_number} is not ASCII"
            ) from error
        if not line or len(line_bytes) > MAX_RPM_LINE_BYTES:
            raise EnvironmentEvidenceError(
                f"RPM record {line_number} is empty or too long"
            )
        fields = line.split("|")
        if len(fields) != 5:
            raise EnvironmentEvidenceError(
                f"RPM record {line_number} must contain exactly five fields"
            )
        name, epoch, version, release, architecture = fields
        if (
            len(name) > MAX_RPM_NAME_BYTES
            or _RPM_NAME.fullmatch(name) is None
        ):
            raise EnvironmentEvidenceError(
                f"RPM record {line_number} has an invalid name"
            )
        if (
            not epoch.isascii()
            or not epoch.isdecimal()
            or len(epoch) > 20
            or int(epoch, 10) > (1 << 64) - 1
        ):
            raise EnvironmentEvidenceError(
                f"RPM record {line_number} has an invalid epoch"
            )
        if (
            len(version) > MAX_RPM_VERSION_BYTES
            or _RPM_VERSION_RELEASE.fullmatch(version) is None
        ):
            raise EnvironmentEvidenceError(
                f"RPM record {line_number} has an invalid version"
            )
        if (
            len(release) > MAX_RPM_RELEASE_BYTES
            or _RPM_VERSION_RELEASE.fullmatch(release) is None
        ):
            raise EnvironmentEvidenceError(
                f"RPM record {line_number} has an invalid release"
            )
        # rpm represents imported signing-key pseudo-packages as
        # `gpg-pubkey ... (none)`.  It is part of the installed inventory on
        # Tumbleweed, but `(none)` is not a valid architecture for ordinary
        # packages and must not broaden the accepted NEVRA grammar.
        architecture_is_valid = (
            _RPM_ARCH.fullmatch(architecture) is not None
            or (name == "gpg-pubkey" and architecture == "(none)")
        )
        if len(architecture) > MAX_RPM_ARCH_BYTES or not architecture_is_valid:
            raise EnvironmentEvidenceError(
                f"RPM record {line_number} has an invalid architecture"
            )
        canonical = "|".join((name, str(int(epoch, 10)), version, release, architecture))
        if canonical in records:
            raise EnvironmentEvidenceError(
                f"RPM record {line_number} duplicates an installed NEVRA"
            )
        records.add(canonical)
    return tuple(sorted(records))


def validate_sha256_digest(raw: bytes | str) -> str:
    """Validate one canonical lowercase SHA-256 digest, without a filename."""

    value = _one_line(raw, 65, "SHA-256 digest")
    if _SHA256_DIGEST.fullmatch(value) is None:
        raise EnvironmentEvidenceError(
            "SHA-256 digest must contain exactly 64 lowercase hex digits"
        )
    return value
