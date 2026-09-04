#!/usr/bin/env python3
"""Bounded real-socket client for the application TCP conntrack E2E path."""

from __future__ import annotations

import ipaddress
from pathlib import Path
import socket
import sys
import time


TRIGGER_TIMEOUT_SECONDS = 20.0
SOCKET_TIMEOUT_SECONDS = 5.0


def wait_for_trigger(path: Path) -> None:
    deadline = time.monotonic() + TRIGGER_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if path.is_file():
            return
        time.sleep(0.05)
    raise TimeoutError(f"timed out waiting for {path}")


def mark_ready(path: Path) -> None:
    path.write_text("ready\n", encoding="ascii")


def receive_exact(stream: socket.socket, size: int) -> bytes:
    received = bytearray()
    while len(received) < size:
        chunk = stream.recv(size - len(received))
        if not chunk:
            raise ConnectionError("TCP echo peer closed the established connection")
        received.extend(chunk)
    return bytes(received)


def round_trip(stream: socket.socket, payload: bytes) -> None:
    stream.sendall(payload)
    if receive_exact(stream, len(payload)) != payload:
        raise RuntimeError("TCP echo peer returned an unexpected payload")


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} IPV4 PORT", file=sys.stderr)
        return 2
    address = str(ipaddress.IPv4Address(sys.argv[1]))
    port = int(sys.argv[2], 10)
    if not 1 <= port <= 65_535:
        raise ValueError("port is outside 1..65535")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
        stream.settimeout(SOCKET_TIMEOUT_SECONDS)
        stream.connect((address, port))

        round_trip(stream, b"learning")
        mark_ready(Path("/tmp/openshield-l2-learning-ready"))

        wait_for_trigger(Path("/tmp/openshield-l2-enforcing-first"))
        round_trip(stream, b"enforcing-first")
        mark_ready(Path("/tmp/openshield-l2-enforcing-first-ready"))

        wait_for_trigger(Path("/tmp/openshield-l2-enforcing-fast"))
        round_trip(stream, b"enforcing-fast")
        mark_ready(Path("/tmp/openshield-l2-enforcing-fast-ready"))

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, TimeoutError, ValueError) as error:
        print(f"openshield TCP session: {error}", file=sys.stderr)
        raise SystemExit(1)
