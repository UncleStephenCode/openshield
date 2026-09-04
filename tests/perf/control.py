#!/usr/bin/env python3
"""Bounded OpenShield control client used only inside the perf DUT container."""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import struct
import sys
from typing import Any


MAX_FRAME_BYTES = 64 * 1024
MAX_RULES = 10_000
CONTROL_SOCKET = "/run/openshield/control.sock"
OBSERVE_SOCKET = "/run/openshield/observe.sock"


def _send(stream: socket.socket, request: dict[str, Any]) -> None:
    payload = json.dumps(request, separators=(",", ":")).encode("utf-8")
    if not payload or len(payload) > MAX_FRAME_BYTES:
        raise RuntimeError("request is outside the protocol frame bound")
    stream.sendall(struct.pack(">I", len(payload)) + payload)


def _receive_exact(stream: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = stream.recv(size - len(result))
        if not chunk:
            raise RuntimeError("truncated OpenShield response")
        result.extend(chunk)
    return bytes(result)


def _receive(stream: socket.socket) -> dict[str, Any]:
    size = struct.unpack(">I", _receive_exact(stream, 4))[0]
    if not 0 < size <= MAX_FRAME_BYTES:
        raise RuntimeError(f"invalid OpenShield response size {size}")
    response = json.loads(_receive_exact(stream, size))
    if not isinstance(response, dict):
        raise RuntimeError("OpenShield response is not an object")
    if response.get("type") == "error":
        raise RuntimeError(f"OpenShield rejected request: {response.get('data')!r}")
    return response


def exchange(path: str, request: dict[str, Any]) -> dict[str, Any]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(5.0)
        stream.connect(path)
        _send(stream, request)
        return _receive(stream)


def status() -> dict[str, Any]:
    response = exchange(
        OBSERVE_SOCKET, {"type": "read", "data": {"type": "status_v2"}}
    )
    if response.get("type") != "status_v2" or not isinstance(
        response.get("data"), dict
    ):
        raise RuntimeError(f"unexpected status response: {response!r}")
    data = response["data"]
    if not isinstance(data.get("runtime_compatibility"), dict):
        raise RuntimeError("status-v2 has no runtime compatibility evidence")
    return data


def rules() -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    cursor: str | None = None
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(5.0)
        stream.connect(OBSERVE_SOCKET)
        # The observation protocol requires synchronization through Status
        # before the first rules page on each connection.
        _send(stream, {"type": "read", "data": {"type": "status"}})
        initial = _receive(stream)
        status_data = initial.get("data")
        if initial.get("type") != "status" or not isinstance(status_data, dict):
            raise RuntimeError(f"unexpected initial status response: {initial!r}")
        revision = status_data.get("revision")
        if not isinstance(revision, int):
            raise RuntimeError("initial status has no numeric revision")
        while True:
            _send(
                stream,
                {
                    "type": "read",
                    "data": {
                        "type": "rules_page",
                        "data": {"after": cursor, "limit": 128},
                    },
                },
            )
            response = _receive(stream)
            if response.get("type") != "rules_page":
                raise RuntimeError(f"unexpected rules response: {response!r}")
            page = response.get("data")
            if not isinstance(page, dict) or not isinstance(page.get("rules"), list):
                raise RuntimeError("malformed rules page")
            page_revision = page.get("revision")
            if not isinstance(page_revision, int):
                raise RuntimeError("rules page has no numeric revision")
            if revision != page_revision:
                raise RuntimeError("policy changed while rules were paginated")
            result.extend(page["rules"])
            if len(result) > MAX_RULES:
                raise RuntimeError("daemon returned more rules than the model bound")
            cursor = page.get("next_after")
            if cursor is None:
                return result
            if not isinstance(cursor, str):
                raise RuntimeError("rules page has an invalid cursor")


def control(payload: dict[str, Any]) -> dict[str, Any]:
    response = exchange(CONTROL_SOCKET, {"type": "control", "data": payload})
    if response.get("type") != "ack" or not isinstance(response.get("data"), dict):
        raise RuntimeError(f"unexpected control response: {response!r}")
    return response["data"]


def set_mode(mode: str) -> dict[str, Any]:
    current = status()
    return control(
        {
            "type": "set_mode",
            "data": {"expected_revision": current["revision"], "mode": mode},
        }
    )


def clear_rules() -> int:
    removed = 0
    for rule in rules():
        identifier = rule.get("id")
        if not isinstance(identifier, str):
            raise RuntimeError("rule without a UUID")
        current = status()
        control(
            {
                "type": "delete_rule",
                "data": {
                    "expected_revision": current["revision"],
                    "id": identifier,
                },
            }
        )
        removed += 1
    return removed


def create_rule(arguments: argparse.Namespace) -> dict[str, Any]:
    peer = str(ipaddress.ip_network(arguments.peer, strict=False))
    if not 1 <= arguments.port <= 65_535:
        raise RuntimeError("port is outside 1..65535")
    application = None
    if arguments.application_executable:
        if arguments.direction != "outbound":
            raise RuntimeError("application selectors are outbound-only")
        if not arguments.application_executable.startswith("/"):
            raise RuntimeError("application executable must be absolute")
        application = {
            "executable": arguments.application_executable,
            "executable_file": None,
            "command_line": None,
            "uid": None,
            "cgroup": None,
            "metadata_redacted": False,
        }
    specification = {
        "name": arguments.name,
        "direction": arguments.direction,
        "protocol": arguments.protocol,
        "peer_network": peer,
        "port": {"start": arguments.port, "end": arguments.port},
        "interface": arguments.interface,
        "application": application,
        "origin": "manual",
        "enabled": True,
    }
    current = status()
    return control(
        {
            "type": "create_rule",
            "data": {
                "expected_revision": current["revision"],
                "rule": specification,
            },
        }
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    commands.add_parser("rules")
    commands.add_parser("clear-rules")
    mode = commands.add_parser("set-mode")
    mode.add_argument("mode", choices=("block_all", "learning", "enforcing"))
    create = commands.add_parser("create-rule")
    create.add_argument("--name", required=True)
    create.add_argument("--direction", choices=("inbound", "outbound"), required=True)
    create.add_argument("--protocol", choices=("tcp", "udp"), required=True)
    create.add_argument("--peer", required=True)
    create.add_argument("--port", type=int, required=True)
    create.add_argument("--interface", default="eth0")
    create.add_argument("--application-executable")
    return parser


def main() -> int:
    arguments = build_parser().parse_args()
    if arguments.command == "status":
        output: Any = status()
    elif arguments.command == "rules":
        output = rules()
    elif arguments.command == "clear-rules":
        output = {"removed": clear_rules()}
    elif arguments.command == "set-mode":
        output = set_mode(arguments.mode)
    elif arguments.command == "create-rule":
        output = create_rule(arguments)
    else:
        raise RuntimeError("unknown command")
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(f"openshield-perf-control: {error}", file=sys.stderr)
        raise SystemExit(1)
