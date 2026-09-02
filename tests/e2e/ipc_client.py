#!/usr/bin/env python3
"""Minimal bounded OpenShield IPC client for isolated end-to-end tests."""

import argparse
import json
import socket
import struct
import sys

MAX_FRAME = 64 * 1024
CONTROL = "/run/openshield/control.sock"
OBSERVE = "/run/openshield/observe.sock"


def exchange(path: str, request: dict) -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(5)
        stream.connect(path)
        send_request(stream, request)
        return receive_response(stream)


def send_request(stream: socket.socket, request: dict) -> None:
    payload = json.dumps(request, separators=(",", ":")).encode("utf-8")
    if not payload or len(payload) > MAX_FRAME:
        raise RuntimeError("outbound frame is outside the protocol bound")
    stream.sendall(struct.pack(">I", len(payload)) + payload)


def receive_response(stream: socket.socket) -> dict:
    header = receive_exact(stream, 4)
    size = struct.unpack(">I", header)[0]
    if size == 0 or size > MAX_FRAME:
        raise RuntimeError(f"invalid response frame size {size}")
    response = json.loads(receive_exact(stream, size))
    if not isinstance(response, dict):
        raise RuntimeError("IPC response is not a JSON object")
    return response


def receive_exact(stream: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = stream.recv(size - len(chunks))
        if not chunk:
            raise RuntimeError("truncated IPC response")
        chunks.extend(chunk)
    return bytes(chunks)


def status() -> dict:
    response = exchange(OBSERVE, {"type": "read", "data": {"type": "status"}})
    if response.get("type") != "status":
        raise RuntimeError(f"unexpected status response: {response}")
    return response["data"]


def all_rules() -> list[dict]:
    rules: list[dict] = []
    after = None
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(5)
        stream.connect(OBSERVE)
        send_request(stream, {"type": "read", "data": {"type": "status"}})
        initial = receive_response(stream)
        if initial.get("type") != "status":
            raise RuntimeError(f"unexpected pagination status: {initial}")
        revision = initial["data"]["revision"]
        while True:
            send_request(
                stream,
                {
                    "type": "read",
                    "data": {
                        "type": "rules_page",
                        "data": {"after": after, "limit": 128},
                    },
                },
            )
            response = receive_response(stream)
            if response.get("type") != "rules_page":
                raise RuntimeError(f"unexpected rules response: {response}")
            page = response["data"]
            if revision != page["revision"]:
                raise RuntimeError("policy changed during E2E pagination")
            rules.extend(page["rules"])
            after = page["next_after"]
            if after is None:
                return rules


def control(payload: dict) -> dict:
    response = exchange(CONTROL, {"type": "control", "data": payload})
    if response.get("type") != "ack":
        raise RuntimeError(f"control request failed: {response}")
    return response["data"]


def main() -> int:
    parser = argparse.ArgumentParser()
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("status")
    mode = subcommands.add_parser("set-mode")
    mode.add_argument("mode", choices=("block_all", "learning", "enforcing"))
    inbound = subcommands.add_parser("allow-inbound-tcp")
    inbound.add_argument("port", type=int)
    subcommands.add_parser("rules")
    learned = subcommands.add_parser("assert-learned")
    learned.add_argument("executable")
    learned.add_argument("address")
    learned.add_argument("port", type=int)
    arguments = parser.parse_args()

    if arguments.command == "status":
        print(json.dumps(status(), sort_keys=True))
    elif arguments.command == "rules":
        print(json.dumps(all_rules(), sort_keys=True))
    elif arguments.command == "set-mode":
        current = status()
        print(
            json.dumps(
                control(
                    {
                        "type": "set_mode",
                        "data": {
                            "expected_revision": current["revision"],
                            "mode": arguments.mode,
                        },
                    }
                ),
                sort_keys=True,
            )
        )
    elif arguments.command == "allow-inbound-tcp":
        if not 1 <= arguments.port <= 65535:
            raise RuntimeError("port is outside 1..65535")
        current = status()
        rule = {
            "name": f"E2E inbound TCP {arguments.port}",
            "direction": "inbound",
            "protocol": "tcp",
            "peer_network": None,
            "port": {"start": arguments.port, "end": arguments.port},
            "interface": "eth0",
            "application": None,
            "origin": "manual",
            "enabled": True,
        }
        print(
            json.dumps(
                control(
                    {
                        "type": "create_rule",
                        "data": {"expected_revision": current["revision"], "rule": rule},
                    }
                ),
                sort_keys=True,
            )
        )
    elif arguments.command == "assert-learned":
        for rule in all_rules():
            spec = rule.get("spec", {})
            application = spec.get("application") or {}
            executable_file = application.get("executable_file") or {}
            command_line = application.get("command_line") or {}
            command_arguments = command_line.get("arguments")
            cgroup = application.get("cgroup")
            port = spec.get("port") or {}
            if (
                spec.get("origin") == "learned"
                and application.get("executable") == arguments.executable
                and application.get("uid") is not None
                and application.get("metadata_redacted") is False
                and all(
                    field in executable_file
                    for field in (
                        "device",
                        "inode",
                        "size",
                        "ctime_seconds",
                        "ctime_nanoseconds",
                    )
                )
                and command_line.get("kind") == "exact"
                and isinstance(command_arguments, list)
                and len(command_arguments) > 0
                and (cgroup is None or (isinstance(cgroup, str) and cgroup.startswith("/")))
                and spec.get("peer_network") in (arguments.address, f"{arguments.address}/32")
                and port.get("start") == arguments.port
                and port.get("end") == arguments.port
            ):
                return 0
        raise RuntimeError("expected learned application rule was not found")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(f"openshield-e2e-client: {error}", file=sys.stderr)
        raise SystemExit(1)
