#!/usr/bin/env python3
"""Shared bounded runtime, rate limiting, and JSONL metrics helpers."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import ipaddress
import json
import math
import os
import random
import selectors
import signal
import socket
import stat
import sys
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple


SCHEMA = "openshield.perf.workload.v1"
CONTROL_PROTOCOL = "stdin_start_finish_release_v2"
CONTROL_TIMEOUT_SECONDS = 120.0
MAX_CONTROL_COMMAND_BYTES = 16
MAX_DURATION_SECONDS = 3_600.0
MAX_CONCURRENCY = 512
# A TCP client can briefly have a replacement connection accepted before the
# server worker serving its just-closed predecessor observes EOF.  Keep enough
# bounded worker capacity for two slots per maximum client flow so the peer is
# not the bottleneck during connection churn.
MAX_SERVER_WORKERS = MAX_CONCURRENCY * 2
MAX_OPERATIONS = 10_000_000
MAX_PPS = 1_000_000.0
MAX_CPS = 100_000.0
MAX_MBPS = 100_000.0
MAX_TCP_BODY_BYTES = 8 * 1024 * 1024
MAX_UDP_BODY_BYTES = 60_000
MAX_MIX_ENTRIES = 32
MAX_MIX_WEIGHT = 1_000_000
MAX_LATENCY_SAMPLES = 100_000
MAX_TIMEOUT_SECONDS = 60.0
MAX_CONFIG_BYTES = 64 * 1024
MAX_PATH_BYTES = 4_096
MAX_INFLIGHT_MEMORY_BYTES = 512 * 1024 * 1024


def bounded_int(name: str, minimum: int, maximum: int):
    """Return an argparse converter enforcing a closed integer interval."""

    def convert(value: str) -> int:
        try:
            parsed = int(value, 10)
        except ValueError as error:
            raise argparse.ArgumentTypeError(f"{name} must be an integer") from error
        if not minimum <= parsed <= maximum:
            raise argparse.ArgumentTypeError(
                f"{name} must be between {minimum} and {maximum}"
            )
        return parsed

    return convert


def bounded_float(name: str, minimum: float, maximum: float):
    """Return an argparse converter enforcing a finite closed float interval."""

    def convert(value: str) -> float:
        try:
            parsed = float(value)
        except ValueError as error:
            raise argparse.ArgumentTypeError(f"{name} must be a number") from error
        if not math.isfinite(parsed) or not minimum <= parsed <= maximum:
            raise argparse.ArgumentTypeError(
                f"{name} must be between {minimum:g} and {maximum:g}"
            )
        return parsed

    return convert


def numeric_ip(value: str) -> str:
    """Accept only canonicalizable numeric IPv4/IPv6 addresses, never DNS names."""

    candidate = value[1:-1] if value.startswith("[") and value.endswith("]") else value
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError as error:
        raise argparse.ArgumentTypeError("host must be a numeric IPv4 or IPv6 address") from error


def socket_address(host: str, port: int) -> Tuple[int, tuple]:
    """Return an address family and bind/connect tuple for a validated numeric IP."""

    address = ipaddress.ip_address(host)
    if address.version == 4:
        return socket.AF_INET, (str(address), port)
    return socket.AF_INET6, (str(address), port, 0, 0)


def require_safe_bind(host: str, allow_non_loopback: bool) -> None:
    """Refuse accidental exposure outside loopback unless explicitly authorized."""

    address = ipaddress.ip_address(host)
    if not address.is_loopback and not allow_non_loopback:
        raise ValueError(
            "non-loopback bind requires the explicit --allow-non-loopback option"
        )


@dataclass(frozen=True)
class WeightedValue:
    value: int
    weight: int


class WeightedMix:
    """A validated integer weighted distribution with deterministic selection."""

    def __init__(self, entries: Sequence[WeightedValue]):
        if not entries or len(entries) > MAX_MIX_ENTRIES:
            raise ValueError(f"response mix must contain 1..{MAX_MIX_ENTRIES} entries")
        total = 0
        normalized: List[WeightedValue] = []
        seen = set()
        for entry in entries:
            if not 0 <= entry.value <= MAX_TCP_BODY_BYTES:
                raise ValueError("response size is outside the global safety bound")
            if entry.value in seen:
                raise ValueError("response sizes must be unique")
            if not 1 <= entry.weight <= MAX_MIX_WEIGHT:
                raise ValueError(f"response weight must be 1..{MAX_MIX_WEIGHT}")
            seen.add(entry.value)
            total += entry.weight
            if total > MAX_MIX_ENTRIES * MAX_MIX_WEIGHT:
                raise ValueError("response weight total is too large")
            normalized.append(entry)
        self.entries = tuple(normalized)
        self.total_weight = total
        self.maximum_value = max(entry.value for entry in normalized)

    @classmethod
    def fixed(cls, value: int) -> "WeightedMix":
        return cls((WeightedValue(value, 1),))

    def choose(self, generator: random.Random) -> int:
        ticket = generator.randrange(self.total_weight)
        cumulative = 0
        for entry in self.entries:
            cumulative += entry.weight
            if ticket < cumulative:
                return entry.value
        raise AssertionError("validated weighted mix did not select an entry")

    def as_json(self, value_key: str = "bytes") -> List[dict]:
        return [
            {value_key: entry.value, "weight": entry.weight}
            for entry in self.entries
        ]

    def weighted_mean(self) -> float:
        return sum(
            entry.value * entry.weight for entry in self.entries
        ) / self.total_weight


def parse_bounded_weighted_mix(
    value: str,
    minimum_value: int,
    maximum_value: int,
    value_name: str,
) -> WeightedMix:
    """Parse a bounded `VALUE:WEIGHT,...` integer distribution."""

    if (
        isinstance(minimum_value, bool)
        or not isinstance(minimum_value, int)
        or isinstance(maximum_value, bool)
        or not isinstance(maximum_value, int)
        or minimum_value < 0
        or maximum_value < minimum_value
        or maximum_value > MAX_TCP_BODY_BYTES
    ):
        raise ValueError("weighted mix bounds are invalid")
    if not value_name or len(value_name) > 64:
        raise ValueError("weighted mix value name is invalid")

    if not value or len(value) > 1_024:
        raise argparse.ArgumentTypeError("weighted mix is empty or too long")
    entries: List[WeightedValue] = []
    seen = set()
    for raw_entry in value.split(","):
        if raw_entry.count(":") != 1:
            raise argparse.ArgumentTypeError(
                "weighted mix entries must use VALUE:WEIGHT"
            )
        raw_value, raw_weight = raw_entry.split(":", 1)
        if not raw_value.isascii() or not raw_value.isdecimal():
            raise argparse.ArgumentTypeError(
                f"{value_name} must be a decimal integer"
            )
        if not raw_weight.isascii() or not raw_weight.isdecimal():
            raise argparse.ArgumentTypeError("mix weight must be a decimal integer")
        parsed_value = int(raw_value, 10)
        weight = int(raw_weight, 10)
        if not minimum_value <= parsed_value <= maximum_value:
            raise argparse.ArgumentTypeError(
                f"{value_name} must be between {minimum_value} and {maximum_value}"
            )
        if not 1 <= weight <= MAX_MIX_WEIGHT:
            raise argparse.ArgumentTypeError(
                f"mix weight must be between 1 and {MAX_MIX_WEIGHT}"
            )
        if parsed_value in seen:
            raise argparse.ArgumentTypeError(f"{value_name} values must be unique")
        seen.add(parsed_value)
        entries.append(WeightedValue(parsed_value, weight))
    try:
        return WeightedMix(entries)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def parse_weighted_mix(value: str, maximum_size: int) -> WeightedMix:
    """Parse a response-size mix without accepting ambiguous entries."""

    return parse_bounded_weighted_mix(value, 0, maximum_size, "response size")


def mix_converter(maximum_size: int):
    return lambda value: parse_weighted_mix(value, maximum_size)


def bounded_mix_converter(
    minimum_value: int, maximum_value: int, value_name: str
):
    return lambda value: parse_bounded_weighted_mix(
        value, minimum_value, maximum_value, value_name
    )


def deterministic_payload(size: int, seed: int, stream_id: int) -> bytes:
    """Build a reproducible bounded payload without global random state."""

    if size < 0 or size > MAX_TCP_BODY_BYTES:
        raise ValueError("payload size is outside the global safety bound")
    if size == 0:
        return b""
    digest = hashlib.sha256(f"{seed}:{stream_id}".encode("ascii")).digest()
    repetitions = (size + len(digest) - 1) // len(digest)
    return (digest * repetitions)[:size]


def recv_exact(connection: socket.socket, size: int) -> bytes:
    """Read exactly `size` bytes or raise ConnectionError on a short stream."""

    if size < 0 or size > MAX_TCP_BODY_BYTES + 256:
        raise ValueError("stream read exceeds the bounded protocol frame")
    chunks: List[bytes] = []
    remaining = size
    while remaining:
        chunk = connection.recv(min(remaining, 64 * 1024))
        if not chunk:
            raise ConnectionError("peer closed the stream before the frame completed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class SampleReservoir:
    """Thread-safe, fixed-memory Algorithm-R sample with exact extrema and mean."""

    def __init__(self, capacity: int, seed: int):
        if not 1 <= capacity <= MAX_LATENCY_SAMPLES:
            raise ValueError("sample capacity is outside the safety bound")
        self._capacity = capacity
        self._values: List[float] = []
        self._count = 0
        self._sum = 0.0
        self._minimum = math.inf
        self._maximum = 0.0
        self._random = random.Random(seed)
        self._lock = threading.Lock()

    def record(self, value: float) -> None:
        if not math.isfinite(value) or value < 0:
            return
        with self._lock:
            self._count += 1
            self._sum += value
            self._minimum = min(self._minimum, value)
            self._maximum = max(self._maximum, value)
            if len(self._values) < self._capacity:
                self._values.append(value)
                return
            replacement = self._random.randrange(self._count)
            if replacement < self._capacity:
                self._values[replacement] = value

    def snapshot(self) -> dict:
        with self._lock:
            count = self._count
            total = self._sum
            minimum = self._minimum
            maximum = self._maximum
            values = sorted(self._values)
        if count == 0:
            return {
                "count": 0,
                "sampled": 0,
                "min": None,
                "mean": None,
                "p50": None,
                "p95": None,
                "p99": None,
                "max": None,
            }

        def percentile(fraction: float) -> float:
            index = int(math.ceil(fraction * len(values))) - 1
            return values[max(0, min(index, len(values) - 1))]

        return {
            "count": count,
            "sampled": len(values),
            "min": round(minimum, 6),
            "mean": round(total / count, 6),
            "p50": round(percentile(0.50), 6),
            "p95": round(percentile(0.95), 6),
            "p99": round(percentile(0.99), 6),
            "max": round(maximum, 6),
        }


class WorkloadStats:
    """Bounded thread-safe counters and process saturation measurements."""

    def __init__(self, seed: int, sample_capacity: int = 20_000):
        self.wall_started = time.monotonic()
        self.cpu_started = time.process_time()
        self.latency_ms = SampleReservoir(sample_capacity, seed ^ 0xA5A5A5A5)
        self.connect_latency_ms = SampleReservoir(sample_capacity, seed ^ 0xC3C3C3C3)
        self.scheduler_lag_ms = SampleReservoir(sample_capacity, seed ^ 0x5A5A5A5A)
        self._counters: MutableMapping[str, int] = defaultdict(int)
        self._lock = threading.Lock()
        self._active_current = 0
        self._active_peak = 0
        self._active_integral = 0.0
        self._active_updated = self.wall_started

    def arm(self) -> int:
        """Start accounting immediately before the controller releases load."""

        with self._lock:
            if (
                any(self._counters.values())
                or self._active_current
                or self._active_integral
            ):
                raise RuntimeError("workload statistics cannot be re-armed after use")
            self.wall_started = time.monotonic()
            self.cpu_started = time.process_time()
            self._active_updated = self.wall_started
        return time.monotonic_ns()

    def add(self, **values: int) -> None:
        with self._lock:
            for name, value in values.items():
                self._counters[name] += int(value)

    def counter(self, name: str) -> int:
        with self._lock:
            return self._counters.get(name, 0)

    def active_change(self, delta: int) -> None:
        """Update the live-flow gauge and its time integral atomically."""

        now = time.monotonic()
        with self._lock:
            self._active_integral += self._active_current * (now - self._active_updated)
            self._active_updated = now
            updated = self._active_current + delta
            if updated < 0:
                raise ValueError("active flow gauge cannot become negative")
            self._active_current = updated
            self._active_peak = max(self._active_peak, updated)

    def summary(self) -> dict:
        now = time.monotonic()
        wall_seconds = max(now - self.wall_started, 1e-9)
        cpu_seconds = max(time.process_time() - self.cpu_started, 0.0)
        with self._lock:
            self._active_integral += self._active_current * (now - self._active_updated)
            self._active_updated = now
            counters = dict(sorted(self._counters.items()))
            active_current = self._active_current
            active_peak = self._active_peak
            active_mean = self._active_integral / wall_seconds
        # Emit mandatory integrity/accounting counters explicitly. Absence is
        # not interchangeable with a measured zero in the harness/report.
        for name in (
            "errors",
            "connections_rejected",
            "protocol_errors",
            "internal_errors",
            "operations",
            "packets_received",
            "barriers_expected",
            "barriers_sent",
            "barrier_acks_received",
            "barrier_errors",
            "barriers_received",
            "barrier_acks_sent",
        ):
            counters.setdefault(name, 0)
        bytes_total = counters.get("bytes_sent", 0) + counters.get("bytes_received", 0)
        operations = counters.get("operations", counters.get("packets_sent", 0))
        connections = counters.get("connections", 0)
        result = {
            "wall_seconds": round(wall_seconds, 6),
            "process_cpu_seconds": round(cpu_seconds, 6),
            "wall_cpu_ratio": round(cpu_seconds / wall_seconds, 6),
            "process_thread_count_end": self._process_thread_count(),
            "application_ops_per_second": round(operations / wall_seconds, 6),
            "actual_cps": round(connections / wall_seconds, 6),
            "actual_mbps": round(bytes_total * 8.0 / wall_seconds / 1_000_000.0, 6),
            "application_mbps": round(
                bytes_total * 8.0 / wall_seconds / 1_000_000.0, 6
            ),
            "latency_ms": self.latency_ms.snapshot(),
            "connect_latency_ms": self.connect_latency_ms.snapshot(),
            "scheduler_lag_ms": self.scheduler_lag_ms.snapshot(),
            "active_flows_current": active_current,
            "active_flows_peak": active_peak,
            "active_flows_time_weighted_mean": round(active_mean, 6),
        }
        result.update(counters)
        return result

    @staticmethod
    def _process_thread_count() -> int:
        try:
            return len(os.listdir("/proc/self/task"))
        except OSError:
            return threading.active_count()


class MultiRateLimiter:
    """One aggregate, burst-free limiter for simultaneous PPS/CPS/byte caps."""

    def __init__(self, rates: Mapping[str, float], lag_samples: SampleReservoir):
        self._rates: Dict[str, float] = {
            name: float(rate) for name, rate in rates.items() if rate > 0
        }
        now = time.monotonic()
        self._next: Dict[str, float] = {name: now for name in self._rates}
        self._lag_samples = lag_samples
        self._lock = threading.Lock()

    def acquire(
        self,
        costs: Mapping[str, float],
        stop: threading.Event,
        deadline: float,
    ) -> bool:
        if stop.is_set():
            return False
        with self._lock:
            now = time.monotonic()
            scheduled = now
            for name in self._rates:
                if costs.get(name, 0.0) > 0:
                    scheduled = max(scheduled, self._next[name])
            beyond_deadline = scheduled >= deadline
            if not beyond_deadline:
                for name, rate in self._rates.items():
                    cost = max(0.0, float(costs.get(name, 0.0)))
                    if cost > 0:
                        self._next[name] = scheduled + cost / rate
        if beyond_deadline:
            stop.wait(max(0.0, deadline - time.monotonic()))
            return False
        delay = scheduled - time.monotonic()
        if delay > 0 and stop.wait(min(delay, max(0.0, deadline - time.monotonic()))):
            return False
        if stop.is_set() or time.monotonic() >= deadline:
            return False
        self._lag_samples.record(max(0.0, time.monotonic() - scheduled) * 1_000.0)
        return True


class AsyncMultiRateLimiter:
    """Single-event-loop equivalent of MultiRateLimiter for socket concurrency."""

    def __init__(self, rates: Mapping[str, float], lag_samples: SampleReservoir):
        self._rates: Dict[str, float] = {
            name: float(rate) for name, rate in rates.items() if rate > 0
        }
        now = time.monotonic()
        self._next: Dict[str, float] = {name: now for name in self._rates}
        self._lag_samples = lag_samples
        self._lock = asyncio.Lock()

    def arm(self) -> None:
        """Discard pre-start idle time without changing configured rate limits."""

        now = time.monotonic()
        self._next = {name: now for name in self._rates}

    async def acquire(
        self,
        costs: Mapping[str, float],
        stop: threading.Event,
        deadline: float,
    ) -> bool:
        if stop.is_set():
            return False
        async with self._lock:
            now = time.monotonic()
            scheduled = now
            for name in self._rates:
                if costs.get(name, 0.0) > 0:
                    scheduled = max(scheduled, self._next[name])
            beyond_deadline = scheduled >= deadline
            if not beyond_deadline:
                for name, rate in self._rates.items():
                    cost = max(0.0, float(costs.get(name, 0.0)))
                    if cost > 0:
                        self._next[name] = scheduled + cost / rate
        if beyond_deadline:
            while not stop.is_set():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                await asyncio.sleep(min(remaining, 0.1))
            return False
        while not stop.is_set():
            remaining = scheduled - time.monotonic()
            if remaining <= 0:
                break
            if time.monotonic() >= deadline:
                return False
            await asyncio.sleep(min(remaining, 0.1))
        if stop.is_set() or time.monotonic() >= deadline:
            return False
        self._lag_samples.record(max(0.0, time.monotonic() - scheduled) * 1_000.0)
        return True


class WorkBudget:
    """Atomic optional operation cap shared by all workload workers."""

    def __init__(self, maximum: int):
        self.maximum = maximum
        self._claimed = 0
        self._lock = threading.Lock()

    def claim(self) -> bool:
        with self._lock:
            if self.maximum and self._claimed >= self.maximum:
                return False
            self._claimed += 1
            return True


def install_stop_handlers(
    stop: threading.Event, *additional_stops: threading.Event
) -> None:
    """Translate SIGINT/SIGTERM into cooperative shutdown in the main process."""

    def request_stop(_signum, _frame) -> None:
        stop.set()
        for additional in additional_stops:
            additional.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)


def emit_json(event: str, **fields) -> dict:
    document = {"schema": SCHEMA, "event": event}
    document.update(fields)
    print(json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False), flush=True)
    return document


def canonical_document_sha256(document: Mapping[str, object]) -> str:
    payload = json.dumps(
        document, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def process_identity() -> dict:
    """Return the minimum immutable identity needed for PID-reuse-safe control."""

    pid = os.getpid()
    with open(f"/proc/{pid}/stat", "r", encoding="ascii") as stat_file:
        stat_text = stat_file.read(4096)
    closing = stat_text.rfind(")")
    fields = stat_text[closing + 2 :].split() if closing >= 0 else []
    if len(fields) <= 19:
        raise RuntimeError("cannot read workload process starttime")
    starttime = int(fields[19], 10)
    executable = os.readlink(f"/proc/{pid}/exe")
    if starttime <= 0 or not executable.startswith("/"):
        raise RuntimeError("workload process identity is invalid")
    return {
        "pid": pid,
        "starttime": starttime,
        "executable": executable,
        "uid": os.getuid(),
    }


def announce_control_process(enabled: bool, transport: str) -> dict | None:
    """Publish identity before bounded client preparation can begin."""

    if not enabled:
        return None
    identity = process_identity()
    emit_json(
        "spawned",
        role="client",
        transport=transport,
        control_protocol=CONTROL_PROTOCOL,
        boundary_monotonic_ns=time.monotonic_ns(),
        **identity,
    )
    return identity


def base_client_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--host", type=numeric_ip, default="127.0.0.1")
    parser.add_argument("--port", type=bounded_int("port", 1, 65_535))
    parser.add_argument(
        "--config-file",
        type=config_path,
        help="trusted fixed JSON file whose allowlisted values override CLI defaults",
    )
    parser.add_argument(
        "--duration",
        type=bounded_float("duration", 0.1, MAX_DURATION_SECONDS),
        default=10.0,
    )
    parser.add_argument(
        "--operations",
        type=bounded_int("operations", 0, MAX_OPERATIONS),
        default=0,
        help="global operation cap; zero uses only the duration bound",
    )
    parser.add_argument("--seed", type=bounded_int("seed", 0, 2**63 - 1), default=1)
    parser.add_argument(
        "--pps",
        type=bounded_float("pps", 0.0, MAX_PPS),
        default=100.0,
        help="approximate aggregate packet-rate cap; zero disables this cap",
    )
    parser.add_argument(
        "--mbps",
        type=bounded_float("mbps", 0.0, MAX_MBPS),
        default=0.0,
        help="aggregate application-byte rate cap in Mbit/s; zero disables it",
    )
    parser.add_argument(
        "--io-timeout",
        type=bounded_float("io-timeout", 0.05, MAX_TIMEOUT_SECONDS),
        default=2.0,
    )
    parser.add_argument(
        "--latency-samples",
        type=bounded_int("latency-samples", 1, MAX_LATENCY_SAMPLES),
        default=20_000,
    )
    parser.add_argument(
        "--start-gate-stdin",
        action="store_true",
        help=(
            "emit a client-ready event after configuration validation and wait "
            "for one exact 'start' line on stdin"
        ),
    )


def wait_for_start_gate(
    enabled: bool,
    control_stop: threading.Event,
    transport: str,
    on_start=None,
    identity: Mapping[str, object] | None = None,
    timeout: float = CONTROL_TIMEOUT_SECONDS,
) -> dict | None:
    """Synchronize a prepared client with a bounded external load controller."""

    if not enabled:
        if on_start is not None:
            on_start()
        return None
    identity = dict(identity) if identity is not None else process_identity()
    emit_json(
        "ready",
        role="client",
        transport=transport,
        control_protocol=CONTROL_PROTOCOL,
        **identity,
    )
    selector = selectors.DefaultSelector()
    input_fd = sys.stdin.fileno()
    selector.register(input_fd, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    buffered = bytearray()
    try:
        while not control_stop.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("client start gate timed out")
            if not selector.select(min(0.2, remaining)):
                continue
            chunk = os.read(input_fd, MAX_CONTROL_COMMAND_BYTES + 1)
            if not chunk:
                raise RuntimeError("client start gate closed before start")
            buffered.extend(chunk)
            if len(buffered) > MAX_CONTROL_COMMAND_BYTES:
                raise RuntimeError("client start gate command exceeded its bound")
            if b"\n" not in buffered:
                continue
            if bytes(buffered) != b"start\n":
                raise RuntimeError("client start gate expected one exact start line")
            if on_start is not None:
                on_start()
            started = {
                **identity,
                "role": "client",
                "transport": transport,
                "control_protocol": CONTROL_PROTOCOL,
                "boundary_monotonic_ns": time.monotonic_ns(),
            }
            emit_json("started", **started)
            return {"schema": SCHEMA, "event": "started", **started}
    finally:
        selector.close()
    raise RuntimeError("client start gate was interrupted")


def wait_for_release_gate(
    enabled: bool,
    control_stop: threading.Event,
    transport: str,
    summary_document: Mapping[str, object],
    exit_code: int,
    timeout: float = CONTROL_TIMEOUT_SECONDS,
) -> dict | None:
    """Publish terminal evidence and keep `/proc` accounting live until release."""

    if not enabled:
        return None
    identity = process_identity()
    finished = {
        **identity,
        "role": "client",
        "transport": transport,
        "control_protocol": CONTROL_PROTOCOL,
        "boundary_monotonic_ns": time.monotonic_ns(),
        "summary_sha256": canonical_document_sha256(summary_document),
        "exit_code": exit_code,
        "hold": "awaiting_release",
    }
    emit_json("finished", **finished)
    selector = selectors.DefaultSelector()
    input_fd = sys.stdin.fileno()
    selector.register(input_fd, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    buffered = bytearray()
    try:
        while not control_stop.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("client release gate timed out")
            if not selector.select(min(0.2, remaining)):
                continue
            chunk = os.read(input_fd, MAX_CONTROL_COMMAND_BYTES + 1)
            if not chunk:
                raise RuntimeError("client release gate closed before release")
            buffered.extend(chunk)
            if len(buffered) > MAX_CONTROL_COMMAND_BYTES:
                raise RuntimeError("client release gate command exceeded its bound")
            if b"\n" not in buffered:
                continue
            if bytes(buffered) != b"release\n":
                raise RuntimeError("client release gate expected one exact release line")
            released = {
                **identity,
                "role": "client",
                "transport": transport,
                "control_protocol": CONTROL_PROTOCOL,
                "boundary_monotonic_ns": time.monotonic_ns(),
            }
            emit_json("released", **released)
            return {"schema": SCHEMA, "event": "released", **released}
    finally:
        selector.close()
    raise RuntimeError("client release gate was interrupted")


def base_server_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--bind", type=numeric_ip, default="127.0.0.1")
    parser.add_argument("--port", type=bounded_int("port", 0, 65_535), default=0)
    parser.add_argument("--allow-non-loopback", action="store_true")
    parser.add_argument(
        "--duration",
        type=bounded_float("duration", 0.1, MAX_DURATION_SECONDS),
        default=30.0,
    )
    parser.add_argument("--seed", type=bounded_int("seed", 0, 2**63 - 1), default=1)
    parser.add_argument(
        "--io-timeout",
        type=bounded_float("io-timeout", 0.05, MAX_TIMEOUT_SECONDS),
        default=2.0,
    )
    parser.add_argument(
        "--processing-delay-ms",
        type=bounded_float("processing-delay-ms", 0.0, 60_000.0),
        default=0.0,
    )


def endpoint_port(sock: socket.socket) -> int:
    return int(sock.getsockname()[1])


def safe_error(error: BaseException, maximum: int = 512) -> str:
    """Return bounded, single-line error text suitable for JSON diagnostics."""

    text = str(error).replace("\n", " ").replace("\r", " ")
    return "".join(character if character.isprintable() else " " for character in text)[:maximum]


def config_path(value: str) -> str:
    if (
        not value
        or len(value.encode("utf-8")) > MAX_PATH_BYTES
        or not os.path.isabs(value)
    ):
        raise argparse.ArgumentTypeError("config-file must be a bounded absolute path")
    return value


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate config key: {key}")
        result[key] = value
    return result


def load_trusted_config(path: str) -> dict:
    """Read one owner-controlled regular JSON file through a no-follow descriptor."""

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid not in (0, os.geteuid())
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o022
            or not 0 < metadata.st_size <= MAX_CONFIG_BYTES
        ):
            raise ValueError(
                "config-file must be a nonempty, singly linked, owner-controlled regular file"
            )
        encoded = bytearray()
        while len(encoded) <= MAX_CONFIG_BYTES:
            chunk = os.read(
                descriptor, min(16 * 1024, MAX_CONFIG_BYTES + 1 - len(encoded))
            )
            if not chunk:
                break
            encoded.extend(chunk)
        if len(encoded) > MAX_CONFIG_BYTES:
            raise ValueError("config-file exceeds the bounded size")
    finally:
        os.close(descriptor)
    try:
        document = json.loads(encoded.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"config-file is not valid UTF-8 JSON: {error}") from error
    if not isinstance(document, dict):
        raise ValueError("config-file root must be an object")
    return document


def apply_config_file(
    arguments: argparse.Namespace,
    parser: argparse.ArgumentParser,
    allowed_fields: Sequence[str],
) -> argparse.Namespace:
    """Apply allowlisted JSON fields through the same argparse validators as CLI values."""

    if not arguments.config_file:
        return arguments
    document = load_trusted_config(arguments.config_file)
    allowed = set(allowed_fields)
    action_by_destination = {}

    def collect_actions(current: argparse.ArgumentParser) -> None:
        for action in current._actions:
            action_by_destination[action.dest] = action
            if isinstance(action, argparse._SubParsersAction):
                for child in action.choices.values():
                    collect_actions(child)

    collect_actions(parser)
    for field, raw_value in document.items():
        if field not in allowed:
            raise ValueError(f"unknown or forbidden config field: {field}")
        action = action_by_destination.get(field)
        if action is None or isinstance(raw_value, (dict, list, bool)):
            raise ValueError(f"config field has unsupported type: {field}")
        try:
            converter = action.type or str
            value = converter(str(raw_value))
        except (ValueError, TypeError, argparse.ArgumentTypeError) as error:
            raise ValueError(f"invalid config field {field}: {error}") from error
        if action.choices is not None and value not in action.choices:
            raise ValueError(f"invalid config choice for {field}")
        setattr(arguments, field, value)
    return arguments


def wait_for_threads(
    threads: Iterable[threading.Thread], stop: threading.Event, timeout: float
) -> None:
    deadline = time.monotonic() + timeout
    for thread in threads:
        thread.join(max(0.0, deadline - time.monotonic()))
    stop.set()
    for thread in threads:
        if thread.is_alive():
            thread.join(0.1)
