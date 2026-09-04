#!/usr/bin/env python3
"""Collect one bounded metric window from an OpenShield DUT namespace."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import selectors
import sys
import time
from typing import Any, TextIO


QUEUE_NUMBER = 1_337
CONTROL_SCHEMA = "openshield.perf.metrics.control.v1"
U32_MODULUS = 1 << 32
MAX_DURATION_SECONDS = 3_600.0
MIN_INTERVAL_SECONDS = 0.02
INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_.:-]{0,14})$")
MAX_COUNTER_VALUE = (1 << 64) - 1


def read_int(path: Path) -> int | None:
    try:
        value = int(path.read_text(encoding="ascii").strip())
    except (OSError, UnicodeError, ValueError):
        return None
    return value if value >= 0 else None


def read_named_int(path: Path, name: str) -> int | None:
    """Read one non-negative, unique counter from a bounded key/value file."""

    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError):
        return None
    values: list[int] = []
    for line in lines:
        fields = line.split()
        if len(fields) != 2 or fields[0] != name:
            continue
        try:
            value = int(fields[1], 10)
        except ValueError:
            return None
        if not 0 <= value <= MAX_COUNTER_VALUE:
            return None
        values.append(value)
    return values[0] if len(values) == 1 else None


def safe_cgroup_relative_path(value: str) -> Path | None:
    """Convert a kernel-provided cgroup path without permitting traversal."""

    if not value.startswith("/") or len(value) > 4_096 or "\x00" in value:
        return None
    parts = PurePosixPath(value).parts[1:]
    if any(part in {"", ".", ".."} for part in parts):
        return None
    return Path(*parts)


def cgroup_cpu_usage(
    cgroup_root: Path = Path("/sys/fs/cgroup"),
    proc_cgroup: Path = Path("/proc/self/cgroup"),
) -> dict[str, Any] | None:
    """Read this container's CPU usage from cgroup v2 or a safe v1 fallback.

    Docker normally exposes the container cgroup as the cgroup filesystem root.
    Older cgroup-v1 hosts can instead expose a controller hierarchy plus the
    process-relative cgroup path.  Only controller names and traversal-free
    paths supplied by the kernel are considered.
    """

    usage_usec = read_named_int(cgroup_root / "cpu.stat", "usage_usec")
    if usage_usec is not None:
        return {
            "usage_seconds": usage_usec / 1_000_000.0,
            "source": "cgroup-v2/cpu.stat:usage_usec",
        }

    candidates: list[Path] = []
    try:
        lines = proc_cgroup.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError):
        lines = []
    for line in lines:
        fields = line.split(":", 2)
        if len(fields) != 3:
            continue
        controllers = fields[1].split(",")
        if "cpuacct" not in controllers or any(
            not controller.isascii()
            or not controller
            or not controller.replace("_", "").isalnum()
            for controller in controllers
        ):
            continue
        relative = safe_cgroup_relative_path(fields[2])
        if relative is None:
            continue
        controller_names = [
            fields[1],
            ",".join(sorted(controllers)),
            "cpuacct",
            "cpu",
        ]
        for controller_name in controller_names:
            candidates.append(
                cgroup_root / controller_name / relative / "cpuacct.usage"
            )
        candidates.append(cgroup_root / relative / "cpuacct.usage")

    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        usage_nsec = read_int(candidate)
        if usage_nsec is None or usage_nsec > MAX_COUNTER_VALUE:
            continue
        return {
            "usage_seconds": usage_nsec / 1_000_000_000.0,
            "source": (
                "cgroup-v1/cpuacct.usage:"
                + candidate.relative_to(cgroup_root).as_posix()
            ),
        }
    return None


def process_cpu_ticks(pid: int) -> int | None:
    if pid <= 0:
        return None
    try:
        value = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except OSError:
        return None
    close = value.rfind(")")
    if close < 0:
        return None
    fields = value[close + 2 :].split()
    try:
        # fields starts at proc(5) field 3; utime/stime are fields 14 and 15.
        return int(fields[11]) + int(fields[12])
    except (IndexError, ValueError):
        return None


def process_rss_bytes(pid: int) -> int | None:
    if pid <= 0:
        return None
    try:
        lines = Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in lines:
        if line.startswith("VmRSS:"):
            fields = line.split()
            try:
                return int(fields[1]) * 1_024
            except (IndexError, ValueError):
                return None
    return None


def softirq_totals() -> dict[str, int | None]:
    # An unavailable or malformed procfs counter is not an observed zero.
    # Keeping the sentinel lets the harness invalidate incomplete evidence.
    result: dict[str, int | None] = {"net_rx": None, "net_tx": None}
    try:
        lines = Path("/proc/softirqs").read_text(encoding="ascii").splitlines()
    except OSError:
        return result
    names = {"NET_RX": "net_rx", "NET_TX": "net_tx"}
    for line in lines:
        label, separator, values = line.partition(":")
        target = names.get(label.strip())
        if not separator or target is None:
            continue
        try:
            result[target] = sum(int(value) for value in values.split())
        except ValueError:
            result[target] = None
    return result


def protocol_counters(
    path: Path, section: str, requested: tuple[str, ...]
) -> dict[str, int | None]:
    result: dict[str, int | None] = {name: None for name in requested}
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except OSError:
        return result
    marker = f"{section}:"
    for index in range(len(lines) - 1):
        if not lines[index].startswith(marker) or not lines[index + 1].startswith(marker):
            continue
        names = lines[index].split()[1:]
        values = lines[index + 1].split()[1:]
        try:
            counters = dict(zip(names, values, strict=True))
        except ValueError:
            return result
        for name in requested:
            try:
                value = int(counters[name])
            except (KeyError, ValueError):
                continue
            result[name] = value if value >= 0 else None
        return result
    return result


def transport_counters() -> dict[str, Any]:
    snmp = Path("/proc/net/snmp")
    netstat = Path("/proc/net/netstat")
    return {
        "tcp": protocol_counters(snmp, "Tcp", ("RetransSegs",)),
        "udp": protocol_counters(
            snmp, "Udp", ("InErrors", "RcvbufErrors", "SndbufErrors")
        ),
        "tcp_ext": protocol_counters(
            netstat, "TcpExt", ("ListenDrops", "ListenOverflows")
        ),
    }


def interface_counters(interface: str) -> dict[str, int | None]:
    root = Path("/sys/class/net") / interface / "statistics"
    return {
        name: read_int(root / name)
        for name in (
            "rx_packets",
            "tx_packets",
            "rx_bytes",
            "tx_bytes",
            "rx_dropped",
            "tx_dropped",
            "rx_errors",
            "tx_errors",
        )
    }


def nfqueue_counters(queue_number: int = QUEUE_NUMBER) -> dict[str, int | None]:
    result: dict[str, int | None] = {
        "depth": None,
        "copy_mode": None,
        "copy_range": None,
        "kernel_dropped": None,
        "user_dropped": None,
        "sequence": None,
    }
    try:
        lines = Path("/proc/net/netfilter/nfnetlink_queue").read_text(
            encoding="ascii"
        ).splitlines()
    except OSError:
        return result
    for line in lines:
        fields = line.split()
        if len(fields) < 9:
            continue
        try:
            if int(fields[0]) != queue_number:
                continue
            values = [int(value) for value in fields[:9]]
        except ValueError:
            continue
        result.update(
            {
                "depth": values[2],
                "copy_mode": values[3],
                "copy_range": values[4],
                "kernel_dropped": values[5],
                "user_dropped": values[6],
                "sequence": values[7],
            }
        )
        return result
    return result


def counter_delta(before: int | None, after: int | None) -> int | None:
    if before is None or after is None:
        return None
    if after >= before:
        return after - before
    return (after - before) % U32_MODULUS


def ordinary_delta(before: int | None, after: int | None) -> int | None:
    if before is None or after is None or after < before:
        return None
    return after - before


def counter_group_delta(
    before: dict[str, int | None], after: dict[str, int | None]
) -> dict[str, int | None]:
    return {
        name: ordinary_delta(before.get(name), after.get(name)) for name in before
    }


def cgroup_cpu_delta(
    before: Any, after: Any, elapsed: float
) -> dict[str, Any]:
    result = {
        "source": None,
        "cpu_seconds": None,
        "cpu_percent_one_core": None,
    }
    if (
        not isinstance(before, dict)
        or not isinstance(after, dict)
        or before.get("source") != after.get("source")
        or not isinstance(elapsed, (int, float))
        or isinstance(elapsed, bool)
        or elapsed <= 0
    ):
        return result
    before_seconds = before.get("usage_seconds")
    after_seconds = after.get("usage_seconds")
    if (
        not isinstance(before_seconds, (int, float))
        or isinstance(before_seconds, bool)
        or not isinstance(after_seconds, (int, float))
        or isinstance(after_seconds, bool)
        or after_seconds < before_seconds
    ):
        return result
    cpu_seconds = float(after_seconds - before_seconds)
    return {
        "source": after.get("source"),
        "cpu_seconds": cpu_seconds,
        "cpu_percent_one_core": cpu_seconds * 100.0 / float(elapsed),
    }


def snapshot(interface: str) -> dict[str, Any]:
    transport = transport_counters()
    return {
        "monotonic": time.monotonic(),
        "cgroup_cpu": cgroup_cpu_usage(),
        "interface": interface_counters(interface),
        "softirq": softirq_totals(),
        "tcp_retransmits": transport["tcp"]["RetransSegs"],
        "udp_errors": {
            "in_errors": transport["udp"]["InErrors"],
            "rcvbuf_errors": transport["udp"]["RcvbufErrors"],
            "sndbuf_errors": transport["udp"]["SndbufErrors"],
        },
        "tcp_listen": {
            "listen_drops": transport["tcp_ext"]["ListenDrops"],
            "listen_overflows": transport["tcp_ext"]["ListenOverflows"],
        },
        "conntrack_count": read_int(
            Path("/proc/sys/net/netfilter/nf_conntrack_count")
        ),
        "nfqueue": nfqueue_counters(),
    }


def collect(
    pid: int,
    workload_pid: int,
    interface: str,
    duration: float,
    interval: float,
    stop_stream: TextIO | None = None,
) -> dict[str, Any]:
    started = snapshot(interface)
    ticks_before = process_cpu_ticks(pid)
    workload_ticks_before = process_cpu_ticks(workload_pid)
    rss_samples: list[int] = []
    workload_rss_samples: list[int] = []
    conntrack_samples: list[int] = []
    queue_depth_samples: list[int] = []
    deadline = time.monotonic() + duration
    stop_reason = "duration_limit"
    stop_selector: selectors.BaseSelector | None = None
    if stop_stream is not None:
        stop_selector = selectors.DefaultSelector()
        stop_selector.register(stop_stream, selectors.EVENT_READ)
    try:
        while True:
            rss = process_rss_bytes(pid)
            if rss is not None:
                rss_samples.append(rss)
            workload_rss = process_rss_bytes(workload_pid)
            if workload_rss is not None:
                workload_rss_samples.append(workload_rss)
            conntrack = read_int(Path("/proc/sys/net/netfilter/nf_conntrack_count"))
            if conntrack is not None:
                conntrack_samples.append(conntrack)
            depth = nfqueue_counters()["depth"]
            if depth is not None:
                queue_depth_samples.append(depth)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            wait = min(interval, remaining)
            if stop_selector is None:
                time.sleep(wait)
                continue
            if not stop_selector.select(wait):
                continue
            command = stop_stream.readline(16)
            if command != "stop\n":
                raise RuntimeError("synchronized collector expected one stop line")
            stop_reason = "requested"
            break
    finally:
        if stop_selector is not None:
            stop_selector.close()
    finished = snapshot(interface)
    ticks_after = process_cpu_ticks(pid)
    workload_ticks_after = process_cpu_ticks(workload_pid)
    elapsed = max(float(finished["monotonic"] - started["monotonic"]), 1e-9)
    clock_ticks = os.sysconf("SC_CLK_TCK")
    cpu_ticks = ordinary_delta(ticks_before, ticks_after)
    cpu_seconds = None if cpu_ticks is None else cpu_ticks / clock_ticks
    workload_cpu_ticks = ordinary_delta(
        workload_ticks_before, workload_ticks_after
    )
    workload_cpu_seconds = (
        None
        if workload_cpu_ticks is None
        else workload_cpu_ticks / clock_ticks
    )
    cgroup = cgroup_cpu_delta(
        started.get("cgroup_cpu"), finished.get("cgroup_cpu"), elapsed
    )
    network = {
        name: ordinary_delta(started["interface"].get(name), finished["interface"].get(name))
        for name in started["interface"]
    }
    queue_before = started["nfqueue"]
    queue_after = finished["nfqueue"]
    queue = {
        "hits": counter_delta(queue_before.get("sequence"), queue_after.get("sequence")),
        "kernel_dropped": ordinary_delta(
            queue_before.get("kernel_dropped"), queue_after.get("kernel_dropped")
        ),
        "user_dropped": ordinary_delta(
            queue_before.get("user_dropped"), queue_after.get("user_dropped")
        ),
        "depth_peak": max(queue_depth_samples, default=None),
        "depth_end": queue_after.get("depth"),
        "copy_mode": queue_after.get("copy_mode"),
        "copy_range": queue_after.get("copy_range"),
    }
    return {
        "schema": "openshield.perf.metrics.v1",
        "elapsed_seconds": elapsed,
        "stop_reason": stop_reason,
        "daemon": {
            "pid": pid if pid > 0 else None,
            "alive_end": process_cpu_ticks(pid) is not None if pid > 0 else None,
            "cpu_seconds": cpu_seconds,
            "cpu_percent_one_core": None
            if cpu_seconds is None
            else cpu_seconds * 100.0 / elapsed,
            "rss_bytes_mean": None
            if not rss_samples
            else sum(rss_samples) / len(rss_samples),
            "rss_bytes_peak": max(rss_samples, default=None),
        },
        "workload_process": {
            "pid": workload_pid if workload_pid > 0 else None,
            "alive_end": process_cpu_ticks(workload_pid) is not None
            if workload_pid > 0
            else None,
            "cpu_seconds": workload_cpu_seconds,
            "cpu_percent_one_core": None
            if workload_cpu_seconds is None
            else workload_cpu_seconds * 100.0 / elapsed,
            "rss_bytes_mean": None
            if not workload_rss_samples
            else sum(workload_rss_samples) / len(workload_rss_samples),
            "rss_bytes_peak": max(workload_rss_samples, default=None),
        },
        "cgroup": cgroup,
        "network": {
            **network,
            "rx_pps": None
            if network.get("rx_packets") is None
            else network["rx_packets"] / elapsed,
            "tx_pps": None
            if network.get("tx_packets") is None
            else network["tx_packets"] / elapsed,
            "rx_mbps": None
            if network.get("rx_bytes") is None
            else network["rx_bytes"] * 8.0 / elapsed / 1_000_000.0,
            "tx_mbps": None
            if network.get("tx_bytes") is None
            else network["tx_bytes"] * 8.0 / elapsed / 1_000_000.0,
        },
        "softirq": {
            name: ordinary_delta(started["softirq"].get(name), finished["softirq"].get(name))
            for name in started["softirq"]
        },
        "tcp_retransmits": ordinary_delta(
            started.get("tcp_retransmits"), finished.get("tcp_retransmits")
        ),
        "udp_errors": counter_group_delta(
            started["udp_errors"], finished["udp_errors"]
        ),
        "tcp_listen": counter_group_delta(
            started["tcp_listen"], finished["tcp_listen"]
        ),
        "conntrack_count_start": started.get("conntrack_count"),
        "conntrack_count_end": finished.get("conntrack_count"),
        "conntrack_count_peak": max(conntrack_samples, default=None),
        "nfqueue": queue,
        "scope_notes": {
            "softirq": "host-wide kernel counters; compare paired baselines",
            "cgroup_cpu": "container-wide CPU; compare the same paired workload window",
            "nfqueue_log_errors": "not included; daemon throttling makes log counts lower bounds",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, default=0)
    parser.add_argument("--workload-pid", type=int, default=0)
    parser.add_argument("--interface", default="eth0")
    parser.add_argument("--duration", type=float, required=True)
    parser.add_argument("--interval", type=float, default=0.1)
    parser.add_argument(
        "--synchronize",
        action="store_true",
        help="announce readiness and wait for a bounded start line on stdin",
    )
    arguments = parser.parse_args()
    if not 0 < arguments.duration <= MAX_DURATION_SECONDS:
        parser.error(f"duration must be in (0, {MAX_DURATION_SECONDS}]")
    if not MIN_INTERVAL_SECONDS <= arguments.interval <= arguments.duration:
        parser.error("interval is outside the safe measurement range")
    if not INTERFACE_PATTERN.fullmatch(arguments.interface):
        parser.error("invalid interface")
    if arguments.pid < 0 or arguments.workload_pid < 0:
        parser.error("process identifiers must be nonnegative")
    if arguments.synchronize:
        print(
            json.dumps(
                {"schema": CONTROL_SCHEMA, "event": "ready"},
                sort_keys=True,
                separators=(",", ":"),
            ),
            flush=True,
        )
        command = sys.stdin.readline(16)
        if command != "start\n":
            parser.error("synchronized collector expected one start line")
    print(
        json.dumps(
            collect(
                arguments.pid,
                arguments.workload_pid,
                arguments.interface,
                arguments.duration,
                arguments.interval,
                sys.stdin if arguments.synchronize else None,
            ),
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
