#!/usr/bin/env python3
"""Bounded UDP echo/stream server and multi-flow high-PPS workload client."""

from __future__ import annotations

import argparse
import asyncio
import random
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from common import (  # type: ignore
        MAX_CONCURRENCY,
        MAX_UDP_BODY_BYTES,
        AsyncMultiRateLimiter,
        WeightedMix,
        WorkBudget,
        WorkloadStats,
        apply_config_file,
        base_client_arguments,
        base_server_arguments,
        bounded_int,
        deterministic_payload,
        emit_json,
        endpoint_port,
        install_stop_handlers,
        mix_converter,
        require_safe_bind,
        safe_error,
        socket_address,
        wait_for_start_gate,
    )
else:
    from .common import (
        MAX_CONCURRENCY,
        MAX_UDP_BODY_BYTES,
        AsyncMultiRateLimiter,
        WeightedMix,
        WorkBudget,
        WorkloadStats,
        apply_config_file,
        base_client_arguments,
        base_server_arguments,
        bounded_int,
        deterministic_payload,
        emit_json,
        endpoint_port,
        install_stop_handlers,
        mix_converter,
        require_safe_bind,
        safe_error,
        socket_address,
        wait_for_start_gate,
    )


VERSION = 1
REQUEST_MAGIC = b"OSUF"
RESPONSE_MAGIC = b"OSUR"
FLAG_REPLY = 0x01
FLAG_BARRIER = 0x02
REQUEST_HEADER = struct.Struct("!4sBBHIIQQQ")
RESPONSE_HEADER = struct.Struct("!4sBBHIQQQQQ")
MAX_DATAGRAM_BYTES = 65_507
RECEIVE_POLL_SECONDS = 0.2
# The server proves a per-flow contiguous prefix before acknowledging a drain
# barrier.  Isolated test traffic should reorder only a small number of
# datagrams; fixed bounds prevent malformed traffic from turning the evidence
# mechanism into unbounded memory use.
MAX_TRACKED_DRAIN_FLOWS = MAX_CONCURRENCY * 2
MAX_UDP_REORDER_WINDOW = 4_096
UDP_CLIENT_CONFIG_FIELDS = (
    "host",
    "port",
    "duration",
    "operations",
    "seed",
    "pps",
    "mbps",
    "io_timeout",
    "latency_samples",
    "flows",
    "reply_every",
    "request_bytes",
    "request_mix",
    "response_bytes",
    "response_mix",
    "socket_buffer_bytes",
    "mtu",
)


@dataclass(frozen=True)
class UdpServerConfig:
    host: str
    port: int
    duration: float
    seed: int
    io_timeout: float
    processing_delay_ms: float
    max_request_bytes: int
    max_response_bytes: int
    socket_buffer_bytes: int
    allow_non_loopback: bool = False


@dataclass(frozen=True)
class UdpClientConfig:
    host: str
    port: int
    duration: float
    operations: int
    seed: int
    pps: float
    mbps: float
    io_timeout: float
    latency_samples: int
    flows: int
    reply_every: int
    request_bytes: int
    response_mix: WeightedMix
    socket_buffer_bytes: int
    mtu: int = 1500
    request_mix: Optional[WeightedMix] = None


@dataclass(frozen=True)
class _PendingBarrier:
    sequence: int
    client_send_ns: int
    server_receive_ns: int


@dataclass
class _FlowDrainState:
    next_contiguous_sequence: int = 1
    reordered_sequences: set[int] = field(default_factory=set)
    pending_barrier: Optional[_PendingBarrier] = None


class UdpWorkloadServer:
    """A single bounded datagram endpoint preserving real UDP flow identities."""

    def __init__(self, config: UdpServerConfig, stop: Optional[threading.Event] = None):
        require_safe_bind(config.host, config.allow_non_loopback)
        self.config = config
        self.stop = stop or threading.Event()
        self.ready = threading.Event()
        self.bound_port: Optional[int] = None
        self.fatal_error: Optional[BaseException] = None
        self.stats = WorkloadStats(config.seed)
        self._response_payload = deterministic_payload(
            config.max_response_bytes, config.seed, 0x55445053
        )

    @staticmethod
    def _flow_state(
        states: dict[tuple[object, int], _FlowDrainState],
        key: tuple[object, int],
    ) -> _FlowDrainState:
        state = states.get(key)
        if state is not None:
            return state
        if len(states) >= MAX_TRACKED_DRAIN_FLOWS:
            raise ValueError("UDP drain-flow tracking limit exceeded")
        state = _FlowDrainState()
        states[key] = state
        return state

    @staticmethod
    def _record_data_sequence(state: _FlowDrainState, sequence: int) -> None:
        if sequence == 0 or sequence < state.next_contiguous_sequence:
            raise ValueError("duplicate or invalid UDP workload sequence")
        barrier = state.pending_barrier
        if barrier is not None and sequence >= barrier.sequence:
            raise ValueError("UDP workload sequence crossed its drain barrier")
        if sequence == state.next_contiguous_sequence:
            state.next_contiguous_sequence += 1
            while state.next_contiguous_sequence in state.reordered_sequences:
                state.reordered_sequences.remove(state.next_contiguous_sequence)
                state.next_contiguous_sequence += 1
            return
        if (
            sequence - state.next_contiguous_sequence > MAX_UDP_REORDER_WINDOW
            or len(state.reordered_sequences) >= MAX_UDP_REORDER_WINDOW
        ):
            raise ValueError("UDP workload reordering exceeded its fixed bound")
        if sequence in state.reordered_sequences:
            raise ValueError("duplicate UDP workload sequence")
        state.reordered_sequences.add(sequence)

    @staticmethod
    def _record_barrier_sequence(
        state: _FlowDrainState,
        sequence: int,
        client_send_ns: int,
        received_at_ns: int,
    ) -> None:
        if sequence == 0 or state.pending_barrier is not None:
            raise ValueError("duplicate or invalid UDP drain barrier")
        if sequence < state.next_contiguous_sequence:
            raise ValueError("UDP drain barrier precedes consumed data")
        if sequence - state.next_contiguous_sequence > MAX_UDP_REORDER_WINDOW:
            raise ValueError("UDP drain-barrier gap exceeded its fixed bound")
        if any(item >= sequence for item in state.reordered_sequences):
            raise ValueError("UDP data sequence crossed its drain barrier")
        state.pending_barrier = _PendingBarrier(
            sequence=sequence,
            client_send_ns=client_send_ns,
            server_receive_ns=received_at_ns,
        )

    def _ack_completed_barrier(
        self,
        server: socket.socket,
        peer: object,
        key: tuple[object, int],
        states: dict[tuple[object, int], _FlowDrainState],
    ) -> bool:
        state = states[key]
        barrier = state.pending_barrier
        if barrier is None or state.next_contiguous_sequence != barrier.sequence:
            return False
        if state.reordered_sequences:
            raise ValueError("UDP drain barrier reached with unresolved sequence gaps")
        response_header = RESPONSE_HEADER.pack(
            RESPONSE_MAGIC,
            VERSION,
            0,
            0,
            0,
            key[1],
            barrier.sequence,
            barrier.client_send_ns,
            barrier.server_receive_ns,
            time.monotonic_ns(),
        )
        sent = server.sendto(response_header, peer)
        if sent != len(response_header):
            raise OSError("short UDP barrier acknowledgement send")
        self.stats.add(
            barrier_acks_sent=1,
            barrier_bytes_sent=sent,
        )
        del states[key]
        return True

    def run(self, on_ready: Optional[Callable[[int], None]] = None) -> dict:
        family, address = socket_address(self.config.host, self.config.port)
        deadline = time.monotonic() + self.config.duration
        server: Optional[socket.socket] = None
        flow_states: dict[tuple[object, int], _FlowDrainState] = {}
        try:
            server = socket.socket(family, socket.SOCK_DGRAM)
            server.setsockopt(
                socket.SOL_SOCKET, socket.SO_RCVBUF, self.config.socket_buffer_bytes
            )
            server.setsockopt(
                socket.SOL_SOCKET, socket.SO_SNDBUF, self.config.socket_buffer_bytes
            )
            server.bind(address)
            server.settimeout(min(self.config.io_timeout, RECEIVE_POLL_SECONDS))
            self.bound_port = endpoint_port(server)
            self.ready.set()
            if on_ready is not None:
                on_ready(self.bound_port)
            while not self.stop.is_set() and time.monotonic() < deadline:
                try:
                    datagram, peer = server.recvfrom(MAX_DATAGRAM_BYTES)
                except socket.timeout:
                    continue
                except OSError:
                    if self.stop.is_set():
                        break
                    raise
                received_at_ns = time.monotonic_ns()
                self.stats.add(
                    datagrams_received_total=1,
                    datagram_bytes_received_total=len(datagram),
                )
                try:
                    if len(datagram) < REQUEST_HEADER.size:
                        raise ValueError("truncated UDP workload request")
                    (
                        magic,
                        version,
                        flags,
                        reserved,
                        request_size,
                        response_size,
                        flow_id,
                        sequence,
                        client_send_ns,
                    ) = REQUEST_HEADER.unpack_from(datagram)
                    if (
                        magic != REQUEST_MAGIC
                        or version != VERSION
                        or reserved != 0
                        or flags & ~(FLAG_REPLY | FLAG_BARRIER)
                        or flags == (FLAG_REPLY | FLAG_BARRIER)
                        or request_size > self.config.max_request_bytes
                        or response_size > self.config.max_response_bytes
                        or len(datagram) != REQUEST_HEADER.size + request_size
                    ):
                        raise ValueError("invalid or oversized UDP workload request")
                    if flags == FLAG_BARRIER:
                        if (
                            request_size != 0
                            or response_size != 0
                            or len(datagram) != REQUEST_HEADER.size
                        ):
                            raise ValueError("invalid UDP drain barrier")
                        key = (peer, flow_id)
                        state = self._flow_state(flow_states, key)
                        self._record_barrier_sequence(
                            state,
                            sequence,
                            client_send_ns,
                            received_at_ns,
                        )
                        self.stats.add(
                            barriers_received=1,
                            barrier_bytes_received=len(datagram),
                        )
                        self._ack_completed_barrier(
                            server, peer, key, flow_states
                        )
                        continue
                    key = (peer, flow_id)
                    state = self._flow_state(flow_states, key)
                    self._record_data_sequence(state, sequence)
                    self.stats.add(
                        packets_received=1,
                        bytes_received=len(datagram),
                    )
                    self.stats.add(operations=1)
                    if flags & FLAG_REPLY:
                        if self.config.processing_delay_ms > 0 and self.stop.wait(
                            self.config.processing_delay_ms / 1_000.0
                        ):
                            break
                        server_receive_ns = received_at_ns
                        server_send_ns = time.monotonic_ns()
                        response_header = RESPONSE_HEADER.pack(
                            RESPONSE_MAGIC,
                            VERSION,
                            0,
                            0,
                            response_size,
                            flow_id,
                            sequence,
                            client_send_ns,
                            server_receive_ns,
                            server_send_ns,
                        )
                        response = response_header + self._response_payload[:response_size]
                        sent = server.sendto(response, peer)
                        if sent != len(response):
                            raise OSError("short UDP response send")
                        self.stats.add(packets_replied=1, bytes_sent=sent)
                    self.stats.latency_ms.record(
                        (time.monotonic_ns() - received_at_ns) / 1_000_000.0
                    )
                    self._ack_completed_barrier(server, peer, key, flow_states)
                except (OSError, ValueError, struct.error):
                    self.stats.add(protocol_errors=1)
        except BaseException as error:
            self.fatal_error = error
            raise
        finally:
            self.stop.set()
            self.ready.set()
            if flow_states:
                self.stats.add(
                    incomplete_drain_flows=len(flow_states),
                    protocol_errors=len(flow_states),
                )
            if server is not None:
                server.close()
        return self.stats.summary()


class UdpWorkloadClient:
    """One-thread event loop using one real connected UDP socket per flow."""

    def __init__(self, config: UdpClientConfig, stop: Optional[threading.Event] = None):
        self.request_mix = config.request_mix or WeightedMix.fixed(
            config.request_bytes
        )
        if (
            self.request_mix.maximum_value > MAX_UDP_BODY_BYTES
            or config.response_mix.maximum_value > MAX_UDP_BODY_BYTES
        ):
            raise ValueError("UDP request/response mix exceeds the datagram safety bound")
        self.config = config
        self.stop = stop or threading.Event()
        self.stats = WorkloadStats(config.seed, config.latency_samples)
        self.budget = WorkBudget(config.operations)
        self.deadline = time.monotonic() + config.duration
        self.limiter = AsyncMultiRateLimiter(
            {
                "packets": config.pps,
                "bytes": config.mbps * 1_000_000.0 / 8.0,
            },
            self.stats.scheduler_lag_ms,
        )
        self._family, self._address = socket_address(config.host, config.port)
        if self._family == socket.AF_INET6 and config.mtu < 1280:
            raise ValueError("IPv6 workload MTU must be at least 1280 bytes")

    def run(self) -> dict:
        asyncio.run(self._run())
        return self.stats.summary()

    async def _run(self) -> None:
        tasks = [
            asyncio.create_task(self._flow(flow_id))
            for flow_id in range(self.config.flows)
        ]
        await asyncio.gather(*tasks)
        self.stop.set()

    def _ip_packet_count(self, udp_payload_bytes: int) -> int:
        ip_header = 20 if self._family == socket.AF_INET else 40
        fragment_payload = max(8, ((self.config.mtu - ip_header) // 8) * 8)
        return max(1, (udp_payload_bytes + 8 + fragment_payload - 1) // fragment_payload)

    def target_rate_model(self) -> dict:
        """Translate aggregate fragment/byte caps into expected datagrams per second."""

        reply_probability = (
            0.0 if self.config.reply_every == 0 else 1.0 / self.config.reply_every
        )
        expected_packets = 0.0
        expected_bytes = 0.0
        for entry in self.request_mix.entries:
            fraction = entry.weight / self.request_mix.total_weight
            request_wire = REQUEST_HEADER.size + entry.value
            expected_packets += fraction * self._ip_packet_count(request_wire)
            expected_bytes += fraction * request_wire
        for entry in self.config.response_mix.entries:
            fraction = entry.weight / self.config.response_mix.total_weight
            response_wire = RESPONSE_HEADER.size + entry.value
            expected_packets += (
                reply_probability
                * fraction
                * self._ip_packet_count(response_wire)
            )
            expected_bytes += reply_probability * fraction * response_wire
        candidates = []
        if self.config.pps > 0 and expected_packets > 0:
            candidates.append(self.config.pps / expected_packets)
        if self.config.mbps > 0 and expected_bytes > 0:
            candidates.append(
                self.config.mbps * 1_000_000.0 / 8.0 / expected_bytes
            )
        target = min(candidates) if candidates else None
        return {
            "target_application_ops_per_second": None
            if target is None
            else round(target, 6),
            "expected_packets_per_operation": round(expected_packets, 6),
            "expected_application_bytes_per_operation": round(expected_bytes, 6),
            "expected_reply_probability": round(reply_probability, 9),
            "scope": "steady-state estimate from configured MTU and reply cadence",
        }

    async def _flow(self, flow_id: int) -> None:
        generator = random.Random(self.config.seed + flow_id * 0x9E3779B1)
        maximum_payload = deterministic_payload(
            self.request_mix.maximum_value, self.config.seed, flow_id + 1
        )
        connection = socket.socket(self._family, socket.SOCK_DGRAM)
        opened = False
        try:
            connection.setblocking(False)
            connection.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_RCVBUF,
                self.config.socket_buffer_bytes,
            )
            connection.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_SNDBUF,
                self.config.socket_buffer_bytes,
            )
            loop = asyncio.get_running_loop()
            connect_started = time.monotonic_ns()
            await asyncio.wait_for(
                loop.sock_connect(connection, self._address), timeout=self.config.io_timeout
            )
            self.stats.connect_latency_ms.record(
                (time.monotonic_ns() - connect_started) / 1_000_000.0
            )
            self.stats.add(flows_opened=1)
            self.stats.active_change(1)
            opened = True
            # Only successfully submitted datagrams consume sequence numbers.
            # A rate-limiter refusal at the phase deadline must not create a
            # fictitious hole immediately before the drain barrier: the server
            # correctly refuses to acknowledge a barrier until every preceding
            # sequence has arrived.
            sequence = 0
            while not self.stop.is_set() and time.monotonic() < self.deadline:
                if not self.budget.claim():
                    break
                candidate_sequence = sequence + 1
                request_size = self.request_mix.choose(generator)
                response_size = self.config.response_mix.choose(generator)
                expect_reply = (
                    self.config.reply_every > 0
                    and candidate_sequence % self.config.reply_every == 0
                )
                socket_payload_bytes = REQUEST_HEADER.size + request_size
                if expect_reply:
                    socket_payload_bytes += RESPONSE_HEADER.size + response_size
                estimated_packets = self._ip_packet_count(
                    REQUEST_HEADER.size + request_size
                )
                if expect_reply:
                    estimated_packets += self._ip_packet_count(
                        RESPONSE_HEADER.size + response_size
                    )
                if not await self.limiter.acquire(
                    {
                        "packets": float(estimated_packets),
                        "bytes": float(socket_payload_bytes),
                    },
                    self.stop,
                    self.deadline,
                ):
                    break
                client_send_ns = time.monotonic_ns()
                request_header = REQUEST_HEADER.pack(
                    REQUEST_MAGIC,
                    VERSION,
                    FLAG_REPLY if expect_reply else 0,
                    0,
                    request_size,
                    response_size,
                    flow_id,
                    candidate_sequence,
                    client_send_ns,
                )
                request = request_header + maximum_payload[:request_size]
                try:
                    await asyncio.wait_for(
                        loop.sock_sendall(connection, request), timeout=self.config.io_timeout
                    )
                    sequence = candidate_sequence
                    sent = len(request)
                    self.stats.add(
                        operations=1,
                        packets_sent=1,
                        bytes_sent=sent,
                        replies_expected=1 if expect_reply else 0,
                        **{f"request_size_{request_size}_datagrams": 1},
                        **{f"response_size_{response_size}_datagrams": 1},
                    )
                    if not expect_reply:
                        continue
                    received_bytes = await self._receive_reply(
                        loop,
                        connection,
                        response_size,
                        flow_id,
                        sequence,
                        client_send_ns,
                    )
                    self.stats.add(packets_replied=1, bytes_received=received_bytes)
                    self.stats.latency_ms.record(
                        (time.monotonic_ns() - client_send_ns) / 1_000_000.0
                    )
                except asyncio.TimeoutError:
                    self.stats.add(errors=1, reply_timeouts=1)
                except (OSError, ValueError, struct.error):
                    self.stats.add(errors=1, invalid_replies=1)
            # A reply from every connected flow is a protocol-level drain
            # barrier. The server acknowledges it only after proving the exact
            # contiguous sequence prefix, rather than assuming that UDP/IP did
            # not reorder packets. Barrier traffic is deliberately excluded
            # from workload packet/operation totals.
            self.stats.add(barriers_expected=1)
            barrier_send_ns = time.monotonic_ns()
            barrier = REQUEST_HEADER.pack(
                REQUEST_MAGIC,
                VERSION,
                FLAG_BARRIER,
                0,
                0,
                0,
                flow_id,
                sequence + 1,
                barrier_send_ns,
            )
            try:
                await asyncio.wait_for(
                    loop.sock_sendall(connection, barrier),
                    timeout=self.config.io_timeout,
                )
                self.stats.add(barriers_sent=1, barrier_bytes_sent=len(barrier))
                received_bytes = await self._receive_reply(
                    loop,
                    connection,
                    0,
                    flow_id,
                    sequence + 1,
                    barrier_send_ns,
                )
                self.stats.add(
                    barrier_acks_received=1,
                    barrier_bytes_received=received_bytes,
                )
            except (asyncio.TimeoutError, OSError, ValueError, struct.error):
                self.stats.add(errors=1, barrier_errors=1)
        finally:
            connection.close()
            self.stats.add(flows_closed=1)
            if opened:
                self.stats.active_change(-1)

    async def _receive_reply(
        self,
        loop: asyncio.AbstractEventLoop,
        connection: socket.socket,
        response_size: int,
        flow_id: int,
        sequence: int,
        client_send_ns: int,
    ) -> int:
        """Receive the matching echo without letting a late echo poison later probes."""

        deadline = time.monotonic() + self.config.io_timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise asyncio.TimeoutError
            response = await asyncio.wait_for(
                loop.sock_recv(connection, MAX_DATAGRAM_BYTES), timeout=remaining
            )
            if len(response) < RESPONSE_HEADER.size:
                raise ValueError("truncated UDP workload response")
            (
                magic,
                version,
                status,
                reserved,
                received_size,
                received_flow,
                received_sequence,
                echoed_send_ns,
                _server_receive_ns,
                _server_send_ns,
            ) = RESPONSE_HEADER.unpack_from(response)
            if (
                magic != RESPONSE_MAGIC
                or version != VERSION
                or status != 0
                or reserved != 0
                or received_size > MAX_UDP_BODY_BYTES
                or len(response) != RESPONSE_HEADER.size + received_size
            ):
                raise ValueError("invalid UDP workload response")
            if (
                received_flow == flow_id
                and received_sequence == sequence
                and echoed_send_ns == client_send_ns
            ):
                if received_size != response_size:
                    raise ValueError("UDP workload response has an unexpected size")
                return len(response)
            self.stats.add(stale_replies=1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="OpenShield bounded real-socket UDP performance workload"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    server = commands.add_parser("server", help="run the UDP stream/echo server")
    base_server_arguments(server)
    server.add_argument(
        "--max-request-bytes",
        type=bounded_int("max-request-bytes", 0, MAX_UDP_BODY_BYTES),
        default=16 * 1024,
    )
    server.add_argument(
        "--max-response-bytes",
        type=bounded_int("max-response-bytes", 0, MAX_UDP_BODY_BYTES),
        default=16 * 1024,
    )
    server.add_argument(
        "--socket-buffer-bytes",
        type=bounded_int("socket-buffer-bytes", 64 * 1024, 16 * 1024 * 1024),
        default=4 * 1024 * 1024,
    )

    client = commands.add_parser("client", help="run high-PPS UDP flows")
    base_client_arguments(client)
    client.add_argument(
        "--flows", type=bounded_int("flows", 1, MAX_CONCURRENCY), default=16
    )
    client.add_argument(
        "--reply-every",
        type=bounded_int("reply-every", 0, 1_000_000),
        default=100,
        help="request one latency echo every N datagrams; zero disables replies",
    )
    client.add_argument(
        "--request-bytes",
        type=bounded_int("request-bytes", 0, MAX_UDP_BODY_BYTES),
        default=256,
    )
    client.add_argument(
        "--request-mix",
        type=mix_converter(MAX_UDP_BODY_BYTES),
        help=(
            "deterministic SIZE:WEIGHT outbound-body distribution; "
            "request-bytes is the fallback"
        ),
    )
    client.add_argument(
        "--response-bytes",
        type=bounded_int("response-bytes", 0, MAX_UDP_BODY_BYTES),
        default=64,
    )
    client.add_argument(
        "--response-mix",
        type=mix_converter(MAX_UDP_BODY_BYTES),
        help="optional deterministic SIZE:WEIGHT reply-size distribution",
    )
    client.add_argument(
        "--socket-buffer-bytes",
        type=bounded_int("socket-buffer-bytes", 64 * 1024, 16 * 1024 * 1024),
        default=1024 * 1024,
    )
    client.add_argument(
        "--mtu",
        type=bounded_int("mtu", 576, 65_535),
        default=1500,
        help="MTU estimate used only to pace approximate IP packet rate",
    )
    return parser


def server_config(arguments: argparse.Namespace) -> UdpServerConfig:
    return UdpServerConfig(
        host=arguments.bind,
        port=arguments.port,
        duration=arguments.duration,
        seed=arguments.seed,
        io_timeout=arguments.io_timeout,
        processing_delay_ms=arguments.processing_delay_ms,
        max_request_bytes=arguments.max_request_bytes,
        max_response_bytes=arguments.max_response_bytes,
        socket_buffer_bytes=arguments.socket_buffer_bytes,
        allow_non_loopback=arguments.allow_non_loopback,
    )


def client_config(arguments: argparse.Namespace) -> UdpClientConfig:
    if arguments.port is None:
        raise ValueError("client port is required through CLI or config-file")
    response_mix = arguments.response_mix or WeightedMix.fixed(arguments.response_bytes)
    return UdpClientConfig(
        host=arguments.host,
        port=arguments.port,
        duration=arguments.duration,
        operations=arguments.operations,
        seed=arguments.seed,
        pps=arguments.pps,
        mbps=arguments.mbps,
        io_timeout=arguments.io_timeout,
        latency_samples=arguments.latency_samples,
        flows=arguments.flows,
        reply_every=arguments.reply_every,
        request_bytes=arguments.request_bytes,
        response_mix=response_mix,
        socket_buffer_bytes=arguments.socket_buffer_bytes,
        mtu=arguments.mtu,
        request_mix=arguments.request_mix,
    )


def run_server(config: UdpServerConfig) -> int:
    stop = threading.Event()
    install_stop_handlers(stop)
    server = UdpWorkloadServer(config, stop)
    try:
        summary = server.run(
            lambda port: emit_json(
                "ready",
                role="server",
                transport="udp",
                host=config.host,
                port=port,
                pid=__import__("os").getpid(),
            )
        )
    except BaseException as error:
        emit_json(
            "error", role="server", transport="udp", error=safe_error(error)
        )
        return 2
    emit_json(
        "summary",
        role="server",
        transport="udp",
        host=config.host,
        port=server.bound_port,
        seed=config.seed,
        metrics=summary,
    )
    return 0


def run_client(config: UdpClientConfig, start_gate_stdin: bool = False) -> int:
    stop = threading.Event()
    install_stop_handlers(stop)
    wait_for_start_gate(start_gate_stdin, stop, "udp")
    client = UdpWorkloadClient(config, stop)
    summary = client.run()
    summary["datagrams_per_second"] = summary["application_ops_per_second"]
    rate_model = client.target_rate_model()
    expected = summary.get("replies_expected", 0)
    received = summary.get("packets_replied", 0)
    summary["reply_loss"] = max(0, expected - received)
    summary["reply_loss_ratio"] = round(
        max(0, expected - received) / expected, 6
    ) if expected else 0.0
    emit_json(
        "summary",
        role="client",
        transport="udp",
        host=config.host,
        port=config.port,
        seed=config.seed,
        config={
            "duration": config.duration,
            "operations": config.operations,
            "target_approximate_pps": config.pps,
            "mbps": config.mbps,
            "packet_rate_basis": (
                "estimated IPv4/IPv6 fragments from configured MTU; "
                "validate NIC PPS externally"
            ),
            "bandwidth_rate_basis": (
                "UDP application datagram bytes in both directions, "
                "including workload headers"
            ),
            "connect_latency_basis": (
                "local connected-UDP socket setup; UDP has no network handshake"
            ),
            "request_latency_basis": "sampled echo datagram round-trip",
            "flows": config.flows,
            "execution_model": "one-thread asyncio event loop",
            "reply_every": config.reply_every,
            "request_bytes": config.request_bytes,
            "request_mix": client.request_mix.as_json(),
            "request_payload_basis": (
                "complete UDP body of the selected size; deterministic prefix "
                "of the per-flow seeded payload"
            ),
            "response_mix": config.response_mix.as_json(),
            "mtu": config.mtu,
            **rate_model,
        },
        ok=summary.get("packets_sent", 0) > 0 and summary.get("errors", 0) == 0,
        metrics=summary,
    )
    return 0 if summary.get("packets_sent", 0) > 0 else 2


def main(argv=None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "client":
            apply_config_file(arguments, parser, UDP_CLIENT_CONFIG_FIELDS)
        if arguments.command == "server":
            return run_server(server_config(arguments))
        return run_client(
            client_config(arguments),
            start_gate_stdin=arguments.start_gate_stdin,
        )
    except (ValueError, OSError, RuntimeError) as error:
        emit_json(
            "error", role=arguments.command, transport="udp", error=safe_error(error)
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
