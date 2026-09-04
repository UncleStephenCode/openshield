use std::collections::HashSet;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail, ensure};
use nix::errno::Errno;
use nix::net::if_::if_indextoname;
use nix::poll::{PollFd, PollFlags, poll};
use nix::sys::socket::{
    AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType, bind, recv, sendto,
    socket,
};
use openshield_core::{
    APPLICATION_QUEUE_NUMBER, InterfaceName, LearnedApplicationEndpoint, LearnedEndpoint, Mode,
    TransportProtocol, application_handoff_mark, application_pending_mark,
};
use tracing::{error, info, warn};

use crate::application::{OutboundConnection, ProcfsResolver, is_attribution_timeout};
use crate::backend::QueueVerdictStrategy;
use crate::engine::{LearningQueueAdmission, NfqueueRuntimeCounters, SharedEngine};

const NFNL_SUBSYS_QUEUE: u16 = 3;
const NFQNL_MSG_PACKET: u16 = 0;
const NFQNL_MSG_VERDICT: u16 = 1;
const NFQNL_MSG_CONFIG: u16 = 2;
const NFQNL_CFG_CMD_BIND: u8 = 1;
const NFQNL_CFG_CMD_UNBIND: u8 = 2;
const NFQNL_COPY_PACKET: u8 = 2;
const NFQA_PACKET_HDR: u16 = 1;
const NFQA_VERDICT_HDR: u16 = 2;
const NFQA_MARK: u16 = 3;
const NFQA_IFINDEX_OUTDEV: u16 = 6;
const NFQA_PAYLOAD: u16 = 10;
const NFQA_UID: u16 = 16;
const NFQA_CFG_CMD: u16 = 1;
const NFQA_CFG_PARAMS: u16 = 2;
const NFQA_CFG_QUEUE_MAXLEN: u16 = 3;
const NFQA_CFG_MASK: u16 = 4;
const NFQA_CFG_FLAGS: u16 = 5;
const NFQA_CFG_F_UID_GID: u32 = 1 << 3;
const NF_DROP: u32 = 0;
const NF_ACCEPT: u32 = 1;
const NF_REPEAT: u32 = 4;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NLMSG_ERROR: u16 = 2;
const NETLINK_HEADER_BYTES: usize = 16;
const NFGENMSG_BYTES: usize = 4;
const ATTRIBUTE_HEADER_BYTES: usize = 4;
const PACKET_HEADER_BYTES: usize = 7;
const COPY_RANGE: u32 = 512;
const QUEUE_MAX_LENGTH: u32 = 256;
const RECEIVE_BUFFER_BYTES: usize = 128 * 1024;
const RECEIVE_POLL_MILLIS: u16 = 100;
const CONFIGURATION_TIMEOUT: Duration = Duration::from_secs(1);
const CONFIGURATION_POLL_MILLIS: u16 = 100;
const LEARNING_QUEUE_CAPACITY: usize = 512;
const LEARNING_BATCH_SIZE: usize = 256;
const NFNETLINK_FAMILY_UNSPEC: u8 = 0;

#[derive(Debug)]
pub struct QueueRuntime {
    packet_thread: JoinHandle<()>,
    learning_thread: JoinHandle<()>,
    counters: Arc<NfqueueRuntimeCounters>,
}

impl QueueRuntime {
    pub fn join(self) -> Result<()> {
        let Self {
            packet_thread,
            learning_thread,
            counters,
        } = self;
        let packet = packet_thread.join();
        let learning = learning_thread.join();
        if packet.is_err() || learning.is_err() {
            counters.record_terminal_queue_error();
            bail!("application quarantine worker terminated unexpectedly");
        }
        Ok(())
    }
}

pub fn spawn(
    engine: &SharedEngine,
    shutdown: &Arc<AtomicBool>,
    verdict_strategy: QueueVerdictStrategy,
) -> Result<QueueRuntime> {
    let counters = engine
        .lock()
        .map_err(|_| anyhow!("policy engine mutex is poisoned during NFQUEUE startup"))?
        .nfqueue_counters();
    let queue = QueueSocket::open(APPLICATION_QUEUE_NUMBER)
        .context("cannot bind the fail-closed application packet queue")?;
    let (learning_sender, learning_receiver) = mpsc::sync_channel(LEARNING_QUEUE_CAPACITY);
    let learning_engine = Arc::clone(engine);
    let learning_shutdown = Arc::clone(shutdown);
    let learning_counters = Arc::clone(&counters);
    let learning_thread = thread::Builder::new()
        .name("openshield-app-learning".to_owned())
        .spawn(move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                learning_loop(
                    &learning_receiver,
                    &learning_engine,
                    &learning_shutdown,
                    &learning_counters,
                );
            }));
            if let Err(payload) = outcome {
                error!("application-learning worker panicked; entering fail-closed quarantine");
                // Stop the packet worker first so dropping its NFQUEUE socket
                // is an independent fail-closed boundary even if quarantine
                // persistence encounters another unexpected failure.
                learning_shutdown.store(true, Ordering::Release);
                quarantine_engine(&learning_engine);
                std::panic::resume_unwind(payload);
            }
        })
        .context("cannot spawn bounded application-learning worker")?;

    let packet_engine = Arc::clone(engine);
    let packet_shutdown = Arc::clone(shutdown);
    let packet_counters = Arc::clone(&counters);
    let packet_thread = match thread::Builder::new()
        .name("openshield-nfqueue".to_owned())
        .spawn(move || {
            packet_loop(
                queue,
                &packet_engine,
                &packet_shutdown,
                &learning_sender,
                verdict_strategy,
                &packet_counters,
            );
        }) {
        Ok(thread) => thread,
        Err(error) => {
            shutdown.store(true, Ordering::Release);
            let _ignored = learning_thread.join();
            return Err(error).context("cannot spawn application quarantine worker");
        }
    };

    Ok(QueueRuntime {
        packet_thread,
        learning_thread,
        counters,
    })
}

fn packet_loop(
    mut queue: QueueSocket,
    engine: &SharedEngine,
    shutdown: &AtomicBool,
    learning: &SyncSender<LearningObservation>,
    verdict_strategy: QueueVerdictStrategy,
    counters: &NfqueueRuntimeCounters,
) {
    let resolver = ProcfsResolver::new();
    let mut receive_buffer = vec![0_u8; RECEIVE_BUFFER_BYTES];
    let mut errors = ErrorThrottle::default();

    while !shutdown.load(Ordering::Acquire) {
        match queue.receive(&mut receive_buffer) {
            Ok(QueueReceive::Idle) => {}
            Ok(QueueReceive::Overflow) => {
                // The kernel has already dropped the datagrams that no longer
                // fit the netlink socket. nftables has no queue bypass flag,
                // so affected traffic remains fail-closed. Keep serving later
                // packets instead of turning transient pressure into a global
                // daemon quarantine/restart loop.
                counters.record_queue_overflow();
                errors.report("application packet queue overflowed; affected packets were denied");
            }
            Ok(QueueReceive::Datagram(size)) => {
                for message in NetlinkMessages::new(&receive_buffer[..size]) {
                    let message = match message {
                        Ok(message) => message,
                        Err(error) => {
                            // A malformed kernel datagram can hide the packet
                            // identifier required to return a verdict.  Do not
                            // continue with an unaccounted queued packet: make
                            // the failure observable and move the whole policy
                            // to the explicit fail-closed quarantine.
                            counters.record_terminal_queue_error();
                            errors.report(&format!("invalid netfilter netlink message: {error:#}"));
                            quarantine_engine(engine);
                            shutdown.store(true, Ordering::Release);
                            return;
                        }
                    };
                    if message.message_type != queue_message_type(NFQNL_MSG_PACKET) {
                        continue;
                    }
                    let Some(packet_id) = packet_id(message.payload) else {
                        counters.record_terminal_queue_error();
                        errors.report("queued packet has no bounded packet identifier");
                        quarantine_engine(engine);
                        shutdown.store(true, Ordering::Release);
                        return;
                    };
                    let decision = decide_packet(message.payload, engine, &resolver, learning);
                    if decision.as_ref().is_err_and(is_attribution_timeout) {
                        counters.record_attribution_timeout();
                    }
                    let returned = return_packet_verdict(
                        &mut queue,
                        packet_id,
                        decision,
                        engine,
                        verdict_strategy,
                    );
                    let (accepted, decision_error) = match returned {
                        Ok(returned) => returned,
                        Err(error) => {
                            counters.record_terminal_queue_error();
                            errors.report(&format!(
                                "cannot return fail-closed packet verdict: {error:#}"
                            ));
                            quarantine_engine(engine);
                            shutdown.store(true, Ordering::Release);
                            return;
                        }
                    };
                    if !accepted {
                        counters.record_denied();
                        if let Some(error) = decision_error {
                            errors.report(&format!("application packet denied: {error:#}"));
                        }
                    }
                }
            }
            Err(error) => {
                counters.record_terminal_queue_error();
                errors.report(&format!("application packet queue failed: {error:#}"));
                quarantine_engine(engine);
                shutdown.store(true, Ordering::Release);
                return;
            }
        }
    }
}

fn return_packet_verdict(
    queue: &mut QueueSocket,
    packet_id: u32,
    decision: Result<PacketAuthorization>,
    engine: &SharedEngine,
    verdict_strategy: QueueVerdictStrategy,
) -> Result<(bool, Option<anyhow::Error>)> {
    let authorization = match decision {
        Ok(authorization) => authorization,
        Err(error) => {
            queue.verdict(packet_id, NF_DROP)?;
            return Ok((false, Some(error)));
        }
    };
    let Ok(guard) = engine.lock() else {
        let error = anyhow!("policy engine mutex is poisoned during decision recheck");
        queue.verdict(packet_id, NF_DROP)?;
        return Ok((false, Some(error)));
    };
    let (current_mode, current_flow_generation) = match guard.application_decision_identity() {
        Ok(current) => current,
        Err(error) => {
            drop(guard);
            queue.verdict(packet_id, NF_DROP)?;
            return Ok((false, Some(anyhow!(error.message))));
        }
    };
    if current_mode != authorization.mode
        || current_flow_generation != authorization.flow_generation
    {
        drop(guard);
        queue.verdict(packet_id, NF_DROP)?;
        return Ok((
            false,
            Some(anyhow!(
                "policy changed while application identity was resolved"
            )),
        ));
    }

    // Netfilter processes the verdict and reinjects the packet synchronously
    // inside sendto(2). Retaining the engine guard until it returns prevents
    // an atomic policy reload between this final recheck and the kernel
    // authorization path. nftables continues in its later base chain after
    // NF_ACCEPT and deliberately keeps the pending mark unchanged. iptables
    // NF_ACCEPT would terminate the filter hook, so that backend uses
    // NF_REPEAT plus a kernel verdict mark; its first repeated filter rule
    // consumes the handoff after mangle/OUTPUT has already sanitized SO_MARK.
    let verdict = match verdict_strategy {
        QueueVerdictStrategy::Accept => queue.verdict(packet_id, NF_ACCEPT),
        QueueVerdictStrategy::RepeatWithHandoffMark => queue.verdict_with_mark(
            packet_id,
            NF_REPEAT,
            application_handoff_mark(authorization.packet_mark),
        ),
    };
    drop(guard);
    verdict?;
    Ok((true, None))
}

fn decide_packet(
    payload: &[u8],
    engine: &SharedEngine,
    resolver: &ProcfsResolver,
    learning: &SyncSender<LearningObservation>,
) -> Result<PacketAuthorization> {
    let packet = parse_queued_packet(payload)?;
    let snapshot = engine
        .lock()
        .map_err(|_| anyhow!("policy engine mutex is poisoned"))?
        .application_decision_snapshot()
        .map_err(|error| anyhow!(error.message))?;
    ensure!(
        snapshot.mode != Mode::BlockAll,
        "BlockAll denies queued traffic"
    );
    ensure!(
        packet.packet_mark == application_pending_mark(packet.packet_mark),
        "queued packet does not carry the kernel pending-mark domain"
    );

    let accepted = match snapshot.mode {
        Mode::BlockAll => false,
        Mode::Enforcing => {
            let requirements = snapshot
                .enforcement_capture_requirements(&packet.connection)
                .ok_or_else(|| {
                    anyhow!(
                        "no enabled application rule matches the queued network endpoint and socket UID"
                    )
                })?;
            let identity = resolver
                .resolve_for_enforcement(&packet.connection, requirements)
                .context("cannot establish race-checked process identity")?;
            snapshot
                .matching_rule(&packet.connection, &identity)
                .is_some()
        }
        Mode::Learning => {
            // Learning persists an exact selector, so it must retain the full
            // command line and cgroup capture even though Enforcing can omit
            // optional fields which no candidate rule references.
            let identity = resolver
                .resolve(&packet.connection)
                .context("cannot establish race-checked process identity")?;
            let selector = identity
                .learned_selector()
                .context("cannot create a stable learned application selector")?;
            let endpoint = LearnedEndpoint {
                address: packet.connection.destination_address,
                protocol: packet.connection.protocol,
                port: packet
                    .connection
                    .destination_port
                    .map(openshield_core::PortRange::single)
                    .transpose()?,
                interface: Some(packet.connection.output_interface.clone()),
            };
            let learned = LearnedApplicationEndpoint {
                endpoint,
                application: selector,
            };
            learned.validate()?;
            let admission = engine
                .lock()
                .map_err(|_| anyhow!("policy engine mutex is poisoned during learning admission"))?
                .application_learning_queue_admission(
                    snapshot.mode,
                    snapshot.flow_generation,
                    &learned,
                )
                .map_err(|error| anyhow!(error.message))?;
            match admission {
                LearningQueueAdmission::Enqueue => {
                    let observation = LearningObservation {
                        flow_generation: snapshot.flow_generation,
                        endpoint: learned,
                    };
                    match learning.try_send(observation) {
                        Ok(()) => true,
                        Err(TrySendError::Full(_)) => bail!("bounded learning queue is full"),
                        Err(TrySendError::Disconnected(_)) => {
                            bail!("application-learning worker is unavailable")
                        }
                    }
                }
                LearningQueueAdmission::AlreadyKnown
                | LearningQueueAdmission::Saturated
                | LearningQueueAdmission::PersistencePaused => true,
            }
        }
    };
    ensure!(accepted, "no enabled application rule matched");
    Ok(PacketAuthorization {
        mode: snapshot.mode,
        flow_generation: snapshot.flow_generation,
        packet_mark: packet.packet_mark,
    })
}

fn learning_loop(
    receiver: &Receiver<LearningObservation>,
    engine: &SharedEngine,
    shutdown: &AtomicBool,
    counters: &NfqueueRuntimeCounters,
) {
    while !shutdown.load(Ordering::Acquire) {
        let first = match receiver.recv_timeout(Duration::from_millis(RECEIVE_POLL_MILLIS.into())) {
            Ok(observation) => observation,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        };
        let (generation, endpoints) = collect_learning_batch(first, receiver);
        let result = (|| {
            let transaction = engine
                .lock()
                .map_err(|_| {
                    anyhow!("policy engine mutex is poisoned during application learning")
                })?
                .prepare_application_learning(generation, endpoints)
                .map_err(|error| anyhow!(error.message))?;
            let Some(transaction) = transaction else {
                return Ok(0);
            };

            // Atomic file replacement and both fsync operations deliberately
            // run without the engine mutex. Packet snapshot/admission/final
            // verdict rechecks therefore remain live while storage is slow.
            let persisted = transaction.persist();
            engine
                .lock()
                .map_err(|_| anyhow!("policy engine mutex is poisoned after application learning"))?
                .finalize_application_learning(persisted)
                .map_err(|error| anyhow!(error.message))
        })();
        match result {
            Ok(0) => {}
            Ok(count) => info!(count, "persisted application-bound outbound rules"),
            Err(error) => {
                counters.record_terminal_queue_error();
                error!(error = %format_args!("{error:#}"), "application learning failed");
                quarantine_engine(engine);
                shutdown.store(true, Ordering::Release);
                return;
            }
        }
    }
}

fn collect_learning_batch(
    first: LearningObservation,
    receiver: &Receiver<LearningObservation>,
) -> (u32, Vec<LearnedApplicationEndpoint>) {
    let generation = first.flow_generation;
    let mut known = HashSet::with_capacity(LEARNING_BATCH_SIZE);
    known.insert(first.endpoint.clone());
    let mut endpoints = vec![first.endpoint];
    let mut drained = 1_usize;
    while drained < LEARNING_BATCH_SIZE {
        match receiver.try_recv() {
            Ok(observation) => {
                drained += 1;
                if observation.flow_generation == generation
                    && known.insert(observation.endpoint.clone())
                {
                    endpoints.push(observation.endpoint);
                }
            }
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
        }
    }
    (generation, endpoints)
}

fn quarantine_engine(engine: &SharedEngine) {
    match engine.lock() {
        Ok(mut engine) => engine.quarantine_after_runtime_failure(),
        Err(poisoned) => {
            error!(
                "policy engine mutex is poisoned; installing BlockAll from the recovered backend"
            );
            let mut recovered = poisoned.into_inner();
            recovered.quarantine_after_engine_poison();
            drop(recovered);
            // The recovered Engine is now fatal and contains no trusted live
            // policy claim. Let shutdown paths acquire it only to repeat
            // BlockAll and terminate; normal protocol calls still see fatal.
            engine.clear_poison();
        }
    }
}

#[derive(Clone, Debug)]
struct LearningObservation {
    flow_generation: u32,
    endpoint: LearnedApplicationEndpoint,
}

#[derive(Clone, Copy, Debug)]
struct PacketAuthorization {
    mode: Mode,
    flow_generation: u32,
    packet_mark: u32,
}

#[derive(Clone, Debug)]
struct QueuedPacket {
    connection: OutboundConnection,
    packet_mark: u32,
}

fn parse_queued_packet(payload: &[u8]) -> Result<QueuedPacket> {
    ensure!(
        payload.len() >= NFGENMSG_BYTES,
        "queued packet netlink payload is truncated"
    );
    let attributes = Attributes::new(&payload[NFGENMSG_BYTES..]);
    let mut packet_payload = None;
    let mut uid = None;
    let mut output_index = None;
    let mut mark = None;
    for attribute in attributes {
        let attribute = attribute?;
        match attribute.kind {
            NFQA_PAYLOAD => packet_payload = Some(attribute.payload),
            NFQA_UID => uid = Some(network_u32(attribute.payload)?),
            NFQA_IFINDEX_OUTDEV => output_index = Some(network_u32(attribute.payload)?),
            NFQA_MARK => mark = Some(network_u32(attribute.payload)?),
            _ => {}
        }
    }
    let packet_payload = packet_payload.ok_or_else(|| anyhow!("queued packet has no payload"))?;
    let socket_uid = uid.ok_or_else(|| anyhow!("queued packet has no kernel socket uid"))?;
    let output_index =
        output_index.ok_or_else(|| anyhow!("queued packet has no output interface"))?;
    let packet_mark = mark.ok_or_else(|| anyhow!("queued packet has no kernel packet mark"))?;
    let output_interface = interface_for_index(output_index)?;
    let parsed = parse_ip_packet(packet_payload)?;
    let connection = OutboundConnection {
        source_address: parsed.source_address,
        source_port: parsed.source_port,
        destination_address: parsed.destination_address,
        destination_port: parsed.destination_port,
        protocol: parsed.protocol,
        output_interface,
        socket_uid,
    };
    connection.validate()?;
    Ok(QueuedPacket {
        connection,
        packet_mark,
    })
}

fn packet_id(payload: &[u8]) -> Option<u32> {
    if payload.len() < NFGENMSG_BYTES {
        return None;
    }
    for attribute in Attributes::new(&payload[NFGENMSG_BYTES..]).flatten() {
        if attribute.kind == NFQA_PACKET_HDR && attribute.payload.len() >= PACKET_HEADER_BYTES {
            return attribute
                .payload
                .get(..4)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u32::from_be_bytes);
        }
    }
    None
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParsedIpPacket {
    source_address: std::net::IpAddr,
    source_port: Option<u16>,
    destination_address: std::net::IpAddr,
    destination_port: Option<u16>,
    protocol: TransportProtocol,
}

fn parse_ip_packet(packet: &[u8]) -> Result<ParsedIpPacket> {
    let version = packet
        .first()
        .map(|byte| byte >> 4)
        .ok_or_else(|| anyhow!("queued IP packet is empty"))?;
    match version {
        4 => parse_ipv4_packet(packet),
        6 => parse_ipv6_packet(packet),
        _ => bail!("queued payload is not IPv4 or IPv6"),
    }
}

fn parse_ipv4_packet(packet: &[u8]) -> Result<ParsedIpPacket> {
    ensure!(packet.len() >= 20, "IPv4 header is truncated");
    let header_length = usize::from(packet[0] & 0x0f) * 4;
    ensure!(
        header_length >= 20 && packet.len() >= header_length,
        "invalid IPv4 IHL"
    );
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    ensure!(
        fragment.trailing_zeros() >= 13,
        "non-initial IPv4 fragment is not attributable"
    );
    let source_address = std::net::Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination_address =
        std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    finish_transport(
        source_address.into(),
        destination_address.into(),
        packet[9],
        packet,
        header_length,
    )
}

fn parse_ipv6_packet(packet: &[u8]) -> Result<ParsedIpPacket> {
    ensure!(packet.len() >= 40, "IPv6 header is truncated");
    let source: [u8; 16] = packet[8..24]
        .try_into()
        .map_err(|_| anyhow!("IPv6 source is truncated"))?;
    let destination: [u8; 16] = packet[24..40]
        .try_into()
        .map_err(|_| anyhow!("IPv6 destination is truncated"))?;
    let mut next_header = packet[6];
    let mut offset = 40_usize;
    for _ in 0..8 {
        match next_header {
            0 | 43 | 60 => {
                ensure!(
                    packet.len() >= offset + 2,
                    "IPv6 extension header is truncated"
                );
                next_header = packet[offset];
                let length = (usize::from(packet[offset + 1]) + 1) * 8;
                offset = offset
                    .checked_add(length)
                    .ok_or_else(|| anyhow!("IPv6 extension offset overflow"))?;
                ensure!(packet.len() >= offset, "IPv6 extension data is truncated");
            }
            44 => {
                ensure!(
                    packet.len() >= offset + 8,
                    "IPv6 fragment header is truncated"
                );
                let fragment = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
                ensure!(
                    fragment & 0xfff8 == 0,
                    "non-initial IPv6 fragment is not attributable"
                );
                next_header = packet[offset];
                offset += 8;
            }
            51 => {
                ensure!(packet.len() >= offset + 2, "IPv6 AH header is truncated");
                next_header = packet[offset];
                let length = (usize::from(packet[offset + 1]) + 2) * 4;
                offset = offset
                    .checked_add(length)
                    .ok_or_else(|| anyhow!("IPv6 AH offset overflow"))?;
                ensure!(packet.len() >= offset, "IPv6 AH data is truncated");
            }
            _ => {
                return finish_transport(
                    std::net::Ipv6Addr::from(source).into(),
                    std::net::Ipv6Addr::from(destination).into(),
                    next_header,
                    packet,
                    offset,
                );
            }
        }
    }
    bail!("IPv6 extension-header bound exceeded")
}

fn finish_transport(
    source_address: std::net::IpAddr,
    destination_address: std::net::IpAddr,
    protocol_number: u8,
    packet: &[u8],
    offset: usize,
) -> Result<ParsedIpPacket> {
    let (protocol, source_port, destination_port) = match protocol_number {
        6 | 17 => {
            ensure!(packet.len() >= offset + 4, "transport header is truncated");
            let source = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
            let destination = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
            ensure!(source != 0 && destination != 0, "transport port is zero");
            (
                if protocol_number == 6 {
                    TransportProtocol::Tcp
                } else {
                    TransportProtocol::Udp
                },
                Some(source),
                Some(destination),
            )
        }
        1 if source_address.is_ipv4() => {
            ensure!(packet.len() >= offset + 8, "ICMP header is truncated");
            ensure!(
                packet[offset] == 8 && packet[offset + 1] == 0,
                "only outbound ICMP echo requests can be attributed"
            );
            let identifier = u16::from_be_bytes([packet[offset + 4], packet[offset + 5]]);
            (TransportProtocol::Icmp, Some(identifier), None)
        }
        58 if source_address.is_ipv6() => {
            ensure!(packet.len() >= offset + 8, "ICMPv6 header is truncated");
            ensure!(
                packet[offset] == 128 && packet[offset + 1] == 0,
                "only outbound ICMPv6 echo requests can be attributed"
            );
            let identifier = u16::from_be_bytes([packet[offset + 4], packet[offset + 5]]);
            (TransportProtocol::IcmpV6, Some(identifier), None)
        }
        _ => bail!("queued packet uses an unsupported transport protocol"),
    };
    Ok(ParsedIpPacket {
        source_address,
        source_port,
        destination_address,
        destination_port,
        protocol,
    })
}

fn interface_for_index(index: u32) -> Result<InterfaceName> {
    ensure!(index != 0, "output interface index is zero");
    let name = if_indextoname(index).context("output interface index does not exist")?;
    let name = name
        .into_string()
        .map_err(|_| anyhow!("interface name is not UTF-8"))?;
    InterfaceName::new(name).context("output interface name is invalid")
}

#[derive(Debug)]
struct QueueSocket {
    socket: OwnedFd,
    queue_number: u16,
    sequence: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QueueReceive {
    Idle,
    Datagram(usize),
    Overflow,
}

impl QueueSocket {
    fn open(queue_number: u16) -> Result<Self> {
        let socket = socket(
            AddressFamily::Netlink,
            SockType::Raw,
            // Verdict delivery happens while the policy-engine guard is held
            // so a restrictive policy reload cannot race packet reinjection.
            // A blocking netlink send would therefore let kernel-buffer
            // pressure freeze all control operations.  Fail closed on EAGAIN
            // instead: the caller quarantines the engine and closing the
            // queue causes outstanding packets to be denied.
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
            SockProtocol::NetlinkNetFilter,
        )
        .context("cannot create NETLINK_NETFILTER socket")?;
        bind(socket.as_raw_fd(), &NetlinkAddr::new(0, 0))
            .context("cannot bind NETLINK_NETFILTER socket")?;
        let mut queue = Self {
            socket,
            queue_number,
            sequence: 0,
        };
        queue.configure_command(NFQNL_CFG_CMD_BIND)?;
        queue.configure_parameters()?;
        Ok(queue)
    }

    fn configure_command(&mut self, command: u8) -> Result<()> {
        let payload = [command, 0, 0, 0];
        self.configuration(&[(NFQA_CFG_CMD, payload.as_slice())])
    }

    fn configure_parameters(&mut self) -> Result<()> {
        let mut parameters = Vec::with_capacity(5);
        parameters.extend_from_slice(&COPY_RANGE.to_be_bytes());
        parameters.push(NFQNL_COPY_PACKET);
        let queue_length = QUEUE_MAX_LENGTH.to_be_bytes();
        let flags = NFQA_CFG_F_UID_GID.to_be_bytes();
        let mask = NFQA_CFG_F_UID_GID.to_be_bytes();
        self.configuration(&[
            (NFQA_CFG_PARAMS, parameters.as_slice()),
            (NFQA_CFG_QUEUE_MAXLEN, queue_length.as_slice()),
            (NFQA_CFG_FLAGS, flags.as_slice()),
            (NFQA_CFG_MASK, mask.as_slice()),
        ])
    }

    fn configuration(&mut self, attributes: &[(u16, &[u8])]) -> Result<()> {
        let sequence = self.next_sequence();
        let message = build_message(
            queue_message_type(NFQNL_MSG_CONFIG),
            NLM_F_REQUEST | NLM_F_ACK,
            sequence,
            NFNETLINK_FAMILY_UNSPEC,
            self.queue_number,
            attributes,
        )?;
        let sent = sendto(
            self.socket.as_raw_fd(),
            &message,
            &NetlinkAddr::new(0, 0),
            MsgFlags::empty(),
        )
        .context("cannot send NFQUEUE configuration")?;
        ensure!(sent == message.len(), "NFQUEUE configuration was truncated");
        self.wait_for_ack(sequence)
    }

    fn wait_for_ack(&mut self, expected_sequence: u32) -> Result<()> {
        let deadline = Instant::now() + CONFIGURATION_TIMEOUT;
        let mut buffer = vec![0_u8; RECEIVE_BUFFER_BYTES].into_boxed_slice();
        loop {
            ensure!(
                Instant::now() <= deadline,
                "NFQUEUE configuration acknowledgement timed out"
            );
            let mut descriptor = [PollFd::new(self.socket.as_fd(), PollFlags::POLLIN)];
            let ready = match poll(&mut descriptor, CONFIGURATION_POLL_MILLIS) {
                Ok(ready) => ready,
                Err(Errno::EINTR) => continue,
                Err(error) => {
                    return Err(error).context("cannot poll NFQUEUE configuration acknowledgement");
                }
            };
            if ready == 0 {
                continue;
            }
            let events = descriptor[0].revents().unwrap_or_else(PollFlags::empty);
            ensure!(
                !events.intersects(PollFlags::POLLHUP | PollFlags::POLLNVAL),
                "NFQUEUE socket closed while awaiting configuration acknowledgement"
            );
            let size = match recv(self.socket.as_raw_fd(), &mut buffer, MsgFlags::MSG_TRUNC) {
                Ok(size) => size,
                Err(Errno::EINTR | Errno::EAGAIN | Errno::ENOBUFS) => continue,
                Err(error) => {
                    return Err(error)
                        .context("cannot receive NFQUEUE configuration acknowledgement");
                }
            };
            ensure!(
                size <= buffer.len(),
                "NFQUEUE configuration datagram exceeded its fixed buffer"
            );
            let mut acknowledged = false;
            for message in NetlinkMessages::new(&buffer[..size]) {
                let message = message?;
                if message.message_type == NLMSG_ERROR && message.sequence == expected_sequence {
                    ensure!(
                        message.payload.len() >= 4,
                        "netlink acknowledgement is truncated"
                    );
                    let error = i32::from_ne_bytes(
                        message.payload[..4]
                            .try_into()
                            .map_err(|_| anyhow!("netlink acknowledgement is malformed"))?,
                    );
                    ensure!(
                        error == 0,
                        "kernel rejected NFQUEUE configuration: errno {}",
                        -error
                    );
                    acknowledged = true;
                } else if message.message_type == queue_message_type(NFQNL_MSG_PACKET) {
                    // Once BIND succeeds, packets may race ahead of its ACK.
                    // Deny them until all queue configuration is complete,
                    // rather than treating their interleaving as startup DoS.
                    if let Some(packet_id) = packet_id(message.payload) {
                        self.verdict(packet_id, NF_DROP)?;
                    }
                }
            }
            if acknowledged {
                return Ok(());
            }
        }
    }

    fn receive(&mut self, buffer: &mut [u8]) -> Result<QueueReceive> {
        let mut descriptor = [PollFd::new(self.socket.as_fd(), PollFlags::POLLIN)];
        let ready = match poll(&mut descriptor, RECEIVE_POLL_MILLIS) {
            Ok(ready) => ready,
            Err(Errno::EINTR | Errno::EAGAIN) => return Ok(QueueReceive::Idle),
            Err(error) => return Err(error).context("cannot poll NFQUEUE socket"),
        };
        if ready == 0 {
            return Ok(QueueReceive::Idle);
        }
        let events = descriptor[0].revents().unwrap_or_else(PollFlags::empty);
        ensure!(
            !events.intersects(PollFlags::POLLHUP | PollFlags::POLLNVAL),
            "NFQUEUE socket reported a terminal poll event"
        );
        let size = match recv(self.socket.as_raw_fd(), buffer, MsgFlags::MSG_TRUNC) {
            Ok(size) => size,
            Err(Errno::EINTR) => return Ok(QueueReceive::Idle),
            Err(Errno::ENOBUFS) => return Ok(QueueReceive::Overflow),
            Err(error) => return Err(error).context("cannot receive queued packet"),
        };
        ensure!(
            size <= buffer.len(),
            "queued netlink datagram exceeded its fixed buffer"
        );
        Ok(QueueReceive::Datagram(size))
    }

    fn verdict(&mut self, packet_id: u32, verdict: u32) -> Result<()> {
        self.send_verdict(packet_id, verdict, None)
    }

    fn verdict_with_mark(&mut self, packet_id: u32, verdict: u32, mark: u32) -> Result<()> {
        self.send_verdict(packet_id, verdict, Some(mark))
    }

    fn send_verdict(&mut self, packet_id: u32, verdict: u32, mark: Option<u32>) -> Result<()> {
        let sequence = self.next_sequence();
        let message = build_verdict_message(sequence, self.queue_number, packet_id, verdict, mark)?;
        let sent = sendto(
            self.socket.as_raw_fd(),
            &message,
            &NetlinkAddr::new(0, 0),
            MsgFlags::empty(),
        )
        .context("cannot send NFQUEUE verdict")?;
        ensure!(sent == message.len(), "NFQUEUE verdict was truncated");
        Ok(())
    }

    fn next_sequence(&mut self) -> u32 {
        advance_netlink_sequence(&mut self.sequence)
    }
}

fn advance_netlink_sequence(sequence: &mut u32) -> u32 {
    *sequence = sequence.wrapping_add(1);
    if *sequence == 0 {
        // Zero conventionally denotes an unsolicited netlink message.
        *sequence = 1;
    }
    *sequence
}

fn build_verdict_message(
    sequence: u32,
    queue_number: u16,
    packet_id: u32,
    verdict: u32,
    mark: Option<u32>,
) -> Result<Vec<u8>> {
    let mut verdict_header = Vec::with_capacity(8);
    verdict_header.extend_from_slice(&verdict.to_be_bytes());
    verdict_header.extend_from_slice(&packet_id.to_be_bytes());
    if let Some(mark) = mark {
        let mark = mark.to_be_bytes();
        build_message(
            queue_message_type(NFQNL_MSG_VERDICT),
            NLM_F_REQUEST,
            sequence,
            NFNETLINK_FAMILY_UNSPEC,
            queue_number,
            &[
                (NFQA_VERDICT_HDR, verdict_header.as_slice()),
                (NFQA_MARK, mark.as_slice()),
            ],
        )
    } else {
        build_message(
            queue_message_type(NFQNL_MSG_VERDICT),
            NLM_F_REQUEST,
            sequence,
            NFNETLINK_FAMILY_UNSPEC,
            queue_number,
            &[(NFQA_VERDICT_HDR, verdict_header.as_slice())],
        )
    }
}

impl Drop for QueueSocket {
    fn drop(&mut self) {
        let _ignored = self.configure_command(NFQNL_CFG_CMD_UNBIND);
    }
}

fn queue_message_type(operation: u16) -> u16 {
    (NFNL_SUBSYS_QUEUE << 8) | operation
}

fn build_message(
    message_type: u16,
    flags: u16,
    sequence: u32,
    family: u8,
    resource_id: u16,
    attributes: &[(u16, &[u8])],
) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    payload.push(family);
    payload.push(0);
    payload.extend_from_slice(&resource_id.to_be_bytes());
    for (kind, value) in attributes {
        append_attribute(&mut payload, *kind, value)?;
    }
    let length = NETLINK_HEADER_BYTES
        .checked_add(payload.len())
        .ok_or_else(|| anyhow!("netlink message size overflow"))?;
    let length = u32::try_from(length).context("netlink message is oversized")?;
    let capacity = usize::try_from(length).context("netlink message length does not fit usize")?;
    let mut message = Vec::with_capacity(capacity);
    message.extend_from_slice(&length.to_ne_bytes());
    message.extend_from_slice(&message_type.to_ne_bytes());
    message.extend_from_slice(&flags.to_ne_bytes());
    message.extend_from_slice(&sequence.to_ne_bytes());
    message.extend_from_slice(&0_u32.to_ne_bytes());
    message.extend_from_slice(&payload);
    Ok(message)
}

fn append_attribute(message: &mut Vec<u8>, kind: u16, payload: &[u8]) -> Result<()> {
    let length = ATTRIBUTE_HEADER_BYTES
        .checked_add(payload.len())
        .ok_or_else(|| anyhow!("netlink attribute size overflow"))?;
    let encoded_length = u16::try_from(length).context("netlink attribute is oversized")?;
    message.extend_from_slice(&encoded_length.to_ne_bytes());
    message.extend_from_slice(&kind.to_ne_bytes());
    message.extend_from_slice(payload);
    let aligned = align4(length)?;
    message.resize(
        message
            .len()
            .checked_add(aligned - length)
            .ok_or_else(|| anyhow!("netlink padding overflow"))?,
        0,
    );
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct NetlinkMessage<'a> {
    message_type: u16,
    sequence: u32,
    payload: &'a [u8],
}

#[derive(Clone, Debug)]
struct NetlinkMessages<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> NetlinkMessages<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
}

impl<'a> Iterator for NetlinkMessages<'a> {
    type Item = Result<NetlinkMessage<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset == self.bytes.len() {
            return None;
        }
        let Some(remaining) = self.bytes.get(self.offset..) else {
            return Some(Err(anyhow!("netlink offset is outside the datagram")));
        };
        if remaining.len() < NETLINK_HEADER_BYTES {
            self.offset = self.bytes.len();
            return Some(Err(anyhow!("netlink header is truncated")));
        }
        let Ok(length_bytes) = remaining[..4].try_into() else {
            self.offset = self.bytes.len();
            return Some(Err(anyhow!("netlink length is malformed")));
        };
        let length = u32::from_ne_bytes(length_bytes);
        let length = match usize::try_from(length) {
            Ok(length) if length >= NETLINK_HEADER_BYTES && length <= remaining.len() => length,
            _ => {
                self.offset = self.bytes.len();
                return Some(Err(anyhow!("netlink message length is invalid")));
            }
        };
        let aligned = match align4(length) {
            Ok(aligned) if aligned <= remaining.len() => aligned,
            // Netlink alignment is required between multipart messages, but
            // the kernel may omit the final message's trailing padding from a
            // datagram. Accept only an exact terminal boundary; one or more
            // stray/truncated padding bytes still fail closed below.
            Ok(_) if length == remaining.len() => length,
            _ => {
                self.offset = self.bytes.len();
                return Some(Err(anyhow!("netlink message alignment is invalid")));
            }
        };
        let message_type = u16::from_ne_bytes([remaining[4], remaining[5]]);
        let sequence =
            u32::from_ne_bytes([remaining[8], remaining[9], remaining[10], remaining[11]]);
        let payload = &remaining[NETLINK_HEADER_BYTES..length];
        self.offset += aligned;
        Some(Ok(NetlinkMessage {
            message_type,
            sequence,
            payload,
        }))
    }
}

#[derive(Clone, Copy, Debug)]
struct Attribute<'a> {
    kind: u16,
    payload: &'a [u8],
}

#[derive(Clone, Debug)]
struct Attributes<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Attributes<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
}

impl<'a> Iterator for Attributes<'a> {
    type Item = Result<Attribute<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset == self.bytes.len() {
            return None;
        }
        let Some(remaining) = self.bytes.get(self.offset..) else {
            return Some(Err(anyhow!("attribute offset is invalid")));
        };
        if remaining.len() < ATTRIBUTE_HEADER_BYTES {
            self.offset = self.bytes.len();
            return Some(Err(anyhow!("netlink attribute header is truncated")));
        }
        let length = usize::from(u16::from_ne_bytes([remaining[0], remaining[1]]));
        let kind = u16::from_ne_bytes([remaining[2], remaining[3]]) & 0x3fff;
        if length < ATTRIBUTE_HEADER_BYTES || length > remaining.len() {
            self.offset = self.bytes.len();
            return Some(Err(anyhow!("netlink attribute length is invalid")));
        }
        let aligned = match align4(length) {
            Ok(aligned) if aligned <= remaining.len() => aligned,
            // As with the containing netlink message, a final attribute may
            // end exactly at the datagram boundary without its alignment pad.
            Ok(_) if length == remaining.len() => length,
            _ => {
                self.offset = self.bytes.len();
                return Some(Err(anyhow!("netlink attribute alignment is invalid")));
            }
        };
        let payload = &remaining[ATTRIBUTE_HEADER_BYTES..length];
        self.offset += aligned;
        Some(Ok(Attribute { kind, payload }))
    }
}

fn align4(value: usize) -> Result<usize> {
    value
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or_else(|| anyhow!("netlink alignment overflow"))
}

fn network_u32(bytes: &[u8]) -> Result<u32> {
    ensure!(
        bytes.len() == 4,
        "network u32 attribute has an invalid size"
    );
    Ok(u32::from_be_bytes(bytes.try_into().map_err(|_| {
        anyhow!("network u32 attribute is malformed")
    })?))
}

#[derive(Debug, Default)]
struct ErrorThrottle {
    last_log: Option<Instant>,
    suppressed: u64,
}

impl ErrorThrottle {
    fn report(&mut self, message: &str) {
        let now = Instant::now();
        if self
            .last_log
            .is_none_or(|last| now.duration_since(last) >= Duration::from_secs(10))
        {
            warn!(
                suppressed = self.suppressed,
                message, "application packet denied"
            );
            self.last_log = Some(now);
            self.suppressed = 0;
        } else {
            self.suppressed = self.suppressed.saturating_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use openshield_core::{ApplicationPath, ApplicationSelector, ExecutableFileId, PortRange};

    use super::*;

    fn learning_observation(generation: u32, address_offset: u32) -> Result<LearningObservation> {
        Ok(LearningObservation {
            flow_generation: generation,
            endpoint: LearnedApplicationEndpoint {
                endpoint: LearnedEndpoint {
                    address: std::net::Ipv4Addr::from(0x0a00_0001_u32 + address_offset).into(),
                    protocol: TransportProtocol::Tcp,
                    port: Some(PortRange::single(443)?),
                    interface: Some(InterfaceName::new("eth0")?),
                },
                application: ApplicationSelector::new(
                    Some(ApplicationPath::new("/usr/bin/openshield-nfqueue-test")?),
                    Some(ExecutableFileId {
                        device: 8,
                        inode: 42,
                        size: 1_024,
                        ctime_seconds: 1_700_000_000,
                        ctime_nanoseconds: 0,
                    }),
                    None,
                    Some(1_000),
                    None,
                )?,
            },
        })
    }

    #[test]
    fn resolves_interface_name_directly_from_the_kernel_index() -> Result<(), Box<dyn Error>> {
        let loopback_index = nix::net::if_::if_nametoindex("lo")?;
        assert_eq!(interface_for_index(loopback_index)?.as_str(), "lo");
        assert!(interface_for_index(0).is_err());
        Ok(())
    }

    #[test]
    fn learning_batch_coalesces_duplicates_and_discards_stale_generations()
    -> Result<(), Box<dyn Error>> {
        let (sender, receiver) = mpsc::sync_channel(LEARNING_QUEUE_CAPACITY);
        let first = learning_observation(7, 1)?;
        sender.try_send(first.clone())?;
        sender.try_send(learning_observation(7, 2)?)?;
        sender.try_send(learning_observation(8, 3)?)?;

        let (generation, endpoints) = collect_learning_batch(first, &receiver);
        assert_eq!(generation, 7);
        assert_eq!(endpoints.len(), 2);
        assert_eq!(
            endpoints[0].endpoint.address,
            "10.0.0.2".parse::<std::net::IpAddr>()?
        );
        assert_eq!(
            endpoints[1].endpoint.address,
            "10.0.0.3".parse::<std::net::IpAddr>()?
        );
        Ok(())
    }

    #[test]
    fn duplicate_storm_does_not_make_one_batch_drain_without_bound() -> Result<(), Box<dyn Error>> {
        let (sender, receiver) = mpsc::sync_channel(LEARNING_QUEUE_CAPACITY);
        let first = learning_observation(7, 1)?;
        for _ in 0..LEARNING_BATCH_SIZE {
            sender.try_send(first.clone())?;
        }

        let (_generation, endpoints) = collect_learning_batch(first, &receiver);
        assert_eq!(endpoints.len(), 1);
        assert!(receiver.try_recv().is_ok());
        Ok(())
    }

    #[test]
    fn message_and_attribute_parsers_reject_truncation() {
        assert!(
            NetlinkMessages::new(&[1, 2, 3])
                .next()
                .is_some_and(|item| item.is_err())
        );
        assert!(
            Attributes::new(&[1, 2, 3])
                .next()
                .is_some_and(|item| item.is_err())
        );
    }

    #[test]
    fn parsers_accept_only_exact_unpadded_terminal_items() -> Result<(), Box<dyn Error>> {
        let mut message = vec![0_u8; NETLINK_HEADER_BYTES + 1];
        let message_length = u32::try_from(message.len())?;
        message[..4].copy_from_slice(&message_length.to_ne_bytes());
        message[4..6].copy_from_slice(&7_u16.to_ne_bytes());
        let parsed = NetlinkMessages::new(&message)
            .next()
            .ok_or("missing unpadded message")??;
        assert_eq!(parsed.payload, &[0]);

        message.push(0);
        assert!(
            NetlinkMessages::new(&message)
                .next()
                .is_some_and(|item| item.is_err())
        );

        let mut attribute = vec![0_u8; ATTRIBUTE_HEADER_BYTES + 1];
        let attribute_length = u16::try_from(attribute.len())?;
        attribute[..2].copy_from_slice(&attribute_length.to_ne_bytes());
        attribute[2..4].copy_from_slice(&9_u16.to_ne_bytes());
        let parsed = Attributes::new(&attribute)
            .next()
            .ok_or("missing unpadded attribute")??;
        assert_eq!(parsed.kind, 9);
        assert_eq!(parsed.payload, &[0]);

        attribute.push(0);
        assert!(
            Attributes::new(&attribute)
                .next()
                .is_some_and(|item| item.is_err())
        );
        Ok(())
    }

    #[test]
    fn configuration_message_is_bounded_and_uses_network_order_attributes()
    -> Result<(), Box<dyn Error>> {
        let queue_length = QUEUE_MAX_LENGTH.to_be_bytes();
        let message = build_message(
            queue_message_type(NFQNL_MSG_CONFIG),
            NLM_F_REQUEST,
            7,
            0,
            APPLICATION_QUEUE_NUMBER,
            &[(NFQA_CFG_QUEUE_MAXLEN, queue_length.as_slice())],
        )?;
        let parsed = NetlinkMessages::new(&message)
            .next()
            .ok_or("missing message")??;
        assert_eq!(parsed.message_type, queue_message_type(NFQNL_MSG_CONFIG));
        assert_eq!(parsed.sequence, 7);
        let attribute = Attributes::new(&parsed.payload[NFGENMSG_BYTES..])
            .next()
            .ok_or("missing attribute")??;
        assert_eq!(attribute.kind, NFQA_CFG_QUEUE_MAXLEN);
        assert_eq!(network_u32(attribute.payload)?, QUEUE_MAX_LENGTH);
        Ok(())
    }

    #[test]
    fn netlink_sequence_wraps_without_entering_the_unsolicited_zero_domain() {
        let mut sequence = u32::MAX;
        assert_eq!(advance_netlink_sequence(&mut sequence), 1);
        assert_eq!(advance_netlink_sequence(&mut sequence), 2);
    }

    #[test]
    fn parses_ipv4_tcp_tuple() -> Result<(), Box<dyn Error>> {
        let mut packet = vec![0_u8; 40];
        packet[0] = 0x45;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[203, 0, 113, 7]);
        packet[20..22].copy_from_slice(&50_000_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
        let parsed = parse_ip_packet(&packet)?;
        assert_eq!(
            parsed.source_address,
            "192.0.2.1".parse::<std::net::IpAddr>()?
        );
        assert_eq!(
            parsed.destination_address,
            "203.0.113.7".parse::<std::net::IpAddr>()?
        );
        assert_eq!(parsed.source_port, Some(50_000));
        assert_eq!(parsed.destination_port, Some(443));
        assert_eq!(parsed.protocol, TransportProtocol::Tcp);
        Ok(())
    }

    #[test]
    fn parses_only_attributable_icmp_echo_identifiers() -> Result<(), Box<dyn Error>> {
        let mut packet = vec![0_u8; 28];
        packet[0] = 0x45;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[203, 0, 113, 7]);
        packet[20] = 8;
        packet[24..26].copy_from_slice(&4_242_u16.to_be_bytes());
        let parsed = parse_ip_packet(&packet)?;
        assert_eq!(parsed.protocol, TransportProtocol::Icmp);
        assert_eq!(parsed.source_port, Some(4_242));
        assert_eq!(parsed.destination_port, None);

        packet[20] = 3;
        assert!(parse_ip_packet(&packet).is_err());
        Ok(())
    }

    #[test]
    fn drops_non_initial_fragments_and_deep_ipv6_extensions() {
        let mut ipv4 = vec![0_u8; 20];
        ipv4[0] = 0x45;
        ipv4[6..8].copy_from_slice(&1_u16.to_be_bytes());
        assert!(parse_ip_packet(&ipv4).is_err());

        let mut ipv6 = vec![0_u8; 40 + 9 * 8];
        ipv6[0] = 0x60;
        ipv6[6] = 0;
        for index in 0..9 {
            let offset = 40 + index * 8;
            ipv6[offset] = 0;
            ipv6[offset + 1] = 0;
        }
        assert!(parse_ip_packet(&ipv6).is_err());
    }

    #[test]
    fn nft_accept_and_drop_verdicts_do_not_carry_a_mark() -> Result<(), Box<dyn Error>> {
        for verdict in [NF_DROP, NF_ACCEPT] {
            let message = build_verdict_message(1, APPLICATION_QUEUE_NUMBER, 7, verdict, None)?;
            let netlink = NetlinkMessages::new(&message)
                .next()
                .ok_or("missing verdict message")??;
            let attributes =
                Attributes::new(&netlink.payload[NFGENMSG_BYTES..]).collect::<Result<Vec<_>>>()?;
            let header = attributes
                .iter()
                .find(|attribute| attribute.kind == NFQA_VERDICT_HDR)
                .ok_or("missing verdict header")?;
            assert_eq!(network_u32(&header.payload[..4])?, verdict);
            assert_eq!(network_u32(&header.payload[4..])?, 7);
            let mark = attributes
                .iter()
                .find(|attribute| attribute.kind == NFQA_MARK)
                .map(|attribute| network_u32(attribute.payload))
                .transpose()?;
            assert_eq!(mark, None);
        }
        Ok(())
    }

    #[test]
    fn iptables_repeat_verdict_carries_the_handoff_mark() -> Result<(), Box<dyn Error>> {
        let mark = application_handoff_mark(0x0012_3456);
        let message = build_verdict_message(1, APPLICATION_QUEUE_NUMBER, 7, NF_REPEAT, Some(mark))?;
        let netlink = NetlinkMessages::new(&message)
            .next()
            .ok_or("missing verdict message")??;
        let attributes =
            Attributes::new(&netlink.payload[NFGENMSG_BYTES..]).collect::<Result<Vec<_>>>()?;
        let header = attributes
            .iter()
            .find(|attribute| attribute.kind == NFQA_VERDICT_HDR)
            .ok_or("missing verdict header")?;
        assert_eq!(network_u32(&header.payload[..4])?, NF_REPEAT);
        assert_eq!(network_u32(&header.payload[4..])?, 7);
        let returned_mark = attributes
            .iter()
            .find(|attribute| attribute.kind == NFQA_MARK)
            .ok_or("missing verdict mark")?;
        assert_eq!(network_u32(returned_mark.payload)?, mark);
        Ok(())
    }

    #[test]
    fn pending_mark_domain_preserves_unreserved_fwmark_bits() {
        for original in [0, 1, 0x0012_3456, 0x3fff_ffff, 0xffff_ffff] {
            let pending = application_pending_mark(original);
            assert_eq!(pending & 0x3fff_ffff, original & 0x3fff_ffff);
            assert_eq!(application_pending_mark(pending), pending);
        }
    }
}
