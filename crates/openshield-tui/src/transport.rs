use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
#[cfg(target_has_atomic = "64")]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, OnceLock};
use std::sync::{Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use nix::unistd::{Group, getegid, geteuid, getgroups};
use openshield_core::{Event, MAX_RULES, Mode, Rule, Snapshot};
use openshield_protocol::{
    Ack, CONTROL_SOCKET_PATH, ControlRequest, FirewallBackendKind, FrameError, MAX_RULES_PER_PAGE,
    OBSERVE_GROUP_NAME, OBSERVE_SOCKET_PATH, ReadRequest, Request, Response, read_response,
    write_request,
};
use thiserror::Error;
use uuid::Uuid;

use crate::i18n::I18n;

// The daemon may publish 256 learned RuleCreated events in one transaction.
// Preserve that complete real-time burst plus connection, snapshot, and counter
// headroom while retaining a fixed memory bound.
const UPDATE_CHANNEL_CAPACITY: usize = 512;
const SNAPSHOT_INTERVAL: Duration = Duration::from_secs(2);
const INITIAL_RECONNECT_DELAY: Duration = Duration::from_millis(250);
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(5);
const IPC_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const CONTROL_SOCKET_MODE: u32 = 0o600;
const OBSERVE_SOCKET_MODE: u32 = 0o660;

/// A portable loss counter. Some supported 32-bit Linux targets do not expose
/// native 64-bit atomics, so they use the same bounded value behind a mutex.
#[derive(Debug, Default)]
struct DroppedCounter {
    #[cfg(target_has_atomic = "64")]
    value: AtomicU64,
    #[cfg(not(target_has_atomic = "64"))]
    value: Mutex<u64>,
}

impl DroppedCounter {
    const fn new() -> Self {
        Self {
            #[cfg(target_has_atomic = "64")]
            value: AtomicU64::new(0),
            #[cfg(not(target_has_atomic = "64"))]
            value: Mutex::new(0),
        }
    }

    fn add(&self, count: u64) {
        #[cfg(target_has_atomic = "64")]
        {
            self.value.fetch_add(count, Ordering::AcqRel);
        }
        #[cfg(not(target_has_atomic = "64"))]
        {
            let mut value = self
                .value
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *value = value.saturating_add(count);
        }
    }

    fn take(&self) -> u64 {
        #[cfg(target_has_atomic = "64")]
        {
            self.value.swap(0, Ordering::AcqRel)
        }
        #[cfg(not(target_has_atomic = "64"))]
        {
            let mut value = self
                .value
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::take(&mut *value)
        }
    }

    #[cfg(test)]
    fn load(&self) -> u64 {
        #[cfg(target_has_atomic = "64")]
        {
            self.value.load(Ordering::Acquire)
        }
        #[cfg(not(target_has_atomic = "64"))]
        {
            *self
                .value
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SocketTrust {
    Control,
    Observe,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketPathIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Debug)]
pub struct SocketPaths {
    pub observe: PathBuf,
    pub control: PathBuf,
    observe_is_test: bool,
    control_is_test: bool,
}

impl SocketPaths {
    #[must_use]
    pub fn fixed() -> Self {
        Self {
            observe: PathBuf::from(OBSERVE_SOCKET_PATH),
            control: PathBuf::from(CONTROL_SOCKET_PATH),
            observe_is_test: false,
            control_is_test: false,
        }
    }

    #[cfg(test)]
    #[must_use]
    pub fn for_explicit_testing(
        observe_override: Option<PathBuf>,
        control_override: Option<PathBuf>,
    ) -> Self {
        let observe_is_test = observe_override.is_some();
        let control_is_test = control_override.is_some();
        let observe = match observe_override {
            Some(path) => path,
            None => PathBuf::from(OBSERVE_SOCKET_PATH),
        };
        let control = match control_override {
            Some(path) => path,
            None => PathBuf::from(CONTROL_SOCKET_PATH),
        };
        Self {
            observe,
            control,
            observe_is_test,
            control_is_test,
        }
    }

    #[cfg(test)]
    #[must_use]
    pub const fn uses_testing_override(&self) -> bool {
        self.observe_is_test || self.control_is_test
    }
}

#[derive(Clone, Debug)]
pub enum ObserverUpdate {
    Connected,
    Disconnected(String),
    TelemetryConnected,
    TelemetryDisconnected(String),
    Snapshot {
        snapshot: Snapshot,
        backend: FirewallBackendKind,
    },
    Restarted {
        snapshot: Snapshot,
        backend: FirewallBackendKind,
    },
    Event(Box<Event>),
    Dropped(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkerKind {
    Snapshot,
    Telemetry,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OfferOutcome {
    Delivered,
    Dropped,
    Disconnected,
}

#[derive(Clone)]
struct ObserverWorkerContext {
    running: Arc<AtomicBool>,
    revision: Arc<Mutex<RevisionEpoch>>,
    dropped: Arc<DroppedCounter>,
    i18n: I18n,
}

#[derive(Debug)]
struct RevisionEpoch {
    revision: u64,
    generation: u64,
    mode: Option<Mode>,
    rule_count: Option<u32>,
    backend: Option<FirewallBackendKind>,
    resync_required: bool,
    restart_update_pending: bool,
}

impl Default for RevisionEpoch {
    fn default() -> Self {
        Self {
            revision: 0,
            generation: 0,
            mode: None,
            rule_count: None,
            backend: None,
            resync_required: true,
            restart_update_pending: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PolicyStatus {
    revision: u64,
    mode: Mode,
    rule_count: u32,
    backend: FirewallBackendKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EventEnqueueOutcome {
    Delivered,
    Dropped,
    GenerationChanged,
    Disconnected,
}

#[derive(Debug)]
pub struct Observer {
    receiver: Receiver<ObserverUpdate>,
    running: Arc<AtomicBool>,
    revision: Arc<Mutex<RevisionEpoch>>,
    _threads: Vec<JoinHandle<()>>,
}

impl Observer {
    #[must_use]
    pub fn start(paths: &SocketPaths, i18n: &I18n) -> Self {
        let (sender, receiver) = mpsc::sync_channel(UPDATE_CHANNEL_CAPACITY);
        let running = Arc::new(AtomicBool::new(true));
        let revision = Arc::new(Mutex::new(RevisionEpoch::default()));
        let dropped = Arc::new(DroppedCounter::new());
        let snapshot_state = Arc::new(AtomicU8::new(0));
        let telemetry_state = Arc::new(AtomicU8::new(0));
        let worker_context = ObserverWorkerContext {
            running: Arc::clone(&running),
            revision: Arc::clone(&revision),
            dropped: Arc::clone(&dropped),
            i18n: i18n.clone(),
        };

        let snapshot_thread = spawn_snapshot_worker(
            paths.observe.clone(),
            paths.observe_is_test,
            sender.clone(),
            worker_context.clone(),
            snapshot_state,
        );
        let event_thread = spawn_event_worker(
            paths.observe.clone(),
            paths.observe_is_test,
            sender,
            worker_context,
            telemetry_state,
        );

        Self {
            receiver,
            running,
            revision,
            _threads: vec![snapshot_thread, event_thread],
        }
    }

    pub fn try_recv(&self) -> Result<ObserverUpdate, mpsc::TryRecvError> {
        self.receiver.try_recv()
    }

    /// Forces the snapshot worker to reload policy after a rejected stale
    /// mutation. The original command is deliberately never retried.
    pub fn request_resync(&self) -> Result<(), IpcError> {
        mark_resync_required(&self.revision)
    }
}

impl Drop for Observer {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Release);
    }
}

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("cannot inspect IPC path {path}: {source}")]
    Inspect { path: PathBuf, source: io::Error },
    #[error("IPC parent directory is not trusted: {0}")]
    UntrustedDirectory(PathBuf),
    #[error("IPC path is not a root-owned Unix socket: {0}")]
    UntrustedSocket(PathBuf),
    #[error("cannot resolve required observation group {OBSERVE_GROUP_NAME}: {0}")]
    ObserverGroup(String),
    #[error("the current user is neither root nor a member of group {OBSERVE_GROUP_NAME}")]
    NotObserverGroupMember,
    #[error("cannot read the current process supplementary groups: {0}")]
    LocalGroups(#[source] nix::Error),
    #[error("IPC socket pathname changed while connecting: {0}")]
    SocketPathChanged(PathBuf),
    #[error("cannot connect to IPC socket {path}: {source}")]
    Connect { path: PathBuf, source: io::Error },
    #[error("cannot read daemon peer credentials: {0}")]
    PeerCredentials(#[source] nix::Error),
    #[error("IPC peer uid {0} is not the privileged daemon")]
    UntrustedPeer(u32),
    #[error("control requests require effective uid 0")]
    NotPrivileged,
    #[error("cannot configure IPC timeout: {0}")]
    Timeout(#[source] io::Error),
    #[error("IPC protocol error: {0}")]
    Frame(#[from] FrameError),
    #[error("daemon rejected request ({code:?}): {message}")]
    Rejected {
        code: openshield_protocol::ErrorCode,
        message: String,
    },
    #[error("unexpected daemon response: {0}")]
    Unexpected(&'static str),
    #[error("daemon returned an invalid snapshot: {0}")]
    InvalidSnapshot(String),
    #[error("policy changed while reading paginated rules; retrying")]
    InconsistentPages,
    #[error("daemon advertised {advertised} rules but returned {received}")]
    RuleCountMismatch { advertised: usize, received: usize },
    #[error("observer revision coordinator is unavailable")]
    RevisionCoordinator,
    #[error("observer generation counter is exhausted")]
    GenerationExhausted,
}

impl IpcError {
    #[must_use]
    pub fn localized(&self, i18n: &I18n) -> String {
        match self {
            Self::Inspect { path, source } => {
                let path = path.display().to_string();
                let error = source.to_string();
                i18n.format(
                    "ipc.inspect_error",
                    &[("path", path.as_str()), ("error", error.as_str())],
                )
            }
            Self::UntrustedDirectory(path) => {
                let path = path.display().to_string();
                i18n.format("ipc.untrusted_directory", &[("path", path.as_str())])
            }
            Self::UntrustedSocket(path) => {
                let path = path.display().to_string();
                i18n.format("ipc.untrusted_socket", &[("path", path.as_str())])
            }
            Self::ObserverGroup(error) => {
                i18n.format("ipc.observer_group_error", &[("error", error)])
            }
            Self::NotObserverGroupMember => i18n.tr("ipc.not_observer_group_member").to_owned(),
            Self::LocalGroups(error) => {
                let error = error.to_string();
                i18n.format("ipc.local_groups_error", &[("error", error.as_str())])
            }
            Self::SocketPathChanged(path) => {
                let path = path.display().to_string();
                i18n.format("ipc.socket_path_changed", &[("path", path.as_str())])
            }
            Self::Connect { path, source } => {
                let path = path.display().to_string();
                let error = source.to_string();
                i18n.format(
                    "ipc.connect_error",
                    &[("path", path.as_str()), ("error", error.as_str())],
                )
            }
            Self::PeerCredentials(error) => {
                let error = error.to_string();
                i18n.format("ipc.peer_credentials_error", &[("error", error.as_str())])
            }
            Self::UntrustedPeer(uid) => {
                let uid = uid.to_string();
                i18n.format("ipc.untrusted_peer", &[("uid", uid.as_str())])
            }
            Self::NotPrivileged => i18n.tr("ipc.control_root_required").to_owned(),
            Self::Timeout(error) => {
                let error = error.to_string();
                i18n.format("ipc.timeout_error", &[("error", error.as_str())])
            }
            Self::Frame(error) => {
                let error = error.to_string();
                i18n.format("ipc.protocol_error", &[("error", error.as_str())])
            }
            Self::Rejected { code, message } => {
                let code = format!("{code:?}");
                i18n.format(
                    "ipc.daemon_rejected",
                    &[("code", code.as_str()), ("message", message)],
                )
            }
            Self::Unexpected(error) => i18n.format("ipc.unexpected_response", &[("error", error)]),
            Self::InvalidSnapshot(error) => {
                i18n.format("ipc.invalid_snapshot", &[("error", error)])
            }
            Self::InconsistentPages => i18n.tr("ipc.inconsistent_pages").to_owned(),
            Self::RuleCountMismatch {
                advertised,
                received,
            } => {
                let advertised = advertised.to_string();
                let received = received.to_string();
                i18n.format(
                    "ipc.rule_count_mismatch",
                    &[
                        ("advertised", advertised.as_str()),
                        ("received", received.as_str()),
                    ],
                )
            }
            Self::RevisionCoordinator => i18n.tr("ipc.coordinator_unavailable").to_owned(),
            Self::GenerationExhausted => i18n.tr("ipc.generation_exhausted").to_owned(),
        }
    }
}

pub fn send_control(paths: &SocketPaths, request: ControlRequest) -> Result<Ack, IpcError> {
    if !is_control_uid(geteuid().as_raw()) {
        return Err(IpcError::NotPrivileged);
    }
    let mut stream = connect_verified(&paths.control, paths.control_is_test, SocketTrust::Control)?;
    set_request_timeouts(&stream)?;
    write_request(&mut stream, &Request::Control(request))?;
    match read_response(&mut stream)? {
        Response::Ack(ack) => Ok(ack),
        Response::Error(error) => Err(IpcError::Rejected {
            code: error.code,
            message: error.message,
        }),
        Response::Status { .. } => Err(IpcError::Unexpected("status on control socket")),
        Response::RulesPage { .. } => Err(IpcError::Unexpected("rules page on control socket")),
        Response::Event(_) => Err(IpcError::Unexpected("event on control socket")),
    }
}

const fn is_control_uid(uid: u32) -> bool {
    uid == 0
}

fn spawn_snapshot_worker(
    path: PathBuf,
    testing_override: bool,
    sender: SyncSender<ObserverUpdate>,
    context: ObserverWorkerContext,
    connection_state: Arc<AtomicU8>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let ObserverWorkerContext {
            running,
            revision,
            dropped,
            i18n,
        } = context;
        let mut retry_delay = INITIAL_RECONNECT_DELAY;
        while running.load(Ordering::Acquire) {
            match refresh_snapshot(&path, testing_override, &sender, &revision, &dropped) {
                Ok(outcome) => {
                    report_connection(
                        &sender,
                        &dropped,
                        &connection_state,
                        WorkerKind::Snapshot,
                        true,
                        String::new(),
                    );
                    match outcome {
                        Some(OfferOutcome::Delivered) => {
                            connection_state.store(1, Ordering::Release);
                        }
                        None | Some(OfferOutcome::Dropped) => {}
                        Some(OfferOutcome::Disconnected) => return,
                    }
                    retry_delay = INITIAL_RECONNECT_DELAY;
                    if !wait_interruptibly(&running, SNAPSHOT_INTERVAL) {
                        return;
                    }
                }
                Err(IpcError::InconsistentPages) => {
                    if !wait_interruptibly(&running, INITIAL_RECONNECT_DELAY) {
                        return;
                    }
                }
                Err(error) => {
                    report_connection(
                        &sender,
                        &dropped,
                        &connection_state,
                        WorkerKind::Snapshot,
                        false,
                        error.localized(&i18n),
                    );
                    if !wait_interruptibly(&running, retry_delay) {
                        return;
                    }
                    retry_delay = next_backoff(retry_delay);
                }
            }
        }
    })
}

fn spawn_event_worker(
    path: PathBuf,
    testing_override: bool,
    sender: SyncSender<ObserverUpdate>,
    context: ObserverWorkerContext,
    connection_state: Arc<AtomicU8>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let ObserverWorkerContext {
            running,
            revision,
            dropped,
            i18n,
        } = context;
        let mut retry_delay = INITIAL_RECONNECT_DELAY;
        while running.load(Ordering::Acquire) {
            let result = subscribe_once(
                &path,
                testing_override,
                &sender,
                &running,
                &revision,
                &dropped,
                &connection_state,
            );
            if !running.load(Ordering::Acquire) || matches!(result, Ok(false)) {
                return;
            }
            if matches!(result, Ok(true)) {
                retry_delay = INITIAL_RECONNECT_DELAY;
                if !wait_interruptibly(&running, retry_delay) {
                    return;
                }
                continue;
            }
            if let Err(error) = result {
                report_connection(
                    &sender,
                    &dropped,
                    &connection_state,
                    WorkerKind::Telemetry,
                    false,
                    error.localized(&i18n),
                );
            }
            if !wait_interruptibly(&running, retry_delay) {
                return;
            }
            retry_delay = next_backoff(retry_delay);
        }
    })
}

fn refresh_snapshot(
    path: &Path,
    testing_override: bool,
    sender: &SyncSender<ObserverUpdate>,
    revision: &Mutex<RevisionEpoch>,
    dropped: &DroppedCounter,
) -> Result<Option<OfferOutcome>, IpcError> {
    let mut stream = connect_verified(path, testing_override, SocketTrust::Observe)?;
    set_request_timeouts(&stream)?;
    let first = fetch_status(&mut stream)?;
    let known_revision = {
        let cursor = lock_revision_epoch(revision)?;
        if status_is_unchanged(&cursor, first) {
            return Ok(None);
        }
        cursor.revision
    };
    if first.revision >= known_revision {
        let snapshot = fetch_consistent_snapshot_from_status(&mut stream, first)?;
        return enqueue_snapshot(sender, revision, dropped, snapshot, first.backend, false);
    }

    // A lower first read can be a harmless race with an event received after
    // Status. A second Status must include that event on the same daemon epoch;
    // if it is still below the captured revision, the daemon has restarted from
    // an older persisted state.
    let confirmed = fetch_status(&mut stream)?;
    let restarted = confirmed.revision < known_revision;
    if !restarted && shared_status_is_unchanged(revision, confirmed)? {
        return Ok(None);
    }
    let snapshot = fetch_consistent_snapshot_from_status(&mut stream, confirmed)?;
    enqueue_snapshot(
        sender,
        revision,
        dropped,
        snapshot,
        confirmed.backend,
        restarted,
    )
}

fn enqueue_snapshot(
    sender: &SyncSender<ObserverUpdate>,
    revision: &Mutex<RevisionEpoch>,
    dropped: &DroppedCounter,
    snapshot: Snapshot,
    backend: FirewallBackendKind,
    restart_confirmed: bool,
) -> Result<Option<OfferOutcome>, IpcError> {
    let rule_count = u32::try_from(snapshot.rules.len())
        .map_err(|_| IpcError::InvalidSnapshot("rule count does not fit u32".to_owned()))?;
    let mut cursor = lock_revision_epoch(revision)?;
    // `AutoBackend` is immutable for one daemon lifetime. A changed backend
    // therefore proves that this snapshot belongs to a new daemon epoch even
    // when the persisted policy revision did not move backwards. Treat it as
    // a restart so an event worker attached to the old daemon is invalidated.
    let restarted = restart_confirmed || cursor.backend.is_some_and(|current| current != backend);
    if restarted {
        cursor.generation = cursor
            .generation
            .checked_add(1)
            .ok_or(IpcError::GenerationExhausted)?;
        cursor.revision = snapshot.revision;
        cursor.mode = Some(snapshot.mode);
        cursor.rule_count = Some(rule_count);
        cursor.backend = Some(backend);
        cursor.resync_required = true;
        cursor.restart_update_pending = true;
    } else if snapshot.revision < cursor.revision && !cursor.restart_update_pending {
        return Ok(None);
    } else {
        cursor.revision = cursor.revision.max(snapshot.revision);
        cursor.mode = Some(snapshot.mode);
        cursor.rule_count = Some(rule_count);
        cursor.backend = Some(backend);
    }

    let is_restart_update = cursor.restart_update_pending;
    let update = if is_restart_update {
        ObserverUpdate::Restarted { snapshot, backend }
    } else {
        ObserverUpdate::Snapshot { snapshot, backend }
    };
    let outcome = offer_update(sender, dropped, update);
    match outcome {
        OfferOutcome::Delivered => {
            cursor.resync_required = false;
            if is_restart_update {
                cursor.restart_update_pending = false;
            }
        }
        OfferOutcome::Dropped | OfferOutcome::Disconnected => cursor.resync_required = true,
    }
    Ok(Some(outcome))
}

fn subscription_cursor(revision: &Mutex<RevisionEpoch>) -> Result<(u64, u64), IpcError> {
    let cursor = lock_revision_epoch(revision)?;
    Ok((cursor.revision, cursor.generation))
}

fn enqueue_event(
    sender: &SyncSender<ObserverUpdate>,
    revision: &Mutex<RevisionEpoch>,
    dropped: &DroppedCounter,
    subscribed_generation: u64,
    event: Event,
) -> Result<EventEnqueueOutcome, IpcError> {
    let mut cursor = lock_revision_epoch(revision)?;
    if cursor.generation != subscribed_generation || cursor.restart_update_pending {
        return Ok(EventEnqueueOutcome::GenerationChanged);
    }
    cursor.revision = cursor.revision.max(event.revision);
    let outcome = match offer_update(sender, dropped, ObserverUpdate::Event(Box::new(event))) {
        OfferOutcome::Delivered => EventEnqueueOutcome::Delivered,
        OfferOutcome::Dropped => {
            cursor.resync_required = true;
            EventEnqueueOutcome::Dropped
        }
        OfferOutcome::Disconnected => EventEnqueueOutcome::Disconnected,
    };
    Ok(outcome)
}

fn status_is_unchanged(cursor: &RevisionEpoch, status: PolicyStatus) -> bool {
    !cursor.resync_required
        && !cursor.restart_update_pending
        && cursor.revision == status.revision
        && cursor.mode == Some(status.mode)
        && cursor.rule_count == Some(status.rule_count)
        && cursor.backend == Some(status.backend)
}

fn shared_status_is_unchanged(
    revision: &Mutex<RevisionEpoch>,
    status: PolicyStatus,
) -> Result<bool, IpcError> {
    let cursor = lock_revision_epoch(revision)?;
    Ok(status_is_unchanged(&cursor, status))
}

fn mark_resync_required(revision: &Mutex<RevisionEpoch>) -> Result<(), IpcError> {
    let mut cursor = lock_revision_epoch(revision)?;
    cursor.resync_required = true;
    Ok(())
}

fn lock_revision_epoch(
    revision: &Mutex<RevisionEpoch>,
) -> Result<MutexGuard<'_, RevisionEpoch>, IpcError> {
    revision.lock().map_err(|_| IpcError::RevisionCoordinator)
}

fn fetch_consistent_snapshot_from_status(
    stream: &mut UnixStream,
    status: PolicyStatus,
) -> Result<Snapshot, IpcError> {
    let expected_count =
        usize::try_from(status.rule_count).map_err(|_| IpcError::RuleCountMismatch {
            advertised: usize::MAX,
            received: 0,
        })?;
    if expected_count > MAX_RULES {
        return Err(IpcError::RuleCountMismatch {
            advertised: expected_count,
            received: 0,
        });
    }

    let mut rules = Vec::with_capacity(expected_count);
    let mut after = None;
    loop {
        let (page_revision, mut page, next_after) = fetch_rules_page(stream, after)?;
        if page_revision != status.revision {
            return Err(IpcError::InconsistentPages);
        }
        if page.len() > usize::from(MAX_RULES_PER_PAGE) {
            return Err(IpcError::Unexpected("rules page exceeds negotiated limit"));
        }
        if page.is_empty() && next_after.is_some() {
            return Err(IpcError::Unexpected("empty non-terminal rules page"));
        }
        if next_after.is_some() && next_after == after {
            return Err(IpcError::Unexpected(
                "rules pagination cursor did not advance",
            ));
        }
        rules.append(&mut page);
        if rules.len() > expected_count || rules.len() > MAX_RULES {
            return Err(IpcError::RuleCountMismatch {
                advertised: expected_count,
                received: rules.len(),
            });
        }
        match next_after {
            Some(cursor) => after = Some(cursor),
            None => break,
        }
    }

    if rules.len() != expected_count {
        return Err(IpcError::RuleCountMismatch {
            advertised: expected_count,
            received: rules.len(),
        });
    }
    let snapshot = Snapshot {
        revision: status.revision,
        flow_generation: 1,
        mode: status.mode,
        rules,
    };
    validate_observer_snapshot(snapshot)
}

fn validate_observer_snapshot(snapshot: Snapshot) -> Result<Snapshot, IpcError> {
    snapshot
        .validate_for_observer()
        .map_err(|error| IpcError::InvalidSnapshot(error.to_string()))?;
    Ok(snapshot)
}

fn fetch_status(stream: &mut UnixStream) -> Result<PolicyStatus, IpcError> {
    write_request(stream, &Request::Read(ReadRequest::Status))?;
    match read_response(stream)? {
        Response::Status {
            revision,
            mode,
            rule_count,
            backend,
            ..
        } => Ok(PolicyStatus {
            revision,
            mode,
            rule_count,
            backend,
        }),
        Response::Error(error) => Err(IpcError::Rejected {
            code: error.code,
            message: error.message,
        }),
        Response::Ack(_) => Err(IpcError::Unexpected("ack on observation socket")),
        Response::Event(_) => Err(IpcError::Unexpected("event instead of status")),
        Response::RulesPage { .. } => Err(IpcError::Unexpected("rules page instead of status")),
    }
}

fn fetch_rules_page(
    stream: &mut UnixStream,
    after: Option<Uuid>,
) -> Result<(u64, Vec<Rule>, Option<Uuid>), IpcError> {
    write_request(
        stream,
        &Request::Read(ReadRequest::RulesPage {
            after,
            limit: MAX_RULES_PER_PAGE,
        }),
    )?;
    match read_response(stream)? {
        Response::RulesPage {
            revision,
            rules,
            next_after,
        } => Ok((revision, rules, next_after)),
        Response::Error(error) => Err(IpcError::Rejected {
            code: error.code,
            message: error.message,
        }),
        Response::Ack(_) => Err(IpcError::Unexpected("ack on observation socket")),
        Response::Event(_) => Err(IpcError::Unexpected("event instead of rules page")),
        Response::Status { .. } => Err(IpcError::Unexpected("status instead of rules page")),
    }
}

fn subscribe_once(
    path: &Path,
    testing_override: bool,
    sender: &SyncSender<ObserverUpdate>,
    running: &AtomicBool,
    revision: &Mutex<RevisionEpoch>,
    dropped: &DroppedCounter,
    connection_state: &AtomicU8,
) -> Result<bool, IpcError> {
    let mut stream = connect_verified(path, testing_override, SocketTrust::Observe)?;
    stream
        .set_write_timeout(Some(IPC_REQUEST_TIMEOUT))
        .map_err(IpcError::Timeout)?;
    let (after_revision, subscribed_generation) = subscription_cursor(revision)?;
    write_request(
        &mut stream,
        &Request::Read(ReadRequest::Subscribe {
            after_revision: Some(after_revision),
        }),
    )?;
    report_connection(
        sender,
        dropped,
        connection_state,
        WorkerKind::Telemetry,
        true,
        String::new(),
    );

    while running.load(Ordering::Acquire) {
        match read_response(&mut stream)? {
            Response::Event(event) => {
                match enqueue_event(sender, revision, dropped, subscribed_generation, event)? {
                    EventEnqueueOutcome::Delivered => {
                        connection_state.store(1, Ordering::Release);
                    }
                    EventEnqueueOutcome::Dropped => {}
                    EventEnqueueOutcome::GenerationChanged => return Ok(true),
                    EventEnqueueOutcome::Disconnected => return Ok(false),
                }
            }
            Response::Error(error) => {
                return Err(IpcError::Rejected {
                    code: error.code,
                    message: error.message,
                });
            }
            Response::Ack(_) => return Err(IpcError::Unexpected("ack on event subscription")),
            Response::Status { .. } => {
                return Err(IpcError::Unexpected("status on event subscription"));
            }
            Response::RulesPage { .. } => {
                return Err(IpcError::Unexpected("rules page on event subscription"));
            }
        }
    }
    Ok(false)
}

fn connect_verified(
    path: &Path,
    testing_override: bool,
    trust: SocketTrust,
) -> Result<UnixStream, IpcError> {
    let identity_before = if testing_override {
        None
    } else {
        Some(verify_default_socket_path(path, trust)?)
    };
    let stream = UnixStream::connect(path).map_err(|source| IpcError::Connect {
        path: path.to_path_buf(),
        source,
    })?;
    if !testing_override {
        let credentials =
            getsockopt(&stream, PeerCredentials).map_err(IpcError::PeerCredentials)?;
        if credentials.uid() != 0 {
            return Err(IpcError::UntrustedPeer(credentials.uid()));
        }
        let identity_after = verify_default_socket_path(path, trust)?;
        if identity_before != Some(identity_after) {
            return Err(IpcError::SocketPathChanged(path.to_path_buf()));
        }
    }
    Ok(stream)
}

fn verify_default_socket_path(
    path: &Path,
    trust: SocketTrust,
) -> Result<SocketPathIdentity, IpcError> {
    let parent = path
        .parent()
        .ok_or_else(|| IpcError::UntrustedDirectory(path.to_path_buf()))?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(|source| IpcError::Inspect {
        path: parent.to_path_buf(),
        source,
    })?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || parent_metadata.uid() != 0
        || parent_metadata.mode() & 0o022 != 0
    {
        return Err(IpcError::UntrustedDirectory(parent.to_path_buf()));
    }

    let metadata = fs::symlink_metadata(path).map_err(|source| IpcError::Inspect {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() || metadata.uid() != 0
    {
        return Err(IpcError::UntrustedSocket(path.to_path_buf()));
    }
    let mode = metadata.mode() & 0o777;
    let observer_gid = match trust {
        SocketTrust::Control => 0,
        SocketTrust::Observe => required_observer_gid()?,
    };
    if !socket_permissions_are_trusted(
        metadata.uid() == 0,
        metadata.gid(),
        mode,
        trust,
        observer_gid,
    ) {
        return Err(IpcError::UntrustedSocket(path.to_path_buf()));
    }
    if trust == SocketTrust::Observe {
        authorize_local_observer(observer_gid)?;
    }
    Ok(SocketPathIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

const fn socket_permissions_are_trusted(
    is_root_owned: bool,
    socket_group: u32,
    mode: u32,
    trust: SocketTrust,
    observer_gid: u32,
) -> bool {
    if !is_root_owned {
        return false;
    }
    match trust {
        SocketTrust::Control => mode == CONTROL_SOCKET_MODE,
        SocketTrust::Observe => socket_group == observer_gid && mode == OBSERVE_SOCKET_MODE,
    }
}

fn required_observer_gid() -> Result<u32, IpcError> {
    static GROUP_GID: OnceLock<Result<u32, String>> = OnceLock::new();
    let resolved = GROUP_GID.get_or_init(|| {
        Group::from_name(OBSERVE_GROUP_NAME)
            .map_err(|error| error.to_string())?
            .map(|group| group.gid.as_raw())
            .ok_or_else(|| "group does not exist".to_owned())
    });
    resolved
        .as_ref()
        .copied()
        .map_err(|error| IpcError::ObserverGroup(error.clone()))
}

fn authorize_local_observer(observer_gid: u32) -> Result<(), IpcError> {
    let uid = geteuid().as_raw();
    if uid == 0 {
        return Ok(());
    }
    let primary_gid = getegid().as_raw();
    let supplementary = getgroups().map_err(IpcError::LocalGroups)?;
    let supplementary: Vec<u32> = supplementary.iter().map(|group| group.as_raw()).collect();
    if local_observer_is_authorized(uid, primary_gid, &supplementary, observer_gid) {
        Ok(())
    } else {
        Err(IpcError::NotObserverGroupMember)
    }
}

const fn local_observer_is_authorized(
    uid: u32,
    primary_gid: u32,
    supplementary_groups: &[u32],
    observer_gid: u32,
) -> bool {
    if uid == 0 || primary_gid == observer_gid {
        return true;
    }
    let mut index = 0;
    while index < supplementary_groups.len() {
        if supplementary_groups[index] == observer_gid {
            return true;
        }
        index += 1;
    }
    false
}

fn set_request_timeouts(stream: &UnixStream) -> Result<(), IpcError> {
    stream
        .set_read_timeout(Some(IPC_REQUEST_TIMEOUT))
        .map_err(IpcError::Timeout)?;
    stream
        .set_write_timeout(Some(IPC_REQUEST_TIMEOUT))
        .map_err(IpcError::Timeout)
}

fn report_connection(
    sender: &SyncSender<ObserverUpdate>,
    dropped: &DroppedCounter,
    state: &AtomicU8,
    worker: WorkerKind,
    connected: bool,
    reason: String,
) -> bool {
    let desired = if connected { 1 } else { 2 };
    if state.load(Ordering::Acquire) == desired {
        return false;
    }
    let update = match (worker, connected) {
        (WorkerKind::Snapshot, true) => ObserverUpdate::Connected,
        (WorkerKind::Snapshot, false) => ObserverUpdate::Disconnected(reason),
        (WorkerKind::Telemetry, true) => ObserverUpdate::TelemetryConnected,
        (WorkerKind::Telemetry, false) => ObserverUpdate::TelemetryDisconnected(reason),
    };
    match sender.try_send(update) {
        Ok(()) => {
            state.store(desired, Ordering::Release);
            true
        }
        Err(TrySendError::Full(_)) => {
            dropped.add(1);
            false
        }
        Err(TrySendError::Disconnected(_)) => false,
    }
}

fn offer_update(
    sender: &SyncSender<ObserverUpdate>,
    dropped: &DroppedCounter,
    update: ObserverUpdate,
) -> OfferOutcome {
    let pending = dropped.take();
    if pending > 0 {
        match sender.try_send(ObserverUpdate::Dropped(pending)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                dropped.add(pending);
            }
            Err(TrySendError::Disconnected(_)) => return OfferOutcome::Disconnected,
        }
    }

    match sender.try_send(update) {
        Ok(()) => OfferOutcome::Delivered,
        Err(TrySendError::Full(_)) => {
            dropped.add(1);
            OfferOutcome::Dropped
        }
        Err(TrySendError::Disconnected(_)) => OfferOutcome::Disconnected,
    }
}

fn wait_interruptibly(running: &AtomicBool, duration: Duration) -> bool {
    let step = Duration::from_millis(50);
    let mut waited = Duration::ZERO;
    while waited < duration {
        if !running.load(Ordering::Acquire) {
            return false;
        }
        let remaining = duration.saturating_sub(waited);
        let sleep_for = remaining.min(step);
        thread::sleep(sleep_for);
        waited = waited.saturating_add(sleep_for);
    }
    running.load(Ordering::Acquire)
}

fn next_backoff(current: Duration) -> Duration {
    current.saturating_mul(2).min(MAX_RECONNECT_DELAY)
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use openshield_core::{
        ApplicationPath, ApplicationSelector, Direction, EventKind, ExecutableFileId,
        FirewallCounters, InterfaceName, PortRange, RuleName, RuleOrigin, RuleSpec,
        TransportProtocol,
    };

    use super::*;

    #[test]
    fn fixed_paths_are_not_testing_overrides() {
        let paths = SocketPaths::fixed();
        assert!(!paths.uses_testing_override());
        assert_eq!(paths.observe, Path::new(OBSERVE_SOCKET_PATH));
        assert_eq!(paths.control, Path::new(CONTROL_SOCKET_PATH));
    }

    #[test]
    fn override_is_explicitly_marked_for_testing() {
        let paths = SocketPaths::for_explicit_testing(Some(PathBuf::from("/tmp/test.sock")), None);
        assert!(paths.uses_testing_override());
    }

    #[test]
    fn ipc_errors_localize_the_category_and_preserve_raw_details()
    -> Result<(), crate::i18n::LocaleError> {
        let i18n = I18n::load(crate::i18n::Locale::Ru)?;
        assert_eq!(
            IpcError::NotObserverGroupMember.localized(&i18n),
            "Наблюдение требует root или членства в группе openshield"
        );

        let error = IpcError::Connect {
            path: PathBuf::from("/run/openshield/observe.sock"),
            source: io::Error::new(io::ErrorKind::ConnectionRefused, "raw-detail"),
        };
        let localized = error.localized(&i18n);
        assert!(localized.starts_with("Не удалось подключиться к IPC-сокету"));
        assert!(localized.contains("/run/openshield/observe.sock"));
        assert!(localized.contains("raw-detail"));
        Ok(())
    }

    #[test]
    fn reconnect_backoff_is_bounded() {
        let mut delay = INITIAL_RECONNECT_DELAY;
        for _ in 0..20 {
            delay = next_backoff(delay);
        }
        assert_eq!(delay, MAX_RECONNECT_DELAY);
    }

    #[test]
    fn only_root_uid_is_allowed_to_send_control_requests() {
        assert!(is_control_uid(0));
        assert!(!is_control_uid(1));
        assert!(!is_control_uid(1_000));
    }

    #[test]
    fn observation_accepts_root_primary_and_supplementary_group_members_only() {
        assert!(local_observer_is_authorized(0, 1000, &[], 991));
        assert!(local_observer_is_authorized(1000, 991, &[], 991));
        assert!(local_observer_is_authorized(
            1000,
            1000,
            &[4, 991, 1000],
            991
        ));
        assert!(!local_observer_is_authorized(
            1000,
            1000,
            &[4, 27, 1000],
            991
        ));
    }

    #[test]
    fn fixed_observation_socket_requires_exact_root_group_and_mode() {
        assert!(socket_permissions_are_trusted(
            true,
            991,
            0o660,
            SocketTrust::Observe,
            991
        ));
        assert!(!socket_permissions_are_trusted(
            true,
            991,
            0o666,
            SocketTrust::Observe,
            991
        ));
        assert!(!socket_permissions_are_trusted(
            true,
            992,
            0o660,
            SocketTrust::Observe,
            991
        ));
        assert!(!socket_permissions_are_trusted(
            false,
            991,
            0o660,
            SocketTrust::Observe,
            991
        ));
        assert!(socket_permissions_are_trusted(
            true,
            0,
            0o600,
            SocketTrust::Control,
            991
        ));
    }

    #[test]
    fn telemetry_worker_reports_independent_health_transitions()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sender, receiver) = mpsc::sync_channel(2);
        let dropped = DroppedCounter::new();
        let state = AtomicU8::new(0);

        assert!(report_connection(
            &sender,
            &dropped,
            &state,
            WorkerKind::Telemetry,
            true,
            String::new(),
        ));
        assert!(matches!(
            receiver.recv()?,
            ObserverUpdate::TelemetryConnected
        ));

        assert!(report_connection(
            &sender,
            &dropped,
            &state,
            WorkerKind::Telemetry,
            false,
            "stream closed".to_owned(),
        ));
        assert!(matches!(
            receiver.recv()?,
            ObserverUpdate::TelemetryDisconnected(reason) if reason == "stream closed"
        ));
        Ok(())
    }

    #[test]
    fn full_learning_burst_has_bounded_service_update_headroom()
    -> Result<(), Box<dyn std::error::Error>> {
        const LEARNING_BURST: usize = 256;
        let (sender, receiver) = mpsc::sync_channel(UPDATE_CHANNEL_CAPACITY);
        let dropped = DroppedCounter::new();

        sender.try_send(ObserverUpdate::Connected)?;
        sender.try_send(ObserverUpdate::TelemetryConnected)?;
        sender.try_send(ObserverUpdate::Snapshot {
            snapshot: empty_snapshot(1),
            backend: FirewallBackendKind::Unknown,
        })?;
        sender.try_send(ObserverUpdate::Event(Box::new(counter_event(1))))?;
        for revision in 2..=u64::try_from(LEARNING_BURST + 1)? {
            assert_eq!(
                offer_update(
                    &sender,
                    &dropped,
                    ObserverUpdate::Event(Box::new(counter_event(revision))),
                ),
                OfferOutcome::Delivered
            );
        }

        assert_eq!(dropped.load(), 0);
        assert_eq!(receiver.try_iter().count(), LEARNING_BURST + 4);
        Ok(())
    }

    #[test]
    fn lower_restart_resets_cursor_without_accepting_old_generation_events()
    -> Result<(), Box<dyn std::error::Error>> {
        let revision = Mutex::new(RevisionEpoch::default());
        let dropped = DroppedCounter::new();
        let (sender, receiver) = mpsc::sync_channel(8);

        assert_eq!(
            enqueue_snapshot(
                &sender,
                &revision,
                &dropped,
                empty_snapshot(10),
                FirewallBackendKind::Unknown,
                false,
            )?,
            Some(OfferOutcome::Delivered)
        );
        assert!(matches!(
            receiver.recv()?,
            ObserverUpdate::Snapshot {
                backend: FirewallBackendKind::Unknown,
                ..
            }
        ));
        let (_, old_generation) = subscription_cursor(&revision)?;

        assert_eq!(
            enqueue_event(
                &sender,
                &revision,
                &dropped,
                old_generation,
                counter_event(11),
            )?,
            EventEnqueueOutcome::Delivered
        );
        assert!(matches!(receiver.recv()?, ObserverUpdate::Event(_)));

        // A merely stale snapshot must not rewind a cursor advanced by a
        // concurrent event from the same daemon epoch.
        assert_eq!(
            enqueue_snapshot(
                &sender,
                &revision,
                &dropped,
                empty_snapshot(10),
                FirewallBackendKind::Unknown,
                false,
            )?,
            None
        );
        assert_eq!(subscription_cursor(&revision)?, (11, old_generation));

        // A second, confirmed lower read starts a new epoch and is delivered
        // explicitly so App does not reject it as stale.
        assert_eq!(
            enqueue_snapshot(
                &sender,
                &revision,
                &dropped,
                empty_snapshot(3),
                FirewallBackendKind::Iptables,
                true,
            )?,
            Some(OfferOutcome::Delivered)
        );
        assert!(matches!(
            receiver.recv()?,
            ObserverUpdate::Restarted {
                backend: FirewallBackendKind::Iptables,
                ..
            }
        ));
        let (current_revision, new_generation) = subscription_cursor(&revision)?;
        assert_eq!(current_revision, 3);
        assert_eq!(new_generation, old_generation + 1);

        assert_eq!(
            enqueue_event(
                &sender,
                &revision,
                &dropped,
                old_generation,
                counter_event(12),
            )?,
            EventEnqueueOutcome::GenerationChanged
        );
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        Ok(())
    }

    #[test]
    fn unchanged_status_skips_pages_but_dropped_event_forces_resync()
    -> Result<(), Box<dyn std::error::Error>> {
        let revision = Mutex::new(RevisionEpoch::default());
        let dropped = DroppedCounter::new();
        let (sender, _receiver) = mpsc::sync_channel(1);
        assert_eq!(
            enqueue_snapshot(
                &sender,
                &revision,
                &dropped,
                empty_snapshot(10),
                FirewallBackendKind::Unknown,
                false,
            )?,
            Some(OfferOutcome::Delivered)
        );
        let unchanged = PolicyStatus {
            revision: 10,
            mode: Mode::BlockAll,
            rule_count: 0,
            backend: FirewallBackendKind::Unknown,
        };
        assert!(shared_status_is_unchanged(&revision, unchanged)?);
        assert!(!shared_status_is_unchanged(
            &revision,
            PolicyStatus {
                rule_count: 1,
                ..unchanged
            }
        )?);
        assert!(!shared_status_is_unchanged(
            &revision,
            PolicyStatus {
                mode: Mode::Learning,
                ..unchanged
            }
        )?);
        assert!(!shared_status_is_unchanged(
            &revision,
            PolicyStatus {
                backend: FirewallBackendKind::Nftables,
                ..unchanged
            }
        )?);

        let (_, generation) = subscription_cursor(&revision)?;
        assert_eq!(
            enqueue_event(&sender, &revision, &dropped, generation, counter_event(11),)?,
            EventEnqueueOutcome::Dropped
        );
        assert!(!shared_status_is_unchanged(
            &revision,
            PolicyStatus {
                revision: 11,
                ..unchanged
            }
        )?);
        Ok(())
    }

    #[test]
    fn backend_change_starts_a_new_epoch_and_invalidates_old_events()
    -> Result<(), Box<dyn std::error::Error>> {
        let revision = Mutex::new(RevisionEpoch::default());
        let dropped = DroppedCounter::new();
        let (sender, receiver) = mpsc::sync_channel(2);

        assert_eq!(
            enqueue_snapshot(
                &sender,
                &revision,
                &dropped,
                empty_snapshot(10),
                FirewallBackendKind::Unknown,
                false,
            )?,
            Some(OfferOutcome::Delivered)
        );
        let _initial = receiver.recv()?;
        let (_, old_generation) = subscription_cursor(&revision)?;

        let changed = PolicyStatus {
            revision: 10,
            mode: Mode::BlockAll,
            rule_count: 0,
            backend: FirewallBackendKind::Nftables,
        };
        assert!(!shared_status_is_unchanged(&revision, changed)?);
        assert_eq!(
            enqueue_snapshot(
                &sender,
                &revision,
                &dropped,
                empty_snapshot(10),
                changed.backend,
                false,
            )?,
            Some(OfferOutcome::Delivered)
        );
        assert!(matches!(
            receiver.recv()?,
            ObserverUpdate::Restarted {
                snapshot: Snapshot { revision: 10, .. },
                backend: FirewallBackendKind::Nftables,
            }
        ));
        assert!(shared_status_is_unchanged(&revision, changed)?);
        let (_, new_generation) = subscription_cursor(&revision)?;
        assert_eq!(new_generation, old_generation + 1);
        assert_eq!(
            enqueue_event(
                &sender,
                &revision,
                &dropped,
                old_generation,
                counter_event(11),
            )?,
            EventEnqueueOutcome::GenerationChanged
        );
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        Ok(())
    }

    #[test]
    fn explicit_conflict_resync_invalidates_an_unchanged_status() -> Result<(), IpcError> {
        let revision = Mutex::new(RevisionEpoch {
            revision: 10,
            generation: 0,
            mode: Some(Mode::BlockAll),
            rule_count: Some(0),
            backend: Some(FirewallBackendKind::Unknown),
            resync_required: false,
            restart_update_pending: false,
        });
        let unchanged = PolicyStatus {
            revision: 10,
            mode: Mode::BlockAll,
            rule_count: 0,
            backend: FirewallBackendKind::Unknown,
        };
        assert!(shared_status_is_unchanged(&revision, unchanged)?);
        mark_resync_required(&revision)?;
        assert!(!shared_status_is_unchanged(&revision, unchanged)?);
        Ok(())
    }

    #[test]
    fn non_root_redacted_application_snapshot_remains_observable()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut specification = RuleSpec::new(
            RuleName::new("sensitive executable")?,
            Direction::Outbound,
            TransportProtocol::Tcp,
            Some("203.0.113.9/32".parse()?),
            Some(PortRange::single(443)?),
            Some(InterfaceName::new("eth0")?),
            RuleOrigin::Learned,
            true,
        )?;
        specification.application = Some(ApplicationSelector::new(
            Some(ApplicationPath::new("/usr/bin/private-client")?),
            Some(ExecutableFileId {
                device: 8,
                inode: 42,
                size: 1_024,
                ctime_seconds: 1_700_000_000,
                ctime_nanoseconds: 123_456_789,
            }),
            None,
            Some(1_000),
            None,
        )?);
        specification.validate()?;
        let rule = Rule::with_id_and_time(Uuid::new_v4(), specification, Utc::now())?
            .redacted_for_observer();
        let snapshot = Snapshot {
            revision: 7,
            flow_generation: 1,
            mode: Mode::Learning,
            rules: vec![rule],
        };

        let validated = validate_observer_snapshot(snapshot)?;
        assert!(
            validated.rules[0]
                .spec
                .application
                .as_ref()
                .is_some_and(|selector| selector.metadata_redacted)
        );
        Ok(())
    }

    fn empty_snapshot(revision: u64) -> Snapshot {
        Snapshot {
            revision,
            flow_generation: 1,
            mode: Mode::BlockAll,
            rules: Vec::new(),
        }
    }

    fn counter_event(revision: u64) -> Event {
        Event {
            revision,
            occurred_at: Utc::now(),
            kind: EventKind::CountersUpdated {
                counters: FirewallCounters::default(),
            },
        }
    }
}
