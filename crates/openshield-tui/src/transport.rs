use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use nix::unistd::geteuid;
use openshield_core::{Event, MAX_RULES, Mode, Rule, Snapshot};
use openshield_protocol::{
    Ack, CONTROL_SOCKET_PATH, ControlRequest, FrameError, MAX_RULES_PER_PAGE, OBSERVE_SOCKET_PATH,
    ReadRequest, Request, Response, read_response, write_request,
};
use thiserror::Error;
use uuid::Uuid;

// The daemon may publish 256 learned RuleCreated events in one transaction.
// Preserve that complete real-time burst plus connection, snapshot, and counter
// headroom while retaining a fixed memory bound.
const UPDATE_CHANNEL_CAPACITY: usize = 512;
const SNAPSHOT_INTERVAL: Duration = Duration::from_secs(2);
const INITIAL_RECONNECT_DELAY: Duration = Duration::from_millis(250);
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(5);
const IPC_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

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
    Snapshot(Snapshot),
    Restarted(Snapshot),
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

#[derive(Debug)]
struct RevisionEpoch {
    revision: u64,
    generation: u64,
    mode: Option<Mode>,
    rule_count: Option<u32>,
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
    pub fn start(paths: &SocketPaths) -> Self {
        let (sender, receiver) = mpsc::sync_channel(UPDATE_CHANNEL_CAPACITY);
        let running = Arc::new(AtomicBool::new(true));
        let revision = Arc::new(Mutex::new(RevisionEpoch::default()));
        let dropped = Arc::new(AtomicU64::new(0));
        let snapshot_state = Arc::new(AtomicU8::new(0));
        let telemetry_state = Arc::new(AtomicU8::new(0));

        let snapshot_thread = spawn_snapshot_worker(
            paths.observe.clone(),
            paths.observe_is_test,
            sender.clone(),
            Arc::clone(&running),
            Arc::clone(&revision),
            Arc::clone(&dropped),
            snapshot_state,
        );
        let event_thread = spawn_event_worker(
            paths.observe.clone(),
            paths.observe_is_test,
            sender,
            Arc::clone(&running),
            Arc::clone(&revision),
            dropped,
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

pub fn send_control(paths: &SocketPaths, request: ControlRequest) -> Result<Ack, IpcError> {
    if !is_control_uid(geteuid().as_raw()) {
        return Err(IpcError::NotPrivileged);
    }
    let mut stream = connect_verified(&paths.control, paths.control_is_test)?;
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
    running: Arc<AtomicBool>,
    revision: Arc<Mutex<RevisionEpoch>>,
    dropped: Arc<AtomicU64>,
    connection_state: Arc<AtomicU8>,
) -> JoinHandle<()> {
    thread::spawn(move || {
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
                        error.to_string(),
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
    running: Arc<AtomicBool>,
    revision: Arc<Mutex<RevisionEpoch>>,
    dropped: Arc<AtomicU64>,
    connection_state: Arc<AtomicU8>,
) -> JoinHandle<()> {
    thread::spawn(move || {
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
                    error.to_string(),
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
    dropped: &AtomicU64,
) -> Result<Option<OfferOutcome>, IpcError> {
    let mut stream = connect_verified(path, testing_override)?;
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
        return enqueue_snapshot(sender, revision, dropped, snapshot, false);
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
    enqueue_snapshot(sender, revision, dropped, snapshot, restarted)
}

fn enqueue_snapshot(
    sender: &SyncSender<ObserverUpdate>,
    revision: &Mutex<RevisionEpoch>,
    dropped: &AtomicU64,
    snapshot: Snapshot,
    restarted: bool,
) -> Result<Option<OfferOutcome>, IpcError> {
    let rule_count = u32::try_from(snapshot.rules.len())
        .map_err(|_| IpcError::InvalidSnapshot("rule count does not fit u32".to_owned()))?;
    let mut cursor = lock_revision_epoch(revision)?;
    if restarted {
        cursor.generation = cursor
            .generation
            .checked_add(1)
            .ok_or(IpcError::GenerationExhausted)?;
        cursor.revision = snapshot.revision;
        cursor.mode = Some(snapshot.mode);
        cursor.rule_count = Some(rule_count);
        cursor.resync_required = true;
        cursor.restart_update_pending = true;
    } else if snapshot.revision < cursor.revision && !cursor.restart_update_pending {
        return Ok(None);
    } else {
        cursor.revision = cursor.revision.max(snapshot.revision);
        cursor.mode = Some(snapshot.mode);
        cursor.rule_count = Some(rule_count);
    }

    let is_restart_update = cursor.restart_update_pending;
    let update = if is_restart_update {
        ObserverUpdate::Restarted(snapshot)
    } else {
        ObserverUpdate::Snapshot(snapshot)
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
    dropped: &AtomicU64,
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
        } => Ok(PolicyStatus {
            revision,
            mode,
            rule_count,
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
    dropped: &AtomicU64,
    connection_state: &AtomicU8,
) -> Result<bool, IpcError> {
    let mut stream = connect_verified(path, testing_override)?;
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

fn connect_verified(path: &Path, testing_override: bool) -> Result<UnixStream, IpcError> {
    if !testing_override {
        verify_default_socket_path(path)?;
    }
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
    }
    Ok(stream)
}

fn verify_default_socket_path(path: &Path) -> Result<(), IpcError> {
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
    Ok(())
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
    dropped: &AtomicU64,
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
            dropped.fetch_add(1, Ordering::AcqRel);
            false
        }
        Err(TrySendError::Disconnected(_)) => false,
    }
}

fn offer_update(
    sender: &SyncSender<ObserverUpdate>,
    dropped: &AtomicU64,
    update: ObserverUpdate,
) -> OfferOutcome {
    let pending = dropped.swap(0, Ordering::AcqRel);
    if pending > 0 {
        match sender.try_send(ObserverUpdate::Dropped(pending)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                dropped.fetch_add(pending, Ordering::AcqRel);
            }
            Err(TrySendError::Disconnected(_)) => return OfferOutcome::Disconnected,
        }
    }

    match sender.try_send(update) {
        Ok(()) => OfferOutcome::Delivered,
        Err(TrySendError::Full(_)) => {
            dropped.fetch_add(1, Ordering::AcqRel);
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
    fn telemetry_worker_reports_independent_health_transitions()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sender, receiver) = mpsc::sync_channel(2);
        let dropped = AtomicU64::new(0);
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
        let dropped = AtomicU64::new(0);

        sender.try_send(ObserverUpdate::Connected)?;
        sender.try_send(ObserverUpdate::TelemetryConnected)?;
        sender.try_send(ObserverUpdate::Snapshot(empty_snapshot(1)))?;
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

        assert_eq!(dropped.load(Ordering::Acquire), 0);
        assert_eq!(receiver.try_iter().count(), LEARNING_BURST + 4);
        Ok(())
    }

    #[test]
    fn lower_restart_resets_cursor_without_accepting_old_generation_events()
    -> Result<(), Box<dyn std::error::Error>> {
        let revision = Mutex::new(RevisionEpoch::default());
        let dropped = AtomicU64::new(0);
        let (sender, receiver) = mpsc::sync_channel(8);

        assert_eq!(
            enqueue_snapshot(&sender, &revision, &dropped, empty_snapshot(10), false,)?,
            Some(OfferOutcome::Delivered)
        );
        assert!(matches!(receiver.recv()?, ObserverUpdate::Snapshot(_)));
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
            enqueue_snapshot(&sender, &revision, &dropped, empty_snapshot(10), false,)?,
            None
        );
        assert_eq!(subscription_cursor(&revision)?, (11, old_generation));

        // A second, confirmed lower read starts a new epoch and is delivered
        // explicitly so App does not reject it as stale.
        assert_eq!(
            enqueue_snapshot(&sender, &revision, &dropped, empty_snapshot(3), true,)?,
            Some(OfferOutcome::Delivered)
        );
        assert!(matches!(receiver.recv()?, ObserverUpdate::Restarted(_)));
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
        let dropped = AtomicU64::new(0);
        let (sender, _receiver) = mpsc::sync_channel(1);
        assert_eq!(
            enqueue_snapshot(&sender, &revision, &dropped, empty_snapshot(10), false,)?,
            Some(OfferOutcome::Delivered)
        );
        let unchanged = PolicyStatus {
            revision: 10,
            mode: Mode::BlockAll,
            rule_count: 0,
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
    fn explicit_conflict_resync_invalidates_an_unchanged_status() -> Result<(), IpcError> {
        let revision = Mutex::new(RevisionEpoch {
            revision: 10,
            generation: 0,
            mode: Some(Mode::BlockAll),
            rule_count: Some(0),
            resync_required: false,
            restart_update_pending: false,
        });
        let unchanged = PolicyStatus {
            revision: 10,
            mode: Mode::BlockAll,
            rule_count: 0,
        };
        assert!(shared_status_is_unchanged(&revision, unchanged)?);
        mark_resync_required(&revision)?;
        assert!(!shared_status_is_unchanged(&revision, unchanged)?);
        Ok(())
    }

    #[test]
    fn public_redacted_application_snapshot_remains_observable()
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
