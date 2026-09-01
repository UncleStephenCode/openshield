use std::collections::BTreeMap;
use std::sync::{
    Arc, Mutex,
    mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError},
};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use chrono::Utc;
#[cfg(test)]
use openshield_core::LearnedEndpoint;
use openshield_core::{
    ApplicationLearningAdmission, ApplicationLearningAdmissionIndex, CoreError, Event, EventKind,
    FirewallCounters, LearnedApplicationEndpoint, MAX_FLOW_GENERATION, MAX_RULES, Mode, Rule,
    RuleOrigin, Snapshot, State, StateStore,
};
use openshield_protocol::{
    Ack, ControlRequest, ErrorCode, ProtocolError, Response, clamp_page_limit,
};
use tracing::{error, warn};
use uuid::Uuid;

use crate::application::{ApplicationDecisionPolicy, pin_rule_application};
use crate::backend::FirewallBackend;

pub const MAX_EVENT_SUBSCRIBERS: usize = 64;
// One learning poll can publish 256 structural events while the engine lock
// prevents subscribers from completing a snapshot refresh. Keep one complete
// batch plus counter/policy-event headroom without making observer memory
// unbounded.
pub const EVENT_QUEUE_CAPACITY: usize = 512;
const MAX_LEARNED_RULES_PER_POLL: usize = 256;

pub type SharedEngine = Arc<Mutex<Engine>>;

#[derive(Debug)]
struct EventBusState {
    next_id: u64,
    subscribers: BTreeMap<u64, SyncSender<Event>>,
    latest_counters: Option<Event>,
}

#[derive(Clone, Debug)]
pub struct EventBus {
    inner: Arc<Mutex<EventBusState>>,
    maximum_subscribers: usize,
    queue_capacity: usize,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl EventBus {
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(MAX_EVENT_SUBSCRIBERS, EVENT_QUEUE_CAPACITY)
    }

    #[must_use]
    fn with_limits(maximum_subscribers: usize, queue_capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(EventBusState {
                next_id: 0,
                subscribers: BTreeMap::new(),
                latest_counters: None,
            })),
            maximum_subscribers,
            queue_capacity,
        }
    }

    pub fn subscribe(&self) -> Result<EventSubscription, SubscribeError> {
        let mut state = self.inner.lock().map_err(|_| SubscribeError::Unavailable)?;
        if state.subscribers.len() >= self.maximum_subscribers {
            return Err(SubscribeError::LimitReached);
        }
        let id = state.next_id;
        state.next_id = state
            .next_id
            .checked_add(1)
            .ok_or(SubscribeError::Unavailable)?;
        let (sender, receiver) = mpsc::sync_channel(self.queue_capacity);
        if let Some(event) = &state.latest_counters {
            sender
                .try_send(event.clone())
                .map_err(|_| SubscribeError::Unavailable)?;
        }
        state.subscribers.insert(id, sender);
        Ok(EventSubscription {
            id,
            receiver,
            bus: self.clone(),
        })
    }

    pub fn publish(&self, event: &Event) {
        let Ok(mut state) = self.inner.lock() else {
            error!("event bus mutex is poisoned; dropping firewall event");
            return;
        };
        if matches!(&event.kind, EventKind::CountersUpdated { .. }) {
            state.latest_counters = Some(event.clone());
        }
        state
            .subscribers
            .retain(|id, sender| match sender.try_send(event.clone()) {
                Ok(()) => true,
                Err(TrySendError::Full(_)) => {
                    warn!(subscriber_id = *id, "dropping slow firewall observer");
                    false
                }
                Err(TrySendError::Disconnected(_)) => false,
            });
    }

    fn remove(&self, id: u64) {
        if let Ok(mut state) = self.inner.lock() {
            state.subscribers.remove(&id);
        }
    }

    fn clear_counter_snapshot(&self) {
        if let Ok(mut state) = self.inner.lock() {
            state.latest_counters = None;
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscribeError {
    LimitReached,
    Unavailable,
}

#[derive(Debug)]
pub struct EventSubscription {
    id: u64,
    receiver: Receiver<Event>,
    bus: EventBus,
}

impl EventSubscription {
    pub fn recv_timeout(&self, timeout: Duration) -> Result<Event, RecvTimeoutError> {
        self.receiver.recv_timeout(timeout)
    }
}

impl Drop for EventSubscription {
    fn drop(&mut self) {
        self.bus.remove(self.id);
    }
}

pub struct Engine {
    state: State,
    application_policy: Arc<ApplicationDecisionPolicy>,
    application_learning_admission: Arc<ApplicationLearningAdmissionIndex>,
    backend: Box<dyn FirewallBackend>,
    store: Box<dyn StateStore>,
    events: EventBus,
    poisoned: bool,
    fatal: bool,
    restart_required: bool,
    startup_policy: StartupPolicy,
    learning_persistence: LearningPersistence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartupPolicy {
    Pending,
    Active,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LearningPersistence {
    Active,
    Paused,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LearningQueueAdmission {
    Enqueue,
    AlreadyKnown,
    Saturated,
    PersistencePaused,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PersistedStateAfterFailure {
    Previous,
    CandidateOrUnknown,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Engine")
            .field("state", &self.state)
            .field(
                "application_policy_rules",
                &self.application_policy.rule_count(),
            )
            .field(
                "application_learning_revision",
                &self.application_learning_admission.revision(),
            )
            .field("store", &self.store)
            .field("events", &self.events)
            .field("poisoned", &self.poisoned)
            .field("fatal", &self.fatal)
            .field("restart_required", &self.restart_required)
            .field("startup_policy", &self.startup_policy)
            .field("learning_persistence", &self.learning_persistence)
            .finish_non_exhaustive()
    }
}

fn rotate_startup_flow_generation(state: &mut State) -> Result<()> {
    // Never reuse an epoch which may still exist in conntrack after an older
    // daemon instance. A random value could collide with N-2 or an earlier
    // live flow; a persisted monotonic epoch cannot. Exhaustion is deliberately
    // fail-closed rather than wrapping an old authorization into validity.
    let generation = state
        .flow_generation()
        .checked_add(1)
        .filter(|generation| *generation <= MAX_FLOW_GENERATION)
        .ok_or_else(|| anyhow!("startup flow-authorization epochs are exhausted"))?;
    state
        .rotate_flow_generation(generation)
        .context("cannot rotate the startup flow-authorization epoch")
}

fn build_application_decision_policy(state: &State) -> ApplicationDecisionPolicy {
    let rules = if state.mode() == Mode::Enforcing {
        state
            .rules()
            .filter(|rule| rule.spec.enabled && rule.spec.application.is_some())
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    ApplicationDecisionPolicy::new(Snapshot {
        revision: state.revision(),
        flow_generation: state.flow_generation(),
        mode: state.mode(),
        rules,
    })
}

fn build_application_learning_admission(state: &State) -> ApplicationLearningAdmissionIndex {
    state.application_learning_admission_index()
}

impl Engine {
    pub fn load(
        mut backend: Box<dyn FirewallBackend>,
        store: Box<dyn StateStore>,
        events: EventBus,
    ) -> Result<Self> {
        // Do not leave a policy from an earlier daemon instance active while
        // persisted state is loaded and re-epoched. This also makes direct
        // invocation safe when the systemd ExecStartPre helper was not used.
        backend
            .fail_closed()
            .context("cannot establish the startup BlockAll quarantine")?;

        let state = match store.load() {
            Ok(Some(mut state)) => {
                rotate_startup_flow_generation(&mut state)?;
                if let Err(save_error) = store.save(&state) {
                    let fail_closed = backend.fail_closed();
                    return match fail_closed {
                        Ok(()) => Err(save_error).context(
                            "new startup flow epoch could not be persisted; fail-closed policy retained",
                        ),
                        Err(fail_error) => Err(anyhow!(
                            "startup flow epoch persistence failed ({save_error}); fail-closed policy also failed ({fail_error:#})"
                        )),
                    };
                }
                state
            }
            Ok(None) => {
                let mut state = State::new();
                state
                    .set_mode(Mode::Learning)
                    .context("cannot construct the initial Learning policy")?;
                rotate_startup_flow_generation(&mut state)?;
                store.save(&state).context(
                    "cannot persist the initial Learning policy; BlockAll remains active",
                )?;
                state
            }
            Err(load_error) => {
                let fail_closed = backend.fail_closed();
                return match fail_closed {
                    Ok(()) => Err(load_error).context(
                        "persisted state is unsafe or invalid; fail-closed policy installed",
                    ),
                    Err(fail_error) => Err(anyhow!(
                        "persisted state failed validation ({load_error}); fail-closed policy also failed ({fail_error:#})"
                    )),
                };
            }
        };

        let application_policy = Arc::new(build_application_decision_policy(&state));
        let application_learning_admission = Arc::new(build_application_learning_admission(&state));
        Ok(Self {
            state,
            application_policy,
            application_learning_admission,
            backend,
            store,
            events,
            poisoned: false,
            fatal: false,
            restart_required: false,
            startup_policy: StartupPolicy::Pending,
            learning_persistence: LearningPersistence::Active,
        })
    }

    /// Installs the validated desired policy after the fail-closed NFQUEUE
    /// consumer is ready. State loading always leaves kernel `BlockAll` active,
    /// so startup cannot expose a queue-listener gap.
    pub fn activate_startup_policy(&mut self) -> Result<()> {
        if self.startup_policy == StartupPolicy::Active {
            return Ok(());
        }
        if let Err(apply_error) = self.backend.apply(&self.state.snapshot()) {
            let fail_closed = self.backend.fail_closed();
            return match fail_closed {
                Ok(()) => Err(apply_error)
                    .context("startup policy could not be applied; BlockAll was retained"),
                Err(fail_error) => Err(anyhow!(
                    "startup policy failed ({apply_error:#}); retaining BlockAll also failed ({fail_error:#})"
                )),
            };
        }
        self.startup_policy = StartupPolicy::Active;
        Ok(())
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.state.revision()
    }

    #[must_use]
    pub const fn mode(&self) -> Mode {
        self.state.mode()
    }

    #[must_use]
    pub const fn is_fatal(&self) -> bool {
        self.fatal
    }

    /// Returns true when the process must exit unsuccessfully so its service
    /// manager can start a fresh instance from the persisted fail-closed
    /// state.  A known emergency `BlockAll` policy and an unknown kernel state
    /// are deliberately tracked separately.
    #[must_use]
    pub const fn restart_required(&self) -> bool {
        self.restart_required || self.fatal
    }

    pub fn subscription_revision(&self) -> Result<u64, ProtocolError> {
        if self.fatal {
            return Err(fatal_protocol_error());
        }
        Ok(self.state.revision())
    }

    /// Returns the bounded policy subset needed by userspace application
    /// attribution.
    ///
    /// Network-only rules are enforced before NFQUEUE and Learning needs no
    /// rule scan at all. Avoid cloning the complete (up to 10,000-rule) state
    /// for every queued packet.
    pub fn application_decision_snapshot(
        &self,
    ) -> Result<Arc<ApplicationDecisionPolicy>, ProtocolError> {
        if self.fatal || self.poisoned {
            return Err(self.emergency_protocol_error());
        }
        Ok(Arc::clone(&self.application_policy))
    }

    /// Reads only the fields which can invalidate an in-flight packet
    /// authorization. This final check runs while holding the engine lock and
    /// must not clone the complete rule set a second time.
    pub fn application_decision_identity(&self) -> Result<(Mode, u32), ProtocolError> {
        if self.fatal || self.poisoned {
            return Err(self.emergency_protocol_error());
        }
        Ok((self.state.mode(), self.state.flow_generation()))
    }

    /// Decides whether an attributed Learning observation can usefully enter
    /// the bounded persistence queue.
    ///
    /// The current state is checked after procfs attribution because learning
    /// commits intentionally retain the flow generation. This makes an exact
    /// rule learned during attribution visible without admitting one more
    /// redundant observation. Policy changes and poisoned state fail closed.
    pub(crate) fn application_learning_queue_admission(
        &self,
        expected_mode: Mode,
        expected_flow_generation: u32,
        endpoint: &LearnedApplicationEndpoint,
    ) -> Result<LearningQueueAdmission, ProtocolError> {
        if self.fatal || self.poisoned {
            return Err(self.emergency_protocol_error());
        }
        if expected_mode != Mode::Learning
            || self.state.mode() != expected_mode
            || self.state.flow_generation() != expected_flow_generation
        {
            return Err(ProtocolError::new(
                ErrorCode::Conflict,
                "policy changed while the application learning endpoint was attributed",
            ));
        }
        if self.application_learning_admission.revision() != self.state.revision()
            || self.application_learning_admission.mode() != self.state.mode()
            || self.application_learning_admission.flow_generation() != self.state.flow_generation()
        {
            return Err(ProtocolError::new(
                ErrorCode::Internal,
                "application learning admission cache is not current",
            ));
        }
        if self.learning_persistence == LearningPersistence::Paused {
            return Ok(LearningQueueAdmission::PersistencePaused);
        }
        match self
            .application_learning_admission
            .classify(endpoint)
            .map_err(|error| ProtocolError::new(ErrorCode::InvalidRequest, error.to_string()))?
        {
            ApplicationLearningAdmission::AlreadyKnown => Ok(LearningQueueAdmission::AlreadyKnown),
            ApplicationLearningAdmission::Saturated => Ok(LearningQueueAdmission::Saturated),
            ApplicationLearningAdmission::Candidate => Ok(LearningQueueAdmission::Enqueue),
        }
    }

    #[must_use]
    pub fn status_response(&self) -> Response {
        if self.fatal {
            return Response::Error(fatal_protocol_error());
        }
        let rule_count = u32::try_from(self.state.rules().len()).unwrap_or(u32::MAX);
        Response::Status {
            revision: self.state.revision(),
            mode: self.state.mode(),
            rule_count,
        }
    }

    #[must_use]
    pub fn rules_page_response(&self, after: Option<Uuid>, requested_limit: u16) -> Response {
        if self.fatal {
            return Response::Error(fatal_protocol_error());
        }
        let limit = usize::from(clamp_page_limit(requested_limit));
        let mut matching = self.state.rules_after(after);
        let rules: Vec<Rule> = matching.by_ref().take(limit).cloned().collect();
        let next_after = matching
            .next()
            .and_then(|_| rules.last().map(|rule| rule.id));
        Response::RulesPage {
            revision: self.state.revision(),
            rules,
            next_after,
        }
    }

    pub fn handle_control(&mut self, request: ControlRequest) -> Result<Ack, ProtocolError> {
        if self.poisoned {
            return Err(ProtocolError::new(
                ErrorCode::BackendUnavailable,
                "policy engine is locked after a failed rollback",
            ));
        }

        let expected_revision = request.expected_revision();
        let current_revision = self.state.revision();
        if expected_revision != current_revision {
            return Err(ProtocolError::new(
                ErrorCode::Conflict,
                format!(
                    "policy revision changed: expected {expected_revision}, current {current_revision}; reload before retrying"
                ),
            ));
        }

        let mut candidate = self.state.clone();
        let (event, affected_rule) = match request {
            ControlRequest::SetMode { mode, .. } => {
                let event = candidate
                    .set_mode(mode)
                    .map_err(|error| core_protocol_error(&error))?;
                (event, None)
            }
            ControlRequest::CreateRule { mut rule, .. } => {
                if rule.origin != RuleOrigin::Manual {
                    return Err(ProtocolError::new(
                        ErrorCode::InvalidRequest,
                        "only the daemon may create rules marked as learned",
                    ));
                }
                pin_rule_application(&mut rule).map_err(|error| {
                    ProtocolError::new(ErrorCode::InvalidRequest, error.to_string())
                })?;
                let (created, event) = candidate
                    .create_rule(rule)
                    .map_err(|error| core_protocol_error(&error))?;
                (event, Some(created))
            }
            ControlRequest::UpdateRule { id, mut rule, .. } => {
                let Some(current) = candidate.rule(id) else {
                    return Err(ProtocolError::new(
                        ErrorCode::NotFound,
                        format!("rule {id} does not exist"),
                    ));
                };
                if current.spec.origin != rule.origin {
                    return Err(ProtocolError::new(
                        ErrorCode::InvalidRequest,
                        "a rule's origin cannot be changed",
                    ));
                }
                pin_rule_application(&mut rule).map_err(|error| {
                    ProtocolError::new(ErrorCode::InvalidRequest, error.to_string())
                })?;
                let (updated, event) = candidate
                    .update_rule(id, rule)
                    .map_err(|error| core_protocol_error(&error))?;
                (event, Some(updated))
            }
            ControlRequest::DeleteRule { id, .. } => {
                let (deleted, event) = candidate
                    .delete_rule(id)
                    .map_err(|error| core_protocol_error(&error))?;
                (event, Some(deleted))
            }
            ControlRequest::SetRuleEnabled { id, enabled, .. } => {
                let (updated, event) = candidate
                    .set_rule_enabled(id, enabled)
                    .map_err(|error| core_protocol_error(&error))?;
                (event, Some(updated))
            }
        };

        candidate
            .validate()
            .map_err(|error| core_protocol_error(&error))?;
        let revision = candidate.revision();
        self.commit(candidate, std::slice::from_ref(&event))?;
        Ok(Ack::new(revision, affected_rule))
    }

    #[cfg(test)]
    pub fn harvest_learning(
        &mut self,
        expected_revision: u64,
        endpoints: Vec<LearnedEndpoint>,
    ) -> Result<usize, ProtocolError> {
        if self.poisoned
            || self.learning_persistence == LearningPersistence::Paused
            || self.state.mode() != Mode::Learning
            || self.state.revision() != expected_revision
            || self.state.rules().len() >= MAX_RULES
        {
            return Ok(0);
        }

        let mut candidate = self.state.clone();
        let valid_endpoints = endpoints.into_iter().take(MAX_RULES).filter(|endpoint| {
            if let Err(error) = endpoint.validate() {
                warn!(%error, "ignoring invalid endpoint from nft learning set");
                false
            } else {
                true
            }
        });
        let outcomes = candidate
            .learn_new_endpoints(valid_endpoints, MAX_LEARNED_RULES_PER_POLL)
            .map_err(|error| core_protocol_error(&error))?;
        let events: Vec<Event> = outcomes
            .into_iter()
            .filter_map(|outcome| outcome.event)
            .collect();
        if events.is_empty() {
            return Ok(0);
        }

        if let Err(error) = candidate.validate() {
            if matches!(error, CoreError::StateSizeLimitReached(_)) {
                self.learning_persistence = LearningPersistence::Paused;
                warn!(%error, "learning stopped at the persisted-state byte limit");
                return Ok(0);
            }
            return Err(core_protocol_error(&error));
        }

        if !self.commit_learning(candidate, &events)? {
            return Ok(0);
        }
        Ok(events.len())
    }

    pub fn harvest_application_learning(
        &mut self,
        expected_flow_generation: u32,
        endpoints: Vec<LearnedApplicationEndpoint>,
    ) -> Result<usize, ProtocolError> {
        if self.poisoned
            || self.learning_persistence == LearningPersistence::Paused
            || self.state.mode() != Mode::Learning
            || self.state.flow_generation() != expected_flow_generation
            || self.state.rules().len() >= MAX_RULES
        {
            return Ok(0);
        }

        let mut candidate = self.state.clone();
        let valid_endpoints = endpoints.into_iter().take(MAX_RULES).filter(|endpoint| {
            if let Err(error) = endpoint.validate() {
                warn!(%error, "ignoring invalid application endpoint from packet quarantine");
                false
            } else {
                true
            }
        });
        let outcomes = candidate
            .learn_new_application_endpoints(valid_endpoints, MAX_LEARNED_RULES_PER_POLL)
            .map_err(|error| core_protocol_error(&error))?;
        let events: Vec<Event> = outcomes
            .into_iter()
            .filter_map(|outcome| outcome.event)
            .collect();
        if events.is_empty() {
            return Ok(0);
        }

        if let Err(error) = candidate.validate() {
            if matches!(error, CoreError::StateSizeLimitReached(_)) {
                self.learning_persistence = LearningPersistence::Paused;
                warn!(%error, "application learning stopped at the persisted-state byte limit");
                return Ok(0);
            }
            return Err(core_protocol_error(&error));
        }

        if !self.commit_learning(candidate, &events)? {
            return Ok(0);
        }
        Ok(events.len())
    }

    pub fn publish_counters_if_current(
        &mut self,
        expected_revision: u64,
        counters: FirewallCounters,
    ) -> bool {
        if self.poisoned || self.state.revision() != expected_revision {
            return false;
        }
        // Every successful observation is also a liveness heartbeat.  Idle
        // counters are therefore republished once per poll without changing or
        // persisting the policy revision.
        let event = self.state.counters_event(counters, Utc::now());
        self.events.publish(&event);
        true
    }

    /// Reinstalls the complete current policy after an observation failure.
    ///
    /// The revision guard prevents an old monitoring result from overwriting a
    /// newer privileged transaction.  A successful repair is intentionally
    /// revision-neutral.  If the current policy cannot be installed, the
    /// engine installs and persists an emergency `BlockAll` state and requests
    /// a supervised restart.  If even `BlockAll` cannot be installed, normal
    /// status is suppressed by the fatal state.
    pub fn repair_policy(&mut self, expected_revision: u64) -> Result<bool, ProtocolError> {
        if self.poisoned {
            return Err(self.emergency_protocol_error());
        }
        if self.restart_required() {
            return Err(if self.fatal {
                fatal_protocol_error()
            } else {
                restart_protocol_error()
            });
        }
        if self.state.revision() != expected_revision {
            return Ok(false);
        }

        let previous = self.state.clone();
        match self.backend.apply(&previous.snapshot()) {
            Ok(()) => {
                self.events.clear_counter_snapshot();
                Ok(true)
            }
            Err(error) => {
                error!(
                    error = %format_args!("{error:#}"),
                    "firewall integrity repair failed; installing emergency BlockAll"
                );
                self.enter_emergency_fail_closed(previous.revision());
                Err(self.emergency_protocol_error())
            }
        }
    }

    pub fn quarantine_after_runtime_failure(&mut self) {
        if self.startup_policy == StartupPolicy::Pending {
            self.poisoned = true;
            self.learning_persistence = LearningPersistence::Paused;
            if let Err(error) = self.backend.fail_closed() {
                error!(error = %format_args!("{error:#}"), "cannot retain startup BlockAll quarantine");
                self.fatal = true;
            }
            return;
        }
        if !self.poisoned && !self.fatal {
            self.enter_emergency_fail_closed(self.state.revision());
        }
    }

    /// Replaces the live kernel policy with `BlockAll` during a normal stop,
    /// while deliberately leaving the persisted user-selected mode intact for
    /// the next supervised start.
    pub fn install_shutdown_quarantine(&mut self) -> Result<()> {
        match self.backend.fail_closed() {
            Ok(()) => {
                self.events.clear_counter_snapshot();
                Ok(())
            }
            Err(error) => {
                self.poisoned = true;
                self.fatal = true;
                Err(error).context("cannot install the shutdown BlockAll quarantine")
            }
        }
    }

    fn commit(&mut self, candidate: State, events: &[Event]) -> Result<(), ProtocolError> {
        let previous = self.state.clone();
        if let Err(error) = self.backend.apply(&candidate.snapshot()) {
            // A timeout or lost process status does not prove that the atomic
            // netlink batch was never committed. Always reinstall the known
            // previous snapshot before claiming it remains active.
            error!(
                error = %format_args!("{error:#}"),
                "firewall transaction outcome is ambiguous; restoring previous policy"
            );
            match self.backend.apply(&previous.snapshot()) {
                Ok(()) => {
                    self.events.clear_counter_snapshot();
                    return Err(ProtocolError::new(
                        ErrorCode::BackendUnavailable,
                        "firewall transaction failed; previous policy was reinstalled",
                    ));
                }
                Err(rollback_error) => {
                    error!(
                        error = %format_args!("{rollback_error:#}"),
                        "firewall rollback after ambiguous apply failed"
                    );
                    self.enter_emergency_fail_closed(previous.revision().max(candidate.revision()));
                    return Err(self.emergency_protocol_error());
                }
            }
        }

        if let Err(save_error) = self.store.save(&candidate) {
            error!(error = %save_error, "state persistence failed; rolling policy back");
            let backend_rollback = self.backend.apply(&previous.snapshot());
            let storage_rollback =
                match self.persisted_state_after_failed_save(&previous, &candidate) {
                    PersistedStateAfterFailure::Previous => Ok(()),
                    PersistedStateAfterFailure::CandidateOrUnknown => self.store.save(&previous),
                };
            if backend_rollback.is_err() || storage_rollback.is_err() {
                if let Err(error) = &backend_rollback {
                    error!(error = %format_args!("{error:#}"), "firewall rollback failed");
                }
                if let Err(error) = &storage_rollback {
                    error!(%error, "state rollback failed");
                }
                self.enter_emergency_fail_closed(previous.revision().max(candidate.revision()));
                return Err(self.emergency_protocol_error());
            }
            return Err(ProtocolError::new(
                ErrorCode::Internal,
                "state persistence failed; previous policy restored",
            ));
        }

        self.replace_state(candidate);
        self.learning_persistence = LearningPersistence::Active;
        self.events.clear_counter_snapshot();
        for event in events {
            self.events.publish(event);
        }
        Ok(())
    }

    fn commit_learning(
        &mut self,
        candidate: State,
        events: &[Event],
    ) -> Result<bool, ProtocolError> {
        let previous = self.state.clone();
        // Learning already permits all outbound traffic.  Newly learned
        // outbound allows do not change the active kernel decision until a
        // later Enforcing transaction, so rebuilding nftables here would only
        // discard dynamic sets and reset live counters.
        if let Err(save_error) = self.store.save(&candidate) {
            error!(
                error = %save_error,
                "learned-state persistence failed; checking the authoritative state file"
            );
            if self.persisted_state_after_failed_save(&previous, &candidate)
                == PersistedStateAfterFailure::CandidateOrUnknown
                && let Err(rollback_error) = self.store.save(&previous)
            {
                error!(
                    error = %rollback_error,
                    "learned-state storage rollback failed"
                );
                self.enter_emergency_fail_closed(previous.revision().max(candidate.revision()));
                return Err(self.emergency_protocol_error());
            }
            // The prior state is still authoritative and the active Learning
            // policy has not changed. Stop further automatic writes until a
            // privileged successful mutation or restart, rather than turning
            // a local traffic/storage-pressure event into destructive global
            // quarantine.
            self.learning_persistence = LearningPersistence::Paused;
            warn!(
                "automatic learning paused after a recoverable persistence failure; previous state retained"
            );
            return Ok(false);
        }

        self.replace_state(candidate);
        self.events.clear_counter_snapshot();
        for event in events {
            self.events.publish(event);
        }
        Ok(true)
    }

    fn persisted_state_after_failed_save(
        &self,
        previous: &State,
        candidate: &State,
    ) -> PersistedStateAfterFailure {
        match self.store.load() {
            Ok(Some(persisted)) if &persisted == previous => PersistedStateAfterFailure::Previous,
            Ok(Some(persisted)) if &persisted == candidate => {
                warn!(
                    "failed save replaced the state file before reporting an error; rollback is required"
                );
                PersistedStateAfterFailure::CandidateOrUnknown
            }
            Ok(_) => {
                error!("state file is absent or differs after a failed save");
                PersistedStateAfterFailure::CandidateOrUnknown
            }
            Err(error) => {
                error!(%error, "cannot validate state file after a failed save");
                PersistedStateAfterFailure::CandidateOrUnknown
            }
        }
    }

    fn enter_emergency_fail_closed(&mut self, revision_floor: u64) {
        self.poisoned = true;
        self.learning_persistence = LearningPersistence::Paused;
        self.restart_required = false;
        match self.backend.fail_closed() {
            Ok(()) => {
                let fail_closed = match State::from_snapshot(Snapshot {
                    revision: revision_floor.saturating_add(1),
                    flow_generation: self.state.flow_generation(),
                    mode: Mode::BlockAll,
                    // BlockAll has no accept path regardless of stored rules.
                    // Retain the last validated policy so a transient runtime
                    // failure cannot become destructive policy data loss.
                    rules: self.state.snapshot().rules,
                }) {
                    Ok(state) => state,
                    Err(error) => {
                        error!(%error, "cannot construct monotonic emergency state");
                        self.fatal = true;
                        self.restart_required = true;
                        return;
                    }
                };
                self.replace_state(fail_closed.clone());
                self.events.clear_counter_snapshot();
                match self.store.save(&fail_closed) {
                    Ok(()) => self.restart_required = true,
                    Err(error) => {
                        // Exiting now could reload an ambiguous candidate or
                        // stale permissive state. Keep the known kernel
                        // BlockAll policy resident and reject all mutations
                        // until an operator repairs storage.
                        error!(
                            %error,
                            "could not persist emergency fail-closed state; daemon quarantined without automatic restart"
                        );
                    }
                }
            }
            Err(error) => {
                error!(error = %format_args!("{error:#}"), "emergency fail-closed update failed");
                // The in-memory state can no longer describe the kernel policy.
                // Refuse all normal status/control responses and make the server
                // terminate so the service manager can restart from persisted
                // state.  Do not overwrite that state with an uninstalled claim.
                self.fatal = true;
                self.restart_required = true;
            }
        }
    }

    fn emergency_protocol_error(&self) -> ProtocolError {
        if self.fatal {
            fatal_protocol_error()
        } else if self.restart_required {
            restart_protocol_error()
        } else {
            ProtocolError::new(
                ErrorCode::BackendUnavailable,
                "emergency BlockAll is active but could not be persisted; daemon is quarantined and requires storage repair",
            )
        }
    }

    fn replace_state(&mut self, state: State) {
        let application_policy = Arc::new(build_application_decision_policy(&state));
        let application_learning_admission = Arc::new(build_application_learning_admission(&state));
        self.state = state;
        self.application_policy = application_policy;
        self.application_learning_admission = application_learning_admission;
    }
}

fn fatal_protocol_error() -> ProtocolError {
    ProtocolError::new(
        ErrorCode::BackendUnavailable,
        "kernel policy state is unknown; daemon is terminating for service-manager recovery",
    )
}

fn restart_protocol_error() -> ProtocolError {
    ProtocolError::new(
        ErrorCode::BackendUnavailable,
        "firewall integrity repair failed; emergency BlockAll is active and the daemon is restarting",
    )
}

fn core_protocol_error(error: &CoreError) -> ProtocolError {
    let code = match error {
        CoreError::Validation(_) => ErrorCode::InvalidRequest,
        CoreError::RuleNotFound(_) => ErrorCode::NotFound,
        CoreError::DuplicateRuleId(_)
        | CoreError::RulesLimitReached(_)
        | CoreError::StateSizeLimitReached(_)
        | CoreError::RevisionOverflow
        | CoreError::FlowGenerationExhausted => ErrorCode::Conflict,
        CoreError::InvalidFlowGeneration
        | CoreError::InvalidObserverRedaction
        | CoreError::StateSerialization(_)
        | CoreError::MismatchedRuleId { .. } => ErrorCode::Internal,
        CoreError::RedactedApplicationMetadata | CoreError::UnpinnedApplicationIdentity => {
            ErrorCode::InvalidRequest
        }
    };
    ProtocolError::new(code, error.to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, Ordering};

    use anyhow::{Result as AnyResult, bail};
    use openshield_core::{
        ApplicationPath, ApplicationSelector, Direction, ExecutableFileId, InterfaceName,
        PortRange, RuleName, RuleSpec, Snapshot, StorageError, TransportProtocol,
    };

    use super::*;
    use crate::backend::FirewallObserver;

    #[derive(Clone, Debug, Default)]
    struct BackendProbe {
        applied: Arc<Mutex<Vec<Snapshot>>>,
        fail_next: Arc<AtomicBool>,
        error_after_apply: Arc<AtomicBool>,
        failure_script: Arc<Mutex<VecDeque<bool>>>,
    }

    impl FirewallObserver for BackendProbe {
        fn policy_observation(&mut self) -> AnyResult<FirewallCounters> {
            Ok(FirewallCounters::default())
        }
    }

    impl FirewallBackend for BackendProbe {
        fn apply(&mut self, snapshot: &Snapshot) -> AnyResult<()> {
            let scripted_failure = self
                .failure_script
                .lock()
                .map_err(|_| anyhow!("backend failure script poisoned"))?
                .pop_front()
                .unwrap_or(false);
            if scripted_failure {
                bail!("injected scripted apply failure");
            }
            if self.fail_next.swap(false, Ordering::SeqCst) {
                bail!("injected apply failure");
            }
            self.applied
                .lock()
                .map_err(|_| anyhow!("backend probe poisoned"))?
                .push(snapshot.clone());
            if self.error_after_apply.swap(false, Ordering::SeqCst) {
                bail!("injected error after policy installation");
            }
            Ok(())
        }

        fn fail_closed(&mut self) -> AnyResult<()> {
            self.apply(&State::new().snapshot())
        }
    }

    #[derive(Clone, Debug)]
    struct StoreProbe {
        state: Arc<Mutex<Option<State>>>,
        fail_next: Arc<AtomicBool>,
        failure_script: Arc<Mutex<VecDeque<bool>>>,
    }

    impl StoreProbe {
        fn new(state: State) -> Self {
            Self {
                state: Arc::new(Mutex::new(Some(state))),
                fail_next: Arc::new(AtomicBool::new(false)),
                failure_script: Arc::new(Mutex::new(VecDeque::new())),
            }
        }

        fn empty() -> Self {
            Self {
                state: Arc::new(Mutex::new(None)),
                fail_next: Arc::new(AtomicBool::new(false)),
                failure_script: Arc::new(Mutex::new(VecDeque::new())),
            }
        }
    }

    impl StateStore for StoreProbe {
        fn load(&self) -> Result<Option<State>, StorageError> {
            self.state
                .lock()
                .map(|state| state.clone())
                .map_err(|_| StorageError::InvalidJson("store probe poisoned".to_owned()))
        }

        fn save(&self, state: &State) -> Result<(), StorageError> {
            let scripted_failure = self
                .failure_script
                .lock()
                .map_err(|_| StorageError::InvalidJson("store failure script poisoned".to_owned()))?
                .pop_front()
                .unwrap_or(false);
            if scripted_failure || self.fail_next.swap(false, Ordering::SeqCst) {
                return Err(StorageError::InvalidJson(
                    "injected persistence failure".to_owned(),
                ));
            }
            *self
                .state
                .lock()
                .map_err(|_| StorageError::InvalidJson("store probe poisoned".to_owned()))? =
                Some(state.clone());
            Ok(())
        }
    }

    fn manual_rule(name: &str) -> AnyResult<RuleSpec> {
        Ok(RuleSpec::new(
            RuleName::new(name)?,
            Direction::Outbound,
            TransportProtocol::Tcp,
            None,
            Some(PortRange::single(443)?),
            None,
            RuleOrigin::Manual,
            true,
        )?)
    }

    fn learned_application_endpoint(
        address_offset: u32,
        uid: u32,
        application_number: u64,
    ) -> AnyResult<LearnedApplicationEndpoint> {
        Ok(LearnedApplicationEndpoint {
            endpoint: LearnedEndpoint {
                address: std::net::Ipv4Addr::from(0x0a00_0001_u32 + address_offset).into(),
                protocol: TransportProtocol::Tcp,
                port: Some(PortRange::single(443)?),
                interface: Some(InterfaceName::new("eth0")?),
            },
            application: ApplicationSelector::new(
                Some(ApplicationPath::new(format!(
                    "/usr/bin/openshield-engine-test-{application_number}"
                ))?),
                Some(ExecutableFileId {
                    device: 8,
                    inode: application_number + 1,
                    size: application_number + 1,
                    ctime_seconds: 1_700_000_000,
                    ctime_nanoseconds: 0,
                }),
                None,
                Some(uid),
                None,
            )?,
        })
    }

    fn engine_with_probes() -> AnyResult<(Engine, BackendProbe, StoreProbe, EventBus)> {
        engine_with_state(State::new())
    }

    fn engine_with_state(state: State) -> AnyResult<(Engine, BackendProbe, StoreProbe, EventBus)> {
        let backend = BackendProbe::default();
        let store = StoreProbe::new(state);
        let events = EventBus::new();
        let mut engine = Engine::load(
            Box::new(backend.clone()),
            Box::new(store.clone()),
            events.clone(),
        )?;
        engine.activate_startup_policy()?;
        backend
            .applied
            .lock()
            .map_err(|_| anyhow!("backend probe poisoned"))?
            .clear();
        Ok((engine, backend, store, events))
    }

    #[test]
    fn packet_decision_omits_rules_that_cannot_require_userspace_attribution() -> AnyResult<()> {
        let mut state = State::new();
        state.create_rule(manual_rule("kernel-only")?)?;
        state.set_mode(Mode::Enforcing)?;
        let (mut engine, _backend, _store, _events) = engine_with_state(state)?;

        let snapshot = engine
            .application_decision_snapshot()
            .map_err(|error| anyhow!(error.message))?;
        let same_policy = engine
            .application_decision_snapshot()
            .map_err(|error| anyhow!(error.message))?;
        assert!(Arc::ptr_eq(&snapshot, &same_policy));
        assert_eq!(snapshot.mode, Mode::Enforcing);
        assert!(snapshot.rules.is_empty());
        assert_eq!(
            engine
                .application_decision_identity()
                .map_err(|error| anyhow!(error.message))?,
            (snapshot.mode, snapshot.flow_generation)
        );

        let previous_revision = engine.revision();
        engine
            .handle_control(ControlRequest::SetMode {
                expected_revision: previous_revision,
                mode: Mode::Learning,
            })
            .map_err(|error| anyhow!(error.message))?;
        let learning_policy = engine
            .application_decision_snapshot()
            .map_err(|error| anyhow!(error.message))?;
        assert!(!Arc::ptr_eq(&snapshot, &learning_policy));
        assert_eq!(learning_policy.mode, Mode::Learning);
        assert!(learning_policy.rules.is_empty());
        Ok(())
    }

    #[test]
    fn learning_admission_cache_skips_known_and_saturated_observations() -> AnyResult<()> {
        let mut state = State::new();
        state.set_mode(Mode::Learning)?;
        let endpoints = (0..256)
            .map(|offset| learned_application_endpoint(offset, 1_000, 1))
            .collect::<AnyResult<Vec<_>>>()?;
        let known = endpoints[0].clone();
        assert_eq!(
            state
                .learn_new_application_endpoints(endpoints, MAX_RULES)?
                .len(),
            256
        );
        let saturated = learned_application_endpoint(300, 1_000, 1)?;
        let candidate = learned_application_endpoint(301, 1_001, 2)?;
        let (mut engine, _backend, _store, _events) = engine_with_state(state)?;
        let generation = engine.state.flow_generation();

        assert_eq!(
            engine
                .application_learning_queue_admission(Mode::Learning, generation, &known)
                .map_err(|error| anyhow!(error.message))?,
            LearningQueueAdmission::AlreadyKnown
        );
        assert_eq!(
            engine
                .application_learning_queue_admission(Mode::Learning, generation, &saturated)
                .map_err(|error| anyhow!(error.message))?,
            LearningQueueAdmission::Saturated
        );
        assert_eq!(
            engine
                .application_learning_queue_admission(Mode::Learning, generation, &candidate)
                .map_err(|error| anyhow!(error.message))?,
            LearningQueueAdmission::Enqueue
        );
        assert!(
            engine
                .application_learning_queue_admission(
                    Mode::Learning,
                    generation.saturating_add(1),
                    &candidate,
                )
                .is_err()
        );

        assert_eq!(
            engine
                .harvest_application_learning(generation, vec![candidate.clone()])
                .map_err(|error| anyhow!(error.message))?,
            1
        );
        assert_eq!(
            engine
                .application_learning_queue_admission(Mode::Learning, generation, &candidate)
                .map_err(|error| anyhow!(error.message))?,
            LearningQueueAdmission::AlreadyKnown
        );

        let later = learned_application_endpoint(302, 1_002, 3)?;
        engine.learning_persistence = LearningPersistence::Paused;
        assert_eq!(
            engine
                .application_learning_queue_admission(Mode::Learning, generation, &later)
                .map_err(|error| anyhow!(error.message))?,
            LearningQueueAdmission::PersistencePaused
        );
        engine.poisoned = true;
        assert!(
            engine
                .application_learning_queue_admission(Mode::Learning, generation, &later)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn first_start_stays_blocked_until_learning_policy_is_explicitly_activated() -> AnyResult<()> {
        let previous_generation = State::new().flow_generation();
        let backend = BackendProbe::default();
        let store = StoreProbe::empty();
        let mut engine = Engine::load(
            Box::new(backend.clone()),
            Box::new(store.clone()),
            EventBus::new(),
        )?;
        let generation = engine.state.flow_generation();
        assert_ne!(generation, previous_generation);
        assert_eq!(engine.mode(), Mode::Learning);
        assert_eq!(
            store
                .state
                .lock()
                .map_err(|_| anyhow!("store probe poisoned"))?
                .as_ref()
                .map(|state| (state.mode(), state.flow_generation())),
            Some((Mode::Learning, generation))
        );
        {
            let applied = backend
                .applied
                .lock()
                .map_err(|_| anyhow!("backend probe poisoned"))?;
            assert_eq!(applied.len(), 1);
            assert_eq!(applied[0].mode, Mode::BlockAll);
        }

        engine.activate_startup_policy()?;
        let applied = backend
            .applied
            .lock()
            .map_err(|_| anyhow!("backend probe poisoned"))?;
        assert_eq!(applied.len(), 2);
        assert_eq!(applied[0].mode, Mode::BlockAll);
        assert_eq!(applied[1].mode, Mode::Learning);
        assert_eq!(applied[1].flow_generation, generation);
        Ok(())
    }

    #[test]
    fn existing_saved_mode_is_preserved_across_startup() -> AnyResult<()> {
        for expected_mode in [Mode::BlockAll, Mode::Learning, Mode::Enforcing] {
            let mut state = State::new();
            if expected_mode != Mode::BlockAll {
                state.set_mode(expected_mode)?;
            }
            let backend = BackendProbe::default();
            let store = StoreProbe::new(state);
            let mut engine =
                Engine::load(Box::new(backend.clone()), Box::new(store), EventBus::new())?;

            assert_eq!(engine.mode(), expected_mode);
            engine.activate_startup_policy()?;
            let applied = backend
                .applied
                .lock()
                .map_err(|_| anyhow!("backend probe poisoned"))?;
            assert_eq!(applied.len(), 2);
            assert_eq!(applied[0].mode, Mode::BlockAll);
            assert_eq!(applied[1].mode, expected_mode);
        }
        Ok(())
    }

    #[test]
    fn exhausted_startup_epoch_stays_fail_closed_instead_of_reusing_a_mark() -> AnyResult<()> {
        let mut state = State::new();
        state.rotate_flow_generation(MAX_FLOW_GENERATION)?;
        let backend = BackendProbe::default();
        let store = StoreProbe::new(state);

        assert!(
            Engine::load(Box::new(backend.clone()), Box::new(store), EventBus::new(),).is_err()
        );
        let applied = backend
            .applied
            .lock()
            .map_err(|_| anyhow!("backend probe poisoned"))?;
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].mode, Mode::BlockAll);
        Ok(())
    }

    #[test]
    fn failed_first_learning_activation_retains_block_all_and_learning_intent() -> AnyResult<()> {
        let backend = BackendProbe::default();
        let store = StoreProbe::empty();
        let mut engine = Engine::load(
            Box::new(backend.clone()),
            Box::new(store.clone()),
            EventBus::new(),
        )?;
        backend
            .failure_script
            .lock()
            .map_err(|_| anyhow!("backend failure script poisoned"))?
            .extend([true, false]);

        assert!(engine.activate_startup_policy().is_err());
        assert_eq!(engine.mode(), Mode::Learning);
        assert_eq!(
            store
                .state
                .lock()
                .map_err(|_| anyhow!("store probe poisoned"))?
                .as_ref()
                .map(State::mode),
            Some(Mode::Learning)
        );
        let applied = backend
            .applied
            .lock()
            .map_err(|_| anyhow!("backend probe poisoned"))?;
        assert_eq!(
            applied.last().map(|snapshot| snapshot.mode),
            Some(Mode::BlockAll)
        );
        Ok(())
    }

    #[test]
    fn shutdown_quarantine_does_not_overwrite_the_saved_mode() -> AnyResult<()> {
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        let (mut engine, backend, store, _events) = engine_with_state(state)?;
        let saved_revision = engine.revision();

        engine.install_shutdown_quarantine()?;

        assert_eq!(engine.mode(), Mode::Enforcing);
        assert_eq!(engine.revision(), saved_revision);
        assert_eq!(
            store
                .state
                .lock()
                .map_err(|_| anyhow!("store probe poisoned"))?
                .as_ref()
                .map(|state| (state.mode(), state.revision())),
            Some((Mode::Enforcing, saved_revision))
        );
        let applied = backend
            .applied
            .lock()
            .map_err(|_| anyhow!("backend probe poisoned"))?;
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].mode, Mode::BlockAll);
        Ok(())
    }

    #[test]
    fn backend_failure_keeps_state_and_emits_no_event() -> AnyResult<()> {
        let (mut engine, backend, store, events) = engine_with_probes()?;
        let subscription = events
            .subscribe()
            .map_err(|_| anyhow!("subscribe failed"))?;
        backend.fail_next.store(true, Ordering::SeqCst);

        let result = engine.handle_control(ControlRequest::SetMode {
            expected_revision: 0,
            mode: Mode::Enforcing,
        });
        assert!(matches!(
            result,
            Err(ProtocolError {
                code: ErrorCode::BackendUnavailable,
                ..
            })
        ));
        assert_eq!(engine.mode(), Mode::BlockAll);
        assert_eq!(
            store
                .state
                .lock()
                .map_err(|_| anyhow!("store probe poisoned"))?
                .as_ref()
                .map(State::mode),
            Some(Mode::BlockAll)
        );
        assert!(matches!(
            subscription.recv_timeout(Duration::from_millis(10)),
            Err(RecvTimeoutError::Timeout)
        ));
        Ok(())
    }

    #[test]
    fn ambiguous_apply_is_rolled_back_even_if_candidate_reached_kernel() -> AnyResult<()> {
        let (mut engine, backend, store, _events) = engine_with_probes()?;
        backend.error_after_apply.store(true, Ordering::SeqCst);

        assert!(
            engine
                .handle_control(ControlRequest::SetMode {
                    expected_revision: 0,
                    mode: Mode::Enforcing,
                })
                .is_err()
        );
        assert_eq!(engine.mode(), Mode::BlockAll);
        assert!(!engine.restart_required());
        let applied = backend
            .applied
            .lock()
            .map_err(|_| anyhow!("backend probe poisoned"))?;
        assert_eq!(applied.len(), 2);
        assert_eq!(applied[0].mode, Mode::Enforcing);
        assert_eq!(applied[1].mode, Mode::BlockAll);
        assert_eq!(
            store
                .state
                .lock()
                .map_err(|_| anyhow!("store probe poisoned"))?
                .as_ref()
                .map(State::mode),
            Some(Mode::BlockAll)
        );
        Ok(())
    }

    #[test]
    fn ambiguous_apply_and_failed_rollback_enter_persisted_emergency() -> AnyResult<()> {
        let (mut engine, backend, store, _events) = engine_with_probes()?;
        backend.error_after_apply.store(true, Ordering::SeqCst);
        backend
            .failure_script
            .lock()
            .map_err(|_| anyhow!("backend failure script poisoned"))?
            .extend([false, true, false]);

        assert!(
            engine
                .handle_control(ControlRequest::SetMode {
                    expected_revision: 0,
                    mode: Mode::Enforcing,
                })
                .is_err()
        );
        assert_eq!(engine.mode(), Mode::BlockAll);
        assert!(engine.restart_required());
        assert_eq!(
            store
                .state
                .lock()
                .map_err(|_| anyhow!("store probe poisoned"))?
                .as_ref()
                .map(State::mode),
            Some(Mode::BlockAll)
        );
        Ok(())
    }

    #[test]
    fn persistence_failure_rolls_firewall_back() -> AnyResult<()> {
        let (mut engine, backend, store, _events) = engine_with_probes()?;
        store.fail_next.store(true, Ordering::SeqCst);
        let result = engine.handle_control(ControlRequest::SetMode {
            expected_revision: 0,
            mode: Mode::Enforcing,
        });
        assert!(matches!(
            result,
            Err(ProtocolError {
                code: ErrorCode::Internal,
                ..
            })
        ));
        assert_eq!(engine.mode(), Mode::BlockAll);
        let applied = backend
            .applied
            .lock()
            .map_err(|_| anyhow!("backend probe poisoned"))?;
        assert_eq!(applied.len(), 2);
        assert_eq!(applied[0].mode, Mode::Enforcing);
        assert_eq!(applied[1].mode, Mode::BlockAll);
        Ok(())
    }

    #[test]
    fn successful_rule_change_is_persisted_before_event() -> AnyResult<()> {
        let (mut engine, _backend, store, events) = engine_with_probes()?;
        let subscription = events
            .subscribe()
            .map_err(|_| anyhow!("subscribe failed"))?;
        let ack = engine
            .handle_control(ControlRequest::CreateRule {
                expected_revision: 0,
                rule: manual_rule("https")?,
            })
            .map_err(|error| anyhow!("control failed: {}", error.message))?;
        assert_eq!(ack.revision, 1);
        assert!(ack.affected_rule.is_some());
        assert_eq!(
            store
                .state
                .lock()
                .map_err(|_| anyhow!("store probe poisoned"))?
                .as_ref()
                .map(State::revision),
            Some(1)
        );
        assert_eq!(
            subscription
                .recv_timeout(Duration::from_millis(50))?
                .revision,
            1
        );
        Ok(())
    }

    #[test]
    fn two_mutations_from_one_revision_apply_exactly_once() -> AnyResult<()> {
        let (mut engine, backend, store, events) = engine_with_probes()?;
        let subscription = events
            .subscribe()
            .map_err(|_| anyhow!("subscribe failed"))?;

        let first = engine
            .handle_control(ControlRequest::SetMode {
                expected_revision: 0,
                mode: Mode::Learning,
            })
            .map_err(|error| anyhow!(error.message))?;
        assert_eq!(first.revision, 1);
        assert_eq!(
            subscription
                .recv_timeout(Duration::from_millis(50))?
                .revision,
            1
        );

        let second = engine.handle_control(ControlRequest::SetMode {
            expected_revision: 0,
            mode: Mode::Enforcing,
        });
        assert!(matches!(
            second,
            Err(ProtocolError {
                code: ErrorCode::Conflict,
                ..
            })
        ));
        assert_eq!(engine.revision(), 1);
        assert_eq!(engine.mode(), Mode::Learning);
        assert_eq!(
            backend
                .applied
                .lock()
                .map_err(|_| anyhow!("backend probe poisoned"))?
                .len(),
            1
        );
        let persisted = store
            .state
            .lock()
            .map_err(|_| anyhow!("store probe poisoned"))?;
        assert_eq!(persisted.as_ref().map(State::revision), Some(1));
        assert_eq!(persisted.as_ref().map(State::mode), Some(Mode::Learning));
        assert!(matches!(
            subscription.recv_timeout(Duration::from_millis(10)),
            Err(RecvTimeoutError::Timeout)
        ));
        Ok(())
    }

    #[test]
    fn pagination_is_sorted_and_has_stable_cursor() -> AnyResult<()> {
        let (mut engine, _backend, _store, _events) = engine_with_probes()?;
        for name in ["one", "two", "three"] {
            let expected_revision = engine.revision();
            engine
                .handle_control(ControlRequest::CreateRule {
                    expected_revision,
                    rule: manual_rule(name)?,
                })
                .map_err(|error| anyhow!("control failed: {}", error.message))?;
        }
        let Response::RulesPage {
            revision,
            rules,
            next_after,
        } = engine.rules_page_response(None, 2)
        else {
            bail!("unexpected response");
        };
        assert_eq!(revision, 3);
        assert_eq!(rules.len(), 2);
        let cursor = next_after.ok_or_else(|| anyhow!("missing page cursor"))?;
        assert_eq!(cursor, rules[1].id);
        let Response::RulesPage {
            rules: final_page,
            next_after: final_cursor,
            ..
        } = engine.rules_page_response(Some(cursor), 2)
        else {
            bail!("unexpected response");
        };
        assert_eq!(final_page.len(), 1);
        assert!(final_cursor.is_none());
        Ok(())
    }

    #[test]
    fn full_subscriber_queue_disconnects_slow_reader() -> AnyResult<()> {
        let bus = EventBus::with_limits(1, 1);
        let subscription = bus.subscribe().map_err(|_| anyhow!("subscribe failed"))?;
        let mut state = State::new();
        bus.publish(&state.set_mode(Mode::Learning)?);
        bus.publish(&state.set_mode(Mode::Enforcing)?);
        assert_eq!(
            subscription
                .recv_timeout(Duration::from_millis(50))?
                .revision,
            1
        );
        assert!(matches!(
            subscription.recv_timeout(Duration::from_millis(50)),
            Err(RecvTimeoutError::Disconnected)
        ));
        Ok(())
    }

    #[test]
    fn new_subscriber_receives_latest_counter_snapshot() -> AnyResult<()> {
        let bus = EventBus::new();
        let state = State::new();
        let mut counters = FirewallCounters::default();
        counters.accepted_out.packets = 7;
        let event = state.counters_event(counters, Utc::now());
        bus.publish(&event);

        let subscription = bus.subscribe().map_err(|_| anyhow!("subscribe failed"))?;
        assert_eq!(subscription.recv_timeout(Duration::from_millis(50))?, event);
        Ok(())
    }

    #[test]
    fn unchanged_counters_are_republished_as_liveness_heartbeats() -> AnyResult<()> {
        let (mut engine, _backend, _store, events) = engine_with_probes()?;
        let subscription = events
            .subscribe()
            .map_err(|_| anyhow!("subscribe failed"))?;
        let revision = engine.revision();
        let counters = FirewallCounters::default();

        assert!(engine.publish_counters_if_current(revision, counters.clone()));
        assert!(engine.publish_counters_if_current(revision, counters));
        let first = subscription.recv_timeout(Duration::from_millis(50))?;
        let second = subscription.recv_timeout(Duration::from_millis(50))?;
        assert_eq!(first.revision, revision);
        assert_eq!(second.revision, revision);
        assert!(matches!(first.kind, EventKind::CountersUpdated { .. }));
        assert!(matches!(second.kind, EventKind::CountersUpdated { .. }));
        Ok(())
    }

    #[test]
    fn failed_emergency_policy_marks_engine_fatal_without_false_status() -> AnyResult<()> {
        let (mut engine, backend, store, _events) = engine_with_probes()?;
        store.fail_next.store(true, Ordering::SeqCst);
        backend
            .failure_script
            .lock()
            .map_err(|_| anyhow!("backend failure script poisoned"))?
            .extend([false, true, true]);

        let result = engine.handle_control(ControlRequest::SetMode {
            expected_revision: 0,
            mode: Mode::Enforcing,
        });
        assert!(matches!(
            result,
            Err(ProtocolError {
                code: ErrorCode::BackendUnavailable,
                ..
            })
        ));
        assert!(engine.is_fatal());
        assert!(matches!(
            engine.status_response(),
            Response::Error(ProtocolError {
                code: ErrorCode::BackendUnavailable,
                ..
            })
        ));
        assert!(engine.subscription_revision().is_err());
        assert_eq!(
            store
                .state
                .lock()
                .map_err(|_| anyhow!("store probe poisoned"))?
                .as_ref()
                .map(State::mode),
            Some(Mode::BlockAll)
        );
        Ok(())
    }

    #[test]
    fn emergency_fail_closed_state_keeps_revision_monotonic() -> AnyResult<()> {
        let mut prior = State::new();
        prior.set_mode(Mode::Learning)?;
        prior.create_rule(manual_rule("preserved through emergency")?)?;
        let prior_revision = prior.revision();
        let (mut engine, backend, store, _events) = engine_with_state(prior)?;
        store.fail_next.store(true, Ordering::SeqCst);
        backend
            .failure_script
            .lock()
            .map_err(|_| anyhow!("backend failure script poisoned"))?
            .extend([false, true, false]);

        let result = engine.handle_control(ControlRequest::SetMode {
            expected_revision: prior_revision,
            mode: Mode::Enforcing,
        });
        assert!(matches!(
            result,
            Err(ProtocolError {
                code: ErrorCode::BackendUnavailable,
                ..
            })
        ));
        assert!(!engine.is_fatal());
        assert!(engine.restart_required());
        assert_eq!(engine.mode(), Mode::BlockAll);
        assert!(engine.revision() > prior_revision);
        let persisted = store
            .state
            .lock()
            .map_err(|_| anyhow!("store probe poisoned"))?
            .clone()
            .ok_or_else(|| anyhow!("emergency state was not persisted"))?;
        assert_eq!(persisted.mode(), Mode::BlockAll);
        assert_eq!(persisted.revision(), engine.revision());
        assert_eq!(persisted.rules().len(), 1);
        assert!(matches!(
            engine.status_response(),
            Response::Status {
                revision,
                mode: Mode::BlockAll,
                rule_count: 1,
            } if revision == engine.revision()
        ));
        Ok(())
    }

    #[test]
    fn unpersisted_emergency_block_all_stays_quarantined_without_restart() -> AnyResult<()> {
        let mut prior = State::new();
        prior.set_mode(Mode::Learning)?;
        let prior_revision = prior.revision();
        let (mut engine, backend, store, _events) = engine_with_state(prior)?;
        store
            .failure_script
            .lock()
            .map_err(|_| anyhow!("store failure script poisoned"))?
            .extend([true, true, true]);
        backend
            .failure_script
            .lock()
            .map_err(|_| anyhow!("backend failure script poisoned"))?
            .extend([false, true, false]);

        assert!(
            engine
                .handle_control(ControlRequest::SetMode {
                    expected_revision: prior_revision,
                    mode: Mode::Enforcing,
                })
                .is_err()
        );
        assert!(!engine.is_fatal());
        assert!(!engine.restart_required());
        assert_eq!(engine.mode(), Mode::BlockAll);
        assert!(engine.revision() > prior_revision);
        assert!(matches!(
            engine.status_response(),
            Response::Status {
                mode: Mode::BlockAll,
                ..
            }
        ));
        let emergency_revision = engine.revision();
        assert!(
            engine
                .handle_control(ControlRequest::SetMode {
                    expected_revision: emergency_revision,
                    mode: Mode::Learning,
                })
                .is_err()
        );
        let persisted = store
            .state
            .lock()
            .map_err(|_| anyhow!("store probe poisoned"))?
            .clone()
            .ok_or_else(|| anyhow!("original persisted state disappeared"))?;
        assert_eq!(persisted.mode(), Mode::Learning);
        Ok(())
    }

    #[test]
    fn observation_repair_reapplies_current_policy_without_revision_change() -> AnyResult<()> {
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        let expected_revision = state.revision();
        let (mut engine, backend, _store, _events) = engine_with_state(state)?;

        assert!(
            engine
                .repair_policy(expected_revision)
                .map_err(|error| anyhow!(error.message))?
        );
        assert_eq!(engine.revision(), expected_revision);
        assert!(!engine.restart_required());
        let applied = backend
            .applied
            .lock()
            .map_err(|_| anyhow!("backend probe poisoned"))?;
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].revision, expected_revision);
        assert_eq!(applied[0].mode, Mode::Enforcing);
        Ok(())
    }

    #[test]
    fn failed_observation_repair_installs_persisted_block_all_and_requests_restart() -> AnyResult<()>
    {
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        let expected_revision = state.revision();
        let (mut engine, backend, store, _events) = engine_with_state(state)?;
        backend
            .failure_script
            .lock()
            .map_err(|_| anyhow!("backend failure script poisoned"))?
            .extend([true, false]);

        let result = engine.repair_policy(expected_revision);
        assert!(matches!(
            result,
            Err(ProtocolError {
                code: ErrorCode::BackendUnavailable,
                ..
            })
        ));
        assert!(engine.restart_required());
        assert!(!engine.is_fatal());
        assert_eq!(engine.mode(), Mode::BlockAll);
        assert!(engine.revision() > expected_revision);
        let persisted = store
            .state
            .lock()
            .map_err(|_| anyhow!("store probe poisoned"))?
            .clone()
            .ok_or_else(|| anyhow!("emergency state was not persisted"))?;
        assert_eq!(persisted.mode(), Mode::BlockAll);
        assert_eq!(persisted.revision(), engine.revision());
        Ok(())
    }

    #[test]
    fn learning_persists_without_rebuilding_the_active_table() -> AnyResult<()> {
        let mut state = State::new();
        state.set_mode(Mode::Learning)?;
        let expected_revision = state.revision();
        let (mut engine, backend, store, events) = engine_with_state(state)?;
        let subscription = events
            .subscribe()
            .map_err(|_| anyhow!("subscribe failed"))?;
        let endpoint = LearnedEndpoint {
            address: "192.0.2.44".parse()?,
            protocol: TransportProtocol::Tcp,
            port: Some(PortRange::single(443)?),
            interface: Some(InterfaceName::new("eth0")?),
        };

        assert_eq!(
            engine
                .harvest_learning(expected_revision, vec![endpoint])
                .map_err(|error| anyhow!(error.message))?,
            1
        );
        assert!(
            backend
                .applied
                .lock()
                .map_err(|_| anyhow!("backend probe poisoned"))?
                .is_empty()
        );
        let persisted = store
            .state
            .lock()
            .map_err(|_| anyhow!("store probe poisoned"))?
            .clone()
            .ok_or_else(|| anyhow!("learned state was not persisted"))?;
        assert_eq!(persisted.rules().len(), 1);
        assert_eq!(persisted.revision(), engine.revision());
        assert_eq!(
            subscription
                .recv_timeout(Duration::from_millis(50))?
                .revision,
            engine.revision()
        );
        Ok(())
    }

    #[test]
    fn learning_poll_bounds_new_rules_and_progresses_past_duplicates() -> AnyResult<()> {
        let mut state = State::new();
        state.set_mode(Mode::Learning)?;
        let (mut engine, backend, store, events) = engine_with_state(state)?;
        let subscription = events
            .subscribe()
            .map_err(|_| anyhow!("subscribe failed"))?;
        let interface = InterfaceName::new("eth0")?;
        let port = PortRange::single(443)?;
        let endpoints: Vec<LearnedEndpoint> = (1_u32..=300)
            .map(|offset| LearnedEndpoint {
                address: std::net::Ipv4Addr::from(0xc633_6400_u32 + offset).into(),
                protocol: TransportProtocol::Tcp,
                port: Some(port),
                interface: Some(interface.clone()),
            })
            .collect();

        let first_revision = engine.revision();
        assert_eq!(
            engine
                .harvest_learning(first_revision, endpoints.clone())
                .map_err(|error| anyhow!(error.message))?,
            MAX_LEARNED_RULES_PER_POLL
        );
        assert_eq!(engine.revision(), first_revision + 256);
        for expected_revision in
            (first_revision + 1)..=(first_revision + MAX_LEARNED_RULES_PER_POLL as u64)
        {
            let event = subscription.recv_timeout(Duration::from_millis(50))?;
            assert_eq!(event.revision, expected_revision);
            assert!(matches!(event.kind, EventKind::RuleCreated { .. }));
        }
        assert_eq!(
            engine
                .harvest_learning(engine.revision(), endpoints)
                .map_err(|error| anyhow!(error.message))?,
            44
        );
        for expected_revision in (first_revision + 257)..=(first_revision + 300) {
            let event = subscription.recv_timeout(Duration::from_millis(50))?;
            assert_eq!(event.revision, expected_revision);
            assert!(matches!(event.kind, EventKind::RuleCreated { .. }));
        }
        assert!(matches!(
            subscription.recv_timeout(Duration::from_millis(1)),
            Err(RecvTimeoutError::Timeout)
        ));
        assert_eq!(
            store
                .state
                .lock()
                .map_err(|_| anyhow!("store probe poisoned"))?
                .as_ref()
                .map(|state| state.rules().len()),
            Some(300)
        );
        assert!(
            backend
                .applied
                .lock()
                .map_err(|_| anyhow!("backend probe poisoned"))?
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn recoverable_learning_storage_failure_pauses_without_quarantine() -> AnyResult<()> {
        let mut state = State::new();
        state.set_mode(Mode::Learning)?;
        let expected_revision = state.revision();
        let (mut engine, backend, store, _events) = engine_with_state(state)?;
        store.fail_next.store(true, Ordering::SeqCst);
        let endpoint = LearnedEndpoint {
            address: "2001:db8::44".parse()?,
            protocol: TransportProtocol::Udp,
            port: Some(PortRange::single(53)?),
            interface: Some(InterfaceName::new("eth1")?),
        };

        assert_eq!(
            engine
                .harvest_learning(expected_revision, vec![endpoint.clone()])
                .map_err(|error| anyhow!(error.message))?,
            0
        );
        assert_eq!(
            engine
                .harvest_learning(expected_revision, vec![endpoint])
                .map_err(|error| anyhow!(error.message))?,
            0
        );
        assert_eq!(engine.revision(), expected_revision);
        assert!(
            backend
                .applied
                .lock()
                .map_err(|_| anyhow!("backend probe poisoned"))?
                .is_empty()
        );
        assert!(!engine.restart_required());
        Ok(())
    }

    #[test]
    fn persistent_learning_storage_pressure_keeps_previous_state_without_rewrite() -> AnyResult<()>
    {
        let mut state = State::new();
        state.set_mode(Mode::Learning)?;
        let expected_revision = state.revision();
        let (mut engine, _backend, store, _events) = engine_with_state(state)?;
        store
            .failure_script
            .lock()
            .map_err(|_| anyhow!("store failure script poisoned"))?
            .extend([true, true]);
        let endpoint = LearnedEndpoint {
            address: "192.0.2.45".parse()?,
            protocol: TransportProtocol::Icmp,
            port: None,
            interface: Some(InterfaceName::new("tun0")?),
        };

        assert_eq!(
            engine
                .harvest_learning(expected_revision, vec![endpoint])
                .map_err(|error| anyhow!(error.message))?,
            0
        );
        assert!(!engine.restart_required());
        assert_eq!(engine.mode(), Mode::Learning);
        assert_eq!(engine.revision(), expected_revision);
        let persisted = store
            .state
            .lock()
            .map_err(|_| anyhow!("store probe poisoned"))?
            .clone()
            .ok_or_else(|| anyhow!("previous state disappeared"))?;
        assert_eq!(persisted.mode(), Mode::Learning);
        assert_eq!(persisted.revision(), expected_revision);
        assert_eq!(persisted.rules().len(), 0);
        assert_eq!(
            store
                .failure_script
                .lock()
                .map_err(|_| anyhow!("store failure script poisoned"))?
                .len(),
            1,
            "the known-good file must not be rewritten after a pre-commit failure"
        );
        Ok(())
    }
}
