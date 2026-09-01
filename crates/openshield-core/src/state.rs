use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{self, Write};
use std::ops::Bound::{Excluded, Unbounded};

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    ApplicationSelector, Direction, FirewallCounters, LearnedApplicationEndpoint, LearnedEndpoint,
    Rule, RuleName, RuleOrigin, RuleSpec, ValidationError, model::REDACTED_APPLICATION_RULE_NAME,
};

pub const MAX_RULES: usize = 10_000;
/// Maximum exact JSON size of persisted policy state.
pub const MAX_STATE_BYTES: usize = 8 * 1024 * 1024;
/// Maximum policy generation representable inside the reserved nftables mark domains.
///
/// Application conntrack marks use two domain bits plus this 30-bit generation.
/// The separate packet-mark handshake reserves only its upper two bits and
/// preserves the remaining 30. Generation exhaustion is fail-closed.
pub const MAX_FLOW_GENERATION: u32 = 0x3fff_ffff;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub revision: u64,
    #[serde(default = "initial_flow_generation")]
    pub flow_generation: u32,
    pub mode: crate::Mode,
    pub rules: Vec<Rule>,
}

impl Snapshot {
    /// Checks rule bounds, identities, and all embedded rule invariants.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the snapshot is too large or malformed.
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.rules.len() > MAX_RULES {
            return Err(CoreError::RulesLimitReached(MAX_RULES));
        }
        if !(1..=MAX_FLOW_GENERATION).contains(&self.flow_generation) {
            return Err(CoreError::InvalidFlowGeneration);
        }
        let mut ids = BTreeSet::new();
        for rule in &self.rules {
            rule.validate()?;
            reject_redacted_rule(rule)?;
            reject_unpinned_application_spec(&rule.spec)?;
            if !ids.insert(rule.id) {
                return Err(CoreError::DuplicateRuleId(rule.id));
            }
        }
        Ok(())
    }

    /// Validates a snapshot received through privileged or public observation IPC.
    ///
    /// Unlike [`Self::validate`], this accepts the one canonical application
    /// redaction emitted for public observers. Redacted metadata remains
    /// forbidden in [`State`] and can therefore never be persisted or
    /// enforced. A snapshot may not mix privileged and redacted application
    /// views.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when bounds, rule identities, application pins,
    /// or observer redaction invariants are violated.
    pub fn validate_for_observer(&self) -> Result<(), CoreError> {
        if self.rules.len() > MAX_RULES {
            return Err(CoreError::RulesLimitReached(MAX_RULES));
        }
        if !(1..=MAX_FLOW_GENERATION).contains(&self.flow_generation) {
            return Err(CoreError::InvalidFlowGeneration);
        }
        let mut ids = BTreeSet::new();
        let mut redaction_state = None;
        for rule in &self.rules {
            rule.validate()?;
            if let Some(selector) = &rule.spec.application {
                let redacted = selector.metadata_redacted;
                if redacted && rule.spec.name.as_str() != REDACTED_APPLICATION_RULE_NAME {
                    return Err(CoreError::InvalidObserverRedaction);
                }
                if !redacted {
                    reject_unpinned_application_spec(&rule.spec)?;
                }
                if redaction_state.is_some_and(|previous| previous != redacted) {
                    return Err(CoreError::InvalidObserverRedaction);
                }
                redaction_state = Some(redacted);
            }
            if !ids.insert(rule.id) {
                return Err(CoreError::DuplicateRuleId(rule.id));
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn redacted_for_observer(&self) -> Self {
        Self {
            revision: self.revision,
            flow_generation: self.flow_generation,
            mode: self.mode,
            rules: self.rules.iter().map(Rule::redacted_for_observer).collect(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub revision: u64,
    pub occurred_at: DateTime<Utc>,
    pub kind: EventKind,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "snake_case",
    tag = "type",
    content = "data"
)]
pub enum EventKind {
    ModeChanged {
        previous: crate::Mode,
        current: crate::Mode,
    },
    RuleCreated {
        rule: Rule,
    },
    RuleUpdated {
        rule: Rule,
    },
    RuleDeleted {
        rule: Rule,
    },
    RuleEnabledChanged {
        rule: Rule,
    },
    CountersUpdated {
        counters: FirewallCounters,
    },
}

impl Event {
    #[must_use]
    pub fn redacted_for_observer(&self) -> Self {
        let kind = match &self.kind {
            EventKind::RuleCreated { rule } => EventKind::RuleCreated {
                rule: rule.redacted_for_observer(),
            },
            EventKind::RuleUpdated { rule } => EventKind::RuleUpdated {
                rule: rule.redacted_for_observer(),
            },
            EventKind::RuleDeleted { rule } => EventKind::RuleDeleted {
                rule: rule.redacted_for_observer(),
            },
            EventKind::RuleEnabledChanged { rule } => EventKind::RuleEnabledChanged {
                rule: rule.redacted_for_observer(),
            },
            other => other.clone(),
        };
        Self {
            revision: self.revision,
            occurred_at: self.occurred_at,
            kind,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    revision: u64,
    #[serde(default = "initial_flow_generation")]
    flow_generation: u32,
    mode: crate::Mode,
    rules: BTreeMap<Uuid, Rule>,
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

impl State {
    #[must_use]
    pub fn new() -> Self {
        Self {
            revision: 0,
            flow_generation: initial_flow_generation(),
            mode: crate::Mode::BlockAll,
            rules: BTreeMap::new(),
        }
    }

    /// Reconstructs mutable state from a validated immutable snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the snapshot violates any state invariant.
    pub fn from_snapshot(snapshot: Snapshot) -> Result<Self, CoreError> {
        snapshot.validate()?;
        let rules = snapshot
            .rules
            .into_iter()
            .map(|rule| (rule.id, rule))
            .collect();
        let state = Self {
            revision: snapshot.revision,
            flow_generation: snapshot.flow_generation,
            mode: snapshot.mode,
            rules,
        };
        state.validate()?;
        Ok(state)
    }

    /// Revalidates a deserialized state before it crosses a trust boundary.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the state is too large or malformed.
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.rules.len() > MAX_RULES {
            return Err(CoreError::RulesLimitReached(MAX_RULES));
        }
        if !(1..=MAX_FLOW_GENERATION).contains(&self.flow_generation) {
            return Err(CoreError::InvalidFlowGeneration);
        }
        for (id, rule) in &self.rules {
            if id != &rule.id {
                return Err(CoreError::MismatchedRuleId {
                    map_id: *id,
                    rule_id: rule.id,
                });
            }
            rule.validate()?;
            reject_redacted_rule(rule)?;
            reject_unpinned_application_spec(&rule.spec)?;
        }
        bounded_serialized_state_size(self)?;
        Ok(())
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn flow_generation(&self) -> u32 {
        self.flow_generation
    }

    /// Replaces the runtime flow-authorization epoch without changing the
    /// user-visible policy revision.
    ///
    /// The daemon calls this once at startup, before installing persisted
    /// policy, so conntrack marks left by an earlier daemon instance cannot
    /// authorize a new instance's traffic.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidFlowGeneration`] for zero, an out-of-domain
    /// value, or accidental reuse of the current epoch.
    pub fn rotate_flow_generation(&mut self, generation: u32) -> Result<(), CoreError> {
        if !(1..=MAX_FLOW_GENERATION).contains(&generation) || generation == self.flow_generation {
            return Err(CoreError::InvalidFlowGeneration);
        }
        self.flow_generation = generation;
        Ok(())
    }

    #[must_use]
    pub const fn mode(&self) -> crate::Mode {
        self.mode
    }

    #[must_use]
    pub fn rules(&self) -> impl ExactSizeIterator<Item = &Rule> {
        self.rules.values()
    }

    /// Iterates over rules ordered by UUID, starting strictly after `cursor`.
    ///
    /// This is a logarithmic `BTreeMap` seek followed by sequential iteration;
    /// callers serving a late pagination cursor do not rescan earlier rules.
    pub fn rules_after(&self, cursor: Option<Uuid>) -> impl Iterator<Item = &Rule> {
        let lower_bound = cursor.map_or(Unbounded, Excluded);
        self.rules
            .range((lower_bound, Unbounded))
            .map(|(_id, rule)| rule)
    }

    #[must_use]
    pub fn rule(&self, id: Uuid) -> Option<&Rule> {
        self.rules.get(&id)
    }

    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            revision: self.revision,
            flow_generation: self.flow_generation,
            mode: self.mode,
            rules: self.rules.values().cloned().collect(),
        }
    }

    /// Changes the operating mode and emits a revisioned event.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::RevisionOverflow`] if no revision remains.
    pub fn set_mode(&mut self, mode: crate::Mode) -> Result<Event, CoreError> {
        self.set_mode_at(mode, Utc::now())
    }

    /// Changes the mode at an explicit event time.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::RevisionOverflow`] if no revision remains.
    pub fn set_mode_at(
        &mut self,
        mode: crate::Mode,
        now: DateTime<Utc>,
    ) -> Result<Event, CoreError> {
        let revision = self.next_revision()?;
        let flow_generation = match self.next_flow_generation() {
            Ok(generation) => generation,
            Err(CoreError::FlowGenerationExhausted) if mode == crate::Mode::BlockAll => {
                self.flow_generation
            }
            Err(error) => return Err(error),
        };
        let previous = self.mode;
        self.mode = mode;
        self.flow_generation = flow_generation;
        self.revision = revision;
        Ok(Event {
            revision,
            occurred_at: now,
            kind: EventKind::ModeChanged {
                previous,
                current: mode,
            },
        })
    }

    /// Validates and inserts a new rule.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] for invalid input, capacity, or revision failure.
    pub fn create_rule(&mut self, spec: RuleSpec) -> Result<(Rule, Event), CoreError> {
        self.create_rule_at(Uuid::new_v4(), spec, Utc::now())
    }

    /// Inserts a rule with an explicit identifier and event time.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] for invalid or duplicate input, capacity, or
    /// revision failure.
    pub fn create_rule_at(
        &mut self,
        id: Uuid,
        spec: RuleSpec,
        now: DateTime<Utc>,
    ) -> Result<(Rule, Event), CoreError> {
        reject_redacted_spec(&spec)?;
        reject_unpinned_application_spec(&spec)?;
        if self.rules.len() >= MAX_RULES {
            return Err(CoreError::RulesLimitReached(MAX_RULES));
        }
        if self.rules.contains_key(&id) {
            return Err(CoreError::DuplicateRuleId(id));
        }
        let rule = Rule::with_id_and_time(id, spec, now)?;
        let revision = self.next_revision()?;
        self.rules.insert(id, rule.clone());
        // Adding an allow rule cannot invalidate an already authorized flow.
        // Keeping the generation avoids interrupting a Learning-mode handshake
        // while its newly observed rule is persisted.
        self.revision = revision;
        let event = Event {
            revision,
            occurred_at: now,
            kind: EventKind::RuleCreated { rule: rule.clone() },
        };
        Ok((rule, event))
    }

    /// Replaces all editable fields of an existing rule.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] if the rule is absent, invalid, or cannot be
    /// revisioned.
    pub fn update_rule(&mut self, id: Uuid, spec: RuleSpec) -> Result<(Rule, Event), CoreError> {
        self.update_rule_at(id, spec, Utc::now())
    }

    /// Replaces a rule at an explicit update time.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] if the rule is absent, invalid, or cannot be
    /// revisioned.
    pub fn update_rule_at(
        &mut self,
        id: Uuid,
        spec: RuleSpec,
        now: DateTime<Utc>,
    ) -> Result<(Rule, Event), CoreError> {
        spec.validate()?;
        reject_redacted_spec(&spec)?;
        reject_unpinned_application_spec(&spec)?;
        let revision = self.next_revision()?;
        let Some(current) = self.rules.get(&id) else {
            return Err(CoreError::RuleNotFound(id));
        };
        let flow_generation = self.next_flow_generation()?;
        let mut rule = current.clone();
        rule.spec = spec;
        // Wall-clock corrections must not make a privileged mutation
        // unavailable. Revisions provide ordering; keep the persisted rule
        // timestamp monotonic when UTC moves backwards.
        rule.updated_at = now.max(rule.updated_at);
        rule.validate()?;
        self.rules.insert(id, rule.clone());
        self.flow_generation = flow_generation;
        self.revision = revision;
        let event = Event {
            revision,
            occurred_at: now,
            kind: EventKind::RuleUpdated { rule: rule.clone() },
        };
        Ok((rule, event))
    }

    /// Deletes a rule by identifier.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] if the rule is absent or cannot be revisioned.
    pub fn delete_rule(&mut self, id: Uuid) -> Result<(Rule, Event), CoreError> {
        self.delete_rule_at(id, Utc::now())
    }

    /// Deletes a rule at an explicit event time.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] if the rule is absent or cannot be revisioned.
    pub fn delete_rule_at(
        &mut self,
        id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<(Rule, Event), CoreError> {
        let revision = self.next_revision()?;
        let Some(rule) = self.rules.get(&id).cloned() else {
            return Err(CoreError::RuleNotFound(id));
        };
        let flow_generation = self.next_flow_generation()?;
        self.rules.remove(&id);
        self.flow_generation = flow_generation;
        self.revision = revision;
        let event = Event {
            revision,
            occurred_at: now,
            kind: EventKind::RuleDeleted { rule: rule.clone() },
        };
        Ok((rule, event))
    }

    /// Enables or disables an existing rule.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] if the rule is absent, invalid after the update,
    /// or cannot be revisioned.
    pub fn set_rule_enabled(
        &mut self,
        id: Uuid,
        enabled: bool,
    ) -> Result<(Rule, Event), CoreError> {
        self.set_rule_enabled_at(id, enabled, Utc::now())
    }

    /// Enables or disables a rule at an explicit update time.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] if the rule is absent, invalid after the update,
    /// or cannot be revisioned.
    pub fn set_rule_enabled_at(
        &mut self,
        id: Uuid,
        enabled: bool,
        now: DateTime<Utc>,
    ) -> Result<(Rule, Event), CoreError> {
        let revision = self.next_revision()?;
        let Some(current) = self.rules.get(&id) else {
            return Err(CoreError::RuleNotFound(id));
        };
        let flow_generation = if current.spec.enabled && !enabled {
            Some(self.next_flow_generation()?)
        } else {
            None
        };
        let mut rule = current.clone();
        rule.spec.enabled = enabled;
        rule.updated_at = now.max(rule.updated_at);
        rule.validate()?;
        self.rules.insert(id, rule.clone());
        if let Some(flow_generation) = flow_generation {
            self.flow_generation = flow_generation;
        }
        self.revision = revision;
        let event = Event {
            revision,
            occurred_at: now,
            kind: EventKind::RuleEnabledChanged { rule: rule.clone() },
        };
        Ok((rule, event))
    }

    /// Deduplicates and persists an endpoint captured in learning mode.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the endpoint is invalid or the generated
    /// rule cannot be inserted.
    pub fn learn_endpoint(&mut self, endpoint: LearnedEndpoint) -> Result<LearnOutcome, CoreError> {
        endpoint.validate()?;
        let key = LearnedRuleKey::from_endpoint(&endpoint);
        if let Some(rule) = self.rules.values().find(|rule| {
            rule.spec.origin == RuleOrigin::Learned
                && rule.spec.direction == Direction::Outbound
                && LearnedRuleKey::from_rule(rule) == key
        }) {
            return Ok(LearnOutcome {
                rule: rule.clone(),
                event: None,
            });
        }
        self.insert_learned_endpoint(endpoint, None)
    }

    /// Creates at most `maximum_new` rules from a bounded endpoint batch using
    /// one O(N) deduplication index.
    ///
    /// The batch form is used by the daemon's learning poll so a full set of
    /// already-known endpoints cannot cause an O(rules × endpoints) scan while
    /// the policy engine is locked. Processing stops safely at [`MAX_RULES`].
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when an endpoint is invalid or a generated rule
    /// cannot be inserted.
    pub fn learn_new_endpoints(
        &mut self,
        endpoints: impl IntoIterator<Item = LearnedEndpoint>,
        maximum_new: usize,
    ) -> Result<Vec<LearnOutcome>, CoreError> {
        let endpoints: Vec<LearnedEndpoint> = endpoints.into_iter().take(MAX_RULES).collect();
        for endpoint in &endpoints {
            endpoint.validate()?;
        }

        let mut known: HashSet<LearnedRuleKey> = self
            .rules
            .values()
            .filter(|rule| {
                rule.spec.origin == RuleOrigin::Learned
                    && rule.spec.direction == Direction::Outbound
            })
            .map(LearnedRuleKey::from_rule)
            .collect();
        let maximum_new = maximum_new.min(MAX_RULES - self.rules.len());
        let mut outcomes = Vec::with_capacity(maximum_new.min(endpoints.len()));

        for endpoint in endpoints {
            let key = LearnedRuleKey::from_endpoint(&endpoint);
            if known.contains(&key) {
                continue;
            }
            if outcomes.len() >= maximum_new {
                break;
            }

            let outcome = self.insert_learned_endpoint(endpoint, None)?;
            known.insert(key);
            outcomes.push(outcome);
        }
        Ok(outcomes)
    }

    /// Creates bounded, deduplicated rules that retain the identity of the
    /// application responsible for each queued outbound connection.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when an endpoint or application selector is
    /// invalid, state capacity is exhausted, or a generated rule cannot be
    /// revisioned.
    pub fn learn_new_application_endpoints(
        &mut self,
        endpoints: impl IntoIterator<Item = LearnedApplicationEndpoint>,
        maximum_new: usize,
    ) -> Result<Vec<LearnOutcome>, CoreError> {
        let endpoints: Vec<LearnedApplicationEndpoint> =
            endpoints.into_iter().take(MAX_RULES).collect();
        for endpoint in &endpoints {
            endpoint.validate().map_err(ValidationError::from)?;
        }

        let mut known: HashSet<LearnedRuleKey> = self
            .rules
            .values()
            .filter(|rule| {
                rule.spec.origin == RuleOrigin::Learned
                    && rule.spec.direction == Direction::Outbound
            })
            .map(LearnedRuleKey::from_rule)
            .collect();
        let maximum_new = maximum_new.min(MAX_RULES - self.rules.len());
        let mut outcomes = Vec::with_capacity(maximum_new.min(endpoints.len()));

        for learned in endpoints {
            let key = LearnedRuleKey::from_application_endpoint(&learned);
            if known.contains(&key) {
                continue;
            }
            if outcomes.len() >= maximum_new {
                break;
            }
            let outcome =
                self.insert_learned_endpoint(learned.endpoint, Some(learned.application))?;
            known.insert(key);
            outcomes.push(outcome);
        }
        Ok(outcomes)
    }

    fn insert_learned_endpoint(
        &mut self,
        endpoint: LearnedEndpoint,
        application: Option<ApplicationSelector>,
    ) -> Result<LearnOutcome, CoreError> {
        let peer_network = Some(IpNet::from(endpoint.address));
        let suffix = endpoint.port.map_or_else(String::new, |port| {
            if port.start() == port.end() {
                format!(":{}", port.start())
            } else {
                format!(":{}-{}", port.start(), port.end())
            }
        });
        let name = RuleName::new(format!(
            "learned {} {}{suffix}",
            endpoint.protocol, endpoint.address
        ))?;
        let mut spec = RuleSpec::new(
            name,
            Direction::Outbound,
            endpoint.protocol,
            peer_network,
            endpoint.port,
            endpoint.interface,
            RuleOrigin::Learned,
            true,
        )?;
        spec.application = application;
        spec.validate()?;
        let (rule, event) = self.create_rule(spec)?;
        Ok(LearnOutcome {
            rule,
            event: Some(event),
        })
    }

    #[must_use]
    pub fn counters_event(&self, counters: FirewallCounters, occurred_at: DateTime<Utc>) -> Event {
        Event {
            revision: self.revision,
            occurred_at,
            kind: EventKind::CountersUpdated { counters },
        }
    }

    fn next_revision(&self) -> Result<u64, CoreError> {
        self.revision
            .checked_add(1)
            .ok_or(CoreError::RevisionOverflow)
    }

    fn next_flow_generation(&self) -> Result<u32, CoreError> {
        if self.flow_generation >= MAX_FLOW_GENERATION {
            return Err(CoreError::FlowGenerationExhausted);
        }
        Ok(self.flow_generation + 1)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct LearnedRuleKey {
    protocol: crate::TransportProtocol,
    peer_network: Option<IpNet>,
    port: Option<crate::PortRange>,
    interface: Option<crate::InterfaceName>,
    application: Option<ApplicationSelector>,
}

impl LearnedRuleKey {
    fn from_endpoint(endpoint: &LearnedEndpoint) -> Self {
        Self {
            protocol: endpoint.protocol,
            peer_network: Some(IpNet::from(endpoint.address)),
            port: endpoint.port,
            interface: endpoint.interface.clone(),
            application: None,
        }
    }

    fn from_application_endpoint(endpoint: &LearnedApplicationEndpoint) -> Self {
        Self {
            protocol: endpoint.endpoint.protocol,
            peer_network: Some(IpNet::from(endpoint.endpoint.address)),
            port: endpoint.endpoint.port,
            interface: endpoint.endpoint.interface.clone(),
            application: Some(endpoint.application.clone()),
        }
    }

    fn from_rule(rule: &Rule) -> Self {
        Self {
            protocol: rule.spec.protocol,
            peer_network: rule.spec.peer_network,
            port: rule.spec.port,
            interface: rule.spec.interface.clone(),
            application: rule.spec.application.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LearnOutcome {
    pub rule: Rule,
    pub event: Option<Event>,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CoreError {
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error("rule {0} does not exist")]
    RuleNotFound(Uuid),
    #[error("rule id {0} appears more than once")]
    DuplicateRuleId(Uuid),
    #[error("state rule key {map_id} differs from embedded id {rule_id}")]
    MismatchedRuleId { map_id: Uuid, rule_id: Uuid },
    #[error("at most {0} rules are allowed")]
    RulesLimitReached(usize),
    #[error("state revision counter is exhausted")]
    RevisionOverflow,
    #[error("state flow-authorization generation is outside the supported mark domain")]
    InvalidFlowGeneration,
    #[error("state flow-authorization generation is exhausted")]
    FlowGenerationExhausted,
    #[error("redacted application metadata cannot enter persisted policy state")]
    RedactedApplicationMetadata,
    #[error("observer snapshot contains a noncanonical or mixed application redaction")]
    InvalidObserverRedaction,
    #[error("application rules require a pinned executable device and inode")]
    UnpinnedApplicationIdentity,
    #[error("serialized state exceeds the {0}-byte persistence limit")]
    StateSizeLimitReached(usize),
    #[error("state serialization failed during size validation: {0}")]
    StateSerialization(String),
}

const fn initial_flow_generation() -> u32 {
    1
}

fn bounded_serialized_state_size(state: &State) -> Result<usize, CoreError> {
    #[derive(Default)]
    struct SizeCounter {
        bytes: usize,
        exceeded: bool,
    }

    impl Write for SizeCounter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let Some(total) = self.bytes.checked_add(bytes.len()) else {
                self.exceeded = true;
                return Err(io::Error::other("serialized state size overflow"));
            };
            if total > MAX_STATE_BYTES {
                self.exceeded = true;
                return Err(io::Error::other("serialized state exceeds fixed limit"));
            }
            self.bytes = total;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut counter = SizeCounter::default();
    match serde_json::to_writer(&mut counter, state) {
        Ok(()) => Ok(counter.bytes),
        Err(_) if counter.exceeded => Err(CoreError::StateSizeLimitReached(MAX_STATE_BYTES)),
        Err(error) => Err(CoreError::StateSerialization(error.to_string())),
    }
}

fn reject_redacted_rule(rule: &Rule) -> Result<(), CoreError> {
    reject_redacted_spec(&rule.spec)
}

fn reject_redacted_spec(spec: &RuleSpec) -> Result<(), CoreError> {
    if spec
        .application
        .as_ref()
        .is_some_and(|selector| selector.metadata_redacted)
    {
        return Err(CoreError::RedactedApplicationMetadata);
    }
    Ok(())
}

fn reject_unpinned_application_spec(spec: &RuleSpec) -> Result<(), CoreError> {
    if spec
        .application
        .as_ref()
        .is_some_and(|selector| selector.executable_file.is_none())
    {
        return Err(CoreError::UnpinnedApplicationIdentity);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use chrono::TimeZone;

    use super::*;
    use crate::{ApplicationPath, Mode, PortRange, TransportProtocol};

    fn fixed_time() -> Result<DateTime<Utc>, Box<dyn Error>> {
        Utc.with_ymd_and_hms(2026, 8, 20, 12, 0, 0)
            .single()
            .ok_or_else(|| "invalid test time".into())
    }

    fn test_spec(name: &str) -> Result<RuleSpec, Box<dyn Error>> {
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

    #[test]
    fn persisted_application_rules_require_a_pinned_file_identity() -> Result<(), Box<dyn Error>> {
        let mut specification = test_spec("unpinned application")?;
        specification.application = Some(ApplicationSelector::new(
            Some(ApplicationPath::new("/usr/bin/example")?),
            None,
            None,
            None,
            None,
        )?);
        let error = State::new().create_rule(specification);
        assert!(matches!(error, Err(CoreError::UnpinnedApplicationIdentity)));
        Ok(())
    }

    #[test]
    fn state_mutations_are_revisioned_and_snapshot_is_sorted() -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        let later = Uuid::parse_str("ffffffff-ffff-4fff-8fff-ffffffffffff")?;
        let earlier = Uuid::parse_str("00000000-0000-4000-8000-000000000001")?;
        state.create_rule_at(later, test_spec("later")?, fixed_time()?)?;
        state.create_rule_at(earlier, test_spec("earlier")?, fixed_time()?)?;

        let snapshot = state.snapshot();
        assert_eq!(snapshot.revision, 2);
        assert_eq!(snapshot.rules[0].id, earlier);
        assert_eq!(snapshot.rules[1].id, later);
        let after_earlier: Vec<_> = state
            .rules_after(Some(earlier))
            .map(|rule| rule.id)
            .collect();
        assert_eq!(after_earlier, vec![later]);
        assert!(state.rules_after(Some(later)).next().is_none());
        Ok(())
    }

    #[test]
    fn failed_update_does_not_change_state() -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        let before = state.clone();
        let missing = Uuid::new_v4();
        assert_eq!(
            state.update_rule_at(missing, test_spec("missing")?, fixed_time()?),
            Err(CoreError::RuleNotFound(missing))
        );
        assert_eq!(state, before);
        Ok(())
    }

    #[test]
    fn fresh_state_is_fail_closed() {
        let state = State::new();
        assert_eq!(state.mode(), Mode::BlockAll);
        assert_eq!(state.flow_generation(), 1);
        assert!(state.rules().next().is_none());
    }

    #[test]
    fn startup_epoch_rotation_rejects_reuse_without_changing_revision() -> Result<(), CoreError> {
        let mut state = State::new();
        state.rotate_flow_generation(42)?;
        assert_eq!(state.flow_generation(), 42);
        assert_eq!(state.revision(), 0);
        assert_eq!(
            state.rotate_flow_generation(42),
            Err(CoreError::InvalidFlowGeneration)
        );
        assert_eq!(
            state.rotate_flow_generation(0),
            Err(CoreError::InvalidFlowGeneration)
        );
        Ok(())
    }

    #[test]
    fn restrictive_mutations_advance_a_non_reused_flow_generation() -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        let (created, _) = state.create_rule(test_spec("generation")?)?;
        assert_eq!(state.flow_generation(), 1);

        state.set_rule_enabled(created.id, false)?;
        assert_eq!(state.flow_generation(), 2);
        state.set_rule_enabled(created.id, true)?;
        assert_eq!(state.flow_generation(), 2);
        state.update_rule(created.id, test_spec("updated generation")?)?;
        assert_eq!(state.flow_generation(), 3);
        state.delete_rule(created.id)?;
        assert_eq!(state.flow_generation(), 4);
        Ok(())
    }

    #[test]
    fn exhausted_generation_can_enter_but_never_leave_block_all() -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        state.mode = Mode::Enforcing;
        state.flow_generation = MAX_FLOW_GENERATION;
        let before = state.clone();
        assert_eq!(
            state.set_mode(Mode::Learning),
            Err(CoreError::FlowGenerationExhausted)
        );
        assert_eq!(state, before);

        state.set_mode(Mode::BlockAll)?;
        assert_eq!(state.mode(), Mode::BlockAll);
        assert_eq!(state.flow_generation(), MAX_FLOW_GENERATION);
        assert_eq!(
            state.set_mode(Mode::Enforcing),
            Err(CoreError::FlowGenerationExhausted)
        );
        Ok(())
    }

    #[test]
    fn mode_change_emits_event() -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        let event = state.set_mode_at(Mode::Enforcing, fixed_time()?)?;
        assert_eq!(state.mode(), Mode::Enforcing);
        assert!(matches!(
            event.kind,
            EventKind::ModeChanged {
                previous: Mode::BlockAll,
                current: Mode::Enforcing
            }
        ));
        Ok(())
    }

    #[test]
    fn learning_deduplicates_endpoints() -> Result<(), Box<dyn Error>> {
        let endpoint = LearnedEndpoint {
            address: "203.0.113.8".parse()?,
            protocol: TransportProtocol::Tcp,
            port: Some(PortRange::single(443)?),
            interface: Some(crate::InterfaceName::new("eth0")?),
        };
        let mut state = State::new();
        let first = state.learn_endpoint(endpoint.clone())?;
        let second = state.learn_endpoint(endpoint)?;
        assert!(first.event.is_some());
        assert!(second.event.is_none());
        assert_eq!(first.rule.id, second.rule.id);
        Ok(())
    }

    #[test]
    fn maximum_learning_batch_is_linear_and_duplicate_safe() -> Result<(), Box<dyn Error>> {
        let interface = crate::InterfaceName::new("eth0")?;
        let port = PortRange::single(443)?;
        let mut endpoints = Vec::with_capacity(MAX_RULES);
        for index in 0..MAX_RULES {
            let offset = u32::try_from(index)?;
            endpoints.push(LearnedEndpoint {
                address: std::net::Ipv4Addr::from(0x0a00_0001_u32 + offset).into(),
                protocol: TransportProtocol::Tcp,
                port: Some(port),
                interface: Some(interface.clone()),
            });
        }

        let mut state = State::new();
        let learned = state.learn_new_endpoints(endpoints.clone(), MAX_RULES)?;
        assert_eq!(learned.len(), MAX_RULES);
        assert!(learned.iter().all(|outcome| outcome.event.is_some()));
        assert_eq!(state.rules().len(), MAX_RULES);
        let full_revision = state.revision();

        let duplicates = state.learn_new_endpoints(endpoints, MAX_RULES)?;
        assert!(duplicates.is_empty());
        assert_eq!(state.revision(), full_revision);
        Ok(())
    }

    #[test]
    fn learning_batch_limits_new_rules_without_losing_later_endpoints() -> Result<(), Box<dyn Error>>
    {
        let interface = crate::InterfaceName::new("eth0")?;
        let port = PortRange::single(53)?;
        let endpoints: Vec<LearnedEndpoint> = (1_u32..=300)
            .map(|offset| LearnedEndpoint {
                address: std::net::Ipv4Addr::from(0xc000_0200_u32 + offset).into(),
                protocol: TransportProtocol::Udp,
                port: Some(port),
                interface: Some(interface.clone()),
            })
            .collect();

        let mut state = State::new();
        assert_eq!(
            state.learn_new_endpoints(endpoints.clone(), 256)?.len(),
            256
        );
        assert_eq!(state.learn_new_endpoints(endpoints, 256)?.len(), 44);
        assert_eq!(state.rules().len(), 300);
        Ok(())
    }

    #[test]
    fn learning_rejects_generic_l3_endpoints() -> Result<(), Box<dyn Error>> {
        let endpoint = LearnedEndpoint {
            address: "2001:db8::7".parse()?,
            protocol: TransportProtocol::Any,
            port: None,
            interface: Some(crate::InterfaceName::new("tun0")?),
        };
        let mut state = State::new();
        assert!(matches!(
            state.learn_endpoint(endpoint),
            Err(CoreError::Validation(
                ValidationError::UnsupportedLearnedProtocol
            ))
        ));
        assert!(state.rules().next().is_none());
        Ok(())
    }

    #[test]
    fn counter_events_do_not_mutate_persisted_state() {
        let state = State::new();
        let before = state.clone();
        let counters = FirewallCounters::default();
        let event = state.counters_event(counters.clone(), Utc::now());
        assert_eq!(event.revision, state.revision());
        assert_eq!(event.kind, EventKind::CountersUpdated { counters });
        assert_eq!(state, before);
    }

    #[test]
    fn clock_rollback_keeps_rule_mutations_available_and_timestamps_monotonic()
    -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        let id = Uuid::new_v4();
        state.create_rule_at(id, test_spec("clock")?, fixed_time()?)?;
        let earlier = Utc
            .with_ymd_and_hms(2026, 8, 20, 11, 59, 59)
            .single()
            .ok_or("invalid earlier test time")?;
        let (disabled, _) = state.set_rule_enabled_at(id, false, earlier)?;
        assert!(!disabled.spec.enabled);
        assert_eq!(disabled.updated_at, fixed_time()?);

        let mut updated_spec = test_spec("updated during rollback")?;
        updated_spec.enabled = false;
        let (updated, _) = state.update_rule_at(id, updated_spec, earlier)?;
        assert_eq!(updated.spec.name.as_str(), "updated during rollback");
        assert_eq!(updated.updated_at, fixed_time()?);
        Ok(())
    }
}
