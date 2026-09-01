//! Security-sensitive domain types and policy generation for `OpenShield`.
//!
//! This crate deliberately contains no shell execution and no packet-capture
//! code.  Inputs are validated into typed values before the nftables compiler
//! can use them.

#![forbid(unsafe_code)]

mod application;
mod model;
mod nftables;
mod state;
mod storage;

pub use application::{
    ApplicationIdentity, ApplicationPath, ApplicationSelector, ApplicationValidationError,
    CgroupPath, CommandArgument, CommandLineMatch, CommandLineSelector, ExecutableFileId,
    LearnedApplicationEndpoint, MAX_APPLICATION_PATH_BYTES, MAX_CGROUP_PATH_BYTES,
    MAX_COMMAND_ARGUMENT_BYTES, MAX_COMMAND_ARGUMENTS, MAX_COMMAND_LINE_BYTES,
};
pub use model::{
    CounterValue, Direction, FirewallCounters, InterfaceName, LearnedEndpoint,
    MAX_INTERFACE_NAME_BYTES, MAX_RULE_NAME_BYTES, Mode, PortRange, Rule, RuleName, RuleOrigin,
    RuleSpec, TransportProtocol, ValidationError,
};
pub use nftables::{
    APPLICATION_QUEUE_NUMBER, COUNTER_ACCEPTED_IN, COUNTER_ACCEPTED_OUT, COUNTER_DROPPED_IN,
    COUNTER_DROPPED_OUT, COUNTER_LEARNED_OUT, CompileError, LEARNED_ICMP_V4_SET,
    LEARNED_ICMP_V6_SET, LEARNED_TCP_V4_SET, LEARNED_TCP_V6_SET, LEARNED_UDP_V4_SET,
    LEARNED_UDP_V6_SET, NftablesCompiler, NftablesPolicy, TABLE_NAME, application_flow_mark,
    application_pending_mark,
};
pub use state::{
    CoreError, Event, EventKind, LearnOutcome, MAX_FLOW_GENERATION, MAX_RULES, MAX_STATE_BYTES,
    Snapshot, State,
};
pub use storage::{AtomicStateStore, StateStore, StorageError};
