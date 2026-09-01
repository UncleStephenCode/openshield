use ipnet::IpNet;
use openshield_core::{
    ApplicationPath, ApplicationSelector, CgroupPath, CommandArgument, CommandLineMatch,
    CommandLineSelector, Direction, Event, EventKind, ExecutableFileId, FirewallCounters,
    InterfaceName, MAX_APPLICATION_PATH_BYTES, MAX_CGROUP_PATH_BYTES, MAX_COMMAND_LINE_BYTES, Mode,
    PortRange, Rule, RuleName, RuleOrigin, RuleSpec, Snapshot, TransportProtocol,
};
use openshield_protocol::ControlRequest;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use uuid::Uuid;

use crate::i18n::I18n;

pub const MAX_VISIBLE_EVENTS: usize = 500;
const MAX_RULE_NAME_CHARS: usize = 128;
const MAX_NETWORK_CHARS: usize = 64;
const MAX_PORT_CHARS: usize = 11;
const MAX_INTERFACE_CHARS: usize = 15;
const MAX_FILE_ID_CHARS: usize = 20;
const MAX_UID_CHARS: usize = 10;
const MAX_ARGUMENTS_JSON_BYTES: usize = MAX_COMMAND_LINE_BYTES * 3;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum View {
    #[default]
    Status,
    Rules,
    Events,
    Help,
}

impl View {
    pub fn title(self, i18n: &I18n) -> &str {
        match self {
            Self::Status => i18n.tr("view.status"),
            Self::Rules => i18n.tr("view.rules"),
            Self::Events => i18n.tr("view.events"),
            Self::Help => i18n.tr("view.help"),
        }
    }

    pub const fn next(self) -> Self {
        match self {
            Self::Status => Self::Rules,
            Self::Rules => Self::Events,
            Self::Events => Self::Help,
            Self::Help => Self::Status,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectionState {
    Connecting,
    Connected,
    Disconnected(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormField {
    Name,
    Direction,
    Protocol,
    PeerNetwork,
    Port,
    Interface,
    Application,
    Executable,
    Device,
    Inode,
    CommandMode,
    Arguments,
    Uid,
    Cgroup,
    Enabled,
}

impl FormField {
    pub const fn next(self) -> Self {
        match self {
            Self::Name => Self::Direction,
            Self::Direction => Self::Protocol,
            Self::Protocol => Self::PeerNetwork,
            Self::PeerNetwork => Self::Port,
            Self::Port => Self::Interface,
            Self::Interface => Self::Application,
            Self::Application => Self::Executable,
            Self::Executable => Self::Device,
            Self::Device => Self::Inode,
            Self::Inode => Self::CommandMode,
            Self::CommandMode => Self::Arguments,
            Self::Arguments => Self::Uid,
            Self::Uid => Self::Cgroup,
            Self::Cgroup => Self::Enabled,
            Self::Enabled => Self::Name,
        }
    }

    pub const fn previous(self) -> Self {
        match self {
            Self::Name => Self::Enabled,
            Self::Direction => Self::Name,
            Self::Protocol => Self::Direction,
            Self::PeerNetwork => Self::Protocol,
            Self::Port => Self::PeerNetwork,
            Self::Interface => Self::Port,
            Self::Application => Self::Interface,
            Self::Executable => Self::Application,
            Self::Device => Self::Executable,
            Self::Inode => Self::Device,
            Self::CommandMode => Self::Inode,
            Self::Arguments => Self::CommandMode,
            Self::Uid => Self::Arguments,
            Self::Cgroup => Self::Uid,
            Self::Enabled => Self::Cgroup,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CommandMode {
    #[default]
    Any,
    Exact,
    Prefix,
}

impl CommandMode {
    const fn cycle(self, reverse: bool) -> Self {
        match (self, reverse) {
            (Self::Any, false) | (Self::Prefix, true) => Self::Exact,
            (Self::Exact, false) | (Self::Any, true) => Self::Prefix,
            (Self::Prefix, false) | (Self::Exact, true) => Self::Any,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleForm {
    pub id: Option<Uuid>,
    pub active_field: FormField,
    pub name: String,
    pub direction: Direction,
    pub protocol: TransportProtocol,
    pub peer_network: String,
    pub port: String,
    pub interface: String,
    pub bind_application: bool,
    pub executable: String,
    pub executable_device: String,
    pub executable_inode: String,
    pub command_mode: CommandMode,
    pub arguments: String,
    pub uid: String,
    pub cgroup: String,
    pub origin: RuleOrigin,
    pub enabled: bool,
    pub error: Option<String>,
}

impl Default for RuleForm {
    fn default() -> Self {
        Self {
            id: None,
            active_field: FormField::Name,
            name: String::new(),
            direction: Direction::Outbound,
            protocol: TransportProtocol::Any,
            peer_network: String::new(),
            port: String::new(),
            interface: String::new(),
            bind_application: false,
            executable: String::new(),
            executable_device: String::new(),
            executable_inode: String::new(),
            command_mode: CommandMode::Any,
            arguments: String::new(),
            uid: String::new(),
            cgroup: String::new(),
            origin: RuleOrigin::Manual,
            enabled: true,
            error: None,
        }
    }
}

impl RuleForm {
    pub fn from_rule(rule: &Rule) -> Self {
        let application = rule.spec.application.as_ref();
        let command_line = application.and_then(|selector| selector.command_line.as_ref());
        let arguments = command_line.map_or_else(String::new, |selector| {
            let values: Vec<&str> = selector
                .arguments
                .iter()
                .map(CommandArgument::as_str)
                .collect();
            serde_json::to_string(&values).unwrap_or_default()
        });
        Self {
            id: Some(rule.id),
            active_field: FormField::Name,
            name: rule.spec.name.to_string(),
            direction: rule.spec.direction,
            protocol: rule.spec.protocol,
            peer_network: rule
                .spec
                .peer_network
                .as_ref()
                .map_or_else(String::new, ToString::to_string),
            port: rule.spec.port.map_or_else(String::new, |range| {
                if range.start() == range.end() {
                    range.start().to_string()
                } else {
                    format!("{}-{}", range.start(), range.end())
                }
            }),
            interface: rule
                .spec
                .interface
                .as_ref()
                .map_or_else(String::new, ToString::to_string),
            bind_application: application.is_some(),
            executable: application
                .and_then(|selector| selector.executable.as_ref())
                .map_or_else(String::new, ToString::to_string),
            executable_device: application
                .and_then(|selector| selector.executable_file)
                .map_or_else(String::new, |file| file.device.to_string()),
            executable_inode: application
                .and_then(|selector| selector.executable_file)
                .map_or_else(String::new, |file| file.inode.to_string()),
            command_mode: command_line.map_or(CommandMode::Any, |selector| match selector.kind {
                CommandLineMatch::Exact => CommandMode::Exact,
                CommandLineMatch::Prefix => CommandMode::Prefix,
            }),
            arguments,
            uid: application
                .and_then(|selector| selector.uid)
                .map_or_else(String::new, |uid| uid.to_string()),
            cgroup: application
                .and_then(|selector| selector.cgroup.as_ref())
                .map_or_else(String::new, ToString::to_string),
            origin: rule.spec.origin,
            enabled: rule.spec.enabled,
            error: None,
        }
    }

    pub fn move_next(&mut self) {
        self.active_field = self.active_field.next();
        self.error = None;
    }

    pub fn move_previous(&mut self) {
        self.active_field = self.active_field.previous();
        self.error = None;
    }

    pub fn insert_char(&mut self, character: char) {
        let (value, limit) = match self.active_field {
            FormField::Name => (&mut self.name, MAX_RULE_NAME_CHARS),
            FormField::PeerNetwork => (&mut self.peer_network, MAX_NETWORK_CHARS),
            FormField::Port => (&mut self.port, MAX_PORT_CHARS),
            FormField::Interface => (&mut self.interface, MAX_INTERFACE_CHARS),
            FormField::Executable => (&mut self.executable, MAX_APPLICATION_PATH_BYTES),
            FormField::Device => {
                if character.is_ascii_digit() && self.executable_device.len() < MAX_FILE_ID_CHARS {
                    self.executable_device.push(character);
                    self.error = None;
                }
                return;
            }
            FormField::Inode => {
                if character.is_ascii_digit() && self.executable_inode.len() < MAX_FILE_ID_CHARS {
                    self.executable_inode.push(character);
                    self.error = None;
                }
                return;
            }
            FormField::Arguments => (&mut self.arguments, MAX_ARGUMENTS_JSON_BYTES),
            FormField::Uid => {
                if character.is_ascii_digit() && self.uid.len() < MAX_UID_CHARS {
                    self.uid.push(character);
                    self.error = None;
                }
                return;
            }
            FormField::Cgroup => (&mut self.cgroup, MAX_CGROUP_PATH_BYTES),
            FormField::Direction
            | FormField::Protocol
            | FormField::Application
            | FormField::CommandMode
            | FormField::Enabled => return,
        };

        if is_safe_form_character(character)
            && value.len().saturating_add(character.len_utf8()) <= limit
        {
            value.push(character);
            self.error = None;
        }
    }

    pub fn backspace(&mut self) {
        match self.active_field {
            FormField::Name => {
                self.name.pop();
            }
            FormField::PeerNetwork => {
                self.peer_network.pop();
            }
            FormField::Port => {
                self.port.pop();
            }
            FormField::Interface => {
                self.interface.pop();
            }
            FormField::Executable => {
                self.executable.pop();
            }
            FormField::Device => {
                self.executable_device.pop();
            }
            FormField::Inode => {
                self.executable_inode.pop();
            }
            FormField::Arguments => {
                self.arguments.pop();
            }
            FormField::Uid => {
                self.uid.pop();
            }
            FormField::Cgroup => {
                self.cgroup.pop();
            }
            FormField::Direction
            | FormField::Protocol
            | FormField::Application
            | FormField::CommandMode
            | FormField::Enabled => return,
        }
        self.error = None;
    }

    pub fn cycle_choice(&mut self, reverse: bool) {
        match self.active_field {
            FormField::Direction => {
                self.direction = match self.direction {
                    Direction::Inbound => Direction::Outbound,
                    Direction::Outbound => Direction::Inbound,
                };
            }
            FormField::Protocol => {
                self.protocol = cycle_protocol(self.protocol, reverse);
            }
            FormField::Application => self.bind_application = !self.bind_application,
            FormField::CommandMode => {
                self.command_mode = self.command_mode.cycle(reverse);
            }
            FormField::Enabled => self.enabled = !self.enabled,
            FormField::Name
            | FormField::PeerNetwork
            | FormField::Port
            | FormField::Interface
            | FormField::Executable
            | FormField::Device
            | FormField::Inode
            | FormField::Arguments
            | FormField::Uid
            | FormField::Cgroup => return,
        }
        self.error = None;
    }

    pub fn to_rule_spec(&self, i18n: &I18n) -> Result<RuleSpec, String> {
        let name = self.name.trim();
        if name.is_empty() {
            return Err(i18n.tr("validation.name_empty").to_owned());
        }

        let peer_network = if self.peer_network.trim().is_empty() {
            None
        } else {
            Some(parse_peer_network(self.peer_network.trim(), i18n)?)
        };

        let port = parse_port_range(self.port.trim(), i18n)?;
        if matches!(
            self.protocol,
            TransportProtocol::Icmp | TransportProtocol::IcmpV6
        ) && port.is_some()
        {
            return Err(i18n.tr("validation.icmp_port").to_owned());
        }

        let interface = if self.interface.trim().is_empty() {
            None
        } else {
            Some(InterfaceName::new(self.interface.trim()).map_err(|error| {
                i18n.format(
                    "validation.invalid_interface",
                    &[("error", error.to_string().as_str())],
                )
            })?)
        };

        let application = self.parse_application(i18n)?;

        let rule = RuleSpec {
            name: RuleName::new(name).map_err(|error| {
                i18n.format(
                    "validation.invalid_name",
                    &[("error", error.to_string().as_str())],
                )
            })?,
            direction: self.direction,
            protocol: self.protocol,
            peer_network,
            port,
            interface,
            application,
            origin: self.origin,
            enabled: self.enabled,
        };
        rule.validate().map_err(|error| {
            i18n.format(
                "validation.invalid_rule",
                &[("error", error.to_string().as_str())],
            )
        })?;
        Ok(rule)
    }

    fn parse_application(&self, i18n: &I18n) -> Result<Option<ApplicationSelector>, String> {
        if !self.bind_application {
            return Ok(None);
        }
        if self.direction != Direction::Outbound {
            return Err(i18n.tr("validation.application_outbound").to_owned());
        }
        let executable = self.executable.trim();
        if executable.is_empty() {
            return Err(i18n.tr("validation.executable_required").to_owned());
        }
        let executable = ApplicationPath::new(executable).map_err(|error| {
            i18n.format(
                "validation.invalid_executable",
                &[("error", error.to_string().as_str())],
            )
        })?;
        let executable_file = parse_file_identity(
            self.executable_device.trim(),
            self.executable_inode.trim(),
            i18n,
        )?;
        let command_line = match self.command_mode {
            CommandMode::Any => {
                if !self.arguments.trim().is_empty() {
                    return Err(i18n.tr("validation.arguments_unused").to_owned());
                }
                None
            }
            CommandMode::Exact | CommandMode::Prefix => {
                let arguments = parse_command_arguments(self.arguments.trim(), i18n)?;
                let kind = if self.command_mode == CommandMode::Exact {
                    CommandLineMatch::Exact
                } else {
                    CommandLineMatch::Prefix
                };
                Some(CommandLineSelector::new(kind, arguments).map_err(|error| {
                    i18n.format(
                        "validation.invalid_arguments",
                        &[("error", error.to_string().as_str())],
                    )
                })?)
            }
        };
        let uid = if self.uid.trim().is_empty() {
            None
        } else {
            Some(
                self.uid
                    .trim()
                    .parse::<u32>()
                    .map_err(|_| i18n.tr("validation.invalid_uid").to_owned())?,
            )
        };
        let cgroup = if self.cgroup.trim().is_empty() {
            None
        } else {
            Some(CgroupPath::new(self.cgroup.trim()).map_err(|error| {
                i18n.format(
                    "validation.invalid_cgroup",
                    &[("error", error.to_string().as_str())],
                )
            })?)
        };
        ApplicationSelector::new(Some(executable), executable_file, command_line, uid, cgroup)
            .map(Some)
            .map_err(|error| {
                i18n.format(
                    "validation.invalid_rule",
                    &[("error", error.to_string().as_str())],
                )
            })
    }
}

fn parse_file_identity(
    device: &str,
    inode: &str,
    i18n: &I18n,
) -> Result<Option<ExecutableFileId>, String> {
    match (device.is_empty(), inode.is_empty()) {
        (true, true) => Ok(None),
        (false, false) => {
            let file = ExecutableFileId {
                device: device
                    .parse::<u64>()
                    .map_err(|_| i18n.tr("validation.invalid_device").to_owned())?,
                inode: inode
                    .parse::<u64>()
                    .map_err(|_| i18n.tr("validation.invalid_inode").to_owned())?,
            };
            file.validate()
                .map_err(|_| i18n.tr("validation.invalid_inode").to_owned())?;
            Ok(Some(file))
        }
        (true, false) | (false, true) => Err(i18n.tr("validation.file_id_pair").to_owned()),
    }
}

fn parse_command_arguments(value: &str, i18n: &I18n) -> Result<Vec<CommandArgument>, String> {
    let values = serde_json::from_str::<Vec<serde_json::Value>>(value)
        .map_err(|_| i18n.tr("validation.arguments_json").to_owned())?;
    values
        .into_iter()
        .map(|value| {
            let value = value
                .as_str()
                .ok_or_else(|| i18n.tr("validation.arguments_strings").to_owned())?;
            CommandArgument::new(value).map_err(|error| {
                i18n.format(
                    "validation.invalid_arguments",
                    &[("error", error.to_string().as_str())],
                )
            })
        })
        .collect()
}

fn is_safe_form_character(character: char) -> bool {
    !character.is_control()
        && !matches!(
            character,
            '\u{061c}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{feff}'
        )
}

fn parse_peer_network(value: &str, i18n: &I18n) -> Result<IpNet, String> {
    if let Ok(network) = value.parse::<IpNet>() {
        return Ok(network);
    }
    value.parse::<IpAddr>().map(IpNet::from).map_err(|error| {
        i18n.format(
            "validation.invalid_peer",
            &[("error", error.to_string().as_str())],
        )
    })
}

fn parse_port_range(value: &str, i18n: &I18n) -> Result<Option<PortRange>, String> {
    if value.is_empty() {
        return Ok(None);
    }

    let mut parts = value.split('-');
    let start = parts
        .next()
        .ok_or_else(|| i18n.tr("validation.port_missing").to_owned())?
        .parse::<u16>()
        .map_err(|_| i18n.tr("validation.port_number").to_owned())?;
    let end = match parts.next() {
        Some(value) => value
            .parse::<u16>()
            .map_err(|_| i18n.tr("validation.port_end_number").to_owned())?,
        None => start,
    };
    if parts.next().is_some() {
        return Err(i18n.tr("validation.port_format").to_owned());
    }

    PortRange::new(start, end).map(Some).map_err(|error| {
        i18n.format(
            "validation.invalid_port_range",
            &[("error", error.to_string().as_str())],
        )
    })
}

const fn cycle_protocol(protocol: TransportProtocol, reverse: bool) -> TransportProtocol {
    match (protocol, reverse) {
        (TransportProtocol::Any, false) | (TransportProtocol::Udp, true) => TransportProtocol::Tcp,
        (TransportProtocol::Tcp, false) | (TransportProtocol::Icmp, true) => TransportProtocol::Udp,
        (TransportProtocol::Udp, false) | (TransportProtocol::IcmpV6, true) => {
            TransportProtocol::Icmp
        }
        (TransportProtocol::Icmp, false) | (TransportProtocol::Any, true) => {
            TransportProtocol::IcmpV6
        }
        (TransportProtocol::IcmpV6, false) | (TransportProtocol::Tcp, true) => {
            TransportProtocol::Any
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Overlay {
    None,
    ModePicker { selected: Mode },
    ConfirmBlockAll,
    Editor(Box<RuleForm>),
    ConfirmDelete { id: Uuid, name: String },
    Message { title: String, body: String },
}

#[derive(Clone, Debug)]
pub struct App {
    pub i18n: I18n,
    pub view: View,
    pub connection: ConnectionState,
    pub telemetry: ConnectionState,
    pub snapshot: Option<Snapshot>,
    pub counters: Option<FirewallCounters>,
    pub events: VecDeque<Event>,
    pub selected_rule: usize,
    pub overlay: Overlay,
    pub read_only: bool,
    pub should_quit: bool,
    pub notice: Option<String>,
    pub dropped_events: u64,
    pending_revision: Option<u64>,
    telemetry_connected_at: Option<Instant>,
    last_counters_at: Option<Instant>,
}

impl App {
    pub fn new(read_only: bool, i18n: I18n) -> Self {
        Self {
            i18n,
            view: View::Status,
            connection: ConnectionState::Connecting,
            telemetry: ConnectionState::Connecting,
            snapshot: None,
            counters: None,
            events: VecDeque::with_capacity(MAX_VISIBLE_EVENTS),
            selected_rule: 0,
            overlay: Overlay::None,
            read_only,
            should_quit: false,
            notice: None,
            dropped_events: 0,
            pending_revision: None,
            telemetry_connected_at: None,
            last_counters_at: None,
        }
    }

    pub fn set_snapshot(&mut self, snapshot: Snapshot) {
        if self
            .snapshot
            .as_ref()
            .is_some_and(|current| current.revision > snapshot.revision)
        {
            return;
        }
        self.snapshot = Some(snapshot);
        self.clamp_rule_selection();
    }

    pub fn set_restarted_snapshot(&mut self, snapshot: Snapshot) {
        self.snapshot = Some(snapshot);
        self.counters = None;
        self.last_counters_at = None;
        self.events.clear();
        self.selected_rule = 0;
        self.clamp_rule_selection();
        self.overlay = Overlay::None;
        self.pending_revision = None;
        self.notice = Some(self.i18n.tr("notice.daemon_restarted").to_owned());
    }

    pub fn set_disconnected(&mut self, reason: String) {
        self.connection = ConnectionState::Disconnected(reason);
        self.snapshot = None;
        self.counters = None;
        self.last_counters_at = None;
        self.selected_rule = 0;
        self.pending_revision = None;
        if !matches!(self.overlay, Overlay::None | Overlay::Message { .. }) {
            self.overlay = Overlay::None;
            self.notice = Some(self.i18n.tr("notice.connection_lost").to_owned());
        }
    }

    pub fn push_event(&mut self, event: Event) {
        self.push_event_at(event, Instant::now());
    }

    pub fn set_telemetry_connected(&mut self) {
        self.set_telemetry_connected_at(Instant::now());
    }

    pub fn set_telemetry_disconnected(&mut self, reason: String) {
        self.telemetry = ConnectionState::Disconnected(reason);
        self.telemetry_connected_at = None;
    }

    #[must_use]
    pub fn counters_age(&self, now: Instant) -> Option<Duration> {
        self.last_counters_at
            .map(|received_at| now.saturating_duration_since(received_at))
    }

    #[must_use]
    pub fn telemetry_connection_age(&self, now: Instant) -> Option<Duration> {
        self.telemetry_connected_at
            .map(|connected_at| now.saturating_duration_since(connected_at))
    }

    fn set_telemetry_connected_at(&mut self, now: Instant) {
        if !matches!(self.telemetry, ConnectionState::Connected) {
            self.telemetry_connected_at = Some(now);
        }
        self.telemetry = ConnectionState::Connected;
    }

    fn push_event_at(&mut self, event: Event, received_at: Instant) {
        self.set_telemetry_connected_at(received_at);
        let record_event = if let EventKind::CountersUpdated { counters } = &event.kind {
            let values_changed = self.counters.as_ref() != Some(counters);
            self.counters = Some(counters.clone());
            self.last_counters_at = Some(received_at);
            values_changed
        } else {
            true
        };
        if let Some(snapshot) = &mut self.snapshot {
            let changes_policy = matches!(
                &event.kind,
                EventKind::ModeChanged { .. }
                    | EventKind::RuleCreated { .. }
                    | EventKind::RuleUpdated { .. }
                    | EventKind::RuleDeleted { .. }
                    | EventKind::RuleEnabledChanged { .. }
            );
            if changes_policy && event.revision > snapshot.revision.saturating_add(1) {
                let first = snapshot.revision.saturating_add(1).to_string();
                let last = event.revision.saturating_sub(1).to_string();
                self.notice = Some(self.i18n.format(
                    "notice.revisions_skipped",
                    &[("first", first.as_str()), ("last", last.as_str())],
                ));
            }
            if changes_policy && event.revision > snapshot.revision {
                match &event.kind {
                    EventKind::ModeChanged { current, .. } => snapshot.mode = *current,
                    EventKind::RuleCreated { rule } => {
                        if !snapshot.rules.iter().any(|current| current.id == rule.id) {
                            snapshot.rules.push(rule.clone());
                            snapshot.rules.sort_unstable_by_key(|current| current.id);
                        }
                    }
                    EventKind::RuleUpdated { rule } | EventKind::RuleEnabledChanged { rule } => {
                        if let Some(current) = snapshot
                            .rules
                            .iter_mut()
                            .find(|current| current.id == rule.id)
                        {
                            *current = rule.clone();
                        }
                    }
                    EventKind::RuleDeleted { rule } => {
                        snapshot.rules.retain(|current| current.id != rule.id);
                    }
                    EventKind::CountersUpdated { .. } => {}
                }
                snapshot.revision = event.revision;
            }
        }
        if record_event {
            if self.events.len() == MAX_VISIBLE_EVENTS {
                self.events.pop_front();
            }
            self.events.push_back(event);
        }
        self.clamp_rule_selection();
    }

    pub fn select_next_rule(&mut self) {
        let len = self.rule_count();
        if len > 0 {
            self.selected_rule = (self.selected_rule + 1).min(len - 1);
        }
    }

    pub fn select_previous_rule(&mut self) {
        self.selected_rule = self.selected_rule.saturating_sub(1);
    }

    pub fn open_mode_picker(&mut self) {
        if !self.require_write_access() {
            return;
        }
        let Some(snapshot) = self.snapshot.as_ref() else {
            self.notice = Some(self.i18n.tr("notice.wait_snapshot").to_owned());
            return;
        };
        let selected = snapshot.mode;
        self.pending_revision = Some(snapshot.revision);
        self.overlay = Overlay::ModePicker { selected };
    }

    pub fn request_mode(&mut self, mode: Mode) -> Option<ControlRequest> {
        if !self.require_write_access() {
            return None;
        }
        if !matches!(self.overlay, Overlay::ModePicker { .. }) {
            return None;
        }
        let Some(expected_revision) = self.pending_revision else {
            self.notice = Some(self.i18n.tr("notice.base_revision_missing").to_owned());
            self.overlay = Overlay::None;
            return None;
        };
        if mode == Mode::BlockAll {
            self.overlay = Overlay::ConfirmBlockAll;
            None
        } else {
            self.overlay = Overlay::None;
            self.pending_revision = None;
            Some(ControlRequest::SetMode {
                expected_revision,
                mode,
            })
        }
    }

    pub fn confirm_block_all(&mut self, confirmed: bool) -> Option<ControlRequest> {
        if !matches!(self.overlay, Overlay::ConfirmBlockAll) {
            return None;
        }
        self.overlay = Overlay::None;
        let expected_revision = self.pending_revision.take();
        if confirmed && expected_revision.is_none() {
            self.notice = Some(self.i18n.tr("notice.base_revision_missing").to_owned());
        }
        expected_revision
            .filter(|_| confirmed)
            .map(|expected_revision| ControlRequest::SetMode {
                expected_revision,
                mode: Mode::BlockAll,
            })
    }

    pub fn open_create_rule(&mut self) {
        if !self.require_write_access() {
            return;
        }
        let Some(snapshot) = self.snapshot.as_ref() else {
            self.notice = Some(self.i18n.tr("notice.wait_snapshot").to_owned());
            return;
        };
        self.pending_revision = Some(snapshot.revision);
        self.overlay = Overlay::Editor(Box::default());
    }

    pub fn open_edit_rule(&mut self) {
        if !self.require_write_access() {
            return;
        }
        let Some(snapshot) = self.snapshot.as_ref() else {
            self.notice = Some(self.i18n.tr("notice.wait_snapshot").to_owned());
            return;
        };
        let Some(rule) = snapshot.rules.get(self.selected_rule).cloned() else {
            self.notice = Some(self.i18n.tr("notice.no_rule_selected").to_owned());
            return;
        };
        self.pending_revision = Some(snapshot.revision);
        self.overlay = Overlay::Editor(Box::new(RuleForm::from_rule(&rule)));
    }

    pub fn submit_editor(&mut self) -> Option<ControlRequest> {
        let Some(expected_revision) = self.pending_revision else {
            self.overlay = Overlay::None;
            self.notice = Some(self.i18n.tr("notice.base_revision_missing").to_owned());
            return None;
        };
        let Overlay::Editor(form) = &mut self.overlay else {
            return None;
        };
        match form.to_rule_spec(&self.i18n) {
            Ok(rule) => {
                let request = if let Some(id) = form.id {
                    ControlRequest::UpdateRule {
                        expected_revision,
                        id,
                        rule,
                    }
                } else {
                    ControlRequest::CreateRule {
                        expected_revision,
                        rule,
                    }
                };
                self.overlay = Overlay::None;
                self.pending_revision = None;
                Some(request)
            }
            Err(error) => {
                form.error = Some(error);
                None
            }
        }
    }

    pub fn open_delete_confirmation(&mut self) {
        if !self.require_write_access() {
            return;
        }
        let Some(snapshot) = self.snapshot.as_ref() else {
            self.notice = Some(self.i18n.tr("notice.wait_snapshot").to_owned());
            return;
        };
        let Some(rule) = snapshot.rules.get(self.selected_rule) else {
            self.notice = Some(self.i18n.tr("notice.no_rule_selected").to_owned());
            return;
        };
        self.pending_revision = Some(snapshot.revision);
        self.overlay = Overlay::ConfirmDelete {
            id: rule.id,
            name: rule.spec.name.to_string(),
        };
    }

    pub fn confirm_delete(&mut self, confirmed: bool) -> Option<ControlRequest> {
        let Overlay::ConfirmDelete { id, .. } = &self.overlay else {
            return None;
        };
        let id = *id;
        self.overlay = Overlay::None;
        let expected_revision = self.pending_revision.take();
        if confirmed && expected_revision.is_none() {
            self.notice = Some(self.i18n.tr("notice.base_revision_missing").to_owned());
        }
        expected_revision
            .filter(|_| confirmed)
            .map(|expected_revision| ControlRequest::DeleteRule {
                expected_revision,
                id,
            })
    }

    pub fn toggle_selected_rule(&mut self) -> Option<ControlRequest> {
        if !self.require_write_access() {
            return None;
        }
        let snapshot = self.snapshot.as_ref()?;
        snapshot
            .rules
            .get(self.selected_rule)
            .map(|rule| ControlRequest::SetRuleEnabled {
                expected_revision: snapshot.revision,
                id: rule.id,
                enabled: !rule.spec.enabled,
            })
    }

    pub fn close_overlay(&mut self) {
        self.overlay = Overlay::None;
        self.pending_revision = None;
    }

    fn require_write_access(&mut self) -> bool {
        if self.read_only {
            self.notice = Some(self.i18n.tr("notice.read_only").to_owned());
            false
        } else {
            true
        }
    }

    fn rule_count(&self) -> usize {
        self.snapshot
            .as_ref()
            .map_or(0, |snapshot| snapshot.rules.len())
    }

    fn clamp_rule_selection(&mut self) {
        let len = self.rule_count();
        self.selected_rule = if len == 0 {
            0
        } else {
            self.selected_rule.min(len - 1)
        };
    }
}

pub fn peer_label(rule: &Rule, i18n: &I18n) -> String {
    rule.spec
        .peer_network
        .as_ref()
        .map_or_else(|| i18n.tr("common.any").to_owned(), ToString::to_string)
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use openshield_core::FirewallCounters;

    use super::*;

    #[test]
    fn unprivileged_state_rejects_every_mutation_entry_point() {
        let mut app = App::new(true, I18n::test_english());

        app.open_mode_picker();
        app.open_create_rule();

        assert_eq!(app.overlay, Overlay::None);
        assert!(app.request_mode(Mode::Learning).is_none());
        assert!(app.toggle_selected_rule().is_none());
        assert!(
            app.notice
                .as_deref()
                .is_some_and(|notice| notice.contains("root"))
        );
    }

    #[test]
    fn block_all_requires_explicit_confirmation() {
        let mut app = App::new(false, I18n::test_english());
        app.set_snapshot(Snapshot {
            revision: 7,
            flow_generation: 1,
            mode: Mode::Learning,
            rules: Vec::new(),
        });

        app.open_mode_picker();
        assert!(app.request_mode(Mode::BlockAll).is_none());
        assert_eq!(app.overlay, Overlay::ConfirmBlockAll);
        assert!(app.confirm_block_all(false).is_none());

        app.open_mode_picker();
        assert!(app.request_mode(Mode::BlockAll).is_none());
        assert_eq!(
            app.confirm_block_all(true),
            Some(ControlRequest::SetMode {
                expected_revision: 7,
                mode: Mode::BlockAll
            })
        );
    }

    #[test]
    fn form_accepts_inbound_allow_rule() {
        let form = RuleForm {
            name: "SSH из локальной сети".to_owned(),
            direction: Direction::Inbound,
            protocol: TransportProtocol::Tcp,
            peer_network: "192.168.1.0/24".to_owned(),
            port: "22".to_owned(),
            interface: "eth0".to_owned(),
            ..RuleForm::default()
        };

        let result = form.to_rule_spec(&I18n::test_english());
        assert!(result.is_ok(), "{result:?}");
        if let Ok(rule) = result {
            assert_eq!(rule.direction, Direction::Inbound);
            assert_eq!(rule.protocol, TransportProtocol::Tcp);
            assert!(rule.port.is_some());
        }
    }

    #[test]
    fn form_preserves_bounded_application_identity_and_argv_boundaries()
    -> Result<(), Box<dyn std::error::Error>> {
        let form = RuleForm {
            name: "curl application".to_owned(),
            protocol: TransportProtocol::Tcp,
            port: "443".to_owned(),
            bind_application: true,
            executable: "/usr/bin/curl".to_owned(),
            executable_device: "8".to_owned(),
            executable_inode: "99".to_owned(),
            command_mode: CommandMode::Exact,
            arguments: r#"["curl","--header=A B"]"#.to_owned(),
            uid: "1000".to_owned(),
            cgroup: "/user.slice/example.scope".to_owned(),
            ..RuleForm::default()
        };

        let rule = form.to_rule_spec(&I18n::test_english()).map_err(io_error)?;
        let selector = rule.application.ok_or("application selector missing")?;
        assert_eq!(
            selector.executable_file,
            Some(ExecutableFileId {
                device: 8,
                inode: 99,
            })
        );
        assert_eq!(selector.uid, Some(1_000));
        assert!(selector.command_line.is_some_and(|command| {
            command.kind == CommandLineMatch::Exact
                && command.arguments.len() == 2
                && command.arguments[1].as_str() == "--header=A B"
        }));
        Ok(())
    }

    #[test]
    fn form_rejects_application_rules_for_inbound_traffic() {
        let form = RuleForm {
            name: "invalid inbound application".to_owned(),
            direction: Direction::Inbound,
            protocol: TransportProtocol::Tcp,
            bind_application: true,
            executable: "/usr/bin/server".to_owned(),
            ..RuleForm::default()
        };
        assert!(form.to_rule_spec(&I18n::test_english()).is_err());
    }

    #[test]
    fn form_rejects_ambiguous_or_non_string_argv() {
        let mut form = RuleForm {
            name: "invalid argv".to_owned(),
            bind_application: true,
            executable: "/usr/bin/example".to_owned(),
            command_mode: CommandMode::Prefix,
            arguments: r#"["example",7]"#.to_owned(),
            ..RuleForm::default()
        };
        assert!(form.to_rule_spec(&I18n::test_english()).is_err());

        form.arguments = "example --flag".to_owned();
        assert!(form.to_rule_spec(&I18n::test_english()).is_err());
    }

    #[test]
    fn form_rejects_reversed_port_range() {
        let form = RuleForm {
            name: "bad ports".to_owned(),
            protocol: TransportProtocol::Tcp,
            port: "9000-8000".to_owned(),
            ..RuleForm::default()
        };

        assert!(form.to_rule_spec(&I18n::test_english()).is_err());
    }

    #[test]
    fn form_accepts_single_peer_address_without_prefix() {
        let form = RuleForm {
            name: "single host".to_owned(),
            protocol: TransportProtocol::Tcp,
            peer_network: "203.0.113.8".to_owned(),
            port: "443".to_owned(),
            ..RuleForm::default()
        };

        let result = form.to_rule_spec(&I18n::test_english());
        assert!(result.is_ok(), "{result:?}");
        if let Ok(rule) = result {
            assert_eq!(
                rule.peer_network.map(|network| network.prefix_len()),
                Some(32)
            );
        }
    }

    #[test]
    fn editing_learned_rule_preserves_immutable_origin() -> Result<(), Box<dyn std::error::Error>> {
        let original_form = RuleForm {
            name: "learned endpoint".to_owned(),
            protocol: TransportProtocol::Tcp,
            peer_network: "203.0.113.9".to_owned(),
            port: "443".to_owned(),
            origin: RuleOrigin::Learned,
            ..RuleForm::default()
        };
        let rule = Rule::new(
            original_form
                .to_rule_spec(&I18n::test_english())
                .map_err(io_error)?,
        )?;
        let rule_id = rule.id;
        let mut app = App::new(false, I18n::test_english());
        app.set_snapshot(Snapshot {
            revision: 1,
            flow_generation: 1,
            mode: Mode::Enforcing,
            rules: vec![rule],
        });

        app.open_edit_rule();
        assert!(matches!(
            &app.overlay,
            Overlay::Editor(form) if form.origin == RuleOrigin::Learned
        ));
        let request = app.submit_editor();
        assert!(matches!(
            request,
            Some(ControlRequest::UpdateRule {
                expected_revision: 1,
                id,
                rule,
            }) if id == rule_id && rule.origin == RuleOrigin::Learned
        ));
        Ok(())
    }

    #[test]
    fn editor_keeps_revision_from_when_the_intent_was_opened()
    -> Result<(), Box<dyn std::error::Error>> {
        let rule = Rule::new(
            RuleForm {
                name: "concurrent rule".to_owned(),
                protocol: TransportProtocol::Tcp,
                port: "443".to_owned(),
                ..RuleForm::default()
            }
            .to_rule_spec(&I18n::test_english())
            .map_err(io_error)?,
        )?;
        let rule_id = rule.id;
        let mut app = App::new(false, I18n::test_english());
        app.set_snapshot(Snapshot {
            revision: 1,
            flow_generation: 1,
            mode: Mode::Enforcing,
            rules: vec![rule.clone()],
        });
        app.open_edit_rule();

        let mut concurrently_updated = rule;
        concurrently_updated.spec.enabled = false;
        app.push_event(Event {
            revision: 2,
            occurred_at: Utc::now(),
            kind: EventKind::RuleEnabledChanged {
                rule: concurrently_updated,
            },
        });

        assert!(matches!(
            app.submit_editor(),
            Some(ControlRequest::UpdateRule {
                expected_revision: 1,
                id,
                ..
            }) if id == rule_id
        ));
        Ok(())
    }

    #[test]
    fn form_rejects_ports_for_icmp() {
        let form = RuleForm {
            name: "icmp".to_owned(),
            protocol: TransportProtocol::Icmp,
            port: "7".to_owned(),
            ..RuleForm::default()
        };

        assert!(form.to_rule_spec(&I18n::test_english()).is_err());
    }

    #[test]
    fn event_buffer_is_bounded() -> Result<(), Box<dyn std::error::Error>> {
        let mut app = App::new(true, I18n::test_english());
        let event_count = u64::try_from(MAX_VISIBLE_EVENTS + 3)?;
        for revision in 0..event_count {
            let mut counters = FirewallCounters::default();
            counters.accepted_in.packets = revision;
            app.push_event(Event {
                revision,
                occurred_at: Utc::now(),
                kind: EventKind::CountersUpdated { counters },
            });
        }
        assert_eq!(app.events.len(), MAX_VISIBLE_EVENTS);
        assert_eq!(app.events.front().map(|event| event.revision), Some(3));
        Ok(())
    }

    #[test]
    fn rule_selection_never_underflows() {
        let mut app = App::new(false, I18n::test_english());
        app.select_previous_rule();
        assert_eq!(app.selected_rule, 0);
    }

    #[test]
    fn stale_snapshot_cannot_roll_state_back() {
        let mut app = App::new(true, I18n::test_english());
        app.set_snapshot(Snapshot {
            revision: 8,
            flow_generation: 1,
            mode: Mode::Learning,
            rules: Vec::new(),
        });
        app.set_snapshot(Snapshot {
            revision: 7,
            flow_generation: 1,
            mode: Mode::BlockAll,
            rules: Vec::new(),
        });

        assert_eq!(app.snapshot.as_ref().map(|state| state.revision), Some(8));
        assert_eq!(
            app.snapshot.as_ref().map(|state| state.mode),
            Some(Mode::Learning)
        );
    }

    #[test]
    fn confirmed_daemon_restart_replaces_higher_revision_state() {
        let mut app = App::new(false, I18n::test_english());
        app.set_snapshot(Snapshot {
            revision: 12,
            flow_generation: 1,
            mode: Mode::Learning,
            rules: Vec::new(),
        });
        app.push_event(Event {
            revision: 12,
            occurred_at: Utc::now(),
            kind: EventKind::CountersUpdated {
                counters: FirewallCounters::default(),
            },
        });
        app.open_create_rule();

        app.set_restarted_snapshot(Snapshot {
            revision: 2,
            flow_generation: 1,
            mode: Mode::BlockAll,
            rules: Vec::new(),
        });

        assert_eq!(app.snapshot.as_ref().map(|state| state.revision), Some(2));
        assert_eq!(
            app.snapshot.as_ref().map(|state| state.mode),
            Some(Mode::BlockAll)
        );
        assert!(app.counters.is_none());
        assert!(app.events.is_empty());
        assert_eq!(app.overlay, Overlay::None);
        assert_eq!(
            app.notice.as_deref(),
            Some(app.i18n.tr("notice.daemon_restarted"))
        );
    }

    #[test]
    fn counter_event_does_not_advance_policy_revision() {
        let mut app = App::new(true, I18n::test_english());
        app.set_snapshot(Snapshot {
            revision: 4,
            flow_generation: 1,
            mode: Mode::BlockAll,
            rules: Vec::new(),
        });
        app.push_event(Event {
            revision: 5,
            occurred_at: Utc::now(),
            kind: EventKind::CountersUpdated {
                counters: FirewallCounters::default(),
            },
        });

        assert_eq!(app.snapshot.as_ref().map(|state| state.revision), Some(4));
        assert!(app.counters.is_some());
    }

    #[test]
    fn telemetry_disconnect_preserves_valid_snapshot_and_counters() {
        let mut app = App::new(true, I18n::test_english());
        let received_at = Instant::now();
        app.set_snapshot(Snapshot {
            revision: 4,
            flow_generation: 1,
            mode: Mode::Learning,
            rules: Vec::new(),
        });
        app.push_event_at(
            Event {
                revision: 4,
                occurred_at: Utc::now(),
                kind: EventKind::CountersUpdated {
                    counters: FirewallCounters::default(),
                },
            },
            received_at,
        );

        app.set_telemetry_disconnected("subscription closed".to_owned());

        assert_eq!(app.snapshot.as_ref().map(|state| state.revision), Some(4));
        assert!(app.counters.is_some());
        assert_eq!(
            app.counters_age(received_at + Duration::from_secs(7)),
            Some(Duration::from_secs(7))
        );
        assert!(matches!(app.telemetry, ConnectionState::Disconnected(_)));
    }

    #[test]
    fn incoming_event_recovers_telemetry_health() {
        let mut app = App::new(true, I18n::test_english());
        let received_at = Instant::now();
        app.set_telemetry_disconnected("temporary failure".to_owned());

        app.push_event_at(
            Event {
                revision: 0,
                occurred_at: Utc::now(),
                kind: EventKind::CountersUpdated {
                    counters: FirewallCounters::default(),
                },
            },
            received_at,
        );

        assert_eq!(app.telemetry, ConnectionState::Connected);
        assert_eq!(
            app.telemetry_connection_age(received_at + Duration::from_secs(2)),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            app.counters_age(received_at + Duration::from_secs(2)),
            Some(Duration::from_secs(2))
        );
    }

    #[test]
    fn unchanged_counter_heartbeat_refreshes_telemetry_freshness() {
        let mut app = App::new(true, I18n::test_english());
        let first_received_at = Instant::now();
        let counters = FirewallCounters::default();
        let counter_event = |occurred_at| Event {
            revision: 0,
            occurred_at,
            kind: EventKind::CountersUpdated {
                counters: counters.clone(),
            },
        };
        app.push_event_at(counter_event(Utc::now()), first_received_at);

        let heartbeat_at = first_received_at + Duration::from_secs(2);
        app.push_event_at(counter_event(Utc::now()), heartbeat_at);

        assert_eq!(
            app.counters_age(first_received_at + Duration::from_secs(4)),
            Some(Duration::from_secs(2))
        );
        assert_eq!(app.counters, Some(counters));
        assert_eq!(app.events.len(), 1);
    }

    #[test]
    fn idle_counter_heartbeats_do_not_evict_policy_events() {
        let mut app = App::new(true, I18n::test_english());
        app.push_event(Event {
            revision: 1,
            occurred_at: Utc::now(),
            kind: EventKind::ModeChanged {
                previous: Mode::BlockAll,
                current: Mode::Learning,
            },
        });
        for _ in 0..(MAX_VISIBLE_EVENTS + 10) {
            app.push_event(Event {
                revision: 1,
                occurred_at: Utc::now(),
                kind: EventKind::CountersUpdated {
                    counters: FirewallCounters::default(),
                },
            });
        }

        assert_eq!(app.events.len(), 2);
        assert!(matches!(
            app.events.front().map(|event| &event.kind),
            Some(EventKind::ModeChanged { .. })
        ));
    }

    #[test]
    fn disconnect_clears_stale_policy_and_cancels_mutation() {
        let mut app = App::new(false, I18n::test_english());
        app.set_snapshot(Snapshot {
            revision: 4,
            flow_generation: 1,
            mode: Mode::Learning,
            rules: Vec::new(),
        });
        app.counters = Some(FirewallCounters::default());
        app.open_create_rule();

        app.set_disconnected("daemon restarted".to_owned());

        assert!(app.snapshot.is_none());
        assert!(app.counters.is_none());
        assert!(app.counters_age(Instant::now()).is_none());
        assert_eq!(app.overlay, Overlay::None);
        assert!(matches!(app.connection, ConnectionState::Disconnected(_)));
    }

    fn io_error(message: String) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, message)
    }
}
