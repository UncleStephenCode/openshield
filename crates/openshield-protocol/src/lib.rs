//! Bounded local IPC protocol shared by the `OpenShield` daemon and TUI.

#![forbid(unsafe_code)]

use std::io::{self, Read, Write};

use openshield_core::{Event, Mode, Rule, RuleSpec};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, de};
use thiserror::Error;
use uuid::Uuid;

pub const MAX_FRAME_SIZE: usize = 64 * 1024;
/// Maximum number of rules considered for one page. The daemon additionally
/// shrinks serialized pages to the fixed frame-byte limit.
pub const MAX_RULES_PER_PAGE: u16 = 128;
pub const MAX_ERROR_MESSAGE_BYTES: usize = 512;
pub const OBSERVE_SOCKET_PATH: &str = "/run/openshield/observe.sock";
pub const CONTROL_SOCKET_PATH: &str = "/run/openshield/control.sock";
pub const OBSERVE_GROUP_NAME: &str = "openshield";

/// Firewall implementation which currently owns the `OpenShield` policy.
///
/// `Unknown` is deliberately the default so an older daemon response or a
/// test backend can never be presented as a verified production backend.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum FirewallBackendKind {
    #[default]
    Unknown,
    Nftables,
    Iptables,
}

/// Monotonic error counters reported by the live NFQUEUE runtime.
///
/// Every field is saturating: a daemon never wraps a counter back to zero.
/// The nested default keeps status responses from older daemons readable by
/// newer clients and permits future producers to omit zero-valued fields.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct NfqueueCounters {
    /// Netlink receive-overflow events (`ENOBUFS`). The kernel denied an
    /// unknown number of queued packets for each event.
    pub queue_overflow: u64,
    /// Packets denied because the bounded `/proc` attribution deadline
    /// expired.
    pub attribution_timeout: u64,
    /// Errors which terminate the queue runtime and trigger fail-closed
    /// quarantine.
    pub terminal_queue_error: u64,
    /// Packets for which userspace successfully returned an explicit drop
    /// verdict. Overflow losses are not included because their cardinality is
    /// unavailable to userspace.
    pub denied: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(
    clippy::large_enum_variant,
    reason = "keeping the stable unboxed control-request API avoids protocol-wide churn"
)]
#[serde(
    deny_unknown_fields,
    rename_all = "snake_case",
    tag = "type",
    content = "data"
)]
pub enum Request {
    Read(ReadRequest),
    Control(ControlRequest),
}

pub type ClientRequest = Request;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "snake_case",
    tag = "type",
    content = "data"
)]
pub enum ReadRequest {
    /// Returns mode, revision, total rule count, active firewall backend, and
    /// process-lifetime NFQUEUE counters.
    Status,
    /// Returns rules ordered by UUID strictly after `after`.
    ///
    /// `limit` is a bounded client hint. Servers may choose any positive page
    /// size up to [`MAX_RULES_PER_PAGE`] (the daemon deliberately ignores tiny
    /// hints to prevent request-amplification attacks). Every page contains a
    /// revision; clients restart pagination if that revision changes.
    RulesPage { after: Option<Uuid>, limit: u16 },
    /// Starts a live event stream after initial status/page synchronization.
    Subscribe { after_revision: Option<u64> },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "snake_case",
    tag = "type",
    content = "data"
)]
pub enum ControlRequest {
    SetMode {
        expected_revision: u64,
        mode: Mode,
    },
    CreateRule {
        expected_revision: u64,
        rule: RuleSpec,
    },
    UpdateRule {
        expected_revision: u64,
        id: Uuid,
        rule: RuleSpec,
    },
    DeleteRule {
        expected_revision: u64,
        id: Uuid,
    },
    SetRuleEnabled {
        expected_revision: u64,
        id: Uuid,
        enabled: bool,
    },
}

impl ControlRequest {
    /// Revision of the snapshot on which this privileged mutation is based.
    #[must_use]
    pub const fn expected_revision(&self) -> u64 {
        match self {
            Self::SetMode {
                expected_revision, ..
            }
            | Self::CreateRule {
                expected_revision, ..
            }
            | Self::UpdateRule {
                expected_revision, ..
            }
            | Self::DeleteRule {
                expected_revision, ..
            }
            | Self::SetRuleEnabled {
                expected_revision, ..
            } => *expected_revision,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "snake_case",
    tag = "type",
    content = "data"
)]
pub enum Response {
    Status {
        revision: u64,
        mode: Mode,
        rule_count: u32,
        #[serde(default)]
        backend: FirewallBackendKind,
        #[serde(default)]
        nfqueue: NfqueueCounters,
    },
    RulesPage {
        revision: u64,
        rules: Vec<Rule>,
        next_after: Option<Uuid>,
    },
    Ack(Ack),
    Event(Event),
    Error(ProtocolError),
}

pub type ServerMessage = Response;

#[must_use]
pub fn clamp_page_limit(limit: u16) -> u16 {
    limit.clamp(1, MAX_RULES_PER_PAGE)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ack {
    pub revision: u64,
    pub affected_rule: Option<Rule>,
}

impl Ack {
    #[must_use]
    pub const fn new(revision: u64, affected_rule: Option<Rule>) -> Self {
        Self {
            revision,
            affected_rule,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidRequest,
    Unauthorized,
    NotFound,
    Conflict,
    BackendUnavailable,
    Internal,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProtocolError {
    pub code: ErrorCode,
    pub message: String,
}

impl ProtocolError {
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: sanitize_error_message(&message.into()),
        }
    }
}

impl<'de> Deserialize<'de> for ProtocolError {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireProtocolError {
            code: ErrorCode,
            message: String,
        }

        let wire = WireProtocolError::deserialize(deserializer)?;
        let sanitized = sanitize_error_message(&wire.message);
        if sanitized != wire.message {
            return Err(de::Error::custom(
                "protocol error message is empty, oversized, or unsafe for a terminal",
            ));
        }
        Ok(Self {
            code: wire.code,
            message: wire.message,
        })
    }
}

fn sanitize_error_message(message: &str) -> String {
    let mut sanitized = String::new();
    for character in message.chars() {
        if character.is_control()
            || matches!(
                character,
                '\u{061c}'
                    | '\u{200b}'..='\u{200f}'
                    | '\u{202a}'..='\u{202e}'
                    | '\u{2060}'..='\u{206f}'
                    | '\u{feff}'
            )
        {
            continue;
        }
        if sanitized.len().saturating_add(character.len_utf8()) > MAX_ERROR_MESSAGE_BYTES {
            break;
        }
        sanitized.push(character);
    }
    if sanitized.is_empty() {
        String::from("unspecified error")
    } else {
        sanitized
    }
}

/// Writes one JSON message prefixed by an unsigned four-byte big-endian size.
///
/// This function never invokes a shell and never writes a partial oversized
/// frame: serialization and the size check happen before the header is sent.
///
/// # Errors
///
/// Returns [`FrameError`] when encoding exceeds the bound, serialization
/// fails, or the destination cannot accept the complete frame.
pub fn write_frame<W, T>(writer: &mut W, value: &T) -> Result<(), FrameError>
where
    W: Write,
    T: Serialize + ?Sized,
{
    let mut bounded = BoundedBuffer::new(MAX_FRAME_SIZE);
    if let Err(source) = serde_json::to_writer(&mut bounded, value) {
        if let Some(actual) = bounded.overflow_size {
            return Err(FrameError::FrameTooLarge {
                actual,
                maximum: MAX_FRAME_SIZE,
            });
        }
        return Err(FrameError::Encode {
            message: source.to_string(),
        });
    }
    let payload = bounded.bytes;
    if payload.is_empty() {
        return Err(FrameError::EmptyFrame);
    }
    if payload.len() > MAX_FRAME_SIZE {
        return Err(FrameError::FrameTooLarge {
            actual: payload.len(),
            maximum: MAX_FRAME_SIZE,
        });
    }
    let size = u32::try_from(payload.len()).map_err(|_| FrameError::FrameTooLarge {
        actual: payload.len(),
        maximum: MAX_FRAME_SIZE,
    })?;
    writer.write_all(&size.to_be_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()?;
    Ok(())
}

#[derive(Debug)]
struct BoundedBuffer {
    bytes: Vec<u8>,
    maximum: usize,
    overflow_size: Option<usize>,
}

impl BoundedBuffer {
    fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum,
            overflow_size: None,
        }
    }
}

impl Write for BoundedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let attempted = self.bytes.len().saturating_add(bytes.len());
        if attempted > self.maximum {
            self.overflow_size = Some(attempted);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "serialized IPC frame exceeds its fixed limit",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Reads exactly one bounded JSON frame.
///
/// An oversized advertised size is rejected before allocating its payload.
///
/// # Errors
///
/// Returns [`FrameError`] for an empty or oversized header, truncated I/O, or
/// JSON that does not strictly decode to `T`.
pub fn read_frame<R, T>(reader: &mut R) -> Result<T, FrameError>
where
    R: Read,
    T: DeserializeOwned,
{
    let mut header = [0_u8; 4];
    reader.read_exact(&mut header)?;
    let size_u32 = u32::from_be_bytes(header);
    let size = usize::try_from(size_u32).map_err(|_| FrameError::FrameTooLarge {
        actual: usize::MAX,
        maximum: MAX_FRAME_SIZE,
    })?;
    if size == 0 {
        return Err(FrameError::EmptyFrame);
    }
    if size > MAX_FRAME_SIZE {
        return Err(FrameError::FrameTooLarge {
            actual: size,
            maximum: MAX_FRAME_SIZE,
        });
    }

    let mut payload = vec![0_u8; size];
    reader.read_exact(&mut payload)?;
    serde_json::from_slice(&payload).map_err(|source| FrameError::Decode {
        message: source.to_string(),
    })
}

/// Writes one typed client request.
///
/// # Errors
///
/// Returns [`FrameError`] under the same conditions as [`write_frame`].
pub fn write_request<W: Write>(writer: &mut W, request: &Request) -> Result<(), FrameError> {
    write_frame(writer, request)
}

/// Reads one typed client request.
///
/// # Errors
///
/// Returns [`FrameError`] under the same conditions as [`read_frame`].
pub fn read_request<R: Read>(reader: &mut R) -> Result<Request, FrameError> {
    read_frame(reader)
}

/// Writes one typed server response.
///
/// # Errors
///
/// Returns [`FrameError`] under the same conditions as [`write_frame`].
pub fn write_response<W: Write>(writer: &mut W, response: &Response) -> Result<(), FrameError> {
    write_frame(writer, response)
}

/// Reads one typed server response.
///
/// # Errors
///
/// Returns [`FrameError`] under the same conditions as [`read_frame`].
pub fn read_response<R: Read>(reader: &mut R) -> Result<Response, FrameError> {
    read_frame(reader)
}

/// Writes one generic bounded message.
///
/// # Errors
///
/// Returns [`FrameError`] under the same conditions as [`write_frame`].
pub fn write_message<W, T>(writer: &mut W, value: &T) -> Result<(), FrameError>
where
    W: Write,
    T: Serialize + ?Sized,
{
    write_frame(writer, value)
}

/// Reads one generic bounded message.
///
/// # Errors
///
/// Returns [`FrameError`] under the same conditions as [`read_frame`].
pub fn read_message<R, T>(reader: &mut R) -> Result<T, FrameError>
where
    R: Read,
    T: DeserializeOwned,
{
    read_frame(reader)
}

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("IPC frame is empty")]
    EmptyFrame,
    #[error("IPC frame is {actual} bytes; maximum is {maximum}")]
    FrameTooLarge { actual: usize, maximum: usize },
    #[error("I/O while processing IPC frame: {0}")]
    Io(#[from] io::Error),
    #[error("failed to encode IPC JSON: {message}")]
    Encode { message: String },
    #[error("failed to decode IPC JSON: {message}")]
    Decode { message: String },
}

#[cfg(test)]
mod tests {
    use std::{error::Error, io::Cursor};

    use openshield_core::{
        ApplicationPath, ApplicationSelector, CgroupPath, CommandArgument, CommandLineMatch,
        CommandLineSelector, Direction, ExecutableFileId, MAX_APPLICATION_PATH_BYTES,
        MAX_CGROUP_PATH_BYTES, MAX_COMMAND_ARGUMENT_BYTES, MAX_COMMAND_LINE_BYTES,
        MAX_RULE_NAME_BYTES, PortRange, RuleName, RuleOrigin, RuleSpec, TransportProtocol,
    };

    use super::*;

    fn largest_rule() -> Result<Rule, Box<dyn Error>> {
        let name = "x".repeat(MAX_RULE_NAME_BYTES);
        let executable = format!("/{}", "\"".repeat(MAX_APPLICATION_PATH_BYTES - 1));
        let cgroup = format!("/{}", "\"".repeat(MAX_CGROUP_PATH_BYTES - 1));
        let argument_size = MAX_COMMAND_ARGUMENT_BYTES - 1;
        let argument_count = MAX_COMMAND_LINE_BYTES / (argument_size + 1);
        let arguments = (0..argument_count)
            .map(|_| CommandArgument::new("\"".repeat(argument_size)))
            .collect::<Result<Vec<_>, _>>()?;
        let mut specification = RuleSpec::new(
            RuleName::new(name)?,
            Direction::Outbound,
            TransportProtocol::Tcp,
            Some("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff/128".parse()?),
            Some(PortRange::new(1, u16::MAX)?),
            None,
            RuleOrigin::Manual,
            true,
        )?;
        specification.application = Some(ApplicationSelector::new(
            Some(ApplicationPath::new(executable)?),
            Some(ExecutableFileId {
                device: u64::MAX,
                inode: u64::MAX,
                size: u64::MAX,
                ctime_seconds: i64::MAX,
                ctime_nanoseconds: 999_999_999,
            }),
            Some(CommandLineSelector::new(
                CommandLineMatch::Exact,
                arguments,
            )?),
            Some(u32::MAX),
            Some(CgroupPath::new(cgroup)?),
        )?);
        Ok(Rule::new(specification)?)
    }

    #[test]
    fn request_round_trip_uses_big_endian_length() -> Result<(), Box<dyn Error>> {
        let request = Request::Read(ReadRequest::Subscribe {
            after_revision: Some(42),
        });
        let mut bytes = Vec::new();
        write_request(&mut bytes, &request)?;
        let advertised = u32::from_be_bytes(bytes[0..4].try_into()?);
        assert_eq!(usize::try_from(advertised)?, bytes.len() - 4);
        assert_eq!(read_request(&mut Cursor::new(bytes))?, request);
        Ok(())
    }

    #[test]
    fn control_request_round_trip_preserves_expected_revision() -> Result<(), Box<dyn Error>> {
        let request = Request::Control(ControlRequest::SetMode {
            expected_revision: 41,
            mode: Mode::Learning,
        });
        let mut bytes = Vec::new();
        write_request(&mut bytes, &request)?;
        assert_eq!(read_request(&mut Cursor::new(bytes))?, request);
        Ok(())
    }

    #[test]
    fn status_round_trip_preserves_backend_and_nfqueue_counters() -> Result<(), Box<dyn Error>> {
        let nfqueue = NfqueueCounters {
            queue_overflow: 1,
            attribution_timeout: 2,
            terminal_queue_error: 3,
            denied: 4,
        };
        let response = Response::Status {
            revision: 7,
            mode: Mode::Learning,
            rule_count: 3,
            backend: FirewallBackendKind::Nftables,
            nfqueue,
        };
        let mut bytes = Vec::new();
        write_response(&mut bytes, &response)?;
        assert_eq!(read_response(&mut Cursor::new(bytes))?, response);
        Ok(())
    }

    #[test]
    fn status_without_backend_is_safely_reported_as_unknown() -> Result<(), Box<dyn Error>> {
        let payload =
            br#"{"type":"status","data":{"revision":7,"mode":"learning","rule_count":3}}"#;
        let mut bytes = Vec::from(u32::try_from(payload.len())?.to_be_bytes());
        bytes.extend_from_slice(payload);
        assert_eq!(
            read_response(&mut Cursor::new(bytes))?,
            Response::Status {
                revision: 7,
                mode: Mode::Learning,
                rule_count: 3,
                backend: FirewallBackendKind::Unknown,
                nfqueue: NfqueueCounters::default(),
            }
        );
        Ok(())
    }

    #[test]
    fn omitted_nested_nfqueue_fields_default_to_zero() -> Result<(), Box<dyn Error>> {
        let payload = br#"{"type":"status","data":{"revision":7,"mode":"learning","rule_count":3,"nfqueue":{"queue_overflow":9}}}"#;
        let mut bytes = Vec::from(u32::try_from(payload.len())?.to_be_bytes());
        bytes.extend_from_slice(payload);
        assert_eq!(
            read_response(&mut Cursor::new(bytes))?,
            Response::Status {
                revision: 7,
                mode: Mode::Learning,
                rule_count: 3,
                backend: FirewallBackendKind::Unknown,
                nfqueue: NfqueueCounters {
                    queue_overflow: 9,
                    ..NfqueueCounters::default()
                },
            }
        );
        Ok(())
    }

    #[test]
    fn oversized_advertised_frame_is_rejected_before_payload_read() -> Result<(), Box<dyn Error>> {
        let advertised = u32::try_from(MAX_FRAME_SIZE + 1)?;
        let bytes = advertised.to_be_bytes();
        let error = read_request(&mut Cursor::new(bytes));
        assert!(matches!(
            error,
            Err(FrameError::FrameTooLarge {
                actual,
                maximum: MAX_FRAME_SIZE
            }) if actual == MAX_FRAME_SIZE + 1
        ));
        Ok(())
    }

    #[test]
    fn zero_length_frame_is_rejected() {
        let error = read_request(&mut Cursor::new(0_u32.to_be_bytes()));
        assert!(matches!(error, Err(FrameError::EmptyFrame)));
    }

    #[test]
    fn malformed_json_is_rejected() -> Result<(), Box<dyn Error>> {
        let payload = b"not json";
        let mut bytes = Vec::from(u32::try_from(payload.len())?.to_be_bytes());
        bytes.extend_from_slice(payload);
        let error = read_request(&mut Cursor::new(bytes));
        assert!(matches!(error, Err(FrameError::Decode { .. })));
        Ok(())
    }

    #[test]
    fn oversized_outbound_message_writes_nothing() {
        let value = "x".repeat(MAX_FRAME_SIZE);
        let mut bytes = Vec::new();
        assert!(matches!(
            write_frame(&mut bytes, &value),
            Err(FrameError::FrameTooLarge { .. })
        ));
        assert!(bytes.is_empty());
    }

    #[test]
    fn page_limit_is_always_clamped_to_safe_bounds() {
        assert_eq!(clamp_page_limit(0), 1);
        assert_eq!(clamp_page_limit(1), 1);
        assert_eq!(clamp_page_limit(MAX_RULES_PER_PAGE), MAX_RULES_PER_PAGE);
        assert_eq!(
            clamp_page_limit(MAX_RULES_PER_PAGE.saturating_add(1)),
            MAX_RULES_PER_PAGE
        );
        assert_eq!(clamp_page_limit(u16::MAX), MAX_RULES_PER_PAGE);
    }

    #[test]
    fn one_largest_rule_fits_one_bounded_frame() -> Result<(), Box<dyn Error>> {
        let rule = largest_rule()?;
        let response = Response::RulesPage {
            revision: 7,
            rules: vec![rule],
            next_after: Some(Uuid::new_v4()),
        };
        let mut bytes = Vec::new();
        write_response(&mut bytes, &response)?;
        assert!(bytes.len() <= MAX_FRAME_SIZE + 4);
        Ok(())
    }

    #[test]
    fn unknown_request_fields_are_rejected() -> Result<(), Box<dyn Error>> {
        let payload = br#"{"type":"read","data":{"type":"status","data":{"smuggled":true}}}"#;
        let mut bytes = Vec::from(u32::try_from(payload.len())?.to_be_bytes());
        bytes.extend_from_slice(payload);
        assert!(matches!(
            read_request(&mut Cursor::new(bytes)),
            Err(FrameError::Decode { .. })
        ));
        Ok(())
    }

    #[test]
    fn control_revision_must_be_present_numeric_and_unambiguous() -> Result<(), Box<dyn Error>> {
        for payload in [
            br#"{"type":"control","data":{"type":"set_mode","data":{"mode":"learning"}}}"#.as_slice(),
            br#"{"type":"control","data":{"type":"set_mode","data":{"expected_revision":"latest","mode":"learning"}}}"#.as_slice(),
            br#"{"type":"control","data":{"type":"set_mode","data":{"expected_revision":7,"mode":"learning","smuggled":true}}}"#.as_slice(),
        ] {
            let mut bytes = Vec::from(u32::try_from(payload.len())?.to_be_bytes());
            bytes.extend_from_slice(payload);
            assert!(matches!(
                read_request(&mut Cursor::new(bytes)),
                Err(FrameError::Decode { .. })
            ));
        }
        Ok(())
    }

    #[test]
    fn error_messages_are_bounded_and_terminal_safe() {
        let error = ProtocolError::new(
            ErrorCode::InvalidRequest,
            format!("bad\u{1b}[31m\n{}", "x".repeat(MAX_ERROR_MESSAGE_BYTES * 2)),
        );
        assert!(!error.message.chars().any(char::is_control));
        assert!(error.message.len() <= MAX_ERROR_MESSAGE_BYTES);

        let unsafe_json = br#"{"code":"internal","message":"bad\nterminal"}"#;
        assert!(serde_json::from_slice::<ProtocolError>(unsafe_json).is_err());
    }
}
