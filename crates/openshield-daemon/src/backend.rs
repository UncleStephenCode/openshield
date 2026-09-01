use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail, ensure};
use openshield_core::{
    COUNTER_ACCEPTED_IN, COUNTER_ACCEPTED_OUT, COUNTER_DROPPED_IN, COUNTER_DROPPED_OUT,
    COUNTER_LEARNED_OUT, CounterValue, FirewallCounters, NftablesCompiler, Snapshot,
};
#[cfg(test)]
use openshield_core::{
    InterfaceName, LEARNED_ICMP_V4_SET, LEARNED_ICMP_V6_SET, LEARNED_TCP_V4_SET,
    LEARNED_TCP_V6_SET, LEARNED_UDP_V4_SET, LEARNED_UDP_V6_SET, LearnedEndpoint, PortRange,
    TransportProtocol,
};
use serde_json::Value;

const NFT_CANDIDATES: [&str; 3] = ["/usr/sbin/nft", "/usr/bin/nft", "/sbin/nft"];
const NFT_TABLE_QUERY: [&str; 4] = ["-j", "list", "tables", "inet"];
const NFT_CHAIN_QUERY: [&str; 4] = ["-j", "list", "chains", "inet"];
const NFT_COUNTER_QUERY: [&str; 4] = ["-j", "list", "counters", "inet"];
#[cfg(test)]
const NFT_SET_QUERY_PREFIX: [&str; 5] = ["-j", "list", "set", "inet", "openshield"];
#[cfg(test)]
const LEARNING_SET_NAMES: [&str; 6] = [
    LEARNED_TCP_V4_SET,
    LEARNED_TCP_V6_SET,
    LEARNED_UDP_V4_SET,
    LEARNED_UDP_V6_SET,
    LEARNED_ICMP_V4_SET,
    LEARNED_ICMP_V6_SET,
];
const NFT_TIMEOUT: Duration = Duration::from_secs(5);
const NFT_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const WAIT_INTERVAL: Duration = Duration::from_millis(10);
// A maximum-size validated state can expand when rendered as nft syntax.  Keep
// the execution input bounded while leaving headroom for all 10,000 rules.
const MAX_POLICY_BYTES: usize = 8 * 1024 * 1024;
const MAX_NFT_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
#[cfg(test)]
const MAX_LEARNED_ENDPOINTS: usize = 6 * 4_096;

pub trait FirewallObserver: Send {
    fn policy_observation(&mut self) -> Result<FirewallCounters>;
}

pub trait FirewallBackend: FirewallObserver {
    fn apply(&mut self, snapshot: &Snapshot) -> Result<()>;
    fn fail_closed(&mut self) -> Result<()>;
}

#[derive(Clone, Debug)]
pub struct NftBackend {
    binary: PathBuf,
}

impl NftBackend {
    pub fn discover() -> Result<Self> {
        for candidate in NFT_CANDIDATES.map(Path::new) {
            if validate_nft_binary(candidate).is_ok() {
                return Ok(Self {
                    binary: candidate.to_path_buf(),
                });
            }
        }
        bail!("no trusted nft executable was found in the fixed allowlist")
    }

    fn checked_apply(&self, policy: &[u8]) -> Result<()> {
        ensure!(
            policy.len() <= MAX_POLICY_BYTES,
            "compiled nftables policy exceeds {MAX_POLICY_BYTES} bytes"
        );

        self.run_with_input(&["-c", "-f", "-"], policy)
            .context("nftables validation failed")?;
        self.run_with_input(&["-f", "-"], policy)
            .context("atomic nftables transaction failed")
    }

    fn run_with_input(&self, args: &[&str], input: &[u8]) -> Result<()> {
        let mut child = self
            .command(args)
            .stdin(Stdio::piped())
            .spawn()
            .with_context(|| {
                format!(
                    "failed to start allowlisted nft executable {}",
                    self.binary.display()
                )
            })?;
        let Some(mut stdin) = child.stdin.take() else {
            terminate_child(&mut child);
            bail!("nft stdin pipe was not created");
        };
        let policy = input.to_vec();
        let writer = match thread::Builder::new()
            .name("openshield-nft-writer".to_owned())
            .spawn(move || stdin.write_all(&policy))
        {
            Ok(writer) => writer,
            Err(error) => {
                terminate_child(&mut child);
                return Err(error).context("failed to create bounded nft input writer");
            }
        };

        let status_result = wait_with_timeout(&mut child, NFT_TIMEOUT);
        let write_result = writer
            .join()
            .map_err(|_| anyhow!("nft input writer terminated unexpectedly"))?;
        let status = status_result?;
        write_result.context("failed to send policy to nft")?;
        ensure!(status.success(), "nft exited with status {status}");
        Ok(())
    }

    fn capture(&self, args: &[&str]) -> Result<Vec<u8>> {
        let mut child = self
            .command(args)
            .stdout(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to start {}", self.binary.display()))?;
        let Some(mut stdout) = child.stdout.take() else {
            terminate_child(&mut child);
            bail!("nft stdout pipe was not created");
        };

        let reader = match thread::Builder::new()
            .name("openshield-nft-reader".to_owned())
            .spawn(move || -> Result<(Vec<u8>, bool)> {
                let mut captured = Vec::new();
                let mut overflow = false;
                let mut chunk = [0_u8; 8192];
                loop {
                    let read = stdout
                        .read(&mut chunk)
                        .context("failed to read nft output")?;
                    if read == 0 {
                        break;
                    }
                    let remaining = MAX_NFT_OUTPUT_BYTES.saturating_sub(captured.len());
                    let keep = remaining.min(read);
                    captured.extend_from_slice(&chunk[..keep]);
                    overflow |= keep != read;
                }
                Ok((captured, overflow))
            }) {
            Ok(reader) => reader,
            Err(error) => {
                terminate_child(&mut child);
                return Err(error).context("failed to create bounded nft output reader");
            }
        };

        let status_result = wait_with_timeout(&mut child, NFT_QUERY_TIMEOUT);
        let output_result = reader
            .join()
            .map_err(|_| anyhow!("nft output reader terminated unexpectedly"))?;
        let status = status_result?;
        let (output, overflow) = output_result?;
        ensure!(status.success(), "nft exited with status {status}");
        ensure!(
            !overflow,
            "nft output exceeded {MAX_NFT_OUTPUT_BYTES} bytes"
        );
        Ok(output)
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(&self.binary);
        command
            .args(args)
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }
}

impl FirewallBackend for NftBackend {
    fn apply(&mut self, snapshot: &Snapshot) -> Result<()> {
        let policy = NftablesCompiler::compile(snapshot).context("failed to compile nft policy")?;
        self.checked_apply(policy.as_bytes())
    }

    fn fail_closed(&mut self) -> Result<()> {
        let snapshot = openshield_core::State::new().snapshot();
        let policy = NftablesCompiler::compile(&snapshot)
            .context("failed to compile fail-closed nft policy")?;
        self.checked_apply(policy.as_bytes())
    }
}

impl FirewallObserver for NftBackend {
    fn policy_observation(&mut self) -> Result<FirewallCounters> {
        // Avoid `list table`: a valid 10,000-rule policy makes that operation
        // O(rules) and can exceed the observation bound. These plural queries
        // are O(named objects) on nftables 1.0.6 and still verify every base
        // hook, default-drop policy, and named counter.
        let tables = self.capture(&NFT_TABLE_QUERY)?;
        verify_table(&tables)?;
        let chains = self.capture(&NFT_CHAIN_QUERY)?;
        verify_base_chains(&chains)?;
        let counters = self.capture(&NFT_COUNTER_QUERY)?;
        parse_counters(&counters)
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Default)]
pub struct MemoryBackend {
    applied: Option<Snapshot>,
    fail_next_apply: bool,
}

#[cfg(test)]
impl MemoryBackend {
    pub fn fail_next_apply(&mut self) {
        self.fail_next_apply = true;
    }
}

#[cfg(test)]
impl FirewallBackend for MemoryBackend {
    fn apply(&mut self, snapshot: &Snapshot) -> Result<()> {
        if self.fail_next_apply {
            self.fail_next_apply = false;
            bail!("injected memory backend failure");
        }
        self.applied = Some(snapshot.clone());
        Ok(())
    }

    fn fail_closed(&mut self) -> Result<()> {
        self.applied = Some(openshield_core::State::new().snapshot());
        Ok(())
    }
}

#[cfg(test)]
impl FirewallObserver for MemoryBackend {
    fn policy_observation(&mut self) -> Result<FirewallCounters> {
        Ok(FirewallCounters::default())
    }
}

fn validate_nft_binary(path: &Path) -> Result<()> {
    ensure!(
        NFT_CANDIDATES
            .iter()
            .any(|candidate| path == Path::new(candidate)),
        "nft path is outside the fixed allowlist"
    );
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect nft executable {}", path.display()))?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "nft executable must not be a symlink"
    );
    ensure!(metadata.is_file(), "nft executable is not a regular file");
    ensure!(metadata.uid() == 0, "nft executable is not owned by root");
    ensure!(
        metadata.mode() & 0o022 == 0,
        "nft executable is writable by group or other users"
    );
    ensure!(
        metadata.permissions().mode() & 0o111 != 0,
        "nft executable is not executable"
    );
    Ok(())
}

fn wait_with_timeout(child: &mut Child, timeout: Duration) -> Result<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(error) => {
                terminate_child(child);
                return Err(error).context("failed to query nft process");
            }
        }
        if Instant::now() >= deadline {
            terminate_child(child);
            bail!("nft process exceeded its {timeout:?} deadline");
        }
        thread::sleep(WAIT_INTERVAL);
    }
}

fn terminate_child(child: &mut Child) {
    let _ignored = child.kill();
    let _ignored = child.wait();
}

#[cfg(test)]
fn parse_learned_endpoints(input: &[u8]) -> Result<Vec<LearnedEndpoint>> {
    let document: Value = serde_json::from_slice(input).context("invalid nft JSON output")?;
    parse_learned_endpoints_document(&document)
}

#[cfg(test)]
fn parse_learned_endpoints_document(document: &Value) -> Result<Vec<LearnedEndpoint>> {
    let objects = nft_objects(document)?;
    let mut endpoints = Vec::new();
    let mut seen = HashSet::new();
    let mut seen_sets = HashSet::new();

    for object in objects {
        let Some(set) = object.get("set") else {
            continue;
        };
        if set.get("family").and_then(Value::as_str) != Some("inet")
            || set.get("table").and_then(Value::as_str) != Some("openshield")
        {
            continue;
        }
        let Some(name) = set.get("name").and_then(Value::as_str) else {
            continue;
        };
        let kind = learned_set_kind(name)
            .ok_or_else(|| anyhow!("unexpected set in the OpenShield learning table"))?;
        ensure!(seen_sets.insert(name), "duplicate OpenShield learning set");
        validate_learning_set_metadata(set, kind)?;
        let Some(elements_value) = set.get("elem") else {
            continue;
        };
        let elements = elements_value
            .as_array()
            .ok_or_else(|| anyhow!("OpenShield learning-set elements are not an array"))?;
        for element in elements {
            if let Some(endpoint) = parse_set_element(element, kind) {
                let key = learned_endpoint_key(&endpoint);
                if seen.insert(key) {
                    ensure!(
                        endpoints.len() < MAX_LEARNED_ENDPOINTS,
                        "nft learning sets exceed their aggregate endpoint bound"
                    );
                    endpoints.push(endpoint);
                }
            }
        }
    }
    let required_sets: HashSet<&str> = LEARNING_SET_NAMES.into_iter().collect();
    ensure!(
        seen_sets == required_sets,
        "one or more OpenShield learning sets are missing"
    );
    Ok(endpoints)
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
struct LearnedSetKind {
    protocol: TransportProtocol,
    requires_port: bool,
    expects_ipv6: bool,
    data_types: &'static [&'static str],
}

#[cfg(test)]
fn learned_set_kind(name: &str) -> Option<LearnedSetKind> {
    match name {
        LEARNED_TCP_V4_SET => Some(LearnedSetKind {
            protocol: TransportProtocol::Tcp,
            requires_port: true,
            expects_ipv6: false,
            data_types: &["ifname", "ipv4_addr", "inet_service"],
        }),
        LEARNED_TCP_V6_SET => Some(LearnedSetKind {
            protocol: TransportProtocol::Tcp,
            requires_port: true,
            expects_ipv6: true,
            data_types: &["ifname", "ipv6_addr", "inet_service"],
        }),
        LEARNED_UDP_V4_SET => Some(LearnedSetKind {
            protocol: TransportProtocol::Udp,
            requires_port: true,
            expects_ipv6: false,
            data_types: &["ifname", "ipv4_addr", "inet_service"],
        }),
        LEARNED_UDP_V6_SET => Some(LearnedSetKind {
            protocol: TransportProtocol::Udp,
            requires_port: true,
            expects_ipv6: true,
            data_types: &["ifname", "ipv6_addr", "inet_service"],
        }),
        LEARNED_ICMP_V4_SET => Some(LearnedSetKind {
            protocol: TransportProtocol::Icmp,
            requires_port: false,
            expects_ipv6: false,
            data_types: &["ifname", "ipv4_addr"],
        }),
        LEARNED_ICMP_V6_SET => Some(LearnedSetKind {
            protocol: TransportProtocol::IcmpV6,
            requires_port: false,
            expects_ipv6: true,
            data_types: &["ifname", "ipv6_addr"],
        }),
        _ => None,
    }
}

#[cfg(test)]
fn validate_learning_set_metadata(set: &Value, kind: LearnedSetKind) -> Result<()> {
    let data_types = set
        .get("type")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("OpenShield learning set has an invalid type"))?;
    ensure!(
        data_types.len() == kind.data_types.len()
            && data_types
                .iter()
                .zip(kind.data_types)
                .all(|(actual, expected)| actual.as_str() == Some(*expected)),
        "OpenShield learning-set type does not match its name"
    );
    let flags = set
        .get("flags")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("OpenShield learning set has invalid flags"))?;
    ensure!(
        flags.len() == 1 && flags.first().and_then(Value::as_str) == Some("timeout"),
        "OpenShield learning set must have the normalized timeout flag"
    );
    ensure!(
        set.get("size").and_then(Value::as_u64) == Some(4_096)
            && set.get("timeout").and_then(Value::as_u64) == Some(300),
        "OpenShield learning-set bounds do not match the compiled policy"
    );
    Ok(())
}

#[cfg(test)]
fn parse_set_element(element: &Value, kind: LearnedSetKind) -> Option<LearnedEndpoint> {
    let value = element
        .get("elem")
        .and_then(|inner| inner.get("val"))
        .or_else(|| element.get("val"))
        .unwrap_or(element);
    let components = value.get("concat").and_then(Value::as_array)?;
    let expected_components = if kind.requires_port { 3 } else { 2 };
    if components.len() != expected_components {
        return None;
    }
    let interface = components
        .first()
        .and_then(Value::as_str)
        .and_then(|name| InterfaceName::new(name).ok())?;
    let address: std::net::IpAddr = components.get(1)?.as_str()?.parse().ok()?;
    if address.is_ipv6() != kind.expects_ipv6 {
        return None;
    }
    let port = components
        .get(2)
        .and_then(json_port)
        .and_then(|port| PortRange::single(port).ok());
    if kind.requires_port && port.is_none() {
        return None;
    }

    Some(LearnedEndpoint {
        address,
        protocol: kind.protocol,
        port,
        interface: Some(interface),
    })
}

#[cfg(test)]
fn learned_endpoint_key(endpoint: &LearnedEndpoint) -> (std::net::IpAddr, u8, u16, u16, String) {
    let protocol = match endpoint.protocol {
        TransportProtocol::Any => 0,
        TransportProtocol::Tcp => 1,
        TransportProtocol::Udp => 2,
        TransportProtocol::Icmp => 3,
        TransportProtocol::IcmpV6 => 4,
    };
    let (port_start, port_end) = endpoint
        .port
        .map_or((0, 0), |port| (port.start(), port.end()));
    let interface = endpoint
        .interface
        .as_ref()
        .map_or_else(String::new, |name| name.as_str().to_owned());
    (endpoint.address, protocol, port_start, port_end, interface)
}

fn parse_counters(input: &[u8]) -> Result<FirewallCounters> {
    let document: Value = serde_json::from_slice(input).context("invalid nft counter JSON")?;
    parse_counters_document(&document)
}

fn nft_objects(document: &Value) -> Result<&[Value]> {
    document
        .get("nftables")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| anyhow!("nft JSON has no nftables array"))
}

fn verify_table(input: &[u8]) -> Result<()> {
    let document: Value = serde_json::from_slice(input).context("invalid nft table JSON")?;
    let objects = nft_objects(&document)?;
    let count = objects
        .iter()
        .filter_map(|object| object.get("table"))
        .filter(|table| {
            table.get("family").and_then(Value::as_str) == Some("inet")
                && table.get("name").and_then(Value::as_str) == Some("openshield")
        })
        .count();
    ensure!(
        count == 1,
        "OpenShield table declaration is missing or duplicated"
    );
    Ok(())
}

fn verify_base_chains(input: &[u8]) -> Result<()> {
    let document: Value = serde_json::from_slice(input).context("invalid nft chain JSON")?;
    let objects = nft_objects(&document)?;
    let required_chains = [
        ("input", "input", 0, "drop"),
        ("output_sanitize", "output", -1, "accept"),
        ("output", "output", 0, "drop"),
        ("output_authorize", "output", 1, "drop"),
        ("forward", "forward", 0, "drop"),
    ];
    let mut chains = HashSet::new();

    for object in objects {
        if let Some(chain) = object.get("chain")
            && chain.get("family").and_then(Value::as_str) == Some("inet")
            && chain.get("table").and_then(Value::as_str) == Some("openshield")
        {
            let name = chain
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("OpenShield chain has no name"))?;
            let (hook, priority, policy) = required_chains
                .iter()
                .find_map(|(required_name, hook, priority, policy)| {
                    (*required_name == name).then_some((*hook, *priority, *policy))
                })
                .ok_or_else(|| anyhow!("unexpected chain in the OpenShield table"))?;
            ensure!(
                chain.get("type").and_then(Value::as_str) == Some("filter")
                    && chain.get("hook").and_then(Value::as_str) == Some(hook)
                    && chain.get("prio").and_then(Value::as_i64) == Some(priority)
                    && chain.get("policy").and_then(Value::as_str) == Some(policy),
                "OpenShield base chain metadata does not match the compiled policy"
            );
            ensure!(chains.insert(name), "duplicate OpenShield base chain");
        }
    }

    ensure!(
        chains.len() == required_chains.len(),
        "one or more required OpenShield base chains are missing"
    );
    Ok(())
}

fn parse_counters_document(document: &Value) -> Result<FirewallCounters> {
    let objects = nft_objects(document)?;

    let mut accepted_in = None;
    let mut accepted_out = None;
    let mut dropped_in = None;
    let mut dropped_out = None;
    let mut learned_out = None;

    for object in objects {
        let Some(counter) = object.get("counter") else {
            continue;
        };
        if counter.get("family").and_then(Value::as_str) != Some("inet")
            || counter.get("table").and_then(Value::as_str) != Some("openshield")
        {
            continue;
        }
        let Some(name) = counter.get("name").and_then(Value::as_str) else {
            continue;
        };
        let value = CounterValue {
            packets: counter
                .get("packets")
                .and_then(Value::as_u64)
                .ok_or_else(|| anyhow!("counter {name} has an invalid packet count"))?,
            bytes: counter
                .get("bytes")
                .and_then(Value::as_u64)
                .ok_or_else(|| anyhow!("counter {name} has an invalid byte count"))?,
        };
        let destination = match name {
            COUNTER_ACCEPTED_IN => &mut accepted_in,
            COUNTER_ACCEPTED_OUT => &mut accepted_out,
            COUNTER_DROPPED_IN => &mut dropped_in,
            COUNTER_DROPPED_OUT => &mut dropped_out,
            COUNTER_LEARNED_OUT => &mut learned_out,
            _ => bail!("unexpected named counter in the OpenShield table"),
        };
        ensure!(
            destination.replace(value).is_none(),
            "duplicate nft counter {name}"
        );
    }

    Ok(FirewallCounters {
        accepted_in: accepted_in.ok_or_else(|| anyhow!("missing {COUNTER_ACCEPTED_IN} counter"))?,
        accepted_out: accepted_out
            .ok_or_else(|| anyhow!("missing {COUNTER_ACCEPTED_OUT} counter"))?,
        dropped_in: dropped_in.ok_or_else(|| anyhow!("missing {COUNTER_DROPPED_IN} counter"))?,
        dropped_out: dropped_out.ok_or_else(|| anyhow!("missing {COUNTER_DROPPED_OUT} counter"))?,
        learned_out: learned_out.ok_or_else(|| anyhow!("missing {COUNTER_LEARNED_OUT} counter"))?,
    })
}

#[cfg(test)]
fn json_port(value: &Value) -> Option<u16> {
    value
        .as_u64()
        .and_then(|port| u16::try_from(port).ok())
        .or_else(|| value.as_str().and_then(|port| port.parse().ok()))
}

#[cfg(test)]
mod tests {
    use super::{
        FirewallCounters, InterfaceName, LearnedEndpoint, PortRange, TransportProtocol,
        parse_counters, parse_learned_endpoints, verify_base_chains, verify_table,
    };
    use anyhow::Result;
    use serde_json::{Value, json};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn learning_set(name: &str, data_types: &[&str], elements: Option<Value>) -> Value {
        let mut object = json!({"set": {
            "family": "inet",
            "table": "openshield",
            "name": name,
            "type": data_types,
            "size": 4096,
            "flags": ["timeout"],
            "timeout": 300
        }});
        if let Some(elements) = elements {
            object["set"]["elem"] = elements;
        }
        object
    }

    fn learning_document(
        tcp_v4: Option<Value>,
        udp_v4: Option<Value>,
        icmp_v6: Option<Value>,
    ) -> Result<Vec<u8>> {
        let document = json!({"nftables": [
            {"set":{"family":"inet","table":"other","name":"learned_tcp_v4"}},
            learning_set(
                "learned_tcp_v4",
                &["ifname", "ipv4_addr", "inet_service"],
                tcp_v4,
            ),
            learning_set(
                "learned_tcp_v6",
                &["ifname", "ipv6_addr", "inet_service"],
                None,
            ),
            learning_set(
                "learned_udp_v4",
                &["ifname", "ipv4_addr", "inet_service"],
                udp_v4,
            ),
            learning_set(
                "learned_udp_v6",
                &["ifname", "ipv6_addr", "inet_service"],
                None,
            ),
            learning_set(
                "learned_icmp_v4",
                &["ifname", "ipv4_addr"],
                None,
            ),
            learning_set(
                "learned_icmp_v6",
                &["ifname", "ipv6_addr"],
                icmp_v6,
            )
        ]});
        Ok(serde_json::to_vec(&document)?)
    }

    #[test]
    fn parses_only_allowlisted_learning_sets_and_deduplicates() -> Result<()> {
        let input = learning_document(
            Some(json!([
                {"concat":["eth0","192.0.2.5",443]},
                {"elem":{"val":{"concat":["eth0","192.0.2.5",443]}}}
            ])),
            None,
            Some(json!([{"concat":["tun0","2001:db8::7"]}])),
        )?;
        let endpoints = parse_learned_endpoints(&input)?;
        assert_eq!(
            endpoints,
            vec![
                LearnedEndpoint {
                    address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)),
                    protocol: TransportProtocol::Tcp,
                    port: Some(PortRange::single(443)?),
                    interface: Some(InterfaceName::new("eth0")?),
                },
                LearnedEndpoint {
                    address: IpAddr::V6("2001:db8::7".parse::<Ipv6Addr>()?),
                    protocol: TransportProtocol::IcmpV6,
                    port: None,
                    interface: Some(InterfaceName::new("tun0")?),
                },
            ]
        );
        Ok(())
    }

    #[test]
    fn rejects_oversized_or_invalid_ports() -> Result<()> {
        let input = learning_document(
            None,
            Some(json!([
                {"concat":["eth0","192.0.2.1",65536]},
                {"concat":["bad;name","192.0.2.2",53]},
                {"concat":["192.0.2.3",53]},
                {"concat":["eth1","192.0.2.2","53"]}
            ])),
            None,
        )?;
        let endpoints = parse_learned_endpoints(&input)?;
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].port, Some(PortRange::single(53)?));
        assert_eq!(endpoints[0].interface, Some(InterfaceName::new("eth1")?));
        Ok(())
    }

    #[test]
    fn rejects_missing_or_unbounded_learning_set_metadata() -> Result<()> {
        let incomplete = serde_json::to_vec(&json!({"nftables": [learning_set(
            "learned_tcp_v4",
            &["ifname", "ipv4_addr", "inet_service"],
            None,
        )]}))?;
        assert!(parse_learned_endpoints(&incomplete).is_err());

        let mut invalid = serde_json::from_slice::<Value>(&learning_document(None, None, None)?)?;
        invalid["nftables"][1]["set"]["size"] = json!(8192);
        assert!(parse_learned_endpoints(&serde_json::to_vec(&invalid)?).is_err());
        Ok(())
    }

    #[test]
    fn parses_only_fixed_table_counters() -> Result<()> {
        let input = br#"{"nftables":[
          {"metainfo":{"json_schema_version":1}},
          {"counter":{"family":"inet","table":"openshield","name":"accepted_in","packets":1,"bytes":10}},
          {"counter":{"family":"inet","table":"openshield","name":"accepted_out","packets":2,"bytes":20}},
          {"counter":{"family":"inet","table":"openshield","name":"dropped_in","packets":3,"bytes":30}},
          {"counter":{"family":"inet","table":"openshield","name":"dropped_out","packets":4,"bytes":40}},
          {"counter":{"family":"inet","table":"openshield","name":"learned_out","packets":5,"bytes":50}},
          {"counter":{"family":"inet","table":"other","name":"accepted_in","packets":99,"bytes":99}}
        ]}"#;
        let counters = parse_counters(input)?;
        assert_eq!(
            counters,
            FirewallCounters {
                accepted_in: openshield_core::CounterValue {
                    packets: 1,
                    bytes: 10
                },
                accepted_out: openshield_core::CounterValue {
                    packets: 2,
                    bytes: 20
                },
                dropped_in: openshield_core::CounterValue {
                    packets: 3,
                    bytes: 30
                },
                dropped_out: openshield_core::CounterValue {
                    packets: 4,
                    bytes: 40
                },
                learned_out: openshield_core::CounterValue {
                    packets: 5,
                    bytes: 50
                },
            }
        );
        Ok(())
    }

    #[test]
    fn rejects_incomplete_counter_snapshot() {
        let input = br#"{"nftables":[]}"#;
        assert!(parse_counters(input).is_err());
    }

    #[test]
    fn observation_queries_use_nft_1_0_6_compatible_grammar() {
        assert_eq!(super::NFT_TABLE_QUERY, ["-j", "list", "tables", "inet"]);
        assert_eq!(super::NFT_CHAIN_QUERY, ["-j", "list", "chains", "inet"]);
        assert_eq!(super::NFT_COUNTER_QUERY, ["-j", "list", "counters", "inet"]);
        assert_eq!(
            super::NFT_SET_QUERY_PREFIX,
            ["-j", "list", "set", "inet", "openshield"]
        );
        assert_eq!(
            super::LEARNING_SET_NAMES,
            [
                "learned_tcp_v4",
                "learned_tcp_v6",
                "learned_udp_v4",
                "learned_udp_v6",
                "learned_icmp_v4",
                "learned_icmp_v6"
            ]
        );
    }

    #[test]
    fn policy_observation_requires_fixed_table_and_all_fail_closed_hooks() -> Result<()> {
        let complete = br#"{"nftables":[
          {"table":{"family":"inet","name":"openshield"}},
          {"chain":{"family":"inet","table":"openshield","name":"input","type":"filter","hook":"input","prio":0,"policy":"drop"}},
          {"chain":{"family":"inet","table":"openshield","name":"output_sanitize","type":"filter","hook":"output","prio":-1,"policy":"accept"}},
          {"chain":{"family":"inet","table":"openshield","name":"output","type":"filter","hook":"output","prio":0,"policy":"drop"}},
          {"chain":{"family":"inet","table":"openshield","name":"output_authorize","type":"filter","hook":"output","prio":1,"policy":"drop"}},
          {"chain":{"family":"inet","table":"openshield","name":"forward","type":"filter","hook":"forward","prio":0,"policy":"drop"}},
          {"counter":{"family":"inet","table":"openshield","name":"accepted_in","packets":1,"bytes":10}},
          {"counter":{"family":"inet","table":"openshield","name":"accepted_out","packets":2,"bytes":20}},
          {"counter":{"family":"inet","table":"openshield","name":"dropped_in","packets":3,"bytes":30}},
          {"counter":{"family":"inet","table":"openshield","name":"dropped_out","packets":4,"bytes":40}},
          {"counter":{"family":"inet","table":"openshield","name":"learned_out","packets":5,"bytes":50}},
          {"rule":{"family":"inet","table":"openshield","chain":"input"}},
          {"rule":{"family":"inet","table":"openshield","chain":"output_sanitize"}},
          {"rule":{"family":"inet","table":"openshield","chain":"output"}},
          {"rule":{"family":"inet","table":"openshield","chain":"output_authorize"}},
          {"rule":{"family":"inet","table":"openshield","chain":"forward"}}
        ]}"#;
        verify_table(complete)?;
        verify_base_chains(complete)?;

        let missing_forward_hook = br#"{"nftables":[
          {"table":{"family":"inet","name":"openshield"}},
          {"chain":{"family":"inet","table":"openshield","name":"input","type":"filter","hook":"input","prio":0,"policy":"drop"}},
          {"chain":{"family":"inet","table":"openshield","name":"output","type":"filter","hook":"output","prio":0,"policy":"drop"}},
          {"chain":{"family":"inet","table":"other","name":"forward","type":"filter","hook":"forward","prio":0,"policy":"drop"}}
        ]}"#;
        assert!(verify_base_chains(missing_forward_hook).is_err());
        Ok(())
    }

    #[test]
    fn memory_backend_supports_bounded_test_observation() -> Result<()> {
        use super::{FirewallBackend, FirewallObserver, MemoryBackend};

        let mut backend = MemoryBackend::default();
        backend.apply(&openshield_core::State::new().snapshot())?;
        backend.fail_next_apply();
        assert!(
            backend
                .apply(&openshield_core::State::new().snapshot())
                .is_err()
        );
        assert_eq!(backend.policy_observation()?, FirewallCounters::default());
        Ok(())
    }

    #[test]
    fn maximum_rule_policy_fits_the_bounded_nft_input() -> Result<()> {
        use openshield_core::{
            Direction, InterfaceName, MAX_RULES, Mode, NftablesCompiler, RuleName, RuleOrigin,
            RuleSpec, State,
        };

        let specification = RuleSpec::new(
            RuleName::new("maximum compiled selector")?,
            Direction::Outbound,
            TransportProtocol::Tcp,
            Some("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128".parse()?),
            Some(PortRange::new(1, u16::MAX)?),
            Some(InterfaceName::new("abcdefghijklmno")?),
            RuleOrigin::Manual,
            true,
        )?;
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        for _index in 0..MAX_RULES {
            state.create_rule(specification.clone())?;
        }

        let policy = NftablesCompiler::compile(&state.snapshot())?;
        assert!(policy.as_bytes().len() > 1024 * 1024);
        assert!(policy.as_bytes().len() <= super::MAX_POLICY_BYTES);
        Ok(())
    }
}
