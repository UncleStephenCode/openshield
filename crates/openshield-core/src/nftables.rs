use ipnet::IpNet;
use thiserror::Error;

use crate::{CoreError, Direction, MAX_FLOW_GENERATION, Mode, Rule, Snapshot, TransportProtocol};

pub const TABLE_NAME: &str = "openshield";
pub const LEARNED_TCP_V4_SET: &str = "learned_tcp_v4";
pub const LEARNED_TCP_V6_SET: &str = "learned_tcp_v6";
pub const LEARNED_UDP_V4_SET: &str = "learned_udp_v4";
pub const LEARNED_UDP_V6_SET: &str = "learned_udp_v6";
pub const LEARNED_ICMP_V4_SET: &str = "learned_icmp_v4";
pub const LEARNED_ICMP_V6_SET: &str = "learned_icmp_v6";
pub const COUNTER_ACCEPTED_IN: &str = "accepted_in";
pub const COUNTER_ACCEPTED_OUT: &str = "accepted_out";
pub const COUNTER_DROPPED_IN: &str = "dropped_in";
pub const COUNTER_DROPPED_OUT: &str = "dropped_out";
pub const COUNTER_LEARNED_OUT: &str = "learned_out";
pub const NFT_OWNERSHIP_COUNTER: &str = "openshield_owner_v1";
pub const APPLICATION_QUEUE_NUMBER: u16 = 1_337;
const APPLICATION_MARK_GENERATION_MASK: u32 = MAX_FLOW_GENERATION;
const APPLICATION_MARK_DOMAIN_MASK: u32 = 0xc000_0000;
const APPLICATION_MARK_PAYLOAD_MASK: u32 = 0x3fff_ffff;
const APPLICATION_PENDING_DOMAIN: u32 = 0x8000_0000;
const APPLICATION_HANDOFF_DOMAIN: u32 = 0xc000_0000;
const APPLICATION_FLOW_DOMAIN: u32 = 0x4000_0000;
// OpenShield owns the low 31 connmark bits. Keep bit 31 available to an
// existing host firewall and mask it out of every generation comparison.
const APPLICATION_CONNMARK_MASK: u32 = 0x7fff_ffff;
const APPLICATION_CONNMARK_FOREIGN_MASK: u32 = 0x8000_0000;

const APPLICATION_REPLY_PROTOCOL_MATCHES: [&str; 4] = [
    "meta l4proto tcp",
    "meta l4proto udp",
    "meta nfproto ipv4 meta l4proto icmp",
    "meta nfproto ipv6 meta l4proto icmpv6",
];
const APPLICATION_NON_TCP_PROTOCOL_MATCHES: [&str; 3] = [
    "meta l4proto udp",
    "meta nfproto ipv4 meta l4proto icmp",
    "meta nfproto ipv6 meta l4proto icmpv6",
];

/// Adds the private pending domain while retaining the unreserved packet-mark bits.
#[must_use]
pub const fn application_pending_mark(packet_mark: u32) -> u32 {
    APPLICATION_PENDING_DOMAIN | (packet_mark & APPLICATION_MARK_PAYLOAD_MASK)
}

/// Adds the private post-NFQUEUE handoff domain while retaining unreserved bits.
#[must_use]
pub const fn application_handoff_mark(packet_mark: u32) -> u32 {
    APPLICATION_HANDOFF_DOMAIN | (packet_mark & APPLICATION_MARK_PAYLOAD_MASK)
}

/// Conntrack mark that binds both directions of an authorized application flow.
#[must_use]
pub const fn application_flow_mark(flow_generation: u32) -> u32 {
    APPLICATION_FLOW_DOMAIN | (flow_generation & APPLICATION_MARK_GENERATION_MASK)
}

/// A complete, atomically loadable nftables policy.
///
/// The script is generated exclusively from validated typed values.  Callers
/// must pass it to `nft -f -` on standard input, never through a shell.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NftablesPolicy {
    script: String,
}

impl NftablesPolicy {
    #[must_use]
    pub fn render(&self) -> &str {
        &self.script
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.script
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.script.as_bytes()
    }

    #[must_use]
    pub fn into_string(self) -> String {
        self.script
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NftablesCompiler;

impl NftablesCompiler {
    /// Compiles a complete deterministic policy from a validated snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`CompileError`] when the snapshot violates a state invariant.
    pub fn compile(snapshot: &Snapshot) -> Result<NftablesPolicy, CompileError> {
        snapshot.validate()?;

        // `add` is idempotent and makes the following `delete` valid on both
        // first boot and reload. Recreating the dedicated table in one netlink
        // batch removes stale objects and resets runtime counters without any
        // externally visible interval lacking policy. This works on nftables
        // versions predating the newer `destroy` command.
        let mut script = String::from("add table inet openshield\n");
        script.push_str("delete table inet openshield\n");
        script.push_str("table inet openshield {\n");
        append_named_counters(&mut script);

        append_chain(&mut script, snapshot, Direction::Inbound);
        append_application_mark_sanitization_chain(&mut script);
        append_chain(&mut script, snapshot, Direction::Outbound);
        // Keep the base-chain topology constant in every mode so integrity
        // observation can enforce one exact structure. In BlockAll, the
        // earlier output chain drops every packet before this chain.
        append_application_authorization_chain(&mut script, snapshot);
        append_forward_chain(&mut script, snapshot.mode);
        script.push_str("}\n");

        Ok(NftablesPolicy { script })
    }
}

fn append_forward_chain(script: &mut String, mode: Mode) {
    // BlockAll covers forwarded traffic as well as host traffic. Other modes
    // leave forwarding to the existing host firewall until OpenShield exposes
    // an explicit forwarding-rule API. An nft `accept` verdict remains subject
    // to later base chains on the same hook.
    script.push_str(
        "  chain forward {\n    type filter hook forward priority filter; policy drop;\n",
    );
    if mode == Mode::BlockAll {
        script.push_str("    counter drop\n");
    } else {
        script.push_str("    accept\n");
    }
    script.push_str("  }\n");
}

fn append_named_counters(script: &mut String) {
    for name in [
        NFT_OWNERSHIP_COUNTER,
        COUNTER_ACCEPTED_IN,
        COUNTER_ACCEPTED_OUT,
        COUNTER_DROPPED_IN,
        COUNTER_DROPPED_OUT,
        COUNTER_LEARNED_OUT,
    ] {
        script.push_str("  counter ");
        script.push_str(name);
        script.push_str(" {\n    packets 0 bytes 0\n  }\n");
    }
}

fn append_chain(script: &mut String, snapshot: &Snapshot, direction: Direction) {
    let chain_name = match direction {
        Direction::Inbound => "input",
        Direction::Outbound => "output",
    };
    script.push_str("  chain ");
    script.push_str(chain_name);
    script.push_str(" {\n    type filter hook ");
    script.push_str(chain_name);
    script.push_str(" priority filter; policy drop;\n");

    let (accepted_counter, dropped_counter) = match direction {
        Direction::Inbound => (COUNTER_ACCEPTED_IN, COUNTER_DROPPED_IN),
        Direction::Outbound => (COUNTER_ACCEPTED_OUT, COUNTER_DROPPED_OUT),
    };

    if snapshot.mode != Mode::BlockAll {
        script.push_str("    ct state invalid counter name ");
        script.push_str(dropped_counter);
        script.push_str(" drop\n");

        if application_interception_required(snapshot) {
            append_application_flow_accept(script, snapshot, direction, accepted_counter);
            if direction == Direction::Outbound {
                append_application_non_tcp_connmark_reset(script);
            }
        }

        let mut direct_rules: Vec<&Rule> = snapshot
            .rules
            .iter()
            .filter(|rule| {
                rule.spec.enabled
                    && rule.spec.direction == direction
                    && rule.spec.application.is_none()
            })
            .collect();
        direct_rules.sort_unstable_by_key(|rule| rule.id);
        for rule in direct_rules {
            append_allow_rule(script, rule, direction, false, accepted_counter);
        }

        // Replies are accepted only when they belong to a connection covered
        // by an enabled rule in the opposite direction.  A blanket conntrack
        // accept would keep traffic alive after its allow rule was removed and
        // would carry unpersisted Learning flows into Enforcing mode.
        let mut reverse_rules: Vec<&Rule> = snapshot
            .rules
            .iter()
            .filter(|rule| {
                rule.spec.enabled
                    && rule.spec.direction != direction
                    && rule.spec.application.is_none()
            })
            .collect();
        reverse_rules.sort_unstable_by_key(|rule| rule.id);
        for rule in reverse_rules {
            append_allow_rule(script, rule, direction, true, accepted_counter);
        }

        if application_interception_required(snapshot) && direction == Direction::Outbound {
            append_application_queue(script);
        }
    }

    script.push_str("    counter name ");
    script.push_str(dropped_counter);
    script.push_str(" drop\n");
    script.push_str("  }\n");
}

fn application_interception_required(snapshot: &Snapshot) -> bool {
    snapshot.mode == Mode::Learning
        || snapshot.rules.iter().any(|rule| {
            rule.spec.enabled
                && rule.spec.direction == Direction::Outbound
                && rule.spec.application.is_some()
        })
}

fn append_application_flow_accept(
    script: &mut String,
    snapshot: &Snapshot,
    direction: Direction,
    accepted_counter: &str,
) {
    // A UDP/ICMP conntrack tuple can outlive its owning socket and then be
    // reused by another process. Outbound caching is consequently TCP-only;
    // inbound replies may use the generation mark for the explicit protocol
    // allowlist because every new non-TCP original packet clears and refreshes
    // that mark after successful attribution.
    let protocol_matches: &[&str] = match direction {
        Direction::Inbound => &APPLICATION_REPLY_PROTOCOL_MATCHES,
        Direction::Outbound => &APPLICATION_REPLY_PROTOCOL_MATCHES[..1],
    };
    for protocol_match in protocol_matches {
        script.push_str("    ct direction ");
        match direction {
            Direction::Inbound => script.push_str("reply ct state established "),
            Direction::Outbound => script.push_str("original ct state established "),
        }
        script.push_str(protocol_match);
        script.push_str(" ct mark & 0x");
        append_hex_u32(script, APPLICATION_CONNMARK_MASK);
        script.push_str(" == 0x");
        append_hex_u32(script, application_flow_mark(snapshot.flow_generation));
        if direction == Direction::Outbound {
            script.push(' ');
            append_packet_mark_domain_set(script, APPLICATION_HANDOFF_DOMAIN);
        }
        script.push_str(" counter name ");
        script.push_str(accepted_counter);
        script.push_str(" accept\n");
    }
}

fn append_application_non_tcp_connmark_reset(script: &mut String) {
    for protocol_match in APPLICATION_NON_TCP_PROTOCOL_MATCHES {
        script.push_str("    ct direction original ");
        script.push_str(protocol_match);
        script.push_str(" ct mark set ct mark & 0x");
        append_hex_u32(script, APPLICATION_CONNMARK_FOREIGN_MASK);
        script.push('\n');
    }
}

fn append_application_queue(script: &mut String) {
    // There is deliberately no `bypass` flag: if the authenticated queue
    // consumer is absent or overloaded, application-scoped traffic fails
    // closed in the kernel.
    script.push_str("    ct direction original ");
    append_packet_mark_domain_set(script, APPLICATION_PENDING_DOMAIN);
    script.push_str(" queue num ");
    script.push_str(&APPLICATION_QUEUE_NUMBER.to_string());
    script.push('\n');
}

fn append_application_mark_sanitization_chain(script: &mut String) {
    // CAP_NET_RAW can use SO_MARK on modern Linux. Strip the two reserved bits
    // in an earlier hook before any allow decision. The remaining 30 bits are
    // retained for policy routing and QoS.
    script.push_str(
        "  chain output_sanitize {\n    type filter hook output priority -1; policy accept;\n",
    );
    script.push_str("    meta mark & 0x");
    append_hex_u32(script, APPLICATION_MARK_DOMAIN_MASK);
    script.push_str(" != 0x00000000 meta mark set meta mark & 0x");
    append_hex_u32(script, APPLICATION_MARK_PAYLOAD_MASK);
    script.push_str("\n  }\n");
}

fn append_packet_mark_domain_set(script: &mut String, domain: u32) {
    script.push_str("meta mark set (meta mark & 0x");
    append_hex_u32(script, APPLICATION_MARK_PAYLOAD_MASK);
    script.push_str(") | 0x");
    append_hex_u32(script, domain);
}

fn append_hex_u32(script: &mut String, value: u32) {
    use std::fmt::Write as _;

    // Formatting into String is infallible; keep generation allocation-free.
    let _infallible = write!(script, "{value:08x}");
}

fn append_application_authorization_chain(script: &mut String, snapshot: &Snapshot) {
    let flow = application_flow_mark(snapshot.flow_generation);
    script.push_str(
        "  chain output_authorize {\n    type filter hook output priority 1; policy drop;\n",
    );
    if application_interception_required(snapshot) && snapshot.mode != Mode::BlockAll {
        // All attributable protocols receive the current generation so a
        // reply can be recognized. Only TCP uses that mark as an outbound
        // cache; UDP/ICMP clear it before every original packet and are queued
        // again. Restricting this branch to the parser's explicit allowlist
        // makes an accidental NF_ACCEPT for another protocol fail closed.
        for protocol_match in APPLICATION_REPLY_PROTOCOL_MATCHES {
            script.push_str("    ");
            script.push_str(protocol_match);
            script.push_str(" meta mark & 0x");
            append_hex_u32(script, APPLICATION_MARK_DOMAIN_MASK);
            script.push_str(" == 0x");
            append_hex_u32(script, APPLICATION_PENDING_DOMAIN);
            script.push_str(" ct mark set (ct mark & 0x");
            append_hex_u32(script, APPLICATION_CONNMARK_FOREIGN_MASK);
            script.push_str(") | 0x");
            append_hex_u32(script, flow);
            script.push_str(" meta mark set meta mark & 0x");
            append_hex_u32(script, APPLICATION_MARK_PAYLOAD_MASK);
            if snapshot.mode == Mode::Learning {
                script.push_str(" counter name ");
                script.push_str(COUNTER_LEARNED_OUT);
            }
            script.push_str(" counter name ");
            script.push_str(COUNTER_ACCEPTED_OUT);
            script.push_str(" accept\n");
        }
    }
    if snapshot.mode != Mode::BlockAll {
        script.push_str("    meta mark & 0x");
        append_hex_u32(script, APPLICATION_MARK_DOMAIN_MASK);
        script.push_str(" == 0x");
        append_hex_u32(script, APPLICATION_HANDOFF_DOMAIN);
        script.push_str(" meta mark set meta mark & 0x");
        append_hex_u32(script, APPLICATION_MARK_PAYLOAD_MASK);
        script.push_str(" accept\n");
    }
    script.push_str("    counter name ");
    script.push_str(COUNTER_DROPPED_OUT);
    script.push_str(" drop\n");
    script.push_str("  }\n");
}

fn append_allow_rule(
    script: &mut String,
    rule: &Rule,
    chain_direction: Direction,
    stateful_reverse: bool,
    accepted_counter: &str,
) {
    script.push_str("    ");

    if stateful_reverse {
        // `related` packets may have a different L4 protocol/port (for example
        // ICMP errors) and therefore cannot safely use these exact reverse
        // selectors. They require an explicit allow rule.
        script.push_str("ct direction reply ct state established ");
    }

    if let Some(interface) = &rule.spec.interface {
        match chain_direction {
            Direction::Inbound => script.push_str("iifname \""),
            Direction::Outbound => script.push_str("oifname \""),
        }
        script.push_str(interface.as_str());
        script.push_str("\" ");
    }

    if let Some(network) = rule.spec.peer_network {
        match (chain_direction, network) {
            (Direction::Inbound, IpNet::V4(network)) => {
                script.push_str("ip saddr ");
                script.push_str(&network.to_string());
                script.push(' ');
            }
            (Direction::Inbound, IpNet::V6(network)) => {
                script.push_str("ip6 saddr ");
                script.push_str(&network.to_string());
                script.push(' ');
            }
            (Direction::Outbound, IpNet::V4(network)) => {
                script.push_str("ip daddr ");
                script.push_str(&network.to_string());
                script.push(' ');
            }
            (Direction::Outbound, IpNet::V6(network)) => {
                script.push_str("ip6 daddr ");
                script.push_str(&network.to_string());
                script.push(' ');
            }
        }
    }

    match rule.spec.protocol {
        TransportProtocol::Any => {}
        TransportProtocol::Tcp => script.push_str("meta l4proto tcp "),
        TransportProtocol::Udp => script.push_str("meta l4proto udp "),
        TransportProtocol::Icmp => {
            script.push_str("meta nfproto ipv4 meta l4proto icmp ");
        }
        TransportProtocol::IcmpV6 => {
            script.push_str("meta nfproto ipv6 meta l4proto icmpv6 ");
        }
    }

    if let Some(port) = rule.spec.port {
        match (rule.spec.protocol, stateful_reverse) {
            (TransportProtocol::Tcp, false) => script.push_str("tcp dport "),
            (TransportProtocol::Tcp, true) => script.push_str("tcp sport "),
            (TransportProtocol::Udp, false) => script.push_str("udp dport "),
            (TransportProtocol::Udp, true) => script.push_str("udp sport "),
            _ => {}
        }
        script.push_str(&port.start().to_string());
        if port.end() != port.start() {
            script.push('-');
            script.push_str(&port.end().to_string());
        }
        script.push(' ');
    }

    if chain_direction == Direction::Outbound {
        append_packet_mark_domain_set(script, APPLICATION_HANDOFF_DOMAIN);
        script.push(' ');
    }
    script.push_str("counter name ");
    script.push_str(accepted_counter);
    script.push_str(" accept\n");
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CompileError {
    #[error(transparent)]
    InvalidState(#[from] CoreError),
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use chrono::{TimeZone, Utc};

    use super::*;
    use crate::{Direction, InterfaceName, Mode, PortRange, RuleName, RuleOrigin, RuleSpec, State};

    fn add_https_rule(
        state: &mut State,
        direction: Direction,
        network: &str,
    ) -> Result<(), Box<dyn Error>> {
        let now = Utc
            .with_ymd_and_hms(2026, 8, 20, 12, 0, 0)
            .single()
            .ok_or("invalid test time")?;
        let id = uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000001")?;
        let spec = RuleSpec::new(
            RuleName::new("https")?,
            direction,
            TransportProtocol::Tcp,
            Some(network.parse()?),
            Some(PortRange::single(443)?),
            Some(InterfaceName::new("eth0")?),
            RuleOrigin::Manual,
            true,
        )?;
        state.create_rule_at(id, spec, now)?;
        Ok(())
    }

    fn add_udp_rule(
        state: &mut State,
        direction: Direction,
        network: &str,
    ) -> Result<(), Box<dyn Error>> {
        let now = Utc
            .with_ymd_and_hms(2026, 8, 20, 12, 0, 0)
            .single()
            .ok_or("invalid test time")?;
        let id = uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000002")?;
        let spec = RuleSpec::new(
            RuleName::new("dns")?,
            direction,
            TransportProtocol::Udp,
            Some(network.parse()?),
            Some(PortRange::single(53)?),
            Some(InterfaceName::new("eth0")?),
            RuleOrigin::Manual,
            true,
        )?;
        state.create_rule_at(id, spec, now)?;
        Ok(())
    }

    #[test]
    fn block_all_has_no_accept_path_even_with_rules() -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        add_https_rule(&mut state, Direction::Outbound, "203.0.113.0/24")?;
        let policy = NftablesCompiler::compile(&state.snapshot())?;
        assert!(
            policy
                .as_str()
                .starts_with("add table inet openshield\ndelete table inet openshield\n")
        );
        assert!(!policy.as_str().contains("destroy table"));
        assert!(!policy.as_str().contains(" accept\n"));
        assert!(policy.as_str().contains("policy drop"));
        for counter in [
            NFT_OWNERSHIP_COUNTER,
            COUNTER_ACCEPTED_IN,
            COUNTER_ACCEPTED_OUT,
            COUNTER_DROPPED_IN,
            COUNTER_DROPPED_OUT,
            COUNTER_LEARNED_OUT,
        ] {
            assert!(policy.as_str().contains(&format!("counter {counter} {{")));
        }
        assert!(policy.as_str().contains("counter name dropped_in drop"));
        assert!(policy.as_str().contains("counter name dropped_out drop"));
        assert!(policy.as_str().contains(
            "chain forward {\n    type filter hook forward priority filter; policy drop;"
        ));
        assert!(!policy.as_str().contains(LEARNED_TCP_V4_SET));
        Ok(())
    }

    #[test]
    fn non_block_modes_leave_forwarding_to_other_base_chains() -> Result<(), Box<dyn Error>> {
        for mode in [Mode::Learning, Mode::Enforcing] {
            let mut state = State::new();
            state.set_mode(mode)?;
            let script = NftablesCompiler::compile(&state.snapshot())?.into_string();
            assert!(script.contains(
                "chain forward {\n    type filter hook forward priority filter; policy drop;\n    accept\n  }"
            ));
            assert!(!script.contains(
                "chain forward {\n    type filter hook forward priority filter; policy drop;\n    counter drop"
            ));
        }
        Ok(())
    }

    #[test]
    fn enforcing_has_default_drop_and_typed_outbound_allow() -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        add_https_rule(&mut state, Direction::Outbound, "203.0.113.0/24")?;
        let snapshot = state.snapshot();
        let script = NftablesCompiler::compile(&snapshot)?.into_string();
        let invalid = script
            .find("ct state invalid counter name dropped_in drop")
            .ok_or("missing invalid drop")?;
        let reverse = script
            .find(
                "ct direction reply ct state established iifname \"eth0\" ip saddr 203.0.113.0/24 meta l4proto tcp tcp sport 443 counter name accepted_in accept",
            )
            .ok_or("missing selector-bound reverse accept")?;
        assert!(invalid < reverse);
        assert!(!script.contains("ct state established,related counter name"));
        assert!(script.contains(
            "oifname \"eth0\" ip daddr 203.0.113.0/24 meta l4proto tcp tcp dport 443 meta mark set (meta mark & 0x3fffffff) | 0xc0000000 counter name accepted_out accept"
        ));
        assert!(script.contains(
            "chain forward {\n    type filter hook forward priority filter; policy drop;\n    accept\n  }"
        ));
        Ok(())
    }

    #[test]
    fn inbound_network_is_matched_as_source() -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        add_https_rule(&mut state, Direction::Inbound, "2001:db8::/32")?;
        let snapshot = state.snapshot();
        let script = NftablesCompiler::compile(&snapshot)?.into_string();
        assert!(script.contains(
            "iifname \"eth0\" ip6 saddr 2001:db8::/32 meta l4proto tcp tcp dport 443 counter name accepted_in accept"
        ));
        assert!(script.contains(
            "ct direction reply ct state established oifname \"eth0\" ip6 daddr 2001:db8::/32 meta l4proto tcp tcp sport 443 meta mark set (meta mark & 0x3fffffff) | 0xc0000000 counter name accepted_out accept"
        ));
        Ok(())
    }

    #[test]
    fn disabled_rule_has_neither_direct_nor_reverse_accept() -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        add_https_rule(&mut state, Direction::Outbound, "203.0.113.0/24")?;
        let id = state.rules().next().ok_or("missing test rule")?.id;
        state.set_rule_enabled(id, false)?;

        let script = NftablesCompiler::compile(&state.snapshot())?.into_string();
        assert!(!script.contains("203.0.113.0/24"));
        assert!(!script.contains("ct state established,related counter name"));
        Ok(())
    }

    #[test]
    fn learning_queues_without_bypass_and_authorizes_with_flow_generation()
    -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        state.set_mode(Mode::Learning)?;
        let snapshot = state.snapshot();
        let flow = format!("{:08x}", application_flow_mark(snapshot.flow_generation));
        let script = NftablesCompiler::compile(&snapshot)?.into_string();
        assert!(script.contains(
            "ct direction original meta mark set (meta mark & 0x3fffffff) | 0x80000000 queue num 1337\n"
        ));
        assert!(!script.contains("queue flags bypass"));
        assert!(script.contains(&format!(
            "meta l4proto tcp meta mark & 0xc0000000 == 0x80000000 ct mark set (ct mark & 0x80000000) | 0x{flow} meta mark set meta mark & 0x3fffffff counter name learned_out counter name accepted_out accept"
        )));
        assert!(script.contains(&format!(
            "ct direction reply ct state established meta l4proto tcp ct mark & 0x7fffffff == 0x{flow} counter name accepted_in accept"
        )));
        assert!(
            script.contains(
                "ct direction original meta l4proto udp ct mark set ct mark & 0x80000000"
            )
        );
        assert!(script.contains(&format!(
            "ct direction reply ct state established meta l4proto udp ct mark & 0x7fffffff == 0x{flow} counter name accepted_in accept"
        )));
        assert!(script.contains(&format!(
            "meta l4proto udp meta mark & 0xc0000000 == 0x80000000 ct mark set (ct mark & 0x80000000) | 0x{flow}"
        )));
        assert!(
            !script.contains("ct direction original ct state established meta l4proto udp ct mark")
        );
        assert!(!script.contains("\n    meta mark & 0xc0000000 == 0x80000000 ct mark set"));
        assert!(script.contains(
            "chain output_sanitize {\n    type filter hook output priority -1; policy accept;"
        ));
        assert!(
            script.contains(
                "meta mark & 0xc0000000 != 0x00000000 meta mark set meta mark & 0x3fffffff"
            )
        );
        assert!(script.contains(
            "chain output_authorize {\n    type filter hook output priority 1; policy drop;"
        ));
        assert!(!script.contains("set learned_"));
        Ok(())
    }

    #[test]
    fn non_tcp_application_reply_allowlist_is_explicit_and_refreshed_before_direct_rules()
    -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        state.set_mode(Mode::Learning)?;
        add_udp_rule(&mut state, Direction::Outbound, "192.0.2.53/32")?;
        let snapshot = state.snapshot();
        let flow = format!("{:08x}", application_flow_mark(snapshot.flow_generation));
        let script = NftablesCompiler::compile(&snapshot)?.into_string();

        for protocol_match in APPLICATION_REPLY_PROTOCOL_MATCHES {
            assert!(script.contains(&format!(
                "ct direction reply ct state established {protocol_match} ct mark & 0x7fffffff == 0x{flow} counter name accepted_in accept"
            )));
        }
        for protocol_match in APPLICATION_NON_TCP_PROTOCOL_MATCHES {
            assert!(script.contains(&format!(
                "ct direction original {protocol_match} ct mark set ct mark & 0x80000000"
            )));
        }

        let reset = script
            .find("ct direction original meta l4proto udp ct mark set ct mark & 0x80000000")
            .ok_or("missing UDP connmark reset")?;
        let direct = script
            .find("oifname \"eth0\" ip daddr 192.0.2.53/32 meta l4proto udp udp dport 53")
            .ok_or("missing direct UDP rule")?;
        let queue = script
            .find("queue num 1337")
            .ok_or("missing application queue")?;
        assert!(reset < direct);
        assert!(reset < queue);
        assert!(!script.contains("ct direction original ct state established meta l4proto udp"));
        assert!(!script.contains("meta l4proto sctp ct mark & 0x7fffffff"));
        Ok(())
    }

    #[test]
    fn compilation_is_independent_of_snapshot_order() -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        add_https_rule(&mut state, Direction::Outbound, "203.0.113.0/24")?;
        let mut reversed = state.snapshot();
        reversed.rules.reverse();
        assert_eq!(
            NftablesCompiler::compile(&state.snapshot())?,
            NftablesCompiler::compile(&reversed)?
        );
        Ok(())
    }
}
