use std::fmt::Write as _;

use ipnet::IpNet;

use crate::{
    CompileError, Direction, MAX_FLOW_GENERATION, Mode, Rule, Snapshot, TransportProtocol,
    application_flow_mark,
};

pub const IPTABLES_INPUT_CHAIN: &str = "OPENSHIELD_IN";
pub const IPTABLES_OUTPUT_CHAIN: &str = "OPENSHIELD_OUT";
pub const IPTABLES_FORWARD_CHAIN: &str = "OPENSHIELD_FWD";
pub const IPTABLES_APPLICATION_TCP_CHAIN: &str = "OPENSHIELD_APP_TCP";
pub const IPTABLES_APPLICATION_PACKET_CHAIN: &str = "OPENSHIELD_APP_PKT";
pub const IPTABLES_OWNERSHIP_COMMENT: &str = "openshield:owner:v1";
pub const IPTABLES_MARK_SANITIZE_CHAIN: &str = "OPENSHIELD_MARK";

const APPLICATION_MARK_DOMAIN_MASK: u32 = 0xc000_0000;
const APPLICATION_PENDING_DOMAIN: u32 = 0x8000_0000;
const APPLICATION_HANDOFF_DOMAIN: u32 = 0xc000_0000;
// OpenShield's application flow identity occupies the low 31 connmark bits.
// Keep bit 31 intact for firewalls which use it independently.  Using a mask
// here is also important for the fast path: comparing the unmasked value would
// reject an otherwise valid OpenShield generation when that foreign bit is set.
const APPLICATION_CONNMARK_MASK: u32 = 0x7fff_ffff;

/// A pair of complete `iptables-restore` programs for the IPv4 and IPv6
/// compatibility backends.
///
/// The programs only flush and repopulate OpenShield-owned chains. They are
/// intended for `iptables-restore --noflush`; they never flush a system table
/// or alter a built-in chain. All interpolated values originate in validated
/// domain types.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IptablesPolicy {
    ipv4: String,
    ipv6: String,
}

impl IptablesPolicy {
    #[must_use]
    pub fn ipv4(&self) -> &str {
        &self.ipv4
    }

    #[must_use]
    pub fn ipv6(&self) -> &str {
        &self.ipv6
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct IptablesCompiler;

impl IptablesCompiler {
    /// Compiles deterministic IPv4 and IPv6 restore programs.
    ///
    /// # Errors
    ///
    /// Returns [`CompileError`] when the snapshot violates a state invariant.
    pub fn compile(snapshot: &Snapshot) -> Result<IptablesPolicy, CompileError> {
        snapshot.validate()?;
        Ok(IptablesPolicy {
            ipv4: compile_family(snapshot, AddressFamily::Ipv4),
            ipv6: compile_family(snapshot, AddressFamily::Ipv6),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AddressFamily {
    Ipv4,
    Ipv6,
}

fn compile_family(snapshot: &Snapshot, family: AddressFamily) -> String {
    let mut script = String::from("*mangle\n");
    for chain in owned_mangle_chains() {
        let _infallible = writeln!(script, "-F {chain}");
        let _infallible = writeln!(
            script,
            "-A {chain} -m comment --comment {IPTABLES_OWNERSHIP_COMMENT}"
        );
        let _infallible = writeln!(
            script,
            "-A {chain} -m mark ! --mark 0x00000000/0x{APPLICATION_MARK_DOMAIN_MASK:08x} -j MARK --set-xmark 0x00000000/0x{APPLICATION_MARK_DOMAIN_MASK:08x}"
        );
        let _infallible = writeln!(script, "-A {chain} -j RETURN");
    }
    script.push_str("COMMIT\n*filter\n");
    for chain in owned_chains() {
        let _infallible = writeln!(script, "-F {chain}");
    }
    for chain in owned_chains() {
        let _infallible = writeln!(
            script,
            "-A {chain} -m comment --comment {IPTABLES_OWNERSHIP_COMMENT}"
        );
    }

    append_input_chain(&mut script, snapshot, family);
    append_output_chain(&mut script, snapshot, family);
    append_application_chains(&mut script, snapshot);
    append_forward_chain(&mut script, snapshot.mode);
    script.push_str("COMMIT\n");
    script
}

fn append_forward_chain(script: &mut String, mode: Mode) {
    if mode == Mode::BlockAll {
        append_counted_verdict(script, IPTABLES_FORWARD_CHAIN, "dropped_out", "DROP");
    } else {
        let _infallible = writeln!(script, "-A {IPTABLES_FORWARD_CHAIN} -j RETURN");
    }
}

#[must_use]
pub const fn owned_chains() -> [&'static str; 5] {
    [
        IPTABLES_INPUT_CHAIN,
        IPTABLES_OUTPUT_CHAIN,
        IPTABLES_FORWARD_CHAIN,
        IPTABLES_APPLICATION_TCP_CHAIN,
        IPTABLES_APPLICATION_PACKET_CHAIN,
    ]
}

#[must_use]
pub const fn owned_mangle_chains() -> [&'static str; 1] {
    [IPTABLES_MARK_SANITIZE_CHAIN]
}

fn append_input_chain(script: &mut String, snapshot: &Snapshot, family: AddressFamily) {
    if snapshot.mode != Mode::BlockAll {
        append_invalid_drop(script, IPTABLES_INPUT_CHAIN, "dropped_in");

        if application_interception_required(snapshot) {
            let flow = application_flow_mark(snapshot.flow_generation);
            for protocol in application_reply_protocols(family) {
                let _infallible = writeln!(
                    script,
                    "-A {IPTABLES_INPUT_CHAIN} -p {protocol} -m conntrack --ctstate ESTABLISHED --ctdir REPLY -m connmark --mark 0x{flow:08x}/0x{APPLICATION_CONNMARK_MASK:08x} -m comment --comment openshield:accepted_in -j RETURN"
                );
            }
        }

        append_direct_rules(script, snapshot, family, Direction::Inbound, false);
        append_reverse_rules(script, snapshot, family, Direction::Inbound);
    }
    append_counted_verdict(script, IPTABLES_INPUT_CHAIN, "dropped_in", "DROP");
}

fn append_output_chain(script: &mut String, snapshot: &Snapshot, family: AddressFamily) {
    if snapshot.mode != Mode::BlockAll {
        if application_interception_required(snapshot) {
            // iptables NF_ACCEPT terminates the current filter hook.  The
            // compatibility queue therefore returns NF_REPEAT with a
            // kernel-supplied handoff mark; these first rules consume it on
            // the repeated traversal before any ordinary allow decision.
            let _infallible = writeln!(
                script,
                "-A {IPTABLES_OUTPUT_CHAIN} -p tcp -m mark --mark 0x{APPLICATION_HANDOFF_DOMAIN:08x}/0x{APPLICATION_MARK_DOMAIN_MASK:08x} -g {IPTABLES_APPLICATION_TCP_CHAIN}"
            );
            for protocol in application_non_tcp_protocols(family) {
                let _infallible = writeln!(
                    script,
                    "-A {IPTABLES_OUTPUT_CHAIN} -p {protocol} -m mark --mark 0x{APPLICATION_HANDOFF_DOMAIN:08x}/0x{APPLICATION_MARK_DOMAIN_MASK:08x} -g {IPTABLES_APPLICATION_PACKET_CHAIN}"
                );
            }
        }
        append_invalid_drop(script, IPTABLES_OUTPUT_CHAIN, "dropped_out");

        if application_interception_required(snapshot) {
            let flow = application_flow_mark(snapshot.flow_generation);
            let _infallible = writeln!(
                script,
                "-A {IPTABLES_OUTPUT_CHAIN} -p tcp -m conntrack --ctstate ESTABLISHED --ctdir ORIGINAL -m connmark --mark 0x{flow:08x}/0x{APPLICATION_CONNMARK_MASK:08x} -m comment --comment openshield:accepted_out -j RETURN"
            );

            // UDP and ICMP conntrack tuples can outlive their owning socket.
            // Clear only OpenShield's low 31 bits before every new outbound
            // packet so another process cannot inherit a cached application
            // decision. The authenticated NFQUEUE handoff restores the
            // current generation for the corresponding inbound reply.
            for protocol in application_non_tcp_protocols(family) {
                let _infallible = writeln!(
                    script,
                    "-A {IPTABLES_OUTPUT_CHAIN} -p {protocol} -m conntrack --ctdir ORIGINAL -j CONNMARK --set-xmark 0x00000000/0x{APPLICATION_CONNMARK_MASK:08x}"
                );
            }
        }

        append_direct_rules(script, snapshot, family, Direction::Outbound, false);
        append_reverse_rules(script, snapshot, family, Direction::Outbound);

        if application_interception_required(snapshot) {
            let _infallible = writeln!(
                script,
                "-A {IPTABLES_OUTPUT_CHAIN} -m conntrack --ctdir ORIGINAL -j MARK --set-xmark 0x{APPLICATION_PENDING_DOMAIN:08x}/0x{APPLICATION_MARK_DOMAIN_MASK:08x}"
            );
            let _infallible = writeln!(
                script,
                "-A {IPTABLES_OUTPUT_CHAIN} -m conntrack --ctdir ORIGINAL -j NFQUEUE --queue-num {}",
                crate::APPLICATION_QUEUE_NUMBER
            );
        }
    }
    append_counted_verdict(script, IPTABLES_OUTPUT_CHAIN, "dropped_out", "DROP");
}

fn append_application_chains(script: &mut String, snapshot: &Snapshot) {
    if application_interception_required(snapshot) && snapshot.mode != Mode::BlockAll {
        let flow = application_flow_mark(snapshot.flow_generation & MAX_FLOW_GENERATION);
        let _infallible = writeln!(
            script,
            "-A {IPTABLES_APPLICATION_TCP_CHAIN} -j CONNMARK --set-xmark 0x{flow:08x}/0x{APPLICATION_CONNMARK_MASK:08x}"
        );
        append_clear_reserved_mark(script, IPTABLES_APPLICATION_TCP_CHAIN);
        append_application_accept(script, IPTABLES_APPLICATION_TCP_CHAIN, snapshot.mode);

        let _infallible = writeln!(
            script,
            "-A {IPTABLES_APPLICATION_PACKET_CHAIN} -j CONNMARK --set-xmark 0x{flow:08x}/0x{APPLICATION_CONNMARK_MASK:08x}"
        );
        append_clear_reserved_mark(script, IPTABLES_APPLICATION_PACKET_CHAIN);
        append_application_accept(script, IPTABLES_APPLICATION_PACKET_CHAIN, snapshot.mode);
    }

    // Inactive application chains and any path which reaches their terminal
    // rule remain fail-closed. Active guarded `--goto` paths return directly
    // to the built-in OUTPUT chain after the reserved packet mark is cleared.
    append_counted_verdict(
        script,
        IPTABLES_APPLICATION_TCP_CHAIN,
        "dropped_out",
        "DROP",
    );
    append_counted_verdict(
        script,
        IPTABLES_APPLICATION_PACKET_CHAIN,
        "dropped_out",
        "DROP",
    );
}

fn application_reply_protocols(family: AddressFamily) -> [&'static str; 3] {
    match family {
        AddressFamily::Ipv4 => ["tcp", "udp", "icmp"],
        AddressFamily::Ipv6 => ["tcp", "udp", "ipv6-icmp"],
    }
}

fn application_non_tcp_protocols(family: AddressFamily) -> [&'static str; 2] {
    match family {
        AddressFamily::Ipv4 => ["udp", "icmp"],
        AddressFamily::Ipv6 => ["udp", "ipv6-icmp"],
    }
}

fn append_clear_reserved_mark(script: &mut String, chain: &str) {
    let _infallible = writeln!(
        script,
        "-A {chain} -j MARK --set-xmark 0x00000000/0x{APPLICATION_MARK_DOMAIN_MASK:08x}"
    );
}

fn append_application_accept(script: &mut String, chain: &str, mode: Mode) {
    let comment = if mode == Mode::Learning {
        "openshield:accepted_out+learned_out"
    } else {
        "openshield:accepted_out"
    };
    let _infallible = writeln!(
        script,
        "-A {chain} -m comment --comment {comment} -j RETURN"
    );
}

fn append_invalid_drop(script: &mut String, chain: &str, counter: &str) {
    let _infallible = writeln!(
        script,
        "-A {chain} -m conntrack --ctstate INVALID -m comment --comment openshield:{counter} -j DROP"
    );
}

fn append_counted_verdict(script: &mut String, chain: &str, counter: &str, verdict: &str) {
    let _infallible = writeln!(
        script,
        "-A {chain} -m comment --comment openshield:{counter} -j {verdict}"
    );
}

fn append_direct_rules(
    script: &mut String,
    snapshot: &Snapshot,
    family: AddressFamily,
    direction: Direction,
    reverse: bool,
) {
    let mut rules: Vec<&Rule> = snapshot
        .rules
        .iter()
        .filter(|rule| {
            rule.spec.enabled
                && rule.spec.direction == direction
                && rule.spec.application.is_none()
                && supports_family(rule, family)
        })
        .collect();
    rules.sort_unstable_by_key(|rule| rule.id);
    for rule in rules {
        append_allow_rule(script, rule, direction, reverse);
    }
}

fn append_reverse_rules(
    script: &mut String,
    snapshot: &Snapshot,
    family: AddressFamily,
    chain_direction: Direction,
) {
    let mut rules: Vec<&Rule> = snapshot
        .rules
        .iter()
        .filter(|rule| {
            rule.spec.enabled
                && rule.spec.direction != chain_direction
                && rule.spec.application.is_none()
                && supports_family(rule, family)
        })
        .collect();
    rules.sort_unstable_by_key(|rule| rule.id);
    for rule in rules {
        append_allow_rule(script, rule, chain_direction, true);
    }
}

fn supports_family(rule: &Rule, family: AddressFamily) -> bool {
    !matches!(
        (rule.spec.protocol, rule.spec.peer_network, family),
        (TransportProtocol::Icmp, _, AddressFamily::Ipv6)
            | (TransportProtocol::IcmpV6, _, AddressFamily::Ipv4)
            | (_, Some(IpNet::V4(_)), AddressFamily::Ipv6)
            | (_, Some(IpNet::V6(_)), AddressFamily::Ipv4)
    )
}

fn append_allow_rule(
    script: &mut String,
    rule: &Rule,
    chain_direction: Direction,
    stateful_reverse: bool,
) {
    let chain = match chain_direction {
        Direction::Inbound => IPTABLES_INPUT_CHAIN,
        Direction::Outbound => IPTABLES_OUTPUT_CHAIN,
    };
    let _infallible = write!(script, "-A {chain}");

    if let Some(network) = rule.spec.peer_network {
        let option = if chain_direction == Direction::Inbound {
            "-s"
        } else {
            "-d"
        };
        let _infallible = write!(script, " {option} {network}");
    }
    if let Some(interface) = &rule.spec.interface {
        let option = if chain_direction == Direction::Inbound {
            "-i"
        } else {
            "-o"
        };
        let _infallible = write!(script, " {option} {}", interface.as_str());
    }

    match rule.spec.protocol {
        TransportProtocol::Any => {}
        TransportProtocol::Tcp => script.push_str(" -p tcp"),
        TransportProtocol::Udp => script.push_str(" -p udp"),
        TransportProtocol::Icmp => script.push_str(" -p icmp"),
        TransportProtocol::IcmpV6 => script.push_str(" -p ipv6-icmp"),
    }
    if stateful_reverse {
        script.push_str(" -m conntrack --ctstate ESTABLISHED --ctdir REPLY");
    }
    if let Some(port) = rule.spec.port {
        let option = if stateful_reverse {
            "--sport"
        } else {
            "--dport"
        };
        let _infallible = write!(script, " {option} {}", port.start());
        if port.end() != port.start() {
            let _infallible = write!(script, ":{}", port.end());
        }
    }

    let counter = if chain_direction == Direction::Inbound {
        "accepted_in"
    } else {
        "accepted_out"
    };
    let _infallible = writeln!(
        script,
        " -m comment --comment openshield:{counter} -j RETURN"
    );
}

fn application_interception_required(snapshot: &Snapshot) -> bool {
    snapshot.mode == Mode::Learning
        || snapshot.rules.iter().any(|rule| {
            rule.spec.enabled
                && rule.spec.direction == Direction::Outbound
                && rule.spec.application.is_some()
        })
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use chrono::{TimeZone, Utc};

    use super::*;
    use crate::{
        ApplicationPath, ApplicationSelector, ExecutableFileId, InterfaceName, PortRange, RuleName,
        RuleOrigin, RuleSpec, State,
    };

    fn add_rule(
        state: &mut State,
        direction: Direction,
        network: &str,
        application: bool,
    ) -> Result<(), Box<dyn Error>> {
        let now = Utc
            .with_ymd_and_hms(2026, 8, 20, 12, 0, 0)
            .single()
            .ok_or("invalid test time")?;
        let mut spec = RuleSpec::new(
            RuleName::new("https")?,
            direction,
            TransportProtocol::Tcp,
            Some(network.parse()?),
            Some(PortRange::single(443)?),
            Some(InterfaceName::new("eth0")?),
            RuleOrigin::Manual,
            true,
        )?;
        if application {
            spec.application = Some(ApplicationSelector::new(
                Some(ApplicationPath::new("/usr/bin/curl")?),
                Some(ExecutableFileId {
                    device: 1,
                    inode: 2,
                    size: 3,
                    ctime_seconds: 4,
                    ctime_nanoseconds: 5,
                }),
                None,
                None,
                None,
            )?);
        }
        state.create_rule_at(uuid::Uuid::new_v4(), spec, now)?;
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
        state.create_rule_at(uuid::Uuid::new_v4(), spec, now)?;
        Ok(())
    }

    #[test]
    fn block_all_has_only_terminal_drop_paths() -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        add_rule(&mut state, Direction::Outbound, "203.0.113.0/24", false)?;
        let policy = IptablesCompiler::compile(&state.snapshot())?;
        for script in [policy.ipv4(), policy.ipv6()] {
            assert!(script.starts_with("*mangle\n-F OPENSHIELD_MARK\n"));
            assert!(script.contains("COMMIT\n*filter\n-F OPENSHIELD_IN\n"));
            assert!(script.ends_with("COMMIT\n"));
            assert!(!script.contains("-j ACCEPT"));
            assert!(!script.contains("-j NFQUEUE"));
            assert!(!script.contains("-F INPUT"));
            assert!(!script.contains("-P INPUT"));
        }
        Ok(())
    }

    #[test]
    fn learning_uses_non_bypass_nfqueue_and_generation_mark() -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        state.set_mode(Mode::Learning)?;
        let snapshot = state.snapshot();
        let policy = IptablesCompiler::compile(&snapshot)?;
        let flow = application_flow_mark(snapshot.flow_generation);
        for script in [policy.ipv4(), policy.ipv6()] {
            assert!(script.contains("-j NFQUEUE --queue-num 1337"));
            assert!(!script.contains("queue-bypass"));
            assert!(script.contains(&format!("-j CONNMARK --set-xmark 0x{flow:08x}/0x7fffffff")));
            assert!(script.contains(&format!("-m connmark --mark 0x{flow:08x}/0x7fffffff")));
            assert!(!script.contains("CONNMARK --set-xmark 0x00000000/0xffffffff"));
            assert!(script.contains("openshield:accepted_out+learned_out"));
            assert!(script.contains(
                "-m mark ! --mark 0x00000000/0xc0000000 -j MARK --set-xmark 0x00000000/0xc0000000"
            ));
            let handoff = script
                .find("-m mark --mark 0xc0000000/0xc0000000 -g OPENSHIELD_APP_TCP")
                .ok_or("missing repeated-filter TCP handoff")?;
            let queue = script
                .find("-j NFQUEUE --queue-num 1337")
                .ok_or("missing application queue")?;
            assert!(handoff < queue);
            assert!(!script.contains("-m mark --mark 0x80000000/0xc0000000 -g OPENSHIELD_APP_TCP"));
        }
        Ok(())
    }

    #[test]
    fn allowed_packets_return_to_the_calling_firewall() -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        state.set_mode(Mode::Learning)?;
        add_rule(&mut state, Direction::Outbound, "203.0.113.0/24", false)?;
        let policy = IptablesCompiler::compile(&state.snapshot())?;

        for script in [policy.ipv4(), policy.ipv6()] {
            assert!(!script.contains("-j ACCEPT"));
            assert!(script.contains("openshield:accepted_out -j RETURN"));
            assert!(script.contains(&format!("-g {IPTABLES_APPLICATION_TCP_CHAIN}")));
            assert!(script.contains(&format!("-g {IPTABLES_APPLICATION_PACKET_CHAIN}")));
            assert!(script.contains("openshield:accepted_out+learned_out -j RETURN"));
        }
        Ok(())
    }

    #[test]
    fn non_tcp_application_replies_use_an_explicit_allowlist_and_masked_generation()
    -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        state.set_mode(Mode::Learning)?;
        add_udp_rule(&mut state, Direction::Outbound, "192.0.2.53/32")?;
        let snapshot = state.snapshot();
        let flow = application_flow_mark(snapshot.flow_generation);
        let policy = IptablesCompiler::compile(&snapshot)?;

        for (script, icmp, other_icmp) in [
            (policy.ipv4(), "icmp", "ipv6-icmp"),
            (policy.ipv6(), "ipv6-icmp", "icmp"),
        ] {
            for protocol in ["tcp", "udp", icmp] {
                assert!(script.contains(&format!(
                    "-A OPENSHIELD_IN -p {protocol} -m conntrack --ctstate ESTABLISHED --ctdir REPLY -m connmark --mark 0x{flow:08x}/0x7fffffff"
                )));
            }
            assert!(!script.contains(&format!("-A OPENSHIELD_IN -p {other_icmp}")));

            for protocol in ["udp", icmp] {
                assert!(script.contains(&format!(
                    "-A OPENSHIELD_OUT -p {protocol} -m conntrack --ctdir ORIGINAL -j CONNMARK --set-xmark 0x00000000/0x7fffffff"
                )));
                assert!(script.contains(&format!(
                    "-A OPENSHIELD_OUT -p {protocol} -m mark --mark 0xc0000000/0xc0000000 -g OPENSHIELD_APP_PKT"
                )));
            }
            assert!(script.contains(&format!(
                "-A OPENSHIELD_APP_PKT -j CONNMARK --set-xmark 0x{flow:08x}/0x7fffffff"
            )));
            assert!(!script.contains(
                "-A OPENSHIELD_OUT -p udp -m conntrack --ctstate ESTABLISHED --ctdir ORIGINAL"
            ));
            assert!(!script.contains(
                "-A OPENSHIELD_OUT -m mark --mark 0xc0000000/0xc0000000 -g OPENSHIELD_APP_PKT"
            ));
            assert!(!script.contains("CONNMARK --set-xmark 0x00000000/0xffffffff"));

            let reset = script
                .find("-A OPENSHIELD_OUT -p udp -m conntrack --ctdir ORIGINAL -j CONNMARK --set-xmark 0x00000000/0x7fffffff")
                .ok_or("missing UDP connmark reset")?;
            let direct = script
                .find("-A OPENSHIELD_OUT -d 192.0.2.53/32 -o eth0 -p udp --dport 53")
                .unwrap_or(usize::MAX);
            let queue = script
                .find("-j NFQUEUE --queue-num 1337")
                .ok_or("missing application queue")?;
            assert!(reset < direct);
            assert!(reset < queue);
        }
        Ok(())
    }

    #[test]
    fn non_block_modes_leave_forwarding_to_the_existing_firewall() -> Result<(), Box<dyn Error>> {
        for mode in [Mode::Learning, Mode::Enforcing] {
            let mut state = State::new();
            state.set_mode(mode)?;
            let policy = IptablesCompiler::compile(&state.snapshot())?;
            for script in [policy.ipv4(), policy.ipv6()] {
                assert!(script.contains("-A OPENSHIELD_FWD -j RETURN"));
                assert!(!script.contains(
                    "-A OPENSHIELD_FWD -m comment --comment openshield:dropped_out -j DROP"
                ));
            }
        }
        Ok(())
    }

    #[test]
    fn family_specific_rules_are_not_cross_compiled() -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        add_rule(&mut state, Direction::Inbound, "2001:db8::/32", false)?;
        let policy = IptablesCompiler::compile(&state.snapshot())?;
        assert!(!policy.ipv4().contains("2001:db8"));
        assert!(policy.ipv6().contains("-s 2001:db8::/32"));
        assert!(policy.ipv6().contains("--dport 443"));
        assert!(policy.ipv6().contains("--sport 443"));
        Ok(())
    }

    #[test]
    fn application_rule_is_queued_instead_of_rendered_as_direct_allow() -> Result<(), Box<dyn Error>>
    {
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        add_rule(&mut state, Direction::Outbound, "203.0.113.7/32", true)?;
        let policy = IptablesCompiler::compile(&state.snapshot())?;
        assert!(policy.ipv4().contains("-j NFQUEUE --queue-num 1337"));
        assert!(!policy.ipv4().contains("-d 203.0.113.7/32"));
        Ok(())
    }

    #[test]
    fn output_is_deterministic_across_snapshot_order() -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        add_rule(&mut state, Direction::Outbound, "203.0.113.0/24", false)?;
        add_rule(&mut state, Direction::Outbound, "198.51.100.0/24", false)?;
        let mut reversed = state.snapshot();
        reversed.rules.reverse();
        assert_eq!(
            IptablesCompiler::compile(&state.snapshot())?,
            IptablesCompiler::compile(&reversed)?
        );
        Ok(())
    }
}
