use openshield_core::{ApplicationInterception, Mode};
#[cfg(test)]
use openshield_protocol::{CompatibilityLevel, CompatibilityReason};
use openshield_protocol::{FirewallBackendKind, RuntimeCompatibility};

/// Describes the packet path which the active policy really uses.
///
/// This selector deliberately contains no speculative eBPF tier. A production
/// backend must first attest its identity; test and third-party backends remain
/// unknown even when their policy happens to contain only network rules.
pub(crate) fn select_runtime_compatibility(
    backend: FirewallBackendKind,
    mode: Mode,
    application_interception: ApplicationInterception,
) -> RuntimeCompatibility {
    RuntimeCompatibility::for_policy(backend, mode, application_interception)
}

#[cfg(test)]
const fn compatibility(
    level: CompatibilityLevel,
    reason: CompatibilityReason,
) -> RuntimeCompatibility {
    RuntimeCompatibility { level, reason }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unverified_backend_never_claims_a_runtime_level() {
        for mode in [Mode::BlockAll, Mode::Learning, Mode::Enforcing] {
            for interception in [
                ApplicationInterception::None,
                ApplicationInterception::TcpInitial,
                ApplicationInterception::PerPacket,
            ] {
                assert_eq!(
                    select_runtime_compatibility(FirewallBackendKind::Unknown, mode, interception,),
                    RuntimeCompatibility::default()
                );
            }
        }
    }

    #[test]
    fn block_all_and_network_only_enforcing_are_kernel_native() {
        assert_eq!(
            select_runtime_compatibility(
                FirewallBackendKind::Nftables,
                Mode::BlockAll,
                ApplicationInterception::PerPacket,
            ),
            compatibility(
                CompatibilityLevel::KernelNative,
                CompatibilityReason::BlockAll
            )
        );

        assert_eq!(
            select_runtime_compatibility(
                FirewallBackendKind::Iptables,
                Mode::Enforcing,
                ApplicationInterception::None,
            ),
            compatibility(
                CompatibilityLevel::KernelNative,
                CompatibilityReason::NetworkOnly,
            )
        );
    }

    #[test]
    fn learning_always_uses_nfqueue() {
        assert_eq!(
            select_runtime_compatibility(
                FirewallBackendKind::Nftables,
                Mode::Learning,
                ApplicationInterception::None,
            ),
            compatibility(CompatibilityLevel::Nfqueue, CompatibilityReason::Learning)
        );
    }

    #[test]
    fn tcp_only_application_enforcement_uses_conntrack_hybrid() {
        assert_eq!(
            select_runtime_compatibility(
                FirewallBackendKind::Nftables,
                Mode::Enforcing,
                ApplicationInterception::TcpInitial,
            ),
            compatibility(
                CompatibilityLevel::ConntrackHybrid,
                CompatibilityReason::ApplicationTcp,
            )
        );
    }

    #[test]
    fn per_packet_application_enforcement_uses_nfqueue() {
        assert_eq!(
            select_runtime_compatibility(
                FirewallBackendKind::Nftables,
                Mode::Enforcing,
                ApplicationInterception::PerPacket,
            ),
            compatibility(
                CompatibilityLevel::Nfqueue,
                CompatibilityReason::ApplicationPerPacket,
            )
        );
    }
}
