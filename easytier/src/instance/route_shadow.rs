//! Read-only shadow verifier and diagnostic bridge for route demands.
//!
//! Provides read-only observation comparing versioned route demands against legacy system
//! router expectations without performing any host system routing writes, system event
//! dispatches, or interface reconfigurations.

use std::{
    collections::BTreeSet,
    net::Ipv4Addr,
    sync::Arc,
};

use cidr::{IpCidr, Ipv4Cidr, Ipv4Inet};
use easytier_core::{
    instance::CoreRouteDemands,
    route_demand::model::{
        RegistrySnapshot, RouteDemand, RoutePurpose, SourceId, SourceKind, SourceStatus,
    },
};
use serde::{Deserialize, Serialize};

/// Categorization of shadow verification observations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShadowDifferenceKind {
    /// Both new versioned demands and legacy expectations match under verified steady state.
    ComparableMatch,
    /// Unaligned demand contents detected under verified steady state.
    ComparableMismatch,
    /// Legacy 1-second timer or asynchronous event loop has not yet aligned versions.
    PendingAlignment,
    /// Known frozen backward-compatibility difference (e.g. mobile union vs override, DNS fake IP).
    ExpectedCompatibilityDifference { reason: String },
    /// Source facts are unavailable; not considered matching just because both are empty.
    SourceUnavailable { reason: String },
}

/// A structured shadow observation record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowObservation {
    pub source_id: Option<SourceId>,
    pub source_kind: SourceKind,
    pub purpose: Option<RoutePurpose>,
    pub sample_revision: u64,
    pub diff_kind: ShadowDifferenceKind,
    pub new_demands: Vec<RouteDemand>,
    pub legacy_expected: Vec<IpCidr>,
    pub details: String,
}

/// Read-only shadow verifier.
///
/// Guaranteed to possess ONLY read access to route demands.
/// It contains NO references to `IfConfiger`, kernel routing tables, or mutation channels.
pub struct RouteShadowVerifier {
    demands: CoreRouteDemands,
}

impl RouteShadowVerifier {
    /// Creates a new read-only shadow verifier.
    pub fn new(demands: CoreRouteDemands) -> Self {
        Self { demands }
    }

    /// Obtains the current snapshot from the underlying demand reader.
    pub fn snapshot(&self) -> Arc<RegistrySnapshot> {
        self.demands.current()
    }

    /// Verifies Core Proxy CIDR demands against legacy expectations.
    pub fn verify_proxy_cidrs(
        &self,
        legacy_cidrs: &BTreeSet<Ipv4Cidr>,
        is_steady_state: bool,
    ) -> Vec<ShadowObservation> {
        let snap = self.snapshot();
        let source_entry = snap
            .sources
            .values()
            .find(|s| s.source_id.kind == SourceKind::ProxyCidr);

        let Some(source) = source_entry else {
            return vec![ShadowObservation {
                source_id: None,
                source_kind: SourceKind::ProxyCidr,
                purpose: Some(RoutePurpose::PeerProxy),
                sample_revision: snap.revision.0,
                diff_kind: ShadowDifferenceKind::SourceUnavailable {
                    reason: "proxy cidr source not registered in demand registry".to_string(),
                },
                new_demands: Vec::new(),
                legacy_expected: legacy_cidrs.iter().copied().map(IpCidr::V4).collect(),
                details: "proxy cidr source missing".to_string(),
            }];
        };

        if let SourceStatus::Unavailable { reason } = &source.status {
            return vec![ShadowObservation {
                source_id: Some(source.source_id),
                source_kind: SourceKind::ProxyCidr,
                purpose: Some(RoutePurpose::PeerProxy),
                sample_revision: snap.revision.0,
                diff_kind: ShadowDifferenceKind::SourceUnavailable {
                    reason: reason.clone(),
                },
                new_demands: Vec::new(),
                legacy_expected: legacy_cidrs.iter().copied().map(IpCidr::V4).collect(),
                details: format!("source is unavailable: {reason}"),
            }];
        }

        if !is_steady_state {
            return vec![ShadowObservation {
                source_id: Some(source.source_id),
                source_kind: SourceKind::ProxyCidr,
                purpose: Some(RoutePurpose::PeerProxy),
                sample_revision: snap.revision.0,
                diff_kind: ShadowDifferenceKind::PendingAlignment,
                new_demands: Vec::new(),
                legacy_expected: legacy_cidrs.iter().copied().map(IpCidr::V4).collect(),
                details: "awaiting steady state alignment".to_string(),
            }];
        }

        let new_demands: Vec<RouteDemand> = source
            .latest_snapshot
            .as_ref()
            .map(|s| s.demands.iter().cloned().collect())
            .unwrap_or_default();

        let new_destinations: BTreeSet<Ipv4Cidr> = new_demands
            .iter()
            .filter_map(|d| match d.destination {
                IpCidr::V4(v4) => Some(v4),
                _ => None,
            })
            .collect();

        let legacy_expected_cidrs: Vec<IpCidr> =
            legacy_cidrs.iter().copied().map(IpCidr::V4).collect();

        let diff_kind = if &new_destinations == legacy_cidrs {
            ShadowDifferenceKind::ComparableMatch
        } else {
            ShadowDifferenceKind::ComparableMismatch
        };

        vec![ShadowObservation {
            source_id: Some(source.source_id),
            source_kind: SourceKind::ProxyCidr,
            purpose: new_demands.first().map(|d| d.purpose),
            sample_revision: snap.revision.0,
            diff_kind,
            new_demands,
            legacy_expected: legacy_expected_cidrs,
            details: format!(
                "new count: {}, legacy count: {}",
                new_destinations.len(),
                legacy_cidrs.len()
            ),
        }]
    }

    /// Verifies Host Magic DNS demands against legacy expectations.
    pub fn verify_magic_dns(
        &self,
        fake_ip: Ipv4Addr,
        tun_inet: Option<Ipv4Inet>,
        is_magic_dns_enabled: bool,
    ) -> Vec<ShadowObservation> {
        let snap = self.snapshot();
        let source_entry = snap
            .sources
            .values()
            .find(|s| s.source_id.kind == SourceKind::MagicDns);

        let Some(source) = source_entry else {
            return vec![ShadowObservation {
                source_id: None,
                source_kind: SourceKind::MagicDns,
                purpose: Some(RoutePurpose::MagicDnsFakeIp),
                sample_revision: snap.revision.0,
                diff_kind: ShadowDifferenceKind::SourceUnavailable {
                    reason: "magic dns source not registered".to_string(),
                },
                new_demands: Vec::new(),
                legacy_expected: Vec::new(),
                details: "magic dns source missing".to_string(),
            }];
        };

        let new_demands: Vec<RouteDemand> = source
            .latest_snapshot
            .as_ref()
            .map(|s| s.demands.iter().cloned().collect())
            .unwrap_or_default();

        let is_inside_subnet = tun_inet
            .map(|inet| inet.contains(&fake_ip))
            .unwrap_or(false);

        let (legacy_expected, diff_kind) = if !is_magic_dns_enabled {
            (Vec::new(), ShadowDifferenceKind::ComparableMatch)
        } else if is_inside_subnet {
            // In legacy code, if fake_ip falls inside tun_inet, no route was added.
            (
                Vec::new(),
                ShadowDifferenceKind::ExpectedCompatibilityDifference {
                    reason: "fake ip falls inside tun interface subnet; no host route needed"
                        .to_string(),
                },
            )
        } else {
            let expected_cidr = IpCidr::V4(Ipv4Cidr::new(fake_ip, 32).unwrap());
            let matches = new_demands.iter().any(|d| d.destination == expected_cidr);
            (
                vec![expected_cidr],
                if matches {
                    ShadowDifferenceKind::ComparableMatch
                } else {
                    ShadowDifferenceKind::ComparableMismatch
                },
            )
        };

        vec![ShadowObservation {
            source_id: Some(source.source_id),
            source_kind: SourceKind::MagicDns,
            purpose: Some(RoutePurpose::MagicDnsFakeIp),
            sample_revision: snap.revision.0,
            diff_kind,
            new_demands,
            legacy_expected,
            details: format!("magic dns enabled: {is_magic_dns_enabled}, inside subnet: {is_inside_subnet}"),
        }]
    }

    /// Verifies Host Interface Prefix demands against platform expectations.
    pub fn verify_interface_prefix(
        &self,
        tun_inet: Option<Ipv4Inet>,
        is_macos_or_freebsd: bool,
    ) -> Vec<ShadowObservation> {
        let snap = self.snapshot();
        let source_entry = snap
            .sources
            .values()
            .find(|s| s.source_id.kind == SourceKind::InterfacePrefix);

        let Some(source) = source_entry else {
            return vec![ShadowObservation {
                source_id: None,
                source_kind: SourceKind::InterfacePrefix,
                purpose: Some(RoutePurpose::InterfaceSubnet),
                sample_revision: snap.revision.0,
                diff_kind: ShadowDifferenceKind::SourceUnavailable {
                    reason: "interface prefix source not registered".to_string(),
                },
                new_demands: Vec::new(),
                legacy_expected: Vec::new(),
                details: "interface prefix source missing".to_string(),
            }];
        };

        let new_demands: Vec<RouteDemand> = source
            .latest_snapshot
            .as_ref()
            .map(|s| s.demands.iter().cloned().collect())
            .unwrap_or_default();

        let (legacy_expected, diff_kind) = if !is_macos_or_freebsd {
            // Linux/Windows: no explicit owned route demand, kernel derives it directly from interface address
            (Vec::new(), ShadowDifferenceKind::ComparableMatch)
        } else if let Some(inet) = tun_inet {
            let expected = IpCidr::V4(Ipv4Cidr::new(inet.first_address(), inet.network_length()).unwrap());
            let matches = new_demands.iter().any(|d| d.destination == expected);
            (
                vec![expected],
                if matches {
                    ShadowDifferenceKind::ComparableMatch
                } else {
                    ShadowDifferenceKind::ComparableMismatch
                },
            )
        } else {
            (Vec::new(), ShadowDifferenceKind::ComparableMatch)
        };

        vec![ShadowObservation {
            source_id: Some(source.source_id),
            source_kind: SourceKind::InterfacePrefix,
            purpose: Some(RoutePurpose::InterfaceSubnet),
            sample_revision: snap.revision.0,
            diff_kind,
            new_demands,
            legacy_expected,
            details: format!("is_macos_or_freebsd: {is_macos_or_freebsd}"),
        }]
    }

    /// Evaluates mobile VPN union configuration against Step 2 override demands.
    ///
    /// The mobile GUI implementation (`mobile_vpn.ts`) currently computes a union of routes.
    /// In Step 2, this difference is explicitly recognized as an [`ShadowDifferenceKind::ExpectedCompatibilityDifference`].
    pub fn evaluate_mobile_vpn_compatibility(
        &self,
        mobile_union_routes: &[IpCidr],
    ) -> ShadowObservation {
        let snap = self.snapshot();
        let all_demands: Vec<RouteDemand> = snap
            .sources
            .values()
            .filter_map(|s| s.latest_snapshot.as_ref())
            .flat_map(|s| s.demands.iter().cloned())
            .collect();

        ShadowObservation {
            source_id: None,
            source_kind: SourceKind::ProxyCidr,
            purpose: None,
            sample_revision: snap.revision.0,
            diff_kind: ShadowDifferenceKind::ExpectedCompatibilityDifference {
                reason: "mobile VPN union vs instance override policy frozen for step 6 transition".to_string(),
            },
            new_demands: all_demands,
            legacy_expected: mobile_union_routes.to_vec(),
            details: format!("mobile union has {} routes", mobile_union_routes.len()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use easytier_core::instance::HostRouteDemandContext;
    use easytier_core::route_demand::model::{InstanceRuntimeId, LogicalEgress, ProjectionBasis};
    use easytier_core::route_demand::projection::project_ipv4_proxy_demands;
    use easytier_core::route_demand::registry::InstanceOwner;
    use crate::instance::route_demand_sources::HostRouteDemandSources;

    #[test]
    fn test_route_shadow_verifier_classification() {
        let instance_id = InstanceRuntimeId::random();
        let owner = InstanceOwner::new(instance_id);
        let demands = CoreRouteDemands::new(owner.reader());
        let host_ctx = HostRouteDemandContext::new(demands.clone(), owner.clone());

        let verifier = RouteShadowVerifier::new(demands.clone());

        // 1. Initial state without registered proxy source -> SourceUnavailable
        let obs = verifier.verify_proxy_cidrs(&BTreeSet::new(), true);
        assert!(matches!(obs[0].diff_kind, ShadowDifferenceKind::SourceUnavailable { .. }));

        // 2. Register proxy source
        let publ = owner.register(SourceKind::ProxyCidr, "core.proxy_cidr").unwrap();
        let egress = LogicalEgress::new(instance_id);

        // Not steady state -> PendingAlignment
        let obs_pending = verifier.verify_proxy_cidrs(&BTreeSet::new(), false);
        assert_eq!(obs_pending[0].diff_kind, ShadowDifferenceKind::PendingAlignment);

        // Publish [10.0.0.0/24]
        let mut cidrs = BTreeSet::new();
        cidrs.insert("10.0.0.0/24".parse().unwrap());
        let d = project_ipv4_proxy_demands(&cidrs, false, egress);
        publ.publish(d, ProjectionBasis::default()).unwrap();

        // Compare with same expected set -> ComparableMatch
        let obs_match = verifier.verify_proxy_cidrs(&cidrs, true);
        assert_eq!(obs_match[0].diff_kind, ShadowDifferenceKind::ComparableMatch);

        // Compare with different expected set -> ComparableMismatch
        let mut wrong_cidrs = BTreeSet::new();
        wrong_cidrs.insert("192.168.1.0/24".parse().unwrap());
        let obs_mismatch = verifier.verify_proxy_cidrs(&wrong_cidrs, true);
        assert_eq!(obs_mismatch[0].diff_kind, ShadowDifferenceKind::ComparableMismatch);

        // 3. Host sources verification
        let host_sources = HostRouteDemandSources::new_with_explicit_prefix_override(true);
        host_sources.initialize(host_ctx).unwrap();

        let fake_ip = Ipv4Addr::new(100, 100, 100, 101);
        let tun_ip = Ipv4Inet::from_str("10.144.1.1/24").unwrap();
        host_sources
            .update_address_and_dns_facts(Some(tun_ip), None, true, fake_ip)
            .unwrap();

        // Magic DNS match
        let obs_dns = verifier.verify_magic_dns(fake_ip, Some(tun_ip), true);
        assert_eq!(obs_dns[0].diff_kind, ShadowDifferenceKind::ComparableMatch);

        // Interface prefix match on simulated macOS/FreeBSD
        let obs_prefix = verifier.verify_interface_prefix(Some(tun_ip), true);
        assert_eq!(obs_prefix[0].diff_kind, ShadowDifferenceKind::ComparableMatch);

        // 4. Mobile VPN compatibility bridge
        let mobile_routes = vec![IpCidr::V4("10.0.0.0/24".parse().unwrap())];
        let obs_mobile = verifier.evaluate_mobile_vpn_compatibility(&mobile_routes);
        assert!(matches!(
            obs_mobile.diff_kind,
            ShadowDifferenceKind::ExpectedCompatibilityDifference { .. }
        ));
    }
}
