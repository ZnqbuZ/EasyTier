//! Pure demand projection and resolution functions.
//!
//! Holds the canonical, single-location business rules for projecting inputs
//! (OSPF peer routes, manual configuration, public IPv6, Magic DNS, interface prefixes)
//! into normalized `RouteDemand` sets.

use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr},
};

use cidr::{IpCidr, Ipv4Cidr, Ipv4Inet, Ipv6Cidr, Ipv6Inet};

use super::model::{LogicalDependency, LogicalEgress, RouteDemand, RoutePurpose};

/// Resolves the effective set of IPv4 proxy CIDRs from peer routes and manual configuration.
///
/// Implements the frozen 3-state behavior:
/// - `None`: Automatic mode. Adopts all valid peer proxy CIDRs.
/// - `Some([])`: Disabled mode. Suppresses peer proxy routes, producing an empty set.
/// - `Some([...])`: Static override mode. Adopts user specified CIDRs, overriding peer proxy routes.
pub fn resolve_proxy_cidrs(
    peer_routes: &BTreeSet<Ipv4Cidr>,
    manual_routes: Option<&BTreeSet<Ipv4Cidr>>,
) -> BTreeSet<Ipv4Cidr> {
    match manual_routes {
        None => peer_routes.clone(),
        Some(manual) => manual.clone(),
    }
}

/// Projects resolved IPv4 proxy CIDRs into normalized `RouteDemand` entries.
pub fn project_ipv4_proxy_demands(
    cidrs: &BTreeSet<Ipv4Cidr>,
    is_manual: bool,
    logical_egress: LogicalEgress,
) -> BTreeSet<RouteDemand> {
    let purpose = if is_manual {
        RoutePurpose::ManualOverrideProxy
    } else {
        RoutePurpose::PeerProxy
    };
    cidrs
        .iter()
        .map(|cidr| {
            RouteDemand::new(
                IpCidr::V4(*cidr),
                purpose,
                logical_egress,
                LogicalDependency::None,
            )
        })
        .collect()
}

/// Projects Public IPv6 default route egress (`::/0`).
///
/// Attaches the IPv6 lease address and version as a typed logical dependency,
/// ensuring that a lease change (A -> B) is recognized as a demand update even
/// though the destination CIDR remains `::/0`.
pub fn project_public_ipv6_egress_demand(
    lease: Option<Ipv6Inet>,
    lease_version: u64,
    logical_egress: LogicalEgress,
) -> BTreeSet<RouteDemand> {
    let mut demands = BTreeSet::new();
    if let Some(lease_inet) = lease {
        let default_v6 = IpCidr::V6(Ipv6Cidr::new(std::net::Ipv6Addr::UNSPECIFIED, 0).unwrap());
        demands.insert(RouteDemand::new(
            default_v6,
            RoutePurpose::PublicIpv6Default,
            logical_egress,
            LogicalDependency::Ipv6Lease {
                address: IpAddr::V6(lease_inet.address()),
                lease_version,
            },
        ));
    }
    demands
}

/// Projects remote peer Public IPv6 routes into demands.
pub fn project_public_ipv6_peer_demands(
    peer_routes: &BTreeSet<Ipv6Inet>,
    logical_egress: LogicalEgress,
) -> BTreeSet<RouteDemand> {
    peer_routes
        .iter()
        .map(|inet| {
            RouteDemand::new(
                IpCidr::V6(Ipv6Cidr::new(inet.first_address(), inet.network_length()).unwrap()),
                RoutePurpose::PublicIpv6Peer,
                logical_egress,
                LogicalDependency::None,
            )
        })
        .collect()
}

/// Projects a Magic DNS fake IP demand.
///
/// Only generates a `/32` demand if the synthetic IP does not fall within
/// the virtual interface's direct subnet.
pub fn project_magic_dns_demand(
    fake_ip: Ipv4Addr,
    tun_inet: Option<Ipv4Inet>,
    logical_egress: LogicalEgress,
) -> BTreeSet<RouteDemand> {
    let mut demands = BTreeSet::new();
    let inside_tun = tun_inet.map(|inet| inet.contains(&fake_ip)).unwrap_or(false);
    if !inside_tun {
        demands.insert(RouteDemand::new(
            IpCidr::V4(Ipv4Cidr::new(fake_ip, 32).unwrap()),
            RoutePurpose::MagicDnsFakeIp,
            logical_egress,
            LogicalDependency::None,
        ));
    }
    demands
}

/// Projects an explicit interface subnet prefix demand (for macOS / FreeBSD).
pub fn project_interface_subnet_demand(
    network_cidr: IpCidr,
    address_fact_version: u64,
    logical_egress: LogicalEgress,
) -> RouteDemand {
    RouteDemand::new(
        network_cidr,
        RoutePurpose::InterfaceSubnet,
        logical_egress,
        LogicalDependency::AddressFactVersion(address_fact_version),
    )
}
