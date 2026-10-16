//! Mobile whole-domain route policy and its public configuration DTO.
//!
//! This module owns member projection and admission, the final exported table
//! and the content identity. The Factory reexports [`MobileTunConfig`]; the
//! accepted member data and local withdrawal objects are internal to the route
//! domain and never serialized to a host.

#[cfg(any(mobile, test))]
use std::collections::BTreeSet;

#[cfg(any(mobile, test))]
use cidr::IpCidr;

#[cfg(mobile)]
use crate::instance::shared_virtual_nic::SharedVirtualNicMember;
#[cfg(any(mobile, test))]
use crate::instance::shared_virtual_nic::{
    SharedIfConfig, SharedIfConfigClaims, SharedIpv4Route, SharedIpv6Route,
};

/// The complete route configuration the external VPN owner should apply.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct MobileTunConfig {
    /// Identifies the exact routes/addresses and instance runs installed by the VPN owner.
    pub snapshot_id: uuid::Uuid,
    pub instance_ids: Vec<uuid::Uuid>,
    pub addresses: Vec<String>,
    pub routes: Vec<String>,
    pub dns: Option<String>,
    pub rejected: Vec<MobileTunMemberError>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MobileTunMemberError {
    pub instance_id: uuid::Uuid,
    pub error: String,
}

/// One instance's contribution before and after whole-domain admission.
#[cfg(any(mobile, test))]
#[derive(Clone)]
pub(crate) struct MobileTunMember {
    pub(crate) instance_id: uuid::Uuid,
    pub(crate) run: uuid::Uuid,
    pub(crate) claims: SharedIfConfigClaims,
    /// The current attached claims, only as a stable-selection hint.
    pub(crate) current_claims: Option<SharedIfConfigClaims>,
    pub(crate) dns: bool,
    /// The prefixes this accepted member must install for this plan.
    pub(crate) installed_prefixes: BTreeSet<IpCidr>,
}

#[cfg(any(mobile, test))]
impl MobileTunMember {
    pub(crate) fn new(
        instance_id: uuid::Uuid,
        run: uuid::Uuid,
        claims: SharedIfConfigClaims,
        current_claims: Option<SharedIfConfigClaims>,
        dns: bool,
    ) -> Self {
        Self {
            instance_id,
            run,
            claims,
            current_claims,
            dns,
            installed_prefixes: BTreeSet::new(),
        }
    }
}

/// The canonical empty exported table used when no route domain exists.
#[cfg(mobile)]
pub(crate) fn empty_mobile_tun_config() -> MobileTunConfig {
    config_for_members(&[], Vec::new())
}

/// The complete result of one policy pass.
#[cfg(mobile)]
pub(crate) struct MobilePlan {
    pub(crate) config: MobileTunConfig,
    /// Accepted members with the claims and prefixes this plan decided.
    pub(crate) members: Vec<MobileTunMember>,
    /// Currently bound members that the complete result no longer accepts.
    pub(crate) withdraw: Vec<MobileWithdraw>,
}

/// A currently bound member that must lose its local contributions.
#[cfg(mobile)]
#[derive(Clone)]
pub(crate) struct MobileWithdraw {
    pub(crate) run: uuid::Uuid,
    pub(crate) registration: uuid::Uuid,
    pub(crate) member: SharedVirtualNicMember,
}

#[cfg(any(mobile, test))]
pub(crate) fn magic_dns_route() -> SharedIpv4Route {
    SharedIpv4Route::new(
        crate::instance::dns_server::MAGIC_DNS_FAKE_IP
            .parse()
            .unwrap(),
        32,
        Some(1),
    )
}

#[cfg(any(mobile, test))]
pub(crate) fn magic_dns_prefix() -> IpCidr {
    IpCidr::V4(
        cidr::Ipv4Cidr::new(
            crate::instance::dns_server::MAGIC_DNS_FAKE_IP
                .parse()
                .expect("Magic DNS fake IP is valid"),
            32,
        )
        .expect("Magic DNS fake IP is a /32"),
    )
}

/// Prefixes contributed by one member to the exported VPN configuration.
#[cfg(any(mobile, test))]
pub(crate) fn member_prefixes(member: &MobileTunMember) -> BTreeSet<IpCidr> {
    let mut prefixes = BTreeSet::new();
    for address in &member.claims.ipv4_addresses {
        prefixes.insert(IpCidr::V4(address.network()));
    }
    for address in &member.claims.ipv6_addresses {
        prefixes.insert(IpCidr::V6(address.network()));
    }
    for route in &member.claims.ipv4_routes {
        if let Ok(route) = cidr::Ipv4Inet::new(route.address, route.prefix) {
            prefixes.insert(IpCidr::V4(route.network()));
        }
    }
    for route in &member.claims.ipv6_routes {
        if let Ok(route) = cidr::Ipv6Inet::new(route.address, route.prefix) {
            prefixes.insert(IpCidr::V6(route.network()));
        }
    }
    if member.dns {
        prefixes.insert(magic_dns_prefix());
    }
    prefixes
}

/// Build the policy claims for one instance from its current facts.
///
/// This is the only place that turns runtime facts into a member's route
/// meaning: the running addresses, the public IPv6 address and its egress
/// default route, and the current declarations under the current policy.
/// Address network prefixes and the DNS fake-IP are projected later by
/// [`member_prefixes`]; the Factory adds none of them.
#[cfg(any(mobile, test))]
pub(crate) fn claims_from_facts(
    ipv4: Option<cidr::Ipv4Inet>,
    ipv6: Option<cidr::Ipv6Inet>,
    public_address: Option<cidr::Ipv6Inet>,
    declarations: impl IntoIterator<Item = IpCidr>,
) -> SharedIfConfigClaims {
    let mut claims = SharedIfConfigClaims::default();
    claims.ipv4_addresses.extend(ipv4);
    claims.ipv6_addresses.extend(ipv6);
    if let Some(public_address) = public_address {
        claims.ipv6_addresses.insert(public_address);
        // The public-address lease also owns the IPv6 egress default route.
        claims.ipv6_routes.insert(SharedIpv6Route::new(
            std::net::Ipv6Addr::UNSPECIFIED,
            0,
            None,
        ));
    }
    for prefix in declarations {
        match prefix {
            IpCidr::V4(prefix) => {
                claims.ipv4_routes.insert(SharedIpv4Route::new(
                    prefix.first_address(),
                    prefix.network_length(),
                    None,
                ));
            }
            IpCidr::V6(prefix) => {
                claims.ipv6_routes.insert(SharedIpv6Route::new(
                    prefix.first_address(),
                    prefix.network_length(),
                    None,
                ));
            }
        }
    }
    claims
}

/// Only members whose instance identity the host selected take part.
///
/// `None` means every live member of this route domain; `Some(empty)` is the
/// explicit empty range; `Some(ids)` is filtered before any admission. An id
/// that is not a live member of this domain is rejected here, so a request for
/// another namespace can never be answered by merging another table.
#[cfg(any(mobile, test))]
pub(crate) fn filter_scope(
    members: Vec<MobileTunMember>,
    scope: Option<&BTreeSet<uuid::Uuid>>,
) -> (Vec<MobileTunMember>, Vec<MobileTunMemberError>) {
    let Some(scope) = scope else {
        return (members, Vec::new());
    };
    let present: BTreeSet<uuid::Uuid> = members.iter().map(|member| member.instance_id).collect();
    let rejected = scope
        .iter()
        .filter(|instance_id| !present.contains(instance_id))
        .map(|instance_id| MobileTunMemberError {
            instance_id: *instance_id,
            error: "instance is not participating in this route domain".to_owned(),
        })
        .collect::<Vec<_>>();
    let selected = members
        .into_iter()
        .filter(|member| scope.contains(&member.instance_id))
        .collect();
    (selected, rejected)
}

/// Stable selection and whole-domain admission.
///
/// An unchanged attached member keeps its place ahead of a new or reconfigured
/// member. The comparison is over normalized address and route meaning only:
/// this plan does not export MTU or route costs, so those representations must
/// not reorder members. The current claims are only an ordering hint; the
/// complete target below is never taken from them.
#[cfg(any(mobile, test))]
pub(crate) fn select_members(
    mut members: Vec<MobileTunMember>,
    mut rejected: Vec<MobileTunMemberError>,
) -> (Vec<MobileTunMember>, Vec<MobileTunMemberError>) {
    members.sort_by_key(|member| {
        !member
            .current_claims
            .as_ref()
            .is_some_and(|current| comparable_claims(current) == comparable_claims(&member.claims))
    });
    let mut ifcfg = SharedIfConfig::default();
    let mut accepted = Vec::new();
    for mut member in members {
        let claims = execution_claims(&member);
        if let Err(error) = ifcfg.ensure_disjoint(member.instance_id, &claims) {
            rejected.push(MobileTunMemberError {
                instance_id: member.instance_id,
                error: error.to_string(),
            });
            continue;
        }
        ifcfg.apply_member_claims(member.instance_id, claims.clone());
        member.claims = claims;
        member.installed_prefixes = member_prefixes(&member);
        accepted.push(member);
    }
    (accepted, rejected)
}

/// The complete claims one accepted member's execution adapter receives.
#[cfg(any(mobile, test))]
fn execution_claims(member: &MobileTunMember) -> SharedIfConfigClaims {
    let mut claims = member.claims.clone();
    if member.dns {
        claims.ipv4_routes.insert(magic_dns_route());
    }
    claims
}

/// Run the one policy entry and build the complete exported configuration.
#[cfg(any(mobile, test))]
pub(crate) fn select_and_project(
    members: Vec<MobileTunMember>,
    rejected: Vec<MobileTunMemberError>,
) -> (Vec<MobileTunMember>, MobileTunConfig) {
    let (members, rejected) = select_members(members, rejected);
    let config = config_for_members(&members, rejected);
    (members, config)
}

#[cfg(any(mobile, test))]
pub(crate) fn config_for_members(
    members: &[MobileTunMember],
    rejected: Vec<MobileTunMemberError>,
) -> MobileTunConfig {
    let mut config = MobileTunConfig {
        rejected,
        ..Default::default()
    };
    let mut addresses = BTreeSet::new();
    let mut routes = BTreeSet::new();
    // Record each member's own contribution so ownership changes alter the
    // snapshot even when the union of addresses and routes does not.
    let mut contributions = Vec::new();
    for member in members {
        config.instance_ids.push(member.instance_id);
        let mut member_addresses = BTreeSet::new();
        for address in &member.claims.ipv4_addresses {
            let address = format!("{address:#}");
            addresses.insert(address.clone());
            member_addresses.insert(address);
        }
        for address in &member.claims.ipv6_addresses {
            let address = format!("{address:#}");
            addresses.insert(address.clone());
            member_addresses.insert(address);
        }
        let prefixes = member_prefixes(member);
        routes.extend(prefixes.iter().map(|prefix| format!("{prefix:#}")));
        if member.dns {
            config.dns = Some(crate::instance::dns_server::MAGIC_DNS_FAKE_IP.to_owned());
        }
        contributions.push((
            member.instance_id,
            member.run,
            member_addresses.into_iter().collect::<Vec<_>>(),
            prefixes,
            member.dns,
        ));
    }
    config.instance_ids.sort();
    config.addresses = addresses.into_iter().collect();
    config.routes = routes.into_iter().collect();
    contributions.sort();
    // Hash normalized content rather than keeping an unbounded server-side
    // snapshot cache. Identical declarations keep the same acknowledgement ID,
    // while a changed run or ownership changes it even when the union is equal.
    config.snapshot_id = uuid::Uuid::new_v5(
        &uuid::Uuid::NAMESPACE_OID,
        format!(
            "{:?}",
            (
                &config.instance_ids,
                &config.addresses,
                &config.routes,
                &config.dns,
                contributions
            )
        )
        .as_bytes(),
    );
    config
}

/// The normalized meaning of claims used only for stable-selection ordering.
///
/// MTU and route costs are not exported by this plan, and the Magic DNS route
/// is a policy exception that may or may not already be present in the current
/// claims. Routes are compared by network, not by their stored host bits.
#[cfg(any(mobile, test))]
#[derive(Debug, PartialEq, Eq)]
struct ComparableClaims {
    ipv4_addresses: BTreeSet<cidr::Ipv4Inet>,
    ipv6_addresses: BTreeSet<cidr::Ipv6Inet>,
    ipv4_routes: BTreeSet<cidr::Ipv4Cidr>,
    ipv6_routes: BTreeSet<cidr::Ipv6Cidr>,
}

#[cfg(any(mobile, test))]
fn comparable_claims(claims: &SharedIfConfigClaims) -> ComparableClaims {
    let magic_dns = magic_dns_prefix();
    let magic_dns = match magic_dns {
        IpCidr::V4(prefix) => Some(prefix),
        IpCidr::V6(_) => None,
    };
    ComparableClaims {
        ipv4_addresses: claims.ipv4_addresses.clone(),
        ipv6_addresses: claims.ipv6_addresses.clone(),
        ipv4_routes: claims
            .ipv4_routes
            .iter()
            .filter_map(|route| cidr::Ipv4Inet::new(route.address, route.prefix).ok())
            .map(|route| route.network())
            .filter(|route| Some(*route) != magic_dns)
            .collect(),
        ipv6_routes: claims
            .ipv6_routes
            .iter()
            .filter_map(|route| cidr::Ipv6Inet::new(route.address, route.prefix).ok())
            .map(|route| route.network())
            .collect(),
    }
}


