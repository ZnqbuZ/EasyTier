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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instance::shared_virtual_nic::SharedIpv6Route as TestIpv6Route;

    fn member(id: u128, address: &str) -> MobileTunMember {
        MobileTunMember::new(
            uuid::Uuid::from_u128(id),
            uuid::Uuid::from_u128(id),
            SharedIfConfigClaims {
                ipv4_addresses: BTreeSet::from([address.parse().unwrap()]),
                ..Default::default()
            },
            None,
            false,
        )
    }

    #[test]
    fn snapshot_tracks_installed_content_and_runs_not_rejection_diagnostics() {
        let members = vec![member(1, "10.126.126.1/24")];
        let plain = config_for_members(&members, Vec::new());
        let rejected = config_for_members(
            &members,
            vec![MobileTunMemberError {
                instance_id: uuid::Uuid::from_u128(2),
                error: "overlapping subnet".into(),
            }],
        );
        assert_eq!(plain.snapshot_id, rejected.snapshot_id);
        let mut restarted = members;
        restarted[0].run = uuid::Uuid::from_u128(3);
        assert_ne!(
            plain.snapshot_id,
            config_for_members(&restarted, Vec::new()).snapshot_id
        );
    }

    #[test]
    fn snapshot_tracks_per_member_route_ownership() {
        let mut owner_a = member(1, "10.0.1.1/24");
        owner_a.claims.ipv4_routes.insert(SharedIpv4Route::new(
            "10.0.5.0".parse().unwrap(),
            24,
            None,
        ));
        let (members, rejected) =
            select_members(vec![owner_a, member(2, "10.0.2.1/24")], Vec::new());
        assert!(rejected.is_empty());
        let before = config_for_members(&members, rejected);

        let mut owner_b = member(2, "10.0.2.1/24");
        owner_b.claims.ipv4_routes.insert(SharedIpv4Route::new(
            "10.0.5.0".parse().unwrap(),
            24,
            None,
        ));
        let (members, rejected) =
            select_members(vec![member(1, "10.0.1.1/24"), owner_b], Vec::new());
        assert!(rejected.is_empty());
        let after = config_for_members(&members, rejected);

        assert_eq!(before.addresses, after.addresses);
        assert_eq!(before.routes, after.routes);
        assert_eq!(before.instance_ids, after.instance_ids);
        assert_ne!(before.snapshot_id, after.snapshot_id);
    }

    #[test]
    fn snapshot_tracks_dns_owner_when_union_is_unchanged() {
        let mut first = member(1, "10.0.1.1/24");
        first.dns = true;
        let (members, rejected) = select_members(vec![first, member(2, "10.0.2.1/24")], Vec::new());
        assert!(rejected.is_empty());
        let before = config_for_members(&members, rejected);

        let mut second = member(2, "10.0.2.1/24");
        second.dns = true;
        let (members, rejected) =
            select_members(vec![member(1, "10.0.1.1/24"), second], Vec::new());
        assert!(rejected.is_empty());
        let after = config_for_members(&members, rejected);

        assert_eq!(before.dns, after.dns);
        assert_eq!(before.routes, after.routes);
        assert_ne!(before.snapshot_id, after.snapshot_id);
    }

    #[test]
    fn snapshot_ignores_member_input_order() {
        let first = member(1, "10.0.1.1/24");
        let second = member(2, "10.0.2.1/24");
        let (members, rejected) = select_members(vec![first.clone(), second.clone()], Vec::new());
        assert!(rejected.is_empty());
        let forward = config_for_members(&members, rejected);
        let (members, rejected) = select_members(vec![second, first], Vec::new());
        assert!(rejected.is_empty());
        let backward = config_for_members(&members, rejected);

        assert_eq!(forward.routes, backward.routes);
        assert_eq!(forward.snapshot_id, backward.snapshot_id);
    }

    #[test]
    fn snapshot_ignores_mtu_costs_hints_and_diagnostics() {
        let first = member(1, "10.0.1.1/24");
        let second = member(2, "10.0.2.1/24");
        let (members, rejected) = select_members(vec![first.clone(), second.clone()], Vec::new());
        assert!(rejected.is_empty());
        let base = config_for_members(&members, rejected);

        let mut with_mtu = first.clone();
        with_mtu.claims.mtu = Some(1300);
        let (members, rejected) = select_members(vec![with_mtu, second.clone()], Vec::new());
        assert!(rejected.is_empty());
        assert_eq!(
            base.snapshot_id,
            config_for_members(&members, rejected).snapshot_id
        );

        let mut cheap = first.clone();
        cheap.claims.ipv4_routes.insert(SharedIpv4Route::new(
            "10.0.7.0".parse().unwrap(),
            24,
            Some(1),
        ));
        let mut expensive = cheap.clone();
        expensive.claims.ipv4_routes = BTreeSet::from([SharedIpv4Route::new(
            "10.0.7.0".parse().unwrap(),
            24,
            Some(9),
        )]);
        let (members, rejected) = select_members(vec![cheap, second.clone()], Vec::new());
        assert!(rejected.is_empty());
        let cheap = config_for_members(&members, rejected);
        let (members, rejected) = select_members(vec![expensive, second.clone()], Vec::new());
        assert!(rejected.is_empty());
        let expensive = config_for_members(&members, rejected);
        assert_eq!(cheap.routes, expensive.routes);
        assert_eq!(cheap.snapshot_id, expensive.snapshot_id);

        let mut hinted = first.clone();
        hinted.current_claims = Some(SharedIfConfigClaims {
            ipv4_addresses: BTreeSet::from(["10.0.9.1/24".parse().unwrap()]),
            ..Default::default()
        });
        let (members, rejected) = select_members(vec![hinted, second], Vec::new());
        assert!(rejected.is_empty());
        assert_eq!(
            base.snapshot_id,
            config_for_members(&members, rejected).snapshot_id
        );

        let (members, rejected) = select_members(vec![first, member(2, "10.0.2.1/24")], Vec::new());
        assert!(rejected.is_empty());
        let diagnosed = config_for_members(
            &members,
            vec![MobileTunMemberError {
                instance_id: uuid::Uuid::from_u128(3),
                error: "overlapping subnet".into(),
            }],
        );
        assert!(base.rejected.is_empty());
        assert_eq!(diagnosed.rejected[0].instance_id, uuid::Uuid::from_u128(3));
        assert_eq!(base.snapshot_id, diagnosed.snapshot_id);
    }

    #[test]
    fn hint_comparison_ignores_unexported_mtu_cost_and_magic_dns() {
        let mut first = member(1, "10.0.1.1/24");
        first.claims.ipv4_routes.insert(SharedIpv4Route::new(
            "10.0.7.0".parse().unwrap(),
            24,
            Some(1),
        ));
        let mut hinted = first.claims.clone();
        hinted.mtu = Some(1300);
        hinted.ipv4_routes = BTreeSet::from([SharedIpv4Route::new(
            "10.0.7.5".parse().unwrap(),
            24,
            Some(9),
        )]);
        hinted.ipv4_routes.insert(magic_dns_route());
        assert_eq!(comparable_claims(&first.claims), comparable_claims(&hinted));

        let mut changed_address = first.claims.clone();
        changed_address.ipv4_addresses = BTreeSet::from(["10.0.1.2/24".parse().unwrap()]);
        assert_ne!(
            comparable_claims(&first.claims),
            comparable_claims(&changed_address)
        );
    }

    #[test]
    fn skips_invalid_claim_route_prefixes_in_member_projection() {
        let mut invalid = member(1, "10.0.1.1/24");
        invalid.claims.ipv4_routes.insert(SharedIpv4Route::new(
            "10.0.9.0".parse().unwrap(),
            33,
            None,
        ));
        let (members, rejected) = select_members(vec![invalid], Vec::new());
        assert!(rejected.is_empty());
        assert_eq!(
            member_prefixes(&members[0]),
            BTreeSet::from(["10.0.1.0/24".parse().unwrap()])
        );
        assert_eq!(
            config_for_members(&members, rejected).routes,
            vec!["10.0.1.0/24"]
        );
    }

    #[test]
    fn keeps_attached_member_when_bootstrap_subnets_overlap() {
        let mut existing = member(2, "10.126.126.2/24");
        existing.current_claims = Some(existing.claims.clone());
        let (members, rejected) =
            select_members(vec![member(1, "10.126.126.1/24"), existing], Vec::new());
        let config = config_for_members(&members, rejected);
        assert_eq!(config.instance_ids, vec![uuid::Uuid::from_u128(2)]);
        assert_eq!(config.addresses, vec!["10.126.126.2/24"]);
        assert_eq!(config.routes, vec!["10.126.126.0/24"]);
        assert_eq!(config.rejected[0].instance_id, uuid::Uuid::from_u128(1));
    }

    #[test]
    fn reconfigured_member_does_not_displace_unchanged_member() {
        let mut changed = member(1, "10.0.2.1/24");
        changed.current_claims = Some(member(1, "10.0.1.1/24").claims);
        let mut unchanged = member(2, "10.0.2.2/24");
        unchanged.current_claims = Some(unchanged.claims.clone());
        unchanged.current_claims.as_mut().unwrap().mtu = Some(1300);
        let (members, rejected) = select_members(vec![changed, unchanged], Vec::new());
        let config = config_for_members(&members, rejected);
        assert_eq!(config.instance_ids, vec![uuid::Uuid::from_u128(2)]);
        assert_eq!(config.rejected[0].instance_id, uuid::Uuid::from_u128(1));
    }

    #[test]
    fn projects_ipv6_and_shared_dns_and_rejects_overlapping_proxy_routes() {
        let mut first = member(1, "10.0.1.1/24");
        first.dns = true;
        first
            .claims
            .ipv4_addresses
            .insert("10.0.4.1/32".parse().unwrap());
        first
            .claims
            .ipv6_addresses
            .insert("2001:db8::1/128".parse().unwrap());
        first
            .claims
            .ipv6_routes
            .insert(TestIpv6Route::new("::".parse().unwrap(), 0, Some(5)));
        let mut second = member(2, "10.0.2.1/24");
        second.dns = true;
        let (members, rejected) = select_members(
            vec![first, second, member(3, "100.100.100.101/32")],
            Vec::new(),
        );
        let config = config_for_members(&members, rejected);
        assert_eq!(config.instance_ids.len(), 2);
        assert!(config.addresses.contains(&"10.0.4.1/32".to_owned()));
        assert!(config.routes.contains(&"10.0.4.1/32".to_owned()));
        assert!(config.addresses.contains(&"2001:db8::1/128".to_owned()));
        assert!(config.routes.contains(&"2001:db8::1/128".to_owned()));
        assert!(config.routes.contains(&"::/0".to_owned()));
        assert_eq!(
            config
                .routes
                .iter()
                .filter(|route| *route == "100.100.100.101/32")
                .count(),
            1
        );
        assert_eq!(config.dns.as_deref(), Some("100.100.100.101"));
        assert_eq!(config.rejected[0].instance_id, uuid::Uuid::from_u128(3));
        let mut route_owner = member(2, "10.0.2.1/24");
        route_owner.claims.ipv4_routes.insert(SharedIpv4Route::new(
            "10.0.1.0".parse().unwrap(),
            24,
            None,
        ));
        let (members, rejected) =
            select_members(vec![member(1, "10.0.1.1/24"), route_owner], Vec::new());
        let config = config_for_members(&members, rejected);
        assert_eq!(config.instance_ids.len(), 1);
        assert_eq!(config.rejected[0].instance_id, uuid::Uuid::from_u128(2));
    }

    #[test]
    fn policy_projects_address_networks_public_default_and_magic_dns() {
        let claims = claims_from_facts(
            Some("10.0.1.1/24".parse().unwrap()),
            Some("fd00::1/64".parse().unwrap()),
            Some("2001:db8::1/128".parse().unwrap()),
            vec!["10.9.0.0/16".parse::<IpCidr>().unwrap()],
        );
        let mut member = MobileTunMember::new(
            uuid::Uuid::from_u128(1),
            uuid::Uuid::from_u128(11),
            claims,
            None,
            true,
        );
        member.claims.mtu = Some(1400);
        let (members, config) = select_and_project(vec![member], Vec::new());
        assert!(config.rejected.is_empty());
        let config = &members[0];
        assert!(config.claims.ipv4_routes.contains(&magic_dns_route()));
        assert_eq!(config.installed_prefixes, member_prefixes(config));
        for prefix in [
            "10.0.1.0/24",
            "fd00::/64",
            "2001:db8::1/128",
            "::/0",
            "10.9.0.0/16",
            "100.100.100.101/32",
        ] {
            assert!(
                config
                    .installed_prefixes
                    .contains(&prefix.parse::<IpCidr>().unwrap()),
                "{prefix} is part of the accepted member's installation data"
            );
        }
    }

    #[test]
    fn scope_is_applied_before_selection_and_rejects_foreign_ids() {
        let first = member(1, "10.0.1.1/24");
        let second = member(2, "10.0.2.1/24");

        let (all, rejected) = filter_scope(vec![first.clone(), second.clone()], None);
        assert_eq!(all.len(), 2);
        assert!(rejected.is_empty());

        let (empty, rejected) =
            filter_scope(vec![first.clone(), second.clone()], Some(&BTreeSet::new()));
        assert!(empty.is_empty());
        assert!(rejected.is_empty());

        let subset = BTreeSet::from([uuid::Uuid::from_u128(2)]);
        let (selected, rejected) = filter_scope(vec![first.clone(), second.clone()], Some(&subset));
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].instance_id, uuid::Uuid::from_u128(2));
        assert!(rejected.is_empty());

        let foreign = BTreeSet::from([uuid::Uuid::from_u128(3)]);
        let (selected, rejected) = filter_scope(vec![first, second], Some(&foreign));
        assert!(selected.is_empty());
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0].instance_id, uuid::Uuid::from_u128(3));
        assert!(rejected[0].error.contains("not participating"));
    }

    #[test]
    fn policy_changes_alter_the_final_table_and_snapshot() {
        let before = claims_from_facts(
            Some("10.0.1.1/24".parse().unwrap()),
            None,
            None,
            vec!["10.9.0.0/16".parse::<IpCidr>().unwrap()],
        );
        let after = claims_from_facts(
            Some("10.0.1.1/24".parse().unwrap()),
            None,
            None,
            vec!["10.10.0.0/16".parse::<IpCidr>().unwrap()],
        );
        let build = |claims| {
            let member = MobileTunMember::new(
                uuid::Uuid::from_u128(1),
                uuid::Uuid::from_u128(1),
                claims,
                None,
                false,
            );
            let (_, config) = select_and_project(vec![member], Vec::new());
            config
        };
        let before = build(before);
        let after = build(after);
        assert_ne!(before.routes, after.routes);
        assert_ne!(before.snapshot_id, after.snapshot_id);
    }
}
