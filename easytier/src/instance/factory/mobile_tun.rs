#[cfg(any(mobile, test))]
use std::collections::BTreeSet;

#[cfg(all(mobile, feature = "management-rpc"))]
use super::{NativeInstanceManager, NativeInstanceRuntimeHost};
#[cfg(any(mobile, test))]
use crate::instance::shared_virtual_nic::{SharedIfConfig, SharedIfConfigClaims, SharedIpv4Route};
#[cfg(any(mobile, test))]
use cidr::IpCidr;
#[cfg(all(mobile, feature = "management-rpc"))]
use easytier_core::instance::CoreInstanceState;

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

#[cfg(any(mobile, test))]
#[derive(Clone)]
pub(crate) struct MobileTunMember {
    pub(crate) instance_id: uuid::Uuid,
    pub(crate) run: uuid::Uuid,
    pub(crate) claims: SharedIfConfigClaims,
    pub(crate) current_claims: Option<SharedIfConfigClaims>,
    pub(crate) dns: bool,
}

#[cfg(any(mobile, test))]
fn magic_dns_route() -> SharedIpv4Route {
    SharedIpv4Route::new(
        crate::instance::dns_server::MAGIC_DNS_FAKE_IP
            .parse()
            .unwrap(),
        32,
        Some(1),
    )
}

#[cfg(any(mobile, test))]
fn comparable_claims(mut claims: SharedIfConfigClaims) -> SharedIfConfigClaims {
    claims.mtu = None;
    let magic_dns = magic_dns_route();
    claims
        .ipv4_routes
        .retain(|route| route.address != magic_dns.address || route.prefix != magic_dns.prefix);
    claims
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
        let magic_dns = magic_dns_route();
        prefixes.insert(IpCidr::V4(
            cidr::Ipv4Cidr::new(magic_dns.address, magic_dns.prefix)
                .expect("magic DNS fake IP prefix is valid"),
        ));
    }
    prefixes
}

#[cfg(any(mobile, test))]
fn select_members(
    mut members: Vec<MobileTunMember>,
    mut rejected: Vec<MobileTunMemberError>,
) -> (Vec<MobileTunMember>, Vec<MobileTunMemberError>) {
    // Keep unchanged attached members ahead of new or reconfigured members.
    members.sort_by_key(|member| {
        !member.current_claims.as_ref().is_some_and(|current| {
            comparable_claims(current.clone()) == comparable_claims(member.claims.clone())
        })
    });
    let mut ifcfg = SharedIfConfig::default();
    let mut accepted = Vec::new();
    for member in members {
        let mut claims = member.claims.clone();
        if member.dns {
            claims.ipv4_routes.insert(magic_dns_route());
        }
        if let Err(error) = ifcfg.ensure_disjoint(member.instance_id, &claims) {
            rejected.push(MobileTunMemberError {
                instance_id: member.instance_id,
                error: error.to_string(),
            });
            continue;
        }
        ifcfg.apply_member_claims(member.instance_id, claims);
        accepted.push(member);
    }
    (accepted, rejected)
}

#[cfg(any(mobile, test))]
fn config_for_members(
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
    // snapshot cache. Identical declarations keep the same acknowledgement ID.
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

#[cfg(all(mobile, feature = "management-rpc"))]
async fn collect_members(
    manager: &NativeInstanceManager,
    instance_ids: &[uuid::Uuid],
) -> (Vec<MobileTunMember>, Vec<MobileTunMemberError>) {
    let mut members = Vec::new();
    let mut rejected = Vec::new();
    let mut seen = BTreeSet::new();
    for &instance_id in instance_ids {
        if !seen.insert(instance_id) {
            continue;
        }
        let instance = manager.instance(instance_id);
        let runtime = instance
            .as_ref()
            .filter(|instance| instance.state() == CoreInstanceState::Running)
            .and_then(|instance| instance.runtime_host::<NativeInstanceRuntimeHost>())
            .filter(|runtime| runtime.tun_enabled());
        let Some(runtime) = runtime else {
            rejected.push(MobileTunMemberError {
                instance_id,
                error: "TUN-enabled instance is not running".to_owned(),
            });
            continue;
        };
        let (claims, current_claims, dns) = match runtime
            .mobile_tun_claims(&instance.as_ref().unwrap().packet_plane())
            .await
        {
            Ok(claims) => claims,
            Err(error) => {
                rejected.push(MobileTunMemberError {
                    instance_id,
                    error: error.to_string(),
                });
                continue;
            }
        };
        members.push(MobileTunMember {
            instance_id,
            run: runtime.instance_run_key(),
            claims,
            current_claims,
            dns,
        });
    }
    (members, rejected)
}

#[cfg(all(mobile, feature = "management-rpc"))]
pub async fn get_mobile_tun_config(
    manager: &NativeInstanceManager,
    instance_ids: &[uuid::Uuid],
) -> MobileTunConfig {
    let (members, rejected) = collect_members(manager, instance_ids).await;
    let (members, rejected) = select_members(members, rejected);
    config_for_members(&members, rejected)
}

#[cfg(test)]
fn is_claim_conflict(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|error| error.is::<crate::instance::shared_virtual_nic::SharedIfConfigConflict>())
}

#[cfg(all(mobile, feature = "management-rpc"))]
pub async fn attach_mobile_tun_fd(
    manager: &NativeInstanceManager,
    fd: i32,
    instance_ids: Option<&[uuid::Uuid]>,
    snapshot_id: Option<uuid::Uuid>,
) -> anyhow::Result<MobileTunConfig> {
    let all_ids = manager
        .instances()
        .into_iter()
        .filter(|instance| {
            instance.state() == CoreInstanceState::Running
                && instance
                    .runtime_host::<NativeInstanceRuntimeHost>()
                    .is_some_and(NativeInstanceRuntimeHost::tun_enabled)
        })
        .map(|instance| instance.instance_id())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if fd <= 0 {
        let mut errors = Vec::new();
        for id in all_ids {
            if let Err(error) = attach_member(manager, id, 0, false, None, None).await {
                errors.push(error.to_string());
            }
        }
        anyhow::ensure!(
            errors.is_empty(),
            "failed to detach mobile TUN fd: {}",
            errors.join("; ")
        );
        return Ok(MobileTunConfig::default());
    }
    let (members, rejected) = collect_members(manager, instance_ids.unwrap_or(&all_ids)).await;
    let (members, rejected) = select_members(members, rejected);
    let config = config_for_members(&members, rejected);
    anyhow::ensure!(
        snapshot_id == Some(config.snapshot_id),
        "mobile TUN configuration changed; query and install a new snapshot before attaching"
    );
    let mut attached = Vec::new();
    // Open once; a rejected member never replaces or tears down this shared fd.
    for member in members {
        match attach_member(
            manager,
            member.instance_id,
            fd,
            attached.is_empty(),
            Some(member.run),
            Some({
                let mut claims = member.claims.clone();
                if member.dns {
                    claims.ipv4_routes.insert(magic_dns_route());
                }
                claims
            }),
        )
        .await
        {
            Ok(()) => attached.push(member),
            Err(error) => {
                for id in &all_ids {
                    let _ = attach_member(manager, *id, 0, false, None, None).await;
                }
                return Err(error.context("failed to attach mobile TUN fd"));
            }
        }
    }
    Ok(config)
}

#[cfg(all(mobile, feature = "management-rpc"))]
async fn attach_member(
    manager: &NativeInstanceManager,
    instance_id: uuid::Uuid,
    fd: i32,
    replace_tun_fd: bool,
    expected_run: Option<uuid::Uuid>,
    claims: Option<SharedIfConfigClaims>,
) -> anyhow::Result<()> {
    let instance = manager
        .instance(instance_id)
        .ok_or_else(|| anyhow::anyhow!("instance {instance_id} is unavailable"))?;
    let runtime = instance
        .runtime_host::<NativeInstanceRuntimeHost>()
        .ok_or_else(|| anyhow::anyhow!("native runtime host is unavailable"))?;
    anyhow::ensure!(
        expected_run.is_none_or(|run| run == runtime.instance_run_key()),
        "instance restarted after its VPN configuration was prepared"
    );
    runtime
        .attach_mobile_tun_fd(fd, replace_tun_fd, claims)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instance::shared_virtual_nic::SharedIpv6Route;

    fn member(id: u128, address: &str) -> MobileTunMember {
        MobileTunMember {
            instance_id: uuid::Uuid::from_u128(id),
            run: uuid::Uuid::from_u128(id),
            claims: SharedIfConfigClaims {
                ipv4_addresses: BTreeSet::from([address.parse().unwrap()]),
                ..Default::default()
            },
            current_claims: None,
            dns: false,
        }
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
            .insert(SharedIpv6Route::new("::".parse().unwrap(), 0, Some(5)));
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
    fn distinguishes_claim_conflicts_from_device_failures_through_context() {
        let mut claims = SharedIfConfig::default();
        claims.apply_member_claims(uuid::Uuid::from_u128(1), member(1, "10.0.1.1/24").claims);
        let conflict = claims
            .ensure_disjoint(uuid::Uuid::from_u128(2), &member(2, "10.0.1.2/24").claims)
            .unwrap_err();
        let error = anyhow::Error::new(crate::common::error::Error::from(conflict))
            .context("attach mobile TUN failed");
        assert!(is_claim_conflict(&error));
        assert!(!is_claim_conflict(&anyhow::Error::new(
            std::io::Error::from_raw_os_error(19)
        )));
    }
}
