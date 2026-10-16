#![cfg(all(mobile, feature = "management-rpc"))]

//! Mobile execution adapter.
//!
//! The Controller owns every route/member decision. This module only locates
//! the existing route domain, accepts the host's participation scope for a
//! query, transfers the complete table, and executes the accepted/withdrawn
//! members through the existing Native attachment queue. It never selects,
//! merges or projects routes of its own.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use anyhow::Context as _;
use easytier_core::instance::CoreInstanceState;
use tokio::sync::Notify;
use uuid::Uuid;

use super::{NativeCoreInstance, NativeInstanceManager, NativeInstanceRuntimeHost};
use crate::instance::{
    route::{
        RouteController,
        mobile::{MobilePlan, MobileTunConfig, MobileTunMember, empty_mobile_tun_config},
    },
    shared_virtual_nic::SharedVirtualNicMember,
};

/// One existing route domain observed through an instance's Native runtime.
struct MobileDomain {
    controller: RouteController,
    instance_ids: BTreeSet<Uuid>,
}

fn route_controller(instance: &NativeCoreInstance) -> Option<RouteController> {
    instance
        .runtime_host::<NativeInstanceRuntimeHost>()?
        .route_context()
        .map(|context| context.controller())
}

fn domains(manager: &NativeInstanceManager) -> Vec<MobileDomain> {
    let mut domains: Vec<MobileDomain> = Vec::new();
    for instance in manager.instances() {
        let Some(controller) = route_controller(&instance) else {
            continue;
        };
        let instance_id = instance.instance_id();
        if let Some(domain) = domains
            .iter_mut()
            .find(|domain| domain.controller.same_controller(&controller))
        {
            domain.instance_ids.insert(instance_id);
        } else {
            domains.push(MobileDomain {
                controller,
                instance_ids: BTreeSet::from([instance_id]),
            });
        }
    }
    domains
}

/// Select exactly one existing route domain for the host's instance scope.
///
/// No domain means there is no Controller-owned table to query. Multiple
/// domains are never merged: the extra instances must disambiguate one, and a
/// scope spanning several domains is rejected.
fn select_domain<'a>(
    domains: &'a [MobileDomain],
    scope: &BTreeSet<Uuid>,
) -> anyhow::Result<Option<&'a MobileDomain>> {
    match domains {
        [] => Ok(None),
        [domain] => Ok(Some(domain)),
        _ => {
            let matching = domains
                .iter()
                .filter(|domain| !domain.instance_ids.is_disjoint(scope))
                .collect::<Vec<_>>();
            match matching.as_slice() {
                [domain] => Ok(Some(domain)),
                [] if scope.is_empty() => {
                    anyhow::bail!(
                        "multiple mobile route domains are available; instance ids are required"
                    )
                }
                [] => anyhow::bail!(
                    "none of the requested instances belongs to an available mobile route domain"
                ),
                _ => anyhow::bail!("requested instances span multiple mobile route domains"),
            }
        }
    }
}

fn instances_by_id(
    manager: &NativeInstanceManager,
) -> BTreeMap<Uuid, std::sync::Arc<NativeCoreInstance>> {
    manager
        .instances()
        .into_iter()
        .map(|instance| (instance.instance_id(), instance))
        .collect()
}

/// Withdraw one member decided by the complete plan.
///
/// A still-existing Native runtime receives the existing local detach request.
/// A removed runtime has no worker left; its Native shutdown owns the final
/// cleanup, so the plan's member handle is used for a direct registration
/// close and any error is returned.
async fn withdraw_plan_member(
    instances: &BTreeMap<Uuid, std::sync::Arc<NativeCoreInstance>>,
    run: Uuid,
    member: Option<&SharedVirtualNicMember>,
) -> anyhow::Result<()> {
    for (instance_id, instance) in instances {
        let Some(runtime) = instance.runtime_host::<NativeInstanceRuntimeHost>() else {
            continue;
        };
        if runtime.instance_run_key() != run {
            continue;
        }
        match runtime
            .attach_mobile_tun_fd(0, false, None, BTreeSet::new())
            .await
        {
            Ok(()) => return Ok(()),
            Err(error) => {
                if let Some(member) = member {
                    // The runtime can no longer run the queued detach (for
                    // example it already stopped); closing this registration is
                    // the remaining local withdrawal.
                    member.close().await.map_err(|close| {
                        anyhow::anyhow!(
                            "failed to detach instance {instance_id} run {run}: {error:#}; \
                             member close also failed: {close:#}"
                        )
                    })?;
                    return Ok(());
                }
                return Err(error)
                    .with_context(|| format!("failed to detach instance {instance_id} run {run}"));
            }
        }
    }
    if let Some(member) = member {
        return member.close().await.map_err(|error| {
            anyhow::anyhow!("failed to close withdrawn member of removed run {run}: {error:#}")
        });
    }
    anyhow::bail!("no native runtime or member handle remains for withdrawn run {run}")
}

/// Borrow the existing mobile route domain's change notification.
///
/// The handle carries no route table, instance or Registry root: a host task
/// may keep it while re-reading the complete configuration and must still
/// decide whether any system VPN action is needed. `None` means no existing
/// route domain can be identified; this function never creates one and starts
/// no worker. Once the host task observes a notification it should subscribe
/// again before reading, because the notification carries no payload and only
/// wakes waiters registered at the time of the change.
pub fn mobile_tun_changed() -> Option<Arc<Notify>> {
    crate::host_runtime::native_host_runtime()
        .existing_route_controller()
        .map(|controller| controller.changed().clone())
}

/// Read the current complete table without submitting a participation scope.
///
/// This is the read-only counterpart of [`get_mobile_tun_config`]. It resolves
/// the same existing Factory domains, then asks the one domain for its current
/// `mobile_config()`; it never calls `set_mobile_scope`, creates a domain, marks
/// the shared route input dirty or computes a second policy result.
///
/// No identifiable domain returns the normalized empty table. Multiple
/// distinct domains are an ambiguity error instead of an arbitrary choice or a
/// merge.
async fn current_mobile_tun_config_from_domains(
    domains: &[MobileDomain],
) -> anyhow::Result<MobileTunConfig> {
    let Some(domain) = select_domain(domains, &BTreeSet::new())? else {
        return Ok(empty_mobile_tun_config());
    };
    domain.controller.mobile_config().await
}

/// Read the current complete table of the existing mobile route domain.
///
/// This does not accept or submit a participation scope and does not mutate
/// Controller input state. It is intended for status/diagnostic consumers;
/// hosts that intentionally change the range must use
/// [`get_mobile_tun_config`].
pub async fn current_mobile_tun_config(
    manager: &NativeInstanceManager,
) -> anyhow::Result<MobileTunConfig> {
    let domains = domains(manager);
    current_mobile_tun_config_from_domains(&domains).await
}

/// Query the complete table for the host's explicit participation scope.
///
/// `instance_ids` is always an explicit scope, including an empty slice. The
/// Factory only sends it to the Controller and returns the complete result.
pub async fn get_mobile_tun_config(
    manager: &NativeInstanceManager,
    instance_ids: &[Uuid],
) -> anyhow::Result<MobileTunConfig> {
    let scope = instance_ids.iter().copied().collect::<BTreeSet<_>>();
    let domains = domains(manager);
    let Some(domain) = select_domain(&domains, &scope)? else {
        // No native route domain exists. This is the normalized empty table,
        // not a synthesized member list.
        return Ok(empty_mobile_tun_config());
    };
    domain.controller.set_mobile_scope(Some(scope))?;
    domain.controller.mobile_config().await
}

/// Detach the host's local TUN from every still-existing Native runtime.
///
/// A stopped instance that no longer has an install worker is confirmed through
/// its Controller record, not by its `closed` flag. An id that was already
/// removed from the manager is confirmed through a surviving route domain; if
/// no domain is available, this reports that local release cannot be confirmed.
async fn detach_mobile_tun_fd(
    manager: &NativeInstanceManager,
    instance_ids: Option<&[Uuid]>,
) -> anyhow::Result<MobileTunConfig> {
    let instances = instances_by_id(manager);
    let mut errors = Vec::new();
    let mut present = BTreeSet::new();

    for (instance_id, instance) in &instances {
        present.insert(*instance_id);
        let Some(runtime) = instance.runtime_host::<NativeInstanceRuntimeHost>() else {
            errors.push(format!(
                "instance {instance_id} has no native runtime; local release cannot be confirmed"
            ));
            continue;
        };
        if !runtime.tun_enabled() {
            continue;
        }
        match runtime
            .attach_mobile_tun_fd(0, false, None, BTreeSet::new())
            .await
        {
            Ok(()) => {}
            Err(error) if instance.state() != CoreInstanceState::Running => {
                let confirmed = match runtime.route_context() {
                    Some(context) => context.drain_local().await,
                    None => {
                        errors.push(format!(
                            "instance {instance_id} has no route context; \
                             local release cannot be confirmed: {error:#}"
                        ));
                        continue;
                    }
                };
                if let Err(confirm) = confirmed {
                    errors.push(format!(
                        "instance {instance_id} local detach failed: {error:#}; \
                         route cleanup is still unconfirmed: {confirm:#}"
                    ));
                }
            }
            Err(error) => errors.push(format!(
                "instance {instance_id} local detach failed: {error:#}"
            )),
        }
    }

    if let Some(instance_ids) = instance_ids {
        let domains = domains(manager);
        for instance_id in instance_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .difference(&present)
        {
            if domains.is_empty() {
                errors.push(format!(
                    "instance {instance_id} is no longer in the manager and no route domain \
                     is available to confirm its local release"
                ));
                continue;
            }
            for domain in &domains {
                if let Err(error) = domain
                    .controller
                    .drain_mobile_instance_id(*instance_id)
                    .await
                {
                    errors.push(format!(
                        "instance {instance_id} was removed from the manager but its local \
                         route release is unconfirmed: {error:#}"
                    ));
                }
            }
        }
    }

    anyhow::ensure!(
        errors.is_empty(),
        "mobile TUN local detach is incomplete: {}",
        errors.join("; ")
    );
    // The non-positive FD branch remains an empty local-detach result, never a
    // complete route table. Callers obtain the target only from get.
    Ok(MobileTunConfig::default())
}

/// Execute one already-validated complete plan.
///
/// The Factory never reselects members. It withdraws exactly the plan's
/// withdrawals, then attaches exactly the accepted members in order. Any real
/// attach failure waits for the completed queue calls, performs the necessary
/// local cleanup and returns the original error with cleanup failures in the
/// chain.
async fn execute_plan(
    manager: &NativeInstanceManager,
    fd: i32,
    plan: &MobilePlan,
    scope: Option<&BTreeSet<Uuid>>,
) -> anyhow::Result<()> {
    if let Some(scope) = scope
        && let Some(member) = plan
            .members
            .iter()
            .find(|member| !scope.contains(&member.instance_id))
    {
        anyhow::bail!(
            "accepted member {} is outside the attach caller's instance list",
            member.instance_id
        );
    }

    let instances = instances_by_id(manager);
    for withdraw in &plan.withdraw {
        withdraw_plan_member(&instances, withdraw.run, Some(&withdraw.member))
            .await
            .with_context(|| {
                format!("failed to execute mobile route withdrawal {}", withdraw.run)
            })?;
    }

    let mut attempted: Vec<&MobileTunMember> = Vec::new();
    for member in &plan.members {
        let instance = instances.get(&member.instance_id).ok_or_else(|| {
            anyhow::anyhow!(
                "accepted instance {} is no longer in the manager",
                member.instance_id
            )
        })?;
        anyhow::ensure!(
            instance.state() == CoreInstanceState::Running,
            "accepted instance {} is not running",
            member.instance_id
        );
        let runtime = instance
            .runtime_host::<NativeInstanceRuntimeHost>()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "accepted instance {} has no native runtime",
                    member.instance_id
                )
            })?;
        anyhow::ensure!(
            runtime.tun_enabled(),
            "accepted instance {} no longer owns a TUN",
            member.instance_id
        );
        anyhow::ensure!(
            runtime.instance_run_key() == member.run,
            "instance {} restarted after its VPN configuration was prepared",
            member.instance_id
        );

        attempted.push(member);
        let replace_tun_fd = attempted.len() == 1;
        if let Err(error) = runtime
            .attach_mobile_tun_fd(
                fd,
                replace_tun_fd,
                Some(member.claims.clone()),
                member.installed_prefixes.clone(),
            )
            .await
        {
            let mut cleanup_errors = Vec::new();
            for attempted_member in &attempted {
                if let Err(cleanup) =
                    withdraw_plan_member(&instances, attempted_member.run, None).await
                {
                    cleanup_errors.push(format!(
                        "instance {}: {cleanup:#}",
                        attempted_member.instance_id
                    ));
                }
            }
            let error = error.context("failed to attach mobile TUN fd");
            if cleanup_errors.is_empty() {
                return Err(error);
            }
            return Err(error.context(format!(
                "mobile TUN cleanup after attach failure is incomplete: {}",
                cleanup_errors.join("; ")
            )));
        }
    }
    Ok(())
}

/// Attach the host's FD to exactly the complete plan accepted for
/// `snapshot_id`. The current scope is never rewritten here.
pub async fn attach_mobile_tun_fd(
    manager: &NativeInstanceManager,
    fd: i32,
    instance_ids: Option<&[Uuid]>,
    snapshot_id: Option<Uuid>,
) -> anyhow::Result<MobileTunConfig> {
    if fd <= 0 {
        return detach_mobile_tun_fd(manager, instance_ids).await;
    }
    let scope = instance_ids.map(|ids| ids.iter().copied().collect::<BTreeSet<_>>());
    let lookup_scope = scope
        .clone()
        .unwrap_or_else(|| manager.instance_ids().into_iter().collect::<BTreeSet<_>>());
    let domains = domains(manager);
    let Some(domain) = select_domain(&domains, &lookup_scope)? else {
        anyhow::bail!("mobile route domain is unavailable; fetch the mobile table first");
    };
    let snapshot_id =
        snapshot_id.ok_or_else(|| anyhow::anyhow!("mobile TUN attach requires a snapshot id"))?;
    let plan = domain.controller.prepare_mobile_attach(snapshot_id).await?;
    execute_plan(manager, fd, &plan, scope.as_ref()).await?;
    Ok(plan.config)
}

#[cfg(test)]
fn is_claim_conflict(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|error| error.is::<crate::instance::shared_virtual_nic::SharedIfConfigConflict>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instance::shared_virtual_nic::SharedIpv6Route;

    fn member(id: u128, address: &str) -> MobileTunMember {
        MobileTunMember {
            instance_id: uuid::Uuid::from_u128(id),
            claims: SharedIfConfigClaims {
                ipv4_addresses: BTreeSet::from([address.parse().unwrap()]),
                ..Default::default()
            },
            current_claims: None,
            dns: false,
        }
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
