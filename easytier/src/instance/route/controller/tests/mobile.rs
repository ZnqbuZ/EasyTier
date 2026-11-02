//! Mobile controller tests: request marks and the actual installation ledger.

use std::{collections::BTreeSet, sync::Arc};

#[cfg(feature = "magic-dns")]
use easytier_core::config::IpPrefix;
use easytier_core::config::{
    peers::PeerRuntimeSnapshot,
    runtime::{CoreRuntimeConfig, CoreRuntimeConfigStore},
};

use super::super::*;
use crate::{
    common::{config::TomlConfig, global_ctx::GlobalCtx, net_ns::tests::test_net_ns},
    instance::{
        factory::MobileTunConfig,
        route::mobile::MobileTunMember,
        shared_virtual_nic::{SharedIfConfigClaims, SharedVirtualNicRegistry},
        virtual_nic::VirtualNicConfig,
    },
};

fn test_controller() -> RouteController {
    RouteController::new(Arc::new(DirtyFlag::new(false)))
}

fn open_run(controller: &RouteController, run: Uuid) -> Arc<Registry> {
    let registry = controller.open_instance(run).unwrap();
    controller.dirty.reset();
    registry
}

fn test_member(registry: &mut SharedVirtualNicRegistry, run: Uuid) -> SharedVirtualNicMember {
    registry.create_member(
        format!("et-{run}"),
        VirtualNicConfig::new(format!("et-{run}"), 1400, test_net_ns(None)),
        run,
        Arc::new(Notify::new()),
    )
}

fn tun_member(run: Uuid) -> MobileTunMember {
    MobileTunMember::new(
        run,
        run,
        SharedIfConfigClaims {
            ipv4_addresses: BTreeSet::from(["10.126.126.7/24".parse().unwrap()]),
            ..Default::default()
        },
        None,
        false,
    )
}

fn config(snapshot_id: Uuid) -> MobileTunConfig {
    MobileTunConfig {
        snapshot_id,
        ..Default::default()
    }
}

#[test]
fn mobile_inputs_bind_once_and_follow_live_authority_values() {
    let controller = test_controller();
    let global = Arc::new(GlobalCtx::new(TomlConfig::default()));
    let run = global.key();
    let _root = controller.open_instance(run).unwrap();
    controller.dirty.reset();
    assert!(
        controller.mobile_inputs(run).unwrap().is_none(),
        "an unbound instance has no authority observation yet"
    );
    let public_address = Arc::new(parking_lot::Mutex::new(None));
    controller
        .bind_mobile_inputs(run, Arc::downgrade(&global), public_address.clone())
        .unwrap();
    assert!(controller.dirty.peek(), "binding marks the input range");
    controller.dirty.reset();

    global.set_ipv4(Some("10.40.0.1/24".parse().unwrap()));
    global.set_ipv6(Some("fd40::1/64".parse().unwrap()));
    *public_address.lock() = Some("2001:db8::40/128".parse().unwrap());
    let inputs = controller.mobile_inputs(run).unwrap().unwrap();
    assert_eq!(inputs.instance_id, global.get_id());
    assert_eq!(inputs.run, run);
    assert_eq!(inputs.ipv4, global.get_ipv4());
    assert_eq!(inputs.ipv6, global.get_ipv6());
    assert_eq!(inputs.public_address, *public_address.lock());
    assert!(
        !controller.dirty.peek(),
        "reading the live authorities does not mark input"
    );

    global.set_ipv4(None);
    global.set_ipv6(None);
    *public_address.lock() = None;
    let cleared = controller.mobile_inputs(run).unwrap().unwrap();
    assert_eq!(cleared.ipv4, None);
    assert_eq!(cleared.ipv6, None);
    assert_eq!(cleared.public_address, None);
}

#[test]
fn mobile_input_binding_rejects_duplicates_mismatches_and_closed_runs() {
    let controller = test_controller();
    let global = Arc::new(GlobalCtx::new(TomlConfig::default()));
    let run = global.key();
    let root = controller.open_instance(run).unwrap();
    let public_address = Arc::new(parking_lot::Mutex::new(None));
    controller
        .bind_mobile_inputs(run, Arc::downgrade(&global), public_address.clone())
        .unwrap();
    assert!(
        controller
            .bind_mobile_inputs(run, Arc::downgrade(&global), public_address)
            .is_err(),
        "the input binding may only be installed once"
    );

    let other = Arc::new(GlobalCtx::new(TomlConfig::default()));
    let other_run = other.key();
    let _other_root = controller.open_instance(other_run).unwrap();
    assert!(
        controller
            .bind_mobile_inputs(
                other_run,
                Arc::downgrade(&global),
                Arc::new(parking_lot::Mutex::new(None)),
            )
            .is_err(),
        "a context for another run is rejected"
    );

    drop(root);
    assert!(
        controller.mobile_inputs(run).unwrap().is_none(),
        "a released root withdraws the whole input even with a live context"
    );
    assert!(
        controller
            .bind_mobile_inputs(
                run,
                Arc::downgrade(&global),
                Arc::new(parking_lot::Mutex::new(None)),
            )
            .is_err(),
        "a closed run cannot be bound"
    );
}

#[test]
fn requests_replace_pending_and_only_the_latest_completes() {
    let controller = test_controller();
    let run = Uuid::new_v4();
    let _root = open_run(&controller, run);
    // Shutdown with a live instance still has cleanup responsibility.
    controller.request_shutdown();
    controller.dirty.reset();

    let a = controller.request_mobile_install().unwrap();
    assert!(!controller.dirty.peek(), "a request mark is not an input");
    let b = controller.request_mobile_install().unwrap();
    let c = controller.request_mobile_install().unwrap();
    assert_ne!(a, b);
    assert_ne!(b, c);
    assert_eq!(controller.pending_mobile_install(), Some(c));

    assert!(!controller.complete_mobile_install(a));
    assert!(!controller.complete_mobile_install(b));
    assert_eq!(controller.pending_mobile_install(), Some(c));
    assert!(!controller.dirty.peek());
    assert!(controller.complete_mobile_install(c));
    assert_eq!(controller.pending_mobile_install(), None);
    assert!(!controller.dirty.peek());
}

#[test]
fn fully_drained_shutdown_rejects_new_requests() {
    let controller = test_controller();
    controller.request_shutdown();
    assert!(controller.request_mobile_install().is_err());
    assert_eq!(controller.pending_mobile_install(), None);
}

#[test]
fn releasing_the_root_or_shutting_down_keeps_the_request_mark() {
    let controller = test_controller();
    let run = Uuid::new_v4();
    let root = open_run(&controller, run);
    let id = controller.request_mobile_install().unwrap();

    drop(root);
    assert_eq!(controller.pending_mobile_install(), Some(id));
    controller.request_shutdown();
    assert_eq!(controller.pending_mobile_install(), Some(id));

    assert!(!controller.complete_mobile_install(Uuid::new_v4()));
    assert_eq!(controller.pending_mobile_install(), Some(id));
    assert!(controller.complete_mobile_install(id));
    assert_eq!(controller.pending_mobile_install(), None);
}

#[test]
fn late_install_facts_are_recorded_over_a_newer_request() {
    let controller = test_controller();
    let run = Uuid::new_v4();
    let root = open_run(&controller, run);
    let a = controller.request_mobile_install().unwrap();
    let d = controller.request_mobile_install().unwrap();
    let snapshot = Uuid::new_v4();

    controller.dirty.reset();
    let mut member = tun_member(run);
    member.current_claims = Some(member.claims.clone());
    controller.record_mobile_install(a, config(snapshot), vec![member]);
    assert!(controller.dirty.peek(), "a real fact wakes the reconciler");
    assert_eq!(controller.current_mobile_attachment(), Some(a));
    assert_eq!(controller.pending_mobile_install(), Some(d));
    assert!(
        controller.runtime.read().applied.as_ref().unwrap().members[0]
            .current_claims
            .is_none(),
        "the selection hint is not part of the recorded fact"
    );

    // A late A is still the real installation even after the domain has
    // shut down and its root has been released.
    drop(root);
    controller.request_shutdown();
    let _cleanup = controller.request_mobile_install().unwrap();
    controller.record_mobile_install(a, config(snapshot), vec![tun_member(run)]);
    assert_eq!(controller.current_mobile_attachment(), Some(a));
}

#[test]
fn only_the_current_registration_and_attachment_change_the_ledger() {
    let controller = test_controller();
    let run = Uuid::new_v4();
    let _root = open_run(&controller, run);
    let mut nics = SharedVirtualNicRegistry::new();
    let first = test_member(&mut nics, run);
    controller.bind_member(run, &first).unwrap();

    let snapshot = Uuid::new_v4();
    let attachment = Uuid::new_v4();
    controller.record_mobile_install(attachment, config(snapshot), vec![tun_member(run)]);
    assert!(controller.mobile_ready(run, &first, attachment));
    controller.dirty.reset();
    assert!(
        controller.mobile_ready(run, &first, attachment),
        "a repeated matching report is still accepted"
    );
    assert!(
        !controller.dirty.peek(),
        "an unchanged attachment record is not a change"
    );

    let second = test_member(&mut nics, run);
    controller.bind_member(run, &second).unwrap();
    assert!(
        !controller.mobile_ready(run, &first, attachment),
        "an old registration cannot attach to the new binding"
    );
    assert!(!controller.mobile_ready(run, &first, Uuid::new_v4()));
    assert!(!controller.mobile_ready(run, &second, Uuid::new_v4()));
    assert!(controller.mobile_ready(run, &second, attachment));

    let newer_snapshot = Uuid::new_v4();
    let newer_attachment = Uuid::new_v4();
    controller.record_mobile_install(
        newer_attachment,
        config(newer_snapshot),
        vec![tun_member(run)],
    );
    assert!(
        !controller.mobile_ready(run, &second, attachment),
        "an old attachment cannot attach to the newer installation"
    );
    assert!(controller.mobile_ready(run, &second, newer_attachment));
    assert_eq!(
        controller.current_mobile_attachment(),
        Some(newer_attachment)
    );
}

#[test]
fn unready_keeps_the_installed_configuration_and_ownership() {
    let controller = test_controller();
    let run = Uuid::new_v4();
    let _root = open_run(&controller, run);
    let mut nics = SharedVirtualNicRegistry::new();
    let member = test_member(&mut nics, run);
    controller.bind_member(run, &member).unwrap();

    let snapshot = Uuid::new_v4();
    let attachment = Uuid::new_v4();
    controller.record_mobile_install(attachment, config(snapshot), vec![tun_member(run)]);
    assert!(controller.mobile_ready(run, &member, attachment));
    assert_eq!(
        controller.mobile_installed_claims(run),
        Some(tun_member(run).claims)
    );
    assert!(controller.mobile_snapshot_attached(snapshot));

    controller.unready(run, member.registration_id());
    assert_eq!(controller.current_mobile_attachment(), Some(attachment));
    assert!(controller.mobile_installed_claims(run).is_none());
    assert!(!controller.mobile_snapshot_attached(snapshot));

    controller.dirty.reset();
    controller.unready(run, member.registration_id());
    assert!(
        !controller.dirty.peek(),
        "a second unready for the same registration is a no-op"
    );
}

#[test]
fn revocation_clears_only_the_matching_installation_and_never_the_request() {
    let controller = test_controller();
    let run = Uuid::new_v4();
    let _root = open_run(&controller, run);
    let snapshot = Uuid::new_v4();
    let attachment = Uuid::new_v4();
    let pending = controller.request_mobile_install().unwrap();
    controller.record_mobile_install(attachment, config(snapshot), vec![tun_member(run)]);

    assert!(!controller.confirm_mobile_revoked(Uuid::new_v4()));
    assert_eq!(controller.current_mobile_attachment(), Some(attachment));
    assert_eq!(controller.pending_mobile_install(), Some(pending));

    controller.dirty.reset();
    assert!(controller.confirm_mobile_revoked(attachment));
    assert!(
        controller.dirty.peek(),
        "a real revocation wakes the worker"
    );
    assert_eq!(controller.current_mobile_attachment(), None);
    assert_eq!(controller.pending_mobile_install(), Some(pending));

    let newer_snapshot = Uuid::new_v4();
    let newer_attachment = Uuid::new_v4();
    controller.record_mobile_install(
        newer_attachment,
        config(newer_snapshot),
        vec![tun_member(run)],
    );
    assert!(
        !controller.confirm_mobile_revoked(attachment),
        "an old revocation must not clear the newer installation"
    );
    assert_eq!(
        controller.current_mobile_attachment(),
        Some(newer_attachment)
    );
    assert_eq!(controller.pending_mobile_install(), Some(pending));
}

#[test]
fn whole_snapshot_attachment_requires_every_current_member() {
    let controller = test_controller();
    let run_a = Uuid::new_v4();
    let run_b = Uuid::new_v4();
    let _root_a = open_run(&controller, run_a);
    let root_b = open_run(&controller, run_b);
    let mut nics = SharedVirtualNicRegistry::new();
    let member_a = test_member(&mut nics, run_a);
    let member_b = test_member(&mut nics, run_b);
    controller.bind_member(run_a, &member_a).unwrap();
    controller.bind_member(run_b, &member_b).unwrap();

    let snapshot = Uuid::new_v4();
    let attachment = Uuid::new_v4();
    controller.record_mobile_install(
        attachment,
        config(snapshot),
        vec![tun_member(run_a), tun_member(run_b)],
    );
    assert!(
        !controller.mobile_snapshot_attached(snapshot),
        "no member is attached yet"
    );
    assert!(controller.mobile_ready(run_a, &member_a, attachment));
    assert!(
        !controller.mobile_snapshot_attached(snapshot),
        "one attached member is not the whole target"
    );
    assert!(controller.mobile_ready(run_b, &member_b, attachment));
    assert!(controller.mobile_snapshot_attached(snapshot));
    assert!(!controller.mobile_snapshot_attached(Uuid::new_v4()));

    // Releasing any real run's root withdraws its input and invalidates
    // the whole-attachment verdict, never a subset of the checks.
    drop(root_b);
    assert!(!controller.mobile_snapshot_attached(snapshot));

    controller.request_shutdown();
    assert!(!controller.mobile_snapshot_attached(snapshot));
}

#[test]
fn empty_target_is_never_reported_attached() {
    let controller = test_controller();
    let run = Uuid::new_v4();
    let _root = open_run(&controller, run);
    let snapshot = Uuid::new_v4();
    controller.record_mobile_install(Uuid::new_v4(), config(snapshot), Vec::new());
    assert!(!controller.mobile_snapshot_attached(snapshot));
}

#[tokio::test]
async fn installed_claims_reads_the_ledger_without_the_nic_lock() {
    let controller = test_controller();
    let run = Uuid::new_v4();
    let _root = open_run(&controller, run);
    let mut nics = SharedVirtualNicRegistry::new();
    let member = test_member(&mut nics, run);
    controller.bind_member(run, &member).unwrap();

    let attachment = Uuid::new_v4();
    controller.record_mobile_install(attachment, config(Uuid::new_v4()), vec![tun_member(run)]);
    assert!(controller.mobile_ready(run, &member, attachment));

    // Holding the NIC lock must not block a synchronous ledger read.
    let nic = member.shared_nic();
    let _guard = nic.lock().await;
    assert_eq!(
        controller.mobile_installed_claims(run),
        Some(tun_member(run).claims)
    );
}

#[cfg(feature = "magic-dns")]
fn peer(accept_dns: bool, ipv4: Option<&str>) -> PeerRuntimeSnapshot {
    let mut peer = PeerRuntimeSnapshot::default();
    peer.flags.accept_dns = accept_dns;
    peer.runtime.core.routes.ipv4 = ipv4.map(|address| IpPrefix {
        address: address.parse().unwrap(),
        prefix_len: 24,
    });
    peer
}

#[cfg(feature = "magic-dns")]
fn dns_enabled_for(accept_dns: bool, ipv4: Option<&str>) -> bool {
    let controller = test_controller();
    let run = Uuid::new_v4();
    let _root = controller.open_instance(run).unwrap();
    controller
        .bind_config(
            run,
            CoreRuntimeConfigStore::new(
                CoreRuntimeConfig::default(),
                Arc::new(peer(accept_dns, ipv4)),
            ),
        )
        .unwrap();
    controller.mobile_dns_enabled(run)
}

#[cfg(feature = "magic-dns")]
#[test]
fn dns_enabled_reads_the_current_configuration() {
    assert!(dns_enabled_for(true, Some("10.126.126.7")));
    assert!(!dns_enabled_for(false, Some("10.126.126.7")));
    assert!(!dns_enabled_for(true, None));

    let controller = test_controller();
    let run = Uuid::new_v4();
    let root = controller.open_instance(run).unwrap();
    controller
        .bind_config(
            run,
            CoreRuntimeConfigStore::new(
                CoreRuntimeConfig::default(),
                Arc::new(peer(true, Some("10.126.126.7"))),
            ),
        )
        .unwrap();
    assert!(!controller.mobile_dns_enabled(Uuid::new_v4()));
    drop(root);
    assert!(!controller.mobile_dns_enabled(run));
    controller.request_shutdown();
    assert!(!controller.mobile_dns_enabled(run));
}

#[tokio::test]
async fn mobile_scope_is_an_input_and_reads_do_not_rewrite_it() {
    let controller = test_controller();
    controller.dirty.reset();
    controller.set_mobile_scope(None).unwrap();
    assert!(
        !controller.dirty.peek(),
        "the default scope is already None"
    );

    let ids = BTreeSet::from([Uuid::new_v4()]);
    controller.set_mobile_scope(Some(ids.clone())).unwrap();
    assert!(controller.dirty.peek(), "a real scope change marks input");
    controller.dirty.reset();
    controller.set_mobile_scope(Some(ids.clone())).unwrap();
    assert!(
        !controller.dirty.peek(),
        "the same scope value does not mark again"
    );

    controller.dirty.reset();
    let _ = controller.mobile_config().await.unwrap();
    assert!(
        !controller.dirty.peek(),
        "reading the complete table does not rewrite the scope"
    );
    controller.set_mobile_scope(Some(BTreeSet::new())).unwrap();
    assert!(
        controller.dirty.peek(),
        "an explicit empty range differs from a set of ids"
    );
    controller.dirty.reset();
    controller.set_mobile_scope(None).unwrap();
    assert!(
        controller.dirty.peek(),
        "removing the range is a real input change"
    );
}

#[tokio::test]
async fn manual_policy_three_states_and_additional_are_projected_without_a_member() {
    let controller = test_controller();
    let global = Arc::new(GlobalCtx::new(TomlConfig::default()));
    let run = global.key();
    let registry = controller.open_instance(run).unwrap();
    controller
        .bind_mobile_inputs(
            run,
            Arc::downgrade(&global),
            Arc::new(parking_lot::Mutex::new(None)),
        )
        .unwrap();
    global.set_ipv4(Some("10.50.0.1/24".parse().unwrap()));
    let store = CoreRuntimeConfigStore::new(
        CoreRuntimeConfig::default(),
        Arc::new(PeerRuntimeSnapshot::default()),
    );
    controller.bind_config(run, store.clone()).unwrap();
    let auto = registry.handle().open_slot(RouteSource::AutoProxy).unwrap();
    auto.set_routes(RouteSet::from([RouteSpec::for_tun(
        "10.51.0.0/24".parse().unwrap(),
    )]));
    let additional = registry
        .handle()
        .open_slot(RouteSource::Additional)
        .unwrap();
    additional.set_routes(RouteSet::from([RouteSpec::for_tun(
        "10.52.0.0/24".parse().unwrap(),
    )]));

    let automatic = controller.mobile_config().await.unwrap();
    assert_eq!(automatic.instance_ids, vec![global.get_id()]);
    assert_eq!(automatic.addresses, vec!["10.50.0.1/24"]);
    assert!(automatic.routes.contains(&"10.50.0.0/24".to_owned()));
    assert!(automatic.routes.contains(&"10.51.0.0/24".to_owned()));
    assert!(automatic.routes.contains(&"10.52.0.0/24".to_owned()));

    store.update_services(|services| services.manual_routes = Some(BTreeSet::new()));
    let empty_manual = controller.mobile_config().await.unwrap();
    assert!(
        !empty_manual.routes.contains(&"10.51.0.0/24".to_owned()),
        "Some(empty) suppresses every AutoProxy declaration"
    );
    assert!(empty_manual.routes.contains(&"10.52.0.0/24".to_owned()));
    assert!(
        empty_manual.routes.contains(&"10.50.0.0/24".to_owned()),
        "the address network prefix is still generated"
    );

    store.update_services(|services| {
        services.manual_routes = Some(BTreeSet::from(["10.53.0.0/24".parse().unwrap()]));
    });
    let manual = controller.mobile_config().await.unwrap();
    assert!(!manual.routes.contains(&"10.51.0.0/24".to_owned()));
    assert!(manual.routes.contains(&"10.52.0.0/24".to_owned()));
    assert!(manual.routes.contains(&"10.53.0.0/24".to_owned()));
}

#[tokio::test]
async fn scope_none_empty_and_subset_select_members_before_export() {
    let controller = test_controller();
    let first = Arc::new(GlobalCtx::new(TomlConfig::default()));
    let second = Arc::new(GlobalCtx::new(TomlConfig::default()));
    let first_run = first.key();
    let second_run = second.key();
    let _first_root = controller.open_instance(first_run).unwrap();
    let _second_root = controller.open_instance(second_run).unwrap();
    for (global, run, address) in [
        (&first, first_run, "10.61.0.1/24"),
        (&second, second_run, "10.62.0.1/24"),
    ] {
        controller
            .bind_mobile_inputs(
                run,
                Arc::downgrade(global),
                Arc::new(parking_lot::Mutex::new(None)),
            )
            .unwrap();
        global.set_ipv4(Some(address.parse().unwrap()));
    }

    let all = controller.mobile_config().await.unwrap();
    assert_eq!(all.instance_ids.len(), 2);

    controller.set_mobile_scope(Some(BTreeSet::new())).unwrap();
    let empty = controller.mobile_config().await.unwrap();
    assert!(empty.instance_ids.is_empty());
    assert!(empty.addresses.is_empty());
    assert!(empty.routes.is_empty());
    assert!(empty.rejected.is_empty());

    controller
        .set_mobile_scope(Some(BTreeSet::from([first.get_id()])))
        .unwrap();
    let subset = controller.mobile_config().await.unwrap();
    assert_eq!(subset.instance_ids, vec![first.get_id()]);
    assert_eq!(subset.addresses, vec!["10.61.0.1/24"]);

    let foreign = Uuid::new_v4();
    controller
        .set_mobile_scope(Some(BTreeSet::from([foreign])))
        .unwrap();
    let missing = controller.mobile_config().await.unwrap();
    assert!(missing.instance_ids.is_empty());
    assert_eq!(missing.rejected.len(), 1);
    assert_eq!(missing.rejected[0].instance_id, foreign);
    assert!(missing.rejected[0].error.contains("not participating"));
}

#[tokio::test]
async fn prepare_uses_the_same_table_and_rejects_stale_markers_without_nic_writes() {
    let controller = test_controller();
    let global = Arc::new(GlobalCtx::new(TomlConfig::default()));
    let run = global.key();
    let registry = controller.open_instance(run).unwrap();
    controller
        .bind_mobile_inputs(
            run,
            Arc::downgrade(&global),
            Arc::new(parking_lot::Mutex::new(None)),
        )
        .unwrap();
    global.set_ipv4(Some("10.70.0.1/24".parse().unwrap()));
    let mut nics = SharedVirtualNicRegistry::new();
    let member = test_member(&mut nics, run);
    controller.bind_member(run, &member).unwrap();
    let additional = registry
        .handle()
        .open_slot(RouteSource::Additional)
        .unwrap();
    additional.set_routes(RouteSet::from([RouteSpec::for_tun(
        "10.71.0.0/24".parse().unwrap(),
    )]));

    let config = controller.mobile_config().await.unwrap();
    let before = member.claims().await;
    let plan = controller
        .prepare_mobile_attach(config.snapshot_id)
        .await
        .unwrap();
    assert_eq!(plan.config.snapshot_id, config.snapshot_id);
    assert_eq!(plan.members.len(), 1);
    assert!(plan.withdraw.is_empty());
    assert!(
        plan.members[0]
            .installed_prefixes
            .contains(&"10.71.0.0/24".parse().unwrap())
    );

    let stale = config.snapshot_id;
    additional.set_routes(RouteSet::from([RouteSpec::for_tun(
        "10.72.0.0/24".parse().unwrap(),
    )]));
    let error = controller
        .prepare_mobile_attach(stale)
        .await
        .err()
        .expect("a stale marker is rejected")
        .to_string();
    assert!(error.contains("configuration changed"));
    assert_eq!(
        member.claims().await,
        before,
        "a mismatched marker performs no NIC write"
    );

    controller.set_mobile_scope(Some(BTreeSet::new())).unwrap();
    let empty = controller.mobile_config().await.unwrap();
    assert!(empty.instance_ids.is_empty());
    let plan = controller
        .prepare_mobile_attach(empty.snapshot_id)
        .await
        .unwrap();
    assert!(plan.members.is_empty());
    assert_eq!(plan.withdraw.len(), 1);
    assert_eq!(plan.withdraw[0].run, run);
    assert_eq!(plan.withdraw[0].registration, member.registration_id());
}
