//! Mobile controller tests: inputs, local evidence and local reconciliation.

use std::{collections::BTreeSet, sync::Arc};

use cidr::IpCidr;
#[cfg(feature = "magic-dns")]
use easytier_core::config::IpPrefix;
use easytier_core::{
    config::{
        peers::PeerRuntimeSnapshot,
        runtime::{CoreRuntimeConfig, CoreRuntimeConfigStore},
    },
    host::route::{RouteSlot, RouteStatus},
};

use super::super::member::claim_prefixes;
use super::super::mobile::RouteReconciler;
use super::super::*;
use crate::{
    common::{config::TomlConfig, global_ctx::GlobalCtx, net_ns::tests::test_net_ns},
    instance::{shared_virtual_nic::SharedVirtualNicRegistry, virtual_nic::VirtualNicConfig},
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

fn test_managed_member(
    registry: &mut SharedVirtualNicRegistry,
    run: Uuid,
) -> SharedVirtualNicMember {
    registry.create_member(
        format!("et-{run}"),
        VirtualNicConfig::new(format!("et-{run}"), 1400, test_net_ns(None))
            .with_routes_managed(true),
        run,
        Arc::new(Notify::new()),
    )
}

fn status_of(slot: &RouteSlot, prefix: IpCidr) -> Option<RouteStatus> {
    slot.statuses()
        .into_iter()
        .find_map(|(declaration, status)| (declaration.destination == prefix).then_some(status))
}

/// One live instance with inputs and declarations but no member. This is the
/// no-NIC export/feedback path.
fn input_only_instance(
    controller: &RouteController,
    ipv4: &str,
    declaration: &str,
) -> (Arc<GlobalCtx>, Arc<Registry>, RouteSlot) {
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
    global.set_ipv4(Some(ipv4.parse().unwrap()));
    let slot = registry
        .handle()
        .open_slot(RouteSource::Additional)
        .unwrap();
    slot.set_routes(RouteSet::from([RouteSpec::for_tun(
        declaration.parse().unwrap(),
    )]));
    (global, registry, slot)
}

/// Attach the member's registration under the NIC lock, as device creation
/// does. No device or dispatcher is created here.
async fn attach_nic_registration(member: &SharedVirtualNicMember) {
    let shared_nic = member.shared_nic();
    let mut nic = shared_nic.lock().await;
    nic.attach_member_registration(member.member_id(), member.registration_id())
        .await
        .unwrap();
}

/// One live mobile instance with a managed member and one Additional route.
struct MobileHarness {
    controller: RouteController,
    _global: Arc<GlobalCtx>,
    run: Uuid,
    registry: Arc<Registry>,
    _nics: SharedVirtualNicRegistry,
    member: SharedVirtualNicMember,
    slot: RouteSlot,
}

impl MobileHarness {
    async fn new(declaration: &str) -> Self {
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
        global.set_ipv4(Some("10.90.0.1/24".parse().unwrap()));
        controller
            .bind_config(
                run,
                CoreRuntimeConfigStore::new(
                    CoreRuntimeConfig::default(),
                    Arc::new(PeerRuntimeSnapshot::default()),
                ),
            )
            .unwrap();
        let mut nics = SharedVirtualNicRegistry::new();
        let member = test_managed_member(&mut nics, run);
        attach_nic_registration(&member).await;
        controller.bind_member(run, &member).unwrap();
        let slot = registry
            .handle()
            .open_slot(RouteSource::Additional)
            .unwrap();
        slot.set_routes(RouteSet::from([RouteSpec::for_tun(
            declaration.parse().unwrap(),
        )]));
        Self {
            controller,
            _global: global,
            run,
            registry,
            _nics: nics,
            member,
            slot,
        }
    }

    fn declaration(&self, prefix: &str) -> IpCidr {
        let _ = self;
        prefix.parse().unwrap()
    }

    fn status(&self, prefix: IpCidr) -> Option<RouteStatus> {
        status_of(&self.slot, prefix)
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

#[tokio::test]
async fn local_evidence_is_registration_scoped_and_never_recreates_records() {
    let controller = test_controller();
    let run = Uuid::new_v4();
    let _root = open_run(&controller, run);
    let mut nics = SharedVirtualNicRegistry::new();
    let first = test_member(&mut nics, run);
    controller.bind_member(run, &first).unwrap();
    let prefixes = BTreeSet::from(["10.126.126.0/24".parse().unwrap()]);

    controller.dirty.reset();
    assert!(controller.record_mobile_ready(run, &first, prefixes.clone()));
    assert!(controller.dirty.peek(), "new local evidence marks");
    assert_eq!(
        controller.mobile_installed_prefixes(run, first.registration_id()),
        Some(prefixes.clone())
    );
    controller.dirty.reset();
    assert!(
        controller.record_mobile_ready(run, &first, prefixes.clone()),
        "a repeated matching report is still accepted"
    );
    assert!(
        !controller.dirty.peek(),
        "unchanged evidence is not a new notification"
    );

    let other = test_member(&mut nics, run);
    assert!(
        !controller.record_mobile_ready(run, &other, prefixes.clone()),
        "only the current registration may record evidence"
    );

    let second = test_member(&mut nics, run);
    controller.bind_member(run, &second).unwrap();
    assert_eq!(
        controller.mobile_installed_prefixes(run, first.registration_id()),
        None,
        "a new binding invalidates the old registration's evidence"
    );
    assert!(controller.record_mobile_ready(run, &second, prefixes.clone()));
    assert!(
        !controller.record_mobile_ready(run, &first, prefixes.clone()),
        "an old registration can never confirm the new binding"
    );

    first.close().await.unwrap();
    controller.unready(run, first.registration_id());
    assert_eq!(
        controller.mobile_installed_prefixes(run, second.registration_id()),
        Some(prefixes.clone()),
        "an old registration's unready cannot invalidate the current evidence"
    );
    second.close().await.unwrap();
    assert!(
        !controller.record_mobile_ready(run, &second, prefixes.clone()),
        "a closed member cannot record evidence"
    );

    controller.unready(run, second.registration_id());
    assert_eq!(
        controller.mobile_installed_prefixes(run, second.registration_id()),
        None
    );
    controller.dirty.reset();
    controller.unready(run, second.registration_id());
    assert!(
        !controller.dirty.peek(),
        "a stale unready for an absent registration is a no-op"
    );

    let third = test_member(&mut nics, run);
    controller.bind_member(run, &third).unwrap();
    controller.runtime.write().instances.remove(&run);
    assert!(
        !controller.record_mobile_ready(run, &third, prefixes),
        "recording evidence never recreates a removed instance record"
    );
    assert_eq!(
        controller.mobile_installed_prefixes(run, third.registration_id()),
        None
    );
}

/// Run a synchronous state-changing action after registering the waiter, then
/// require that the Controller's real notification wakes it.
async fn expect_wake(changed: &Notify, action: impl FnOnce()) {
    let notified = changed.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    action();
    tokio::time::timeout(std::time::Duration::from_secs(1), notified)
        .await
        .expect("a real state change must wake the host notification");
}

/// Run a no-op action after registering the waiter and require that it does
/// not manufacture a notification.
async fn expect_no_wake(changed: &Notify, action: impl FnOnce()) {
    let notified = changed.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    action();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), notified)
            .await
            .is_err(),
        "an unchanged state must not notify the host"
    );
}

#[tokio::test]
async fn only_real_local_evidence_changes_notify_the_host() {
    let controller = test_controller();
    let run = Uuid::new_v4();
    let _root = open_run(&controller, run);
    let mut nics = SharedVirtualNicRegistry::new();
    let member = test_member(&mut nics, run);
    controller.bind_member(run, &member).unwrap();
    let changed = controller.changed().clone();
    let prefixes = BTreeSet::from(["10.127.127.0/24".parse().unwrap()]);

    expect_wake(&changed, || {
        assert!(controller.record_mobile_ready(run, &member, prefixes.clone()));
    })
    .await;
    expect_no_wake(&changed, || {
        assert!(controller.record_mobile_ready(run, &member, prefixes.clone()));
    })
    .await;

    expect_wake(&changed, || {
        controller.unready(run, member.registration_id());
    })
    .await;
    expect_no_wake(&changed, || {
        controller.unready(run, member.registration_id());
    })
    .await;

    // A later real attachment report is recovery, not a duplicate ACK.
    expect_wake(&changed, || {
        assert!(controller.record_mobile_ready(run, &member, prefixes));
    })
    .await;
}

#[tokio::test]
async fn worker_consumes_real_inputs_notifies_once_and_then_waits() {
    let controller = test_controller();
    let changed = controller.changed().clone();
    let worker = tokio::spawn(RouteReconciler::new(controller.clone()).run());

    // The worker's first round consumes its own initial mark. Wait for that
    // real notification before asserting the quiet state.
    let notified = changed.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    tokio::time::timeout(std::time::Duration::from_secs(1), notified)
        .await
        .expect("the initial policy round must be observable");
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), changed.notified())
            .await
            .is_err(),
        "an idle worker must not produce a self-notification loop"
    );

    let scope = BTreeSet::from([Uuid::new_v4()]);
    let notified = changed.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    controller.set_mobile_scope(Some(scope.clone())).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), notified)
        .await
        .expect("a real scope input must reach the host after processing");
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), changed.notified())
            .await
            .is_err(),
        "consuming one input must not leave a second wake pending"
    );
    expect_no_wake(&changed, || {
        controller.set_mobile_scope(Some(scope)).unwrap();
    })
    .await;

    let run = Uuid::new_v4();
    let notified = changed.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    let root = controller.open_instance(run).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), notified)
        .await
        .expect("a new instance record must reach the host");

    // Address, DHCP, public-address and DNS writers mark the same input; the
    // host must observe the resulting processing, not a stale cached table.
    let notified = changed.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    controller.invalidate_instance(&run);
    tokio::time::timeout(std::time::Duration::from_secs(1), notified)
        .await
        .expect("a real route input invalidation must reach the host");

    let config = CoreRuntimeConfigStore::new(
        CoreRuntimeConfig::default(),
        Arc::new(PeerRuntimeSnapshot::default()),
    );
    let notified = changed.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    controller.bind_config(run, config.clone()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), notified)
        .await
        .expect("binding the current configuration must reach the host");

    let mut dns_peer = PeerRuntimeSnapshot::default();
    dns_peer.flags.accept_dns = true;
    let dns_peer = Arc::new(dns_peer);
    let notified = changed.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    config.update_peer(dns_peer.clone());
    tokio::time::timeout(std::time::Duration::from_secs(1), notified)
        .await
        .expect("a real DNS policy change must reach the host");
    expect_no_wake(&changed, || config.update_peer(dns_peer)).await;

    let notified = changed.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    drop(root);
    tokio::time::timeout(std::time::Duration::from_secs(1), notified)
        .await
        .expect("the last Root release and cleanup progress must reach the host");

    controller.request_shutdown();
    tokio::time::timeout(std::time::Duration::from_secs(1), worker)
        .await
        .expect("the idle worker must stop after shutdown")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn ready_requires_the_complete_plan_ack_and_this_members_installed_evidence() {
    let h = MobileHarness::new("10.91.0.0/24").await;
    let declaration = h.declaration("10.91.0.0/24");
    let mut reconciler = RouteReconciler::new(h.controller.clone());

    reconciler.reconcile().await;
    assert_eq!(
        h.status(declaration),
        Some(RouteStatus::Pending { error: None }),
        "local route ACK without installed evidence is only Pending"
    );
    let claims_after_reconcile = h.member.claims().await;
    assert!(
        claim_prefixes(&claims_after_reconcile).contains(&declaration),
        "the worker really committed the Controller-decided target"
    );

    let config = h.controller.mobile_config().await.unwrap();
    let plan = h
        .controller
        .prepare_mobile_attach(config.snapshot_id)
        .await
        .unwrap();
    let accepted = plan
        .members
        .iter()
        .find(|member| member.run == h.run)
        .expect("the live member is accepted");
    assert!(accepted.installed_prefixes.contains(&declaration));
    assert_eq!(
        plan.config.snapshot_id, config.snapshot_id,
        "get and prepare must return the same complete result"
    );
    assert_eq!(
        accepted.installed_prefixes,
        claim_prefixes(&h.member.claims().await),
        "the worker committed exactly the plan's member target"
    );
    assert!(h.controller.record_mobile_ready(
        h.run,
        &h.member,
        accepted.installed_prefixes.clone()
    ));

    reconciler.reconcile().await;
    assert_eq!(
        h.status(declaration),
        Some(RouteStatus::Ready),
        "ready needs the exact plan target, its ACK and this member's evidence"
    );

    h.controller.unready(h.run, h.member.registration_id());
    reconciler.reconcile().await;
    assert_eq!(
        h.status(declaration),
        Some(RouteStatus::Pending { error: None }),
        "removing this member's evidence invalidates Ready"
    );
}

#[tokio::test]
async fn root_withdrawal_keeps_the_record_until_real_registration_cleanup() {
    let h = MobileHarness::new("10.92.0.0/24").await;
    let mut reconciler = RouteReconciler::new(h.controller.clone());
    reconciler.reconcile().await;
    let config = h.controller.mobile_config().await.unwrap();
    let plan = h
        .controller
        .prepare_mobile_attach(config.snapshot_id)
        .await
        .unwrap();
    let accepted = plan
        .members
        .iter()
        .find(|member| member.run == h.run)
        .expect("the live member is accepted");
    assert!(h.controller.record_mobile_ready(
        h.run,
        &h.member,
        accepted.installed_prefixes.clone()
    ));

    drop(h.registry);
    reconciler.reconcile().await;
    assert!(
        h.controller.runtime.read().instances.contains_key(&h.run),
        "empty routes do not remove a record while installed evidence remains"
    );
    h.controller.request_shutdown();
    reconciler.reconcile().await;
    assert!(
        h.controller.ensure_drained().is_err(),
        "local installed evidence is still outstanding"
    );

    h.member.close().await.unwrap();
    reconciler.reconcile().await;
    assert!(
        !h.controller.runtime.read().instances.contains_key(&h.run),
        "the record is removed only after the real registration cleanup"
    );
    assert!(
        h.controller.ensure_drained().is_ok(),
        "drain waits for local records and evidence, not external VPN state"
    );
}

#[tokio::test]
async fn drain_waits_only_for_local_records() {
    let controller = test_controller();
    let run = Uuid::new_v4();
    let root = open_run(&controller, run);
    controller.request_shutdown();
    assert!(controller.ensure_drained().is_err());

    drop(root);
    let mut reconciler = RouteReconciler::new(controller.clone());
    reconciler.reconcile().await;
    assert!(
        controller.ensure_drained().is_ok(),
        "a released root with no local member responsibility drains immediately"
    );
}

#[tokio::test]
async fn controller_rejection_is_fed_back_without_recomputing_the_target() {
    let controller = test_controller();
    let (first, _first_root, first_slot) =
        input_only_instance(&controller, "10.95.0.1/24", "10.95.0.0/24");
    let (_second, _second_root, second_slot) =
        input_only_instance(&controller, "10.95.0.2/24", "10.95.0.0/24");
    let first_declaration: IpCidr = "10.95.0.0/24".parse().unwrap();

    let config = controller.mobile_config().await.unwrap();
    assert_eq!(config.rejected.len(), 1);
    let rejected = &config.rejected[0];
    let (rejected_slot, accepted_slot) = if rejected.instance_id == first.get_id() {
        (&first_slot, &second_slot)
    } else {
        (&second_slot, &first_slot)
    };

    let mut reconciler = RouteReconciler::new(controller.clone());
    reconciler.reconcile().await;
    match status_of(rejected_slot, first_declaration) {
        Some(RouteStatus::Rejected(error)) => {
            assert_eq!(&*error, rejected.error.as_str());
        }
        other => panic!("expected the Controller's rejection, got {other:?}"),
    }
    assert_eq!(
        status_of(accepted_slot, first_declaration),
        Some(RouteStatus::Pending { error: None }),
        "the accepted instance has no registration or installed evidence yet"
    );
}

#[tokio::test]
async fn another_members_evidence_cannot_confirm_this_member() {
    let controller = test_controller();
    let first = Arc::new(GlobalCtx::new(TomlConfig::default()));
    let second = Arc::new(GlobalCtx::new(TomlConfig::default()));
    let first_run = first.key();
    let second_run = second.key();
    let first_registry = controller.open_instance(first_run).unwrap();
    let second_registry = controller.open_instance(second_run).unwrap();
    let mut nics = SharedVirtualNicRegistry::new();
    let first_member = test_managed_member(&mut nics, first_run);
    let second_member = test_managed_member(&mut nics, second_run);
    attach_nic_registration(&first_member).await;
    attach_nic_registration(&second_member).await;
    for (global, run, address, member) in [
        (&first, first_run, "10.96.0.1/24", &first_member),
        (&second, second_run, "10.97.0.1/24", &second_member),
    ] {
        controller
            .bind_mobile_inputs(
                run,
                Arc::downgrade(global),
                Arc::new(parking_lot::Mutex::new(None)),
            )
            .unwrap();
        global.set_ipv4(Some(address.parse().unwrap()));
        controller
            .bind_config(
                run,
                CoreRuntimeConfigStore::new(
                    CoreRuntimeConfig::default(),
                    Arc::new(PeerRuntimeSnapshot::default()),
                ),
            )
            .unwrap();
        controller.bind_member(run, member).unwrap();
    }
    let first_slot = first_registry
        .handle()
        .open_slot(RouteSource::Additional)
        .unwrap();
    first_slot.set_routes(RouteSet::from([RouteSpec::for_tun(
        "10.96.0.0/24".parse().unwrap(),
    )]));
    let second_slot = second_registry
        .handle()
        .open_slot(RouteSource::Additional)
        .unwrap();
    second_slot.set_routes(RouteSet::from([RouteSpec::for_tun(
        "10.97.0.0/24".parse().unwrap(),
    )]));
    let first_declaration: IpCidr = "10.96.0.0/24".parse().unwrap();
    let second_declaration: IpCidr = "10.97.0.0/24".parse().unwrap();

    let mut reconciler = RouteReconciler::new(controller.clone());
    reconciler.reconcile().await;
    let config = controller.mobile_config().await.unwrap();
    let plan = controller
        .prepare_mobile_attach(config.snapshot_id)
        .await
        .unwrap();
    let first_accepted = plan
        .members
        .iter()
        .find(|member| member.run == first_run)
        .expect("the first member is accepted");
    assert!(controller.record_mobile_ready(
        first_run,
        &first_member,
        first_accepted.installed_prefixes.clone()
    ));

    reconciler.reconcile().await;
    assert_eq!(
        status_of(&first_slot, first_declaration),
        Some(RouteStatus::Ready)
    );
    assert_eq!(
        status_of(&second_slot, second_declaration),
        Some(RouteStatus::Pending { error: None }),
        "the first member's installed evidence must not confirm the second"
    );
}

#[tokio::test]
async fn a_later_declaration_is_not_confirmed_by_previous_installed_evidence() {
    let h = MobileHarness::new("10.93.0.0/24").await;
    let first: IpCidr = "10.93.0.0/24".parse().unwrap();
    let second: IpCidr = "10.94.0.0/24".parse().unwrap();
    let mut reconciler = RouteReconciler::new(h.controller.clone());
    reconciler.reconcile().await;
    let config = h.controller.mobile_config().await.unwrap();
    let plan = h
        .controller
        .prepare_mobile_attach(config.snapshot_id)
        .await
        .unwrap();
    let accepted = plan
        .members
        .iter()
        .find(|member| member.run == h.run)
        .unwrap();
    assert!(h.controller.record_mobile_ready(
        h.run,
        &h.member,
        accepted.installed_prefixes.clone()
    ));
    reconciler.reconcile().await;
    assert_eq!(h.status(first), Some(RouteStatus::Ready));

    // The declaration changes while the old installed evidence remains. The
    // worker can ACK the new target, but the new prefix has no system evidence.
    h.slot.set_routes(RouteSet::from([
        RouteSpec::for_tun(first.into()),
        RouteSpec::for_tun(second.into()),
    ]));
    reconciler.reconcile().await;
    assert_eq!(
        h.status(first),
        Some(RouteStatus::Ready),
        "unchanged prefix keeps its own evidence"
    );
    assert_eq!(
        h.status(second),
        Some(RouteStatus::Pending { error: None }),
        "a declaration added after installation is not confirmed by old evidence"
    );
}

#[tokio::test]
async fn closed_flag_does_not_count_as_cleanup_evidence() {
    let h = MobileHarness::new("10.95.0.0/24").await;
    let mut reconciler = RouteReconciler::new(h.controller.clone());
    reconciler.reconcile().await;
    let config = h.controller.mobile_config().await.unwrap();
    let plan = h
        .controller
        .prepare_mobile_attach(config.snapshot_id)
        .await
        .unwrap();
    let accepted = plan
        .members
        .iter()
        .find(|member| member.run == h.run)
        .unwrap();
    assert!(h.controller.record_mobile_ready(
        h.run,
        &h.member,
        accepted.installed_prefixes.clone()
    ));
    h.controller.request_shutdown();

    let shared_nic = h.member.shared_nic();
    let guard = shared_nic.lock().await;
    let mut close = Box::pin(h.member.close());
    assert!(
        futures::poll!(close.as_mut()).is_pending(),
        "close must block on the held NIC lock after setting its flag"
    );
    assert!(
        h.member.ensure_open().is_err(),
        "close marks the member closed before its cleanup finishes"
    );
    assert_eq!(
        h.controller
            .mobile_installed_prefixes(h.run, h.member.registration_id()),
        Some(accepted.installed_prefixes.clone()),
        "the closed flag must not erase real installed evidence"
    );
    assert!(
        h.controller.ensure_drained().is_err(),
        "shutdown cannot be reported drained while cleanup is blocked"
    );
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            h.controller.drain(h.run)
        )
        .await
        .is_err(),
        "the local drain must not finish before the member cleanup"
    );

    drop(guard);
    close.await.unwrap();
    reconciler.reconcile().await;
    assert!(h.controller.ensure_drained().is_ok());
}
