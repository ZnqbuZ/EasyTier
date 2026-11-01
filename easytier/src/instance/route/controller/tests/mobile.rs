//! Mobile controller tests: request marks and the actual installation ledger.

use std::{collections::BTreeSet, sync::Arc};

#[cfg(feature = "magic-dns")]
use easytier_core::config::{IpPrefix, peers::PeerRuntimeSnapshot, runtime::CoreRuntimeConfig};

use super::super::*;
use crate::{
    common::net_ns::tests::test_net_ns,
    instance::{
        factory::{MobileTunConfig, mobile_tun::MobileTunMember},
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
    MobileTunMember {
        instance_id: run,
        run,
        claims: SharedIfConfigClaims {
            ipv4_addresses: BTreeSet::from(["10.126.126.7/24".parse().unwrap()]),
            ..Default::default()
        },
        current_claims: None,
        dns: false,
    }
}

fn config(snapshot_id: Uuid) -> MobileTunConfig {
    MobileTunConfig {
        snapshot_id,
        ..Default::default()
    }
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
