//! Unit tests for route_demand models, registry, and projection rules.

use std::{
    collections::BTreeSet,
    net::Ipv4Addr,
    str::FromStr,
    time::Duration,
};

use cidr::{IpCidr, Ipv4Cidr, Ipv4Inet, Ipv6Inet};

use super::*;

fn test_egress() -> LogicalEgress {
    LogicalEgress::new(InstanceRuntimeId::random())
}

#[tokio::test]
async fn test_source_registration_and_duplicate_slot() {
    let owner = InstanceOwner::new(InstanceRuntimeId::random());

    let pub1 = owner.register(SourceKind::ProxyCidr, "proxy").unwrap();
    assert_eq!(pub1.logical_slot, "proxy");
    assert_eq!(pub1.epoch, SourceEpoch(1));

    // Duplicate slot should fail
    let err = owner.register(SourceKind::ProxyCidr, "proxy").unwrap_err();
    assert_eq!(err, RegistryError::SlotAlreadyExists("proxy".into()));
}

#[tokio::test]
async fn test_publish_and_token_monotonicity() {
    let owner = InstanceOwner::new(InstanceRuntimeId::random());
    let reader = owner.reader();
    let publisher = owner.register(SourceKind::ProxyCidr, "slot1").unwrap();
    let egress = test_egress();

    let cidr1 = IpCidr::from_str("10.0.0.0/24").unwrap();
    let demand1 = RouteDemand::new(cidr1, RoutePurpose::PeerProxy, egress, LogicalDependency::None);

    let mut demands1 = BTreeSet::new();
    demands1.insert(demand1);

    // Initial publish
    let receipt1 = publisher
        .publish(demands1.clone(), ProjectionBasis::new())
        .unwrap();
    assert_eq!(receipt1.token.epoch, SourceEpoch(1));
    assert_eq!(receipt1.token.revision, SourceRevision(1));

    // Idempotent publish with identical demands: should return SAME token without bumping revision
    let receipt1_idempotent = publisher
        .publish(demands1.clone(), ProjectionBasis::new())
        .unwrap();
    assert_eq!(receipt1_idempotent.token, receipt1.token);

    // Publish with new demand set: should bump revision
    let cidr2 = IpCidr::from_str("10.1.0.0/24").unwrap();
    let demand2 = RouteDemand::new(cidr2, RoutePurpose::PeerProxy, egress, LogicalDependency::None);
    let mut demands2 = demands1.clone();
    demands2.insert(demand2);

    let receipt2 = publisher
        .publish(demands2.clone(), ProjectionBasis::new())
        .unwrap();
    assert_eq!(receipt2.token.epoch, SourceEpoch(1));
    assert_eq!(receipt2.token.revision, SourceRevision(2));

    // Verify snapshot in reader
    let snap = reader.current();
    let record = snap.sources.get(&publisher.source_id).unwrap();
    assert_eq!(record.epoch, SourceEpoch(1));
    assert!(matches!(record.status, SourceStatus::Active));
    assert_eq!(record.latest_snapshot.as_ref().unwrap().demands, demands2);
}

#[tokio::test]
async fn test_publish_basis_update_does_not_bump_demand_revision() {
    let owner = InstanceOwner::new(InstanceRuntimeId::random());
    let reader = owner.reader();
    let publisher = owner.register(SourceKind::ProxyCidr, "slot1").unwrap();
    let egress = test_egress();

    let cidr = IpCidr::from_str("10.0.0.0/24").unwrap();
    let mut demands = BTreeSet::new();
    demands.insert(RouteDemand::new(
        cidr,
        RoutePurpose::PeerProxy,
        egress,
        LogicalDependency::None,
    ));

    let receipt1 = publisher
        .publish(
            demands.clone(),
            ProjectionBasis::new().with_revision("ospf", 1),
        )
        .unwrap();
    assert_eq!(receipt1.token.revision, SourceRevision(1));
    let initial_reg_rev = receipt1.registry_revision;

    // Same demands, but updated diagnostic basis
    let receipt2 = publisher
        .publish(
            demands.clone(),
            ProjectionBasis::new().with_revision("ospf", 2),
        )
        .unwrap();
    // Demand token revision remains unchanged!
    assert_eq!(receipt2.token, receipt1.token);
    // But registry view revision is advanced to reflect the diagnostic update
    assert!(receipt2.registry_revision > initial_reg_rev);

    let snap = reader.current();
    let source_snap = snap
        .sources
        .get(&publisher.source_id)
        .unwrap()
        .latest_snapshot
        .as_ref()
        .unwrap();
    assert_eq!(
        source_snap.basis.input_revisions.get("ospf"),
        Some(&2)
    );
}

#[tokio::test]
async fn test_source_restart_epoch_increment_and_stale_baseline() {
    let owner = InstanceOwner::new(InstanceRuntimeId::random());
    let reader = owner.reader();
    let publisher_epoch1 = owner.register(SourceKind::ProxyCidr, "proxy").unwrap();
    let source_id = publisher_epoch1.source_id;
    let egress = test_egress();

    let cidr = IpCidr::from_str("10.0.0.0/24").unwrap();
    let mut demands = BTreeSet::new();
    demands.insert(RouteDemand::new(
        cidr,
        RoutePurpose::PeerProxy,
        egress,
        LogicalDependency::None,
    ));

    let receipt1 = publisher_epoch1
        .publish(demands.clone(), ProjectionBasis::new())
        .unwrap();
    let token1 = receipt1.token;

    // Restart the source
    let publisher_epoch2 = owner.restart(source_id).unwrap();
    assert_eq!(publisher_epoch2.source_id, source_id);
    assert_eq!(publisher_epoch2.epoch, SourceEpoch(2));

    // Old handle should be rejected with StaleEpoch
    let err = publisher_epoch1
        .publish(demands.clone(), ProjectionBasis::new())
        .unwrap_err();
    assert_eq!(
        err,
        PublishError::StaleEpoch {
            submitted: SourceEpoch(1),
            current: SourceEpoch(2),
        }
    );

    // Before epoch 2 publishes, reader observes Initializing with stale baseline preserved
    let snap_before = reader.current();
    let rec_before = snap_before.sources.get(&source_id).unwrap();
    assert!(matches!(rec_before.status, SourceStatus::Initializing));
    assert!(rec_before.latest_snapshot.is_none());
    assert_eq!(
        rec_before
            .stale_baseline
            .as_ref()
            .unwrap()
            .demands,
        demands
    );

    // Query for token1: should report Superseded by epoch 2 (even before epoch 2 publishes a token!)
    let lifecycle1 = reader.query_token(token1).unwrap();
    assert_eq!(
        lifecycle1,
        SubmissionLifecycle::Superseded {
            superseded_by_epoch: Some(SourceEpoch(2)),
            superseded_by_token: None,
        }
    );

    // Epoch 2 publishes its first snapshot
    let receipt2 = publisher_epoch2
        .publish(demands.clone(), ProjectionBasis::new())
        .unwrap();
    assert_eq!(receipt2.token.epoch, SourceEpoch(2));
    assert_eq!(receipt2.token.revision, SourceRevision(1));

    // Now query for token1 reports superseded with the new token
    let lifecycle1_after = reader.query_token(token1).unwrap();
    assert_eq!(
        lifecycle1_after,
        SubmissionLifecycle::Superseded {
            superseded_by_epoch: Some(SourceEpoch(2)),
            superseded_by_token: Some(receipt2.token),
        }
    );

    // Query for token2 reports Current and Fresh
    let lifecycle2 = reader.query_token(receipt2.token).unwrap();
    assert_eq!(lifecycle2, SubmissionLifecycle::Current { is_fresh: true });
}

#[tokio::test]
async fn test_source_explicit_revocation_and_tombstone() {
    let owner = InstanceOwner::new(InstanceRuntimeId::random());
    let reader = owner.reader();
    let publisher = owner.register(SourceKind::ProxyCidr, "proxy").unwrap();
    let source_id = publisher.source_id;
    let egress = test_egress();

    let cidr = IpCidr::from_str("10.0.0.0/24").unwrap();
    let mut demands = BTreeSet::new();
    demands.insert(RouteDemand::new(
        cidr,
        RoutePurpose::PeerProxy,
        egress,
        LogicalDependency::None,
    ));

    let receipt = publisher
        .publish(demands.clone(), ProjectionBasis::new())
        .unwrap();
    let token = receipt.token;

    // Explicitly revoke source
    let revocation = publisher.revoke().unwrap();
    assert_eq!(revocation.source_id, source_id);
    assert_eq!(revocation.epoch, SourceEpoch(1));

    // Snapshot should record Revoked and have no active demands
    let snap = reader.current();
    let rec = snap.sources.get(&source_id).unwrap();
    assert!(matches!(rec.status, SourceStatus::Revoked { .. }));
    assert!(rec.latest_snapshot.is_none());
    assert_eq!(snap.tombstones.get(&source_id), Some(&SourceEpoch(1)));

    // Token query must report Revoked
    let lifecycle = reader.query_token(token).unwrap();
    assert_eq!(lifecycle, SubmissionLifecycle::Revoked);
}

#[tokio::test]
async fn test_batch_publication_atomicity() {
    let owner = InstanceOwner::new(InstanceRuntimeId::random());
    let reader = owner.reader();
    let egress = test_egress();

    let pub_dns = owner.register(SourceKind::MagicDns, "dns").unwrap();
    let pub_prefix = owner
        .register(SourceKind::InterfacePrefix, "prefix")
        .unwrap();

    let scoped = owner
        .scoped_publisher(&[pub_dns.source_id, pub_prefix.source_id])
        .unwrap();

    let mut dns_demands = BTreeSet::new();
    dns_demands.insert(RouteDemand::new(
        IpCidr::from_str("7.7.7.7/32").unwrap(),
        RoutePurpose::MagicDnsFakeIp,
        egress,
        LogicalDependency::None,
    ));

    let mut prefix_demands = BTreeSet::new();
    prefix_demands.insert(RouteDemand::new(
        IpCidr::from_str("10.144.144.0/24").unwrap(),
        RoutePurpose::InterfaceSubnet,
        egress,
        LogicalDependency::AddressFactVersion(1),
    ));

    let updates = vec![
        SourceDemandUpdate {
            source_id: pub_dns.source_id,
            epoch: pub_dns.epoch,
            demands: dns_demands.clone(),
            basis: ProjectionBasis::new(),
        },
        SourceDemandUpdate {
            source_id: pub_prefix.source_id,
            epoch: pub_prefix.epoch,
            demands: prefix_demands.clone(),
            basis: ProjectionBasis::new(),
        },
    ];

    let batch_receipt = scoped.publish_batch(updates).unwrap();
    assert_eq!(batch_receipt.receipts.len(), 2);
    assert_eq!(
        batch_receipt.receipts[0].registry_revision,
        batch_receipt.registry_revision
    );
    assert_eq!(
        batch_receipt.receipts[1].registry_revision,
        batch_receipt.registry_revision
    );

    let snap = reader.current();
    assert_eq!(snap.revision, batch_receipt.registry_revision);
    assert_eq!(
        snap.sources
            .get(&pub_dns.source_id)
            .unwrap()
            .latest_snapshot
            .as_ref()
            .unwrap()
            .demands,
        dns_demands
    );
    assert_eq!(
        snap.sources
            .get(&pub_prefix.source_id)
            .unwrap()
            .latest_snapshot
            .as_ref()
            .unwrap()
            .demands,
        prefix_demands
    );
}

#[tokio::test]
async fn test_wait_obsolete_lifecycle_transitions() {
    let owner = InstanceOwner::new(InstanceRuntimeId::random());
    let reader = owner.reader();
    let publisher = owner.register(SourceKind::ProxyCidr, "proxy").unwrap();
    let egress = test_egress();

    let cidr1 = IpCidr::from_str("10.0.0.0/24").unwrap();
    let mut demands1 = BTreeSet::new();
    demands1.insert(RouteDemand::new(cidr1, RoutePurpose::PeerProxy, egress, LogicalDependency::None));

    let receipt1 = publisher
        .publish(demands1.clone(), ProjectionBasis::new())
        .unwrap();
    let token1 = receipt1.token;

    // Timeout waiting for obsolete when token is current
    let timeout_res = reader
        .wait_obsolete(token1, Some(Duration::from_millis(50)))
        .await;
    assert_eq!(timeout_res.unwrap_err(), WaitObsoleteError::Timeout);

    // Spawn task to supersede token1
    let pub_clone_source_id = publisher.source_id;
    let pub_clone_epoch = publisher.epoch;
    let cidr2 = IpCidr::from_str("10.1.0.0/24").unwrap();
    let mut demands2 = demands1.clone();
    demands2.insert(RouteDemand::new(cidr2, RoutePurpose::PeerProxy, egress, LogicalDependency::None));

    let publisher_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(30)).await;
        publisher
            .publish(demands2, ProjectionBasis::new())
            .unwrap();
    });

    let outcome = reader
        .wait_obsolete(token1, Some(Duration::from_secs(2)))
        .await
        .unwrap();

    publisher_task.await.unwrap();

    match outcome {
        ObsoleteOutcome::Superseded {
            superseded_by_epoch,
            superseded_by_token,
        } => {
            assert_eq!(superseded_by_epoch, Some(pub_clone_epoch));
            assert_eq!(
                superseded_by_token,
                Some(SourceSubmissionToken::new(
                    pub_clone_source_id,
                    pub_clone_epoch,
                    SourceRevision(2)
                ))
            );
        }
        other => panic!("expected Superseded, got {other:?}"),
    }
}

#[test]
fn test_resolve_proxy_cidrs_three_state_rules() {
    let peer_a = Ipv4Cidr::from_str("10.0.0.0/8").unwrap();
    let peer_b = Ipv4Cidr::from_str("172.16.0.0/16").unwrap();
    let mut peer_routes = BTreeSet::new();
    peer_routes.insert(peer_a);
    peer_routes.insert(peer_b);

    // 1. None: follows peer routes
    let res_none = resolve_proxy_cidrs(&peer_routes, None);
    assert_eq!(res_none, peer_routes);

    // 2. Some([]): explicit empty set suppresses peer routes
    let empty_set = BTreeSet::new();
    let res_empty = resolve_proxy_cidrs(&peer_routes, Some(&empty_set));
    assert!(res_empty.is_empty());

    // 3. Some([C]): manual override
    let manual_c = Ipv4Cidr::from_str("192.168.1.0/24").unwrap();
    let mut manual_routes = BTreeSet::new();
    manual_routes.insert(manual_c);

    let res_manual = resolve_proxy_cidrs(&peer_routes, Some(&manual_routes));
    assert_eq!(res_manual, manual_routes);
    assert_eq!(res_manual.len(), 1);
    assert!(res_manual.contains(&manual_c));
}

#[test]
fn test_normalize_cidr_clears_host_bits() {
    // 192.168.1.100/24 -> 192.168.1.0/24
    let normalized_v4 = parse_and_normalize_cidr("192.168.1.100/24").unwrap();
    assert_eq!(normalized_v4.to_string(), "192.168.1.0/24");

    // fd00::1234/64 -> fd00::/64
    let normalized_v6 = parse_and_normalize_cidr("fd00::1234/64").unwrap();
    assert_eq!(normalized_v6.to_string(), "fd00::/64");
}

#[test]
fn test_public_ipv6_egress_dependency_change_detected() {
    let egress = test_egress();
    let lease_a = Ipv6Inet::from_str("2001:db8::1/64").unwrap();
    let lease_b = Ipv6Inet::from_str("2001:db8::2/64").unwrap();

    let demands_a = project_public_ipv6_egress_demand(Some(lease_a), 1, egress);
    let demands_b = project_public_ipv6_egress_demand(Some(lease_b), 2, egress);

    // Even though both have destination ::/0 and PublicIpv6Default, their dependencies differ!
    assert_ne!(demands_a, demands_b);

    // When lease is None, output is empty
    let demands_none = project_public_ipv6_egress_demand(None, 0, egress);
    assert!(demands_none.is_empty());
}

#[test]
fn test_magic_dns_fake_ip_projection_inside_vs_outside_subnet() {
    let egress = test_egress();
    let fake_ip = Ipv4Addr::new(7, 7, 7, 7);

    // Tun device subnet is 10.144.144.1/24. 7.7.7.7 is outside subnet -> generates /32
    let tun_inet = Some(Ipv4Inet::from_str("10.144.144.1/24").unwrap());
    let demands_outside = project_magic_dns_demand(fake_ip, tun_inet, egress);
    assert_eq!(demands_outside.len(), 1);
    let demand = demands_outside.iter().next().unwrap();
    assert_eq!(demand.destination.network_length(), 32);
    assert_eq!(demand.destination.first_address(), std::net::IpAddr::V4(fake_ip));

    // If fake IP is 10.144.144.100 (inside tun subnet) -> empty set
    let fake_ip_inside = Ipv4Addr::new(10, 144, 144, 100);
    let demands_inside = project_magic_dns_demand(fake_ip_inside, tun_inet, egress);
    assert!(demands_inside.is_empty());
}
