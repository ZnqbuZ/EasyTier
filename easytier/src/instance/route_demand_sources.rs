//! Host-side route demand sources for Magic DNS and Explicit Interface Prefixes.
//!
//! Translates host address and DNS lifecycle events into versioned demands published
//! to the instance DemandRegistry, without executing any new host system routing writes.

use std::{
    collections::BTreeSet,
    net::Ipv4Addr,
    sync::Arc,
};

use cidr::{IpCidr, Ipv4Cidr, Ipv4Inet, Ipv6Cidr, Ipv6Inet};
use easytier_core::{
    instance::HostRouteDemandContext,
    route_demand::{
        model::{
            LogicalEgress, ProjectionBasis, SourceKind,
        },
        projection::{project_interface_subnet_demand, project_magic_dns_demand},
        registry::{PublishError, RegistryError, ScopedPublisher, SourceDemandUpdate, SourcePublisher},
    },
};
use parking_lot::Mutex;

/// Returns true if the host platform requires explicit route entries for virtual interface
/// subnet prefixes (e.g. macOS without NetworkExtension and FreeBSD).
pub fn platform_requires_explicit_interface_prefix() -> bool {
    cfg!(any(
        all(target_os = "macos", not(feature = "macos-ne")),
        target_os = "freebsd"
    ))
}

struct HostDemandPublishers {
    #[allow(dead_code)]
    context: HostRouteDemandContext,
    magic_dns_publisher: SourcePublisher,
    interface_prefix_publisher: SourcePublisher,
    scoped_publisher: ScopedPublisher,
    address_fact_version: u64,
    egress: LogicalEgress,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingFacts {
    ipv4: Option<Ipv4Inet>,
    ipv6: Option<Ipv6Inet>,
    accept_dns: bool,
    fake_ip: Ipv4Addr,
}

/// Host demand sources manager held by the host runtime.
pub struct HostRouteDemandSources {
    inner: Mutex<Option<HostDemandPublishers>>,
    pending_facts: Mutex<Option<PendingFacts>>,
    force_explicit_prefix: bool,
}

impl HostRouteDemandSources {
    /// Constructs host demand sources adhering to native platform semantics.
    pub fn new() -> Arc<Self> {
        Self::new_with_explicit_prefix_override(false)
    }

    /// Constructs host demand sources with an explicit prefix requirement override
    /// for deterministic cross-platform unit and integration testing.
    pub fn new_with_explicit_prefix_override(force_explicit_prefix: bool) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(None),
            pending_facts: Mutex::new(None),
            force_explicit_prefix,
        })
    }

    /// Initializes host sources using the context received from Core lifecycle.
    pub fn initialize(&self, context: HostRouteDemandContext) -> Result<(), RegistryError> {
        let magic_dns_publisher = context.register_source(SourceKind::MagicDns, "host.magic_dns")?;
        let interface_prefix_publisher =
            context.register_source(SourceKind::InterfacePrefix, "host.interface_prefix")?;
        let scoped_publisher = context.scoped_publisher(&[
            magic_dns_publisher.source_id,
            interface_prefix_publisher.source_id,
        ])?;
        let egress = LogicalEgress::new(context.instance_runtime_id());

        let publishers = HostDemandPublishers {
            context,
            magic_dns_publisher,
            interface_prefix_publisher,
            scoped_publisher,
            address_fact_version: 0,
            egress,
        };

        *self.inner.lock() = Some(publishers);

        let pending = self.pending_facts.lock().take();
        if let Some(facts) = pending {
            let _ = self.update_address_and_dns_facts(
                facts.ipv4,
                facts.ipv6,
                facts.accept_dns,
                facts.fake_ip,
            );
        }

        Ok(())
    }

    /// Publishes updated address and DNS facts atomically across both host sources.
    pub fn update_address_and_dns_facts(
        &self,
        ipv4: Option<Ipv4Inet>,
        ipv6: Option<Ipv6Inet>,
        accept_dns: bool,
        fake_ip: Ipv4Addr,
    ) -> Result<(), PublishError> {
        let mut lock = self.inner.lock();
        let Some(inner) = lock.as_mut() else {
            *self.pending_facts.lock() = Some(PendingFacts {
                ipv4,
                ipv6,
                accept_dns,
                fake_ip,
            });
            return Ok(());
        };

        inner.address_fact_version = inner.address_fact_version.saturating_add(1);
        let fact_version = inner.address_fact_version;
        let egress = inner.egress;

        // 1. Magic DNS demands
        let dns_demands = if accept_dns {
            project_magic_dns_demand(fake_ip, ipv4, egress)
        } else {
            BTreeSet::new()
        };
        let mut dns_basis = ProjectionBasis::default();
        dns_basis
            .input_revisions
            .insert("address_fact_version".to_string(), fact_version);
        dns_basis
            .input_revisions
            .insert("accept_dns".to_string(), if accept_dns { 1 } else { 0 });

        // 2. Explicit interface prefix demands
        let mut prefix_demands = BTreeSet::new();
        if self.force_explicit_prefix || platform_requires_explicit_interface_prefix() {
            if let Some(inet) = ipv4 {
                let cidr = Ipv4Cidr::new(inet.first_address(), inet.network_length())
                    .map_err(|e| PublishError::InvalidDemand(e.to_string()))?;
                prefix_demands.insert(project_interface_subnet_demand(
                    IpCidr::V4(cidr),
                    fact_version,
                    egress,
                ));
            }
            if let Some(inet) = ipv6 {
                let cidr = Ipv6Cidr::new(inet.first_address(), inet.network_length())
                    .map_err(|e| PublishError::InvalidDemand(e.to_string()))?;
                prefix_demands.insert(project_interface_subnet_demand(
                    IpCidr::V6(cidr),
                    fact_version,
                    egress,
                ));
            }
        }
        let mut prefix_basis = ProjectionBasis::default();
        prefix_basis
            .input_revisions
            .insert("address_fact_version".to_string(), fact_version);

        // 3. Commit atomically via scoped publisher
        let updates = vec![
            SourceDemandUpdate {
                source_id: inner.magic_dns_publisher.source_id,
                epoch: inner.magic_dns_publisher.epoch,
                demands: dns_demands,
                basis: dns_basis,
            },
            SourceDemandUpdate {
                source_id: inner.interface_prefix_publisher.source_id,
                epoch: inner.interface_prefix_publisher.epoch,
                demands: prefix_demands,
                basis: prefix_basis,
            },
        ];

        inner.scoped_publisher.publish_batch(updates)?;
        Ok(())
    }

    /// Marks Magic DNS source as temporarily unavailable.
    pub fn mark_magic_dns_unavailable(&self, reason: impl Into<String>) {
        if let Some(inner) = self.inner.lock().as_ref() {
            let _ = inner.magic_dns_publisher.mark_unavailable(reason);
        }
    }

    /// Marks interface prefix source as temporarily unavailable.
    pub fn mark_interface_unavailable(&self, reason: impl Into<String>) {
        if let Some(inner) = self.inner.lock().as_ref() {
            let _ = inner.interface_prefix_publisher.mark_unavailable(reason);
        }
    }

    /// Revokes both host sources on runtime shutdown.
    pub fn shutdown(&self) {
        let mut lock = self.inner.lock();
        if let Some(inner) = lock.take() {
            let _ = inner.magic_dns_publisher.revoke();
            let _ = inner.interface_prefix_publisher.revoke();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use easytier_core::instance::CoreRouteDemands;
    use easytier_core::route_demand::model::{InstanceRuntimeId, RoutePurpose};
    use easytier_core::route_demand::registry::InstanceOwner;

    #[test]
    fn test_host_route_demand_sources_lifecycle() {
        let instance_id = InstanceRuntimeId::random();
        let owner = InstanceOwner::new(instance_id);
        let demands = CoreRouteDemands::new(owner.reader());
        let host_ctx = HostRouteDemandContext::new(demands.clone(), owner);

        let sources = HostRouteDemandSources::new_with_explicit_prefix_override(true);

        // Update facts before initialize (pending facts)
        let fake_ip = Ipv4Addr::new(100, 100, 100, 101);
        let tun_ip = Ipv4Inet::from_str("10.144.1.5/24").unwrap();
        sources
            .update_address_and_dns_facts(Some(tun_ip), None, true, fake_ip)
            .unwrap();

        // Initialize transfers pending facts and publishes atomically
        sources.initialize(host_ctx).unwrap();

        let snap = demands.current();
        assert_eq!(snap.sources.len(), 2);

        // Magic DNS has /32
        let dns_source = snap
            .sources
            .values()
            .find(|s| s.source_id.kind == SourceKind::MagicDns)
            .unwrap();
        let dns_snap = dns_source.latest_snapshot.as_ref().unwrap();
        assert_eq!(dns_snap.demands.len(), 1);
        let dns_demand = dns_snap.demands.iter().next().unwrap();
        assert_eq!(dns_demand.purpose, RoutePurpose::MagicDnsFakeIp);
        assert_eq!(
            dns_demand.destination,
            IpCidr::V4(Ipv4Cidr::new(fake_ip, 32).unwrap())
        );

        // Interface prefix has /24
        let prefix_source = snap
            .sources
            .values()
            .find(|s| s.source_id.kind == SourceKind::InterfacePrefix)
            .unwrap();
        let prefix_snap = prefix_source.latest_snapshot.as_ref().unwrap();
        assert_eq!(prefix_snap.demands.len(), 1);
        let prefix_demand = prefix_snap.demands.iter().next().unwrap();
        assert_eq!(prefix_demand.purpose, RoutePurpose::InterfaceSubnet);
        assert_eq!(
            prefix_demand.destination,
            IpCidr::V4(Ipv4Cidr::new(tun_ip.first_address(), 24).unwrap())
        );

        // Address change to a subnet containing fake_ip -> Magic DNS emits empty demands!
        let overlap_ip = Ipv4Inet::from_str("100.100.100.10/24").unwrap();
        sources
            .update_address_and_dns_facts(Some(overlap_ip), None, true, fake_ip)
            .unwrap();

        let snap2 = demands.current();
        let dns_source2 = snap2
            .sources
            .values()
            .find(|s| s.source_id.kind == SourceKind::MagicDns)
            .unwrap();
        assert!(dns_source2.latest_snapshot.as_ref().unwrap().demands.is_empty());

        // Shutdown revokes sources
        sources.shutdown();
        let snap3 = demands.current();
        for s in snap3.sources.values() {
            assert!(matches!(
                s.status,
                easytier_core::route_demand::model::SourceStatus::Revoked { .. }
            ));
        }
    }
}
