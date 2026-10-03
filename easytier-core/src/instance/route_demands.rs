//! Core route demand supervisor and projection tasks.
//!
//! Provides the read-only facade for route demands, the host context for registering
//! host-side demand sources, and the core projection tasks for peer proxy CIDRs and
//! public IPv6 leases/peers.

use std::{
    sync::Arc,
    time::Duration,
};

use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::{
    config::runtime::CoreRuntimeConfigStore,
    peers::{
        peer_manager::PeerManagerCore,
        public_ipv6::CorePublicIpv6Runtime,
    },
    route_demand::{
        model::{
            InstanceRuntimeId, LogicalEgress, ProjectionBasis, RegistryId, RegistrySnapshot,
            SourceId, SourceKind,
        },
        projection::{
            project_ipv4_proxy_demands, project_public_ipv6_egress_demand,
            project_public_ipv6_peer_demands, resolve_proxy_cidrs,
        },
        registry::{
            DemandReader, InstanceOwner, PublishError, RegistryError, ScopedPublisher,
            SourcePublisher,
        },
        subscription::Subscription,
        token::{
            ObsoleteOutcome, SourceSubmissionToken, SubmissionLifecycle, TokenQueryError,
            WaitObsoleteError,
        },
    },
};

/// Read-only facade wrapping [`DemandReader`].
///
/// Provides caller-safe, read-only inspection of instance route demands without
/// exposing internal registration or publication handles.
#[derive(Clone)]
pub struct CoreRouteDemands {
    reader: DemandReader,
}

impl CoreRouteDemands {
    pub fn new(reader: DemandReader) -> Self {
        Self { reader }
    }

    /// Obtains the current authoritative snapshot of all route demands.
    pub fn current(&self) -> Arc<RegistrySnapshot> {
        self.reader.current()
    }

    /// Establishes a subscription and returns the initial snapshot.
    pub fn subscribe(&self) -> (Subscription, Arc<RegistrySnapshot>) {
        self.reader.subscribe()
    }

    /// Queries the lifecycle state of a previously issued submission token.
    pub fn query_token(
        &self,
        token: SourceSubmissionToken,
    ) -> Result<SubmissionLifecycle, TokenQueryError> {
        self.reader.query_token(token)
    }

    /// Awaits until the given token becomes obsolete (superseded, revoked, or registry closed).
    pub async fn wait_obsolete(
        &self,
        token: SourceSubmissionToken,
        timeout: Option<Duration>,
    ) -> Result<ObsoleteOutcome, WaitObsoleteError> {
        self.reader.wait_obsolete(token, timeout).await
    }

    /// Returns the unique registry ID for this instance run.
    pub fn registry_id(&self) -> RegistryId {
        self.reader.registry_id()
    }

    /// Returns the instance runtime ID.
    pub fn instance_runtime_id(&self) -> InstanceRuntimeId {
        self.reader.instance_runtime_id()
    }

    /// Access the underlying demand reader.
    pub fn reader(&self) -> &DemandReader {
        &self.reader
    }
}

/// Host context provided to the host runtime during instance preparation.
///
/// Grants read access to instance demands and scoped registration authority for host sources.
#[derive(Clone)]
pub struct HostRouteDemandContext {
    demands: CoreRouteDemands,
    owner: InstanceOwner,
}

impl HostRouteDemandContext {
    pub fn new(demands: CoreRouteDemands, owner: InstanceOwner) -> Self {
        Self { demands, owner }
    }

    /// Read-only view of route demands.
    pub fn demands(&self) -> &CoreRouteDemands {
        &self.demands
    }

    /// Registers a host-owned demand source.
    pub fn register_source(
        &self,
        kind: SourceKind,
        logical_slot: impl Into<String>,
    ) -> Result<SourcePublisher, RegistryError> {
        self.owner.register(kind, logical_slot)
    }

    /// Restarts an existing host-owned demand source with an incremented epoch.
    pub fn restart_source(&self, source_id: SourceId) -> Result<SourcePublisher, RegistryError> {
        self.owner.restart(source_id)
    }

    /// Creates a scoped multi-source publisher for atomic batch publication.
    pub fn scoped_publisher(&self, sources: &[SourceId]) -> Result<ScopedPublisher, RegistryError> {
        self.owner.scoped_publisher(sources)
    }

    /// Returns the unique registry ID.
    pub fn registry_id(&self) -> RegistryId {
        self.owner.registry_id()
    }

    /// Returns the instance runtime ID.
    pub fn instance_runtime_id(&self) -> InstanceRuntimeId {
        self.owner.instance_runtime_id()
    }
}

/// Task guard ensuring that abnormal task termination or panic transitions the source
/// to [`crate::route_demand::model::SourceStatus::Unavailable`] rather than leaving it
/// permanently Active.
struct SourceTaskGuard {
    publisher: Option<SourcePublisher>,
}

impl SourceTaskGuard {
    fn new(publisher: SourcePublisher) -> Self {
        Self {
            publisher: Some(publisher),
        }
    }

    fn revoke(mut self) {
        if let Some(publisher) = self.publisher.take() {
            let _ = publisher.revoke();
        }
    }

    fn mark_unavailable(&mut self, reason: impl Into<String>) {
        if let Some(publisher) = &self.publisher {
            let _ = publisher.mark_unavailable(reason);
        }
    }
}

impl Drop for SourceTaskGuard {
    fn drop(&mut self) {
        if let Some(publisher) = self.publisher.take() {
            let _ = publisher.mark_unavailable("projection task terminated unexpectedly");
        }
    }
}

/// Reactive projection task for Core Proxy CIDR demands.
///
/// Reacts to changes in peer route advertisements and runtime configuration manual routes.
pub(crate) struct ProxyCidrDemandProjectionTask;

impl ProxyCidrDemandProjectionTask {
    pub(crate) fn spawn(
        publisher: SourcePublisher,
        peer_manager: Arc<PeerManagerCore>,
        runtime_config: CoreRuntimeConfigStore,
        logical_egress: LogicalEgress,
        cancel: CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut guard = SourceTaskGuard::new(publisher);
            let mut peer_route_rx = peer_manager.get_route().subscribe_host_route_inputs();
            let mut service_changes_rx = runtime_config.subscribe_service_runtime_changes();

            let mut last_manual_routes;
            let mut manual_routes_rev = 0u64;

            // Initial projection
            {
                let peer_input = peer_route_rx.borrow_and_update().clone();
                let _ = *service_changes_rx.borrow_and_update();
                let config = runtime_config.snapshot();
                last_manual_routes = config.services.manual_routes.clone();
                let is_manual = config.services.manual_routes.is_some();
                let resolved = resolve_proxy_cidrs(
                    &peer_input.proxy_cidrs,
                    config.services.manual_routes.as_ref(),
                );
                let demands = project_ipv4_proxy_demands(&resolved, is_manual, logical_egress);
                let mut basis = ProjectionBasis::default();
                basis.input_revisions.insert("peer_route".to_string(), peer_input.revision);
                basis.input_revisions.insert("manual_routes".to_string(), manual_routes_rev);

                if let Some(publ) = &guard.publisher {
                    if let Err(e) = publ.publish(demands, basis) {
                        tracing::warn!("failed initial publish for proxy cidr: {e:?}");
                        guard.mark_unavailable(format!("publish error: {e:?}"));
                        return;
                    }
                }
            }

            loop {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => {
                        guard.revoke();
                        break;
                    }
                    res = peer_route_rx.changed() => {
                        if res.is_err() {
                            guard.mark_unavailable("peer_route input closed");
                            break;
                        }
                    }
                    res = service_changes_rx.changed() => {
                        if res.is_err() {
                            guard.mark_unavailable("service_changes input closed");
                            break;
                        }
                    }
                }

                let peer_input = peer_route_rx.borrow_and_update().clone();
                let _ = *service_changes_rx.borrow_and_update();
                let config = runtime_config.snapshot();

                if config.services.manual_routes != last_manual_routes {
                    manual_routes_rev = manual_routes_rev.saturating_add(1);
                    last_manual_routes = config.services.manual_routes.clone();
                }

                let is_manual = config.services.manual_routes.is_some();
                let resolved = resolve_proxy_cidrs(
                    &peer_input.proxy_cidrs,
                    config.services.manual_routes.as_ref(),
                );
                let demands = project_ipv4_proxy_demands(&resolved, is_manual, logical_egress);
                let mut basis = ProjectionBasis::default();
                basis.input_revisions.insert("peer_route".to_string(), peer_input.revision);
                basis.input_revisions.insert("manual_routes".to_string(), manual_routes_rev);

                if let Some(publ) = &guard.publisher {
                    if let Err(e) = publ.publish(demands, basis) {
                        if matches!(e, PublishError::RegistryClosed | PublishError::Revoked(_)) {
                            break;
                        }
                        tracing::warn!("failed publish for proxy cidr: {e:?}");
                        guard.mark_unavailable(format!("publish error: {e:?}"));
                    }
                }
            }
        })
    }
}

/// Reactive projection task for Core Public IPv6 demands.
///
/// Reacts to changes in public IPv6 address lease acquisition, expiration, and peer routes.
pub(crate) struct PublicIpv6DemandProjectionTask;

impl PublicIpv6DemandProjectionTask {
    pub(crate) fn spawn(
        publisher: SourcePublisher,
        public_ipv6_runtime: Arc<CorePublicIpv6Runtime>,
        logical_egress: LogicalEgress,
        cancel: CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut guard = SourceTaskGuard::new(publisher);
            let mut snapshot_rx = public_ipv6_runtime.subscribe_snapshot();

            // Initial projection
            {
                let snap = snapshot_rx.borrow_and_update().clone();
                let mut demands = project_public_ipv6_egress_demand(
                    snap.lease,
                    snap.lease_version,
                    logical_egress,
                );
                demands.extend(project_public_ipv6_peer_demands(
                    &snap.routes,
                    logical_egress,
                ));
                let mut basis = ProjectionBasis::default();
                basis.input_revisions.insert("public_ipv6".to_string(), snap.revision);

                if let Some(publ) = &guard.publisher {
                    if let Err(e) = publ.publish(demands, basis) {
                        tracing::warn!("failed initial publish for public ipv6: {e:?}");
                        guard.mark_unavailable(format!("publish error: {e:?}"));
                        return;
                    }
                }
            }

            loop {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => {
                        guard.revoke();
                        break;
                    }
                    res = snapshot_rx.changed() => {
                        if res.is_err() {
                            guard.mark_unavailable("public_ipv6 snapshot input closed");
                            break;
                        }
                    }
                }

                let snap = snapshot_rx.borrow_and_update().clone();
                let mut demands = project_public_ipv6_egress_demand(
                    snap.lease,
                    snap.lease_version,
                    logical_egress,
                );
                demands.extend(project_public_ipv6_peer_demands(
                    &snap.routes,
                    logical_egress,
                ));
                let mut basis = ProjectionBasis::default();
                basis.input_revisions.insert("public_ipv6".to_string(), snap.revision);

                if let Some(publ) = &guard.publisher {
                    if let Err(e) = publ.publish(demands, basis) {
                        if matches!(e, PublishError::RegistryClosed | PublishError::Revoked(_)) {
                            break;
                        }
                        tracing::warn!("failed publish for public ipv6: {e:?}");
                        guard.mark_unavailable(format!("publish error: {e:?}"));
                    }
                }
            }
        })
    }
}

/// Supervisor managing core route demand projection tasks and registry lifecycle.
pub(crate) struct RouteDemandSupervisor {
    owner: InstanceOwner,
    demands: CoreRouteDemands,
    tasks: Arc<Mutex<Option<Vec<tokio::task::JoinHandle<()>>>>>,
}

impl RouteDemandSupervisor {
    pub(crate) fn new(instance_runtime_id: InstanceRuntimeId) -> Self {
        let owner = InstanceOwner::new(instance_runtime_id);
        let demands = CoreRouteDemands::new(owner.reader());
        Self {
            owner,
            demands,
            tasks: Arc::new(Mutex::new(None)),
        }
    }

    pub(crate) fn demands(&self) -> CoreRouteDemands {
        self.demands.clone()
    }

    pub(crate) fn host_context(&self) -> HostRouteDemandContext {
        HostRouteDemandContext::new(self.demands.clone(), self.owner.clone())
    }

    pub(crate) async fn start(
        &self,
        peer_manager: Arc<PeerManagerCore>,
        runtime_config: CoreRuntimeConfigStore,
        public_ipv6_runtime: Arc<CorePublicIpv6Runtime>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        let mut tasks_lock = self.tasks.lock().await;
        if tasks_lock.is_some() {
            return Ok(());
        }

        let proxy_pub = self
            .owner
            .register(SourceKind::ProxyCidr, "core.proxy_cidr")
            .map_err(|e| anyhow::anyhow!("failed to register proxy cidr source: {e:?}"))?;

        let ipv6_pub = self
            .owner
            .register(SourceKind::PublicIpv6, "core.public_ipv6")
            .map_err(|e| anyhow::anyhow!("failed to register public ipv6 source: {e:?}"))?;

        let egress = LogicalEgress::new(self.owner.instance_runtime_id());

        let t1 = ProxyCidrDemandProjectionTask::spawn(
            proxy_pub,
            peer_manager,
            runtime_config,
            egress,
            cancel.clone(),
        );

        let t2 = PublicIpv6DemandProjectionTask::spawn(
            ipv6_pub,
            public_ipv6_runtime,
            egress,
            cancel,
        );

        *tasks_lock = Some(vec![t1, t2]);
        Ok(())
    }

    pub(crate) async fn stop(&self) {
        let handles = self.tasks.lock().await.take();
        if let Some(handles) = handles {
            for handle in &handles {
                handle.abort();
            }
            for handle in handles {
                let _ = handle.await;
            }
        }
        let _ = self.owner.close();
    }
}

impl Drop for RouteDemandSupervisor {
    fn drop(&mut self) {
        let _ = self.owner.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::str::FromStr;
    use cidr::Ipv6Inet;
    use crate::config::peers::PeerRuntimeSnapshot;
    use crate::config::runtime::CoreRuntimeConfig;

    #[tokio::test]
    async fn test_route_demands_facade_and_host_context() {
        let supervisor = RouteDemandSupervisor::new(InstanceRuntimeId::random());
        let demands = supervisor.demands();
        let host_ctx = supervisor.host_context();

        assert_eq!(demands.registry_id(), host_ctx.registry_id());
        assert_eq!(demands.instance_runtime_id(), host_ctx.instance_runtime_id());

        // Register host source
        let publ = host_ctx
            .register_source(SourceKind::MagicDns, "host.magic_dns")
            .unwrap();

        let snap = demands.current();
        assert_eq!(snap.sources.len(), 1);
        let src = snap.sources.get(&publ.source_id).unwrap();
        assert_eq!(src.status, crate::route_demand::model::SourceStatus::Initializing);

        supervisor.stop().await;
        let snap_closed = demands.current();
        assert!(snap_closed.is_closed);
    }

    #[tokio::test]
    async fn test_public_ipv6_projection_task_lifecycle() {
        use crate::peers::public_ipv6::PublicIpv6Runtime;

        let store = CoreRuntimeConfigStore::new(
            CoreRuntimeConfig::default(),
            Arc::new(PeerRuntimeSnapshot::default()),
        );
        let runtime = CorePublicIpv6Runtime::new(store, Arc::new(()), Arc::new(()));

        let instance_id = InstanceRuntimeId::random();
        let egress = LogicalEgress::new(instance_id);
        let owner = InstanceOwner::new(instance_id);
        let reader = owner.reader();
        let publ = owner.register(SourceKind::PublicIpv6, "core.public_ipv6").unwrap();
        let source_id = publ.source_id;

        let cancel = CancellationToken::new();
        let handle = PublicIpv6DemandProjectionTask::spawn(publ, runtime.clone(), egress, cancel.clone());

        // Initial empty demands published
        let (mut sub, snap) = reader.subscribe();
        let snap = if snap.sources.get(&source_id).unwrap().status
            == crate::route_demand::model::SourceStatus::Initializing
        {
            sub.wait_next().await.unwrap()
        } else {
            snap
        };
        let rec = snap.sources.get(&source_id).unwrap();
        assert_eq!(rec.status, crate::route_demand::model::SourceStatus::Active);
        assert!(rec.latest_snapshot.as_ref().unwrap().demands.is_empty());

        // Acquire lease
        let lease = Ipv6Inet::from_str("2001:db8:1::1/64").unwrap();
        runtime.update_public_ipv6_snapshot(Some(lease), BTreeSet::new());

        let _ = sub.wait_next().await.unwrap();
        let snap = reader.current();
        let rec = snap.sources.get(&source_id).unwrap();
        let latest = rec.latest_snapshot.as_ref().unwrap();
        assert_eq!(latest.demands.len(), 1);
        let d = latest.demands.iter().next().unwrap();
        assert_eq!(d.purpose, crate::route_demand::model::RoutePurpose::PublicIpv6Default);

        // Cancel
        cancel.cancel();
        let _ = handle.await;

        let snap_after_cancel = reader.current();
        let rec_after = snap_after_cancel.sources.get(&source_id).unwrap();
        assert!(matches!(rec_after.status, crate::route_demand::model::SourceStatus::Revoked { .. }));
    }
}
