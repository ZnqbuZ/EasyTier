//! Native route controller managing route slots, interfaces, and reconciliation.

use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU32,
    sync::{Arc, Weak},
    time::Duration,
};

use easytier_core::host::route::{
    ClaimRouteStatus, DeviceEpoch, InstanceRouteStatus, InstanceRoutes, RouteDemand,
    RouteInputSnapshot, RouteInputs, RouteSpec,
};
use uuid::Uuid;

#[cfg(mobile)]
use cidr::IpCidr;

use crate::{
    common::net_ns::NetNS,
    instance::route::{
        AppliedRoute, AppliedRoutes, InterfaceInfo, OsRoute, OsRouteSlotKey, PlatformRouteBackend,
        RouteBackend, RouteError, validate_tun_spec,
    },
    utils::dirty::DirtyFlag,
};

#[cfg(mobile)]
use crate::instance::route::AppliedSnapshot;

/// Aggregates all route claims for a target destination.
/// Claims are sorted in ascending order of Metric; the first entry (first_key_value)
/// is always the active winner.
#[derive(Clone, Debug, Default)]
pub(crate) struct RouteSlot {
    pub(crate) claims: BTreeMap<NonZeroU32, BTreeSet<Uuid>>,
}

impl RouteSlot {
    pub(crate) fn add_claim(&mut self, owner: Uuid, metric: NonZeroU32) {
        self.claims.entry(metric).or_default().insert(owner);
    }

    pub(crate) fn remove_claim(&mut self, owner: &Uuid, metric: NonZeroU32) {
        if let Some(owners) = self.claims.get_mut(&metric) {
            owners.remove(owner);
            if owners.is_empty() {
                self.claims.remove(&metric);
            }
        }
    }

    pub(crate) fn winner(&self) -> Option<(NonZeroU32, &BTreeSet<Uuid>)> {
        self.claims
            .first_key_value()
            .map(|(metric, owners)| (*metric, owners))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn suppressed_owners(&self) -> BTreeSet<Uuid> {
        let mut suppressed = BTreeSet::new();
        let mut iter = self.claims.iter();
        let _ = iter.next();
        for (_, owners) in iter {
            suppressed.extend(owners.iter().copied());
        }
        suppressed
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.claims.is_empty()
    }
}

pub(crate) struct InstanceEntry {
    #[allow(dead_code)]
    pub(crate) name: String,
    pub(crate) inputs: Arc<RouteInputs>,
    pub(crate) snapshot: Option<RouteInputSnapshot>,
}

/// Unified facade for native route coordination with internal zero-lock mutation.
pub(crate) struct RouteController<B = PlatformRouteBackend> {
    backend: B,
    dirty: Arc<DirtyFlag>,
    interface: Option<InterfaceInfo>,
    slots: BTreeMap<OsRouteSlotKey, RouteSlot>,
    instances: BTreeMap<Uuid, InstanceEntry>,
    applied: AppliedRoutes,
    shutdown: bool,
}

impl<B> RouteController<B> {
    pub fn new(backend: B, dirty: Arc<DirtyFlag>) -> Self {
        Self {
            backend,
            dirty,
            interface: None,
            slots: BTreeMap::new(),
            instances: BTreeMap::new(),
            applied: Default::default(),
            shutdown: false,
        }
    }

    pub fn open_instance(&mut self, run: Uuid, name: String) -> anyhow::Result<InstanceRoutes> {
        anyhow::ensure!(!self.shutdown, "route controller is shut down");
        let dirty = self.dirty.clone();
        let routes = InstanceRoutes::new(Arc::new(move || {
            dirty.mark();
        }));
        let inputs = routes.inputs();
        self.instances.insert(
            run,
            InstanceEntry {
                name,
                inputs,
                snapshot: None,
            },
        );
        self.dirty.mark();
        Ok(routes)
    }

    pub fn set_interface(&mut self, info: Option<InterfaceInfo>) {
        if self.interface != info {
            self.interface = info;
            self.dirty.mark();
        }
    }

    #[allow(dead_code)]
    pub fn interface(&self) -> Option<&InterfaceInfo> {
        self.interface.as_ref()
    }

    pub fn abandon_instance(&mut self, run: Uuid, _reason: Arc<str>) {
        if let Some(entry) = self.instances.remove(&run) {
            let mut empty_slots = Vec::new();
            for (slot_key, slot) in &mut self.slots {
                for owners in slot.claims.values_mut() {
                    owners.remove(&run);
                }
                slot.claims.retain(|_, owners| !owners.is_empty());
                if slot.is_empty() {
                    empty_slots.push(slot_key.clone());
                }
            }
            for empty in empty_slots {
                self.slots.remove(&empty);
            }
            entry.inputs.close();
            self.dirty.mark();
        }
    }

    pub fn ensure_instance_open(&self, run: Uuid) -> anyhow::Result<()> {
        anyhow::ensure!(!self.shutdown, "route controller is shut down");
        anyhow::ensure!(
            self.instances
                .get(&run)
                .is_some_and(|e| !e.inputs.is_closed()),
            "instance route capability is closed"
        );
        Ok(())
    }

    pub fn request_shutdown(&mut self) {
        self.shutdown = true;
        self.dirty.mark();
    }

    pub fn set_instance_default_device(&mut self, run: &Uuid, epoch: Option<DeviceEpoch>) {
        if let Some(entry) = self.instances.get(run) {
            entry.inputs.set_default_device(*run, epoch).ok();
        }
    }

    pub fn invalidate_instance(&mut self, run: &Uuid) {
        if let Some(entry) = self.instances.get(run) {
            entry.inputs.invalidate();
        }
    }

    #[cfg(mobile)]
    pub fn effective_routes_for_instance(
        &self,
        run: &Uuid,
    ) -> easytier_core::host::route::RouteSet {
        self.instances
            .get(run)
            .and_then(|entry| entry.snapshot.as_ref())
            .map(|s| s.effective_routes())
            .unwrap_or_default()
    }
}

impl RouteController<PlatformRouteBackend> {
    pub fn start(
        net_ns: NetNS,
        handle: &tokio::runtime::Handle,
    ) -> anyhow::Result<Arc<tokio::sync::Mutex<Self>>> {
        let backend = PlatformRouteBackend::new(&net_ns, handle)?;
        let dirty = Arc::new(DirtyFlag::new(false));
        let controller = Arc::new(tokio::sync::Mutex::new(Self::new(backend, dirty.clone())));
        let weak = Arc::downgrade(&controller);
        handle.spawn(Self::run(weak, dirty));
        Ok(controller)
    }
}

impl<B: RouteBackend> RouteController<B> {
    /// Controller background scheduling loop: reacts to dirty events and 60-second audit timers.
    pub async fn run(controller: Weak<tokio::sync::Mutex<Self>>, dirty: Arc<DirtyFlag>) {
        loop {
            tokio::select! {
                _ = dirty.wait() => {
                    dirty.reset();
                    let Some(strong) = controller.upgrade() else {
                        break;
                    };
                    let mut guard = strong.lock().await;
                    if guard.shutdown {
                        break;
                    }
                    #[cfg(not(mobile))]
                    let _ = guard.reconcile().await;
                }
                _ = tokio::time::sleep(Duration::from_secs(60)) => {
                    let Some(strong) = controller.upgrade() else {
                        break;
                    };
                    let mut guard = strong.lock().await;
                    if guard.shutdown {
                        break;
                    }
                    #[cfg(not(mobile))]
                    let _ = guard.audit().await;
                }
            }
        }
    }
}

#[cfg(not(mobile))]
impl<B: RouteBackend> RouteController<B> {
    /// Declarative reconciliation: aligns desired slots with current applied state.
    pub async fn reconcile(&mut self) -> Result<(), RouteError> {
        let mut closed_instances = Vec::new();
        for (run, entry) in &mut self.instances {
            let latest = entry.inputs.snapshot();
            let old_routes = entry
                .snapshot
                .as_ref()
                .map(|s| s.effective_routes())
                .unwrap_or_default();
            let new_routes = latest.effective_routes();

            let old_os_routes: BTreeSet<OsRoute> = old_routes
                .iter()
                .filter_map(|spec| {
                    let metric = validate_tun_spec(spec).ok()?;
                    Some(OsRoute {
                        table: spec.table.unwrap_or(254),
                        destination: spec.destination,
                        metric,
                        ifindex: self.interface.as_ref().map(|i| i.ifindex).unwrap_or(0),
                        preferred_source: spec.preferred_source,
                    })
                })
                .collect();

            let new_os_routes: BTreeSet<OsRoute> = new_routes
                .iter()
                .filter_map(|spec| {
                    let metric = validate_tun_spec(spec).ok()?;
                    Some(OsRoute {
                        table: spec.table.unwrap_or(254),
                        destination: spec.destination,
                        metric,
                        ifindex: self.interface.as_ref().map(|i| i.ifindex).unwrap_or(0),
                        preferred_source: spec.preferred_source,
                    })
                })
                .collect();

            if old_os_routes != new_os_routes {
                for removed in old_os_routes.difference(&new_os_routes) {
                    let slot = removed.slot();
                    if let Some(slot_entry) = self.slots.get_mut(&slot) {
                        slot_entry.remove_claim(run, removed.metric);
                        if slot_entry.is_empty() {
                            self.slots.remove(&slot);
                        }
                    }
                }
                for added in new_os_routes.difference(&old_os_routes) {
                    let slot = added.slot();
                    self.slots
                        .entry(slot)
                        .or_default()
                        .add_claim(*run, added.metric);
                }
            }

            if latest.closed {
                closed_instances.push(*run);
            }
            entry.snapshot = Some(latest);
        }

        let Some(active_if) = &self.interface else {
            self.applied.clear();
            self.update_feedback();
            return Ok(());
        };

        let all_keys: BTreeSet<OsRouteSlotKey> = self
            .slots
            .keys()
            .chain(self.applied.keys())
            .cloned()
            .collect();

        for slot_key in all_keys {
            let desired = self.slots.get(&slot_key).and_then(|s| s.winner());
            let current = self.applied.get(&slot_key);

            match (desired, current) {
                (None, Some(applied)) => {
                    self.backend.remove(&applied.route).await?;
                    self.applied.remove(&slot_key);
                }
                (Some((metric, owners)), None) => {
                    let route = OsRoute {
                        table: slot_key.table,
                        destination: slot_key.destination,
                        metric,
                        ifindex: active_if.ifindex,
                        preferred_source: None,
                    };
                    self.backend.add(&route).await?;
                    self.applied
                        .insert(slot_key.clone(), AppliedRoute::new(route, owners.clone()));
                }
                (Some((metric, owners)), Some(applied)) => {
                    if applied.route.metric != metric || applied.route.ifindex != active_if.ifindex
                    {
                        self.backend.remove(&applied.route).await?;
                        let route = OsRoute {
                            table: slot_key.table,
                            destination: slot_key.destination,
                            metric,
                            ifindex: active_if.ifindex,
                            preferred_source: None,
                        };
                        self.backend.add(&route).await?;
                        self.applied
                            .insert(slot_key.clone(), AppliedRoute::new(route, owners.clone()));
                    } else if applied.owners != *owners {
                        let applied_mut = self.applied.get_mut(&slot_key).unwrap();
                        applied_mut.owners = owners.clone();
                    }
                }
                (None, None) => {}
            }
        }

        self.update_feedback();

        for run in closed_instances {
            let has_routes = self.applied.values().any(|r| r.owners.contains(&run));
            if !has_routes && let Some(entry) = self.instances.remove(&run) {
                let snapshot = entry.inputs.snapshot();
                entry.inputs.publish_feedback(
                    &snapshot,
                    InstanceRouteStatus::Drained,
                    BTreeMap::new(),
                );
            }
        }

        Ok(())
    }

    fn update_feedback(&self) {
        for (run, entry) in &self.instances {
            let snapshot = entry.inputs.snapshot();
            if snapshot.closed {
                let has_routes = self.applied.values().any(|r| r.owners.contains(run));
                let status = if has_routes {
                    InstanceRouteStatus::Draining { remaining: Some(1) }
                } else {
                    InstanceRouteStatus::Drained
                };
                entry
                    .inputs
                    .publish_feedback(&snapshot, status, BTreeMap::new());
                continue;
            }

            let mut claim_statuses = BTreeMap::new();
            for (claim_id, demand) in &snapshot.claims {
                if snapshot.auto_suppressed()
                    && matches!(demand.as_ref(), RouteDemand::AutoProxy(_))
                {
                    claim_statuses.insert(*claim_id, ClaimRouteStatus::Suppressed);
                    continue;
                }

                let specs: Vec<RouteSpec> = match demand.as_ref() {
                    RouteDemand::AutoProxy(prefixes) => prefixes
                        .iter()
                        .map(|p| RouteSpec::for_tun((*p).into()))
                        .collect(),
                    RouteDemand::Additional(routes) => routes.iter().cloned().collect(),
                };

                let mut all_ready = true;
                let mut any_suppressed = false;

                for spec in &specs {
                    let Ok(metric) = validate_tun_spec(spec) else {
                        all_ready = false;
                        continue;
                    };
                    let slot_key = OsRoute {
                        table: spec.table.unwrap_or(254),
                        destination: spec.destination,
                        metric,
                        ifindex: self.interface.as_ref().map(|i| i.ifindex).unwrap_or(0),
                        preferred_source: spec.preferred_source,
                    }
                    .slot();

                    if let Some(slot) = self.slots.get(&slot_key) {
                        if let Some((win_metric, win_owners)) = slot.winner() {
                            if win_metric == metric && win_owners.contains(run) {
                                if !self.applied.contains_key(&slot_key) {
                                    all_ready = false;
                                }
                            } else {
                                any_suppressed = true;
                                all_ready = false;
                            }
                        } else {
                            all_ready = false;
                        }
                    } else {
                        all_ready = false;
                    }
                }

                let status = if any_suppressed {
                    ClaimRouteStatus::Suppressed
                } else if all_ready {
                    ClaimRouteStatus::Ready
                } else {
                    ClaimRouteStatus::Pending
                };

                claim_statuses.insert(*claim_id, status);
            }

            entry
                .inputs
                .publish_feedback(&snapshot, InstanceRouteStatus::Active, claim_statuses);
        }
    }

    pub async fn audit(&mut self) -> Result<(), RouteError> {
        let requested = self
            .applied
            .values()
            .map(|a| a.route.clone())
            .collect::<BTreeSet<_>>();

        if requested.is_empty() {
            return Ok(());
        }

        let existing = self.backend.existing(&requested).await?;
        let mut missing = Vec::new();
        for (slot_key, applied) in &self.applied {
            if !existing.contains(&applied.route) {
                missing.push(slot_key.clone());
            }
        }

        if !missing.is_empty() {
            for key in &missing {
                self.applied.remove(key);
            }
            self.dirty.mark();
        }

        Ok(())
    }
}

#[cfg(mobile)]
impl<B> RouteController<B> {
    pub fn export_snapshot(&self) -> Option<AppliedSnapshot> {
        self.applied.clone()
    }

    pub fn acknowledge_external(&mut self, epoch: DeviceEpoch, prefixes: BTreeSet<IpCidr>) {
        self.applied = Some(AppliedSnapshot {
            epoch,
            prefixes: prefixes.clone(),
        });
        self.update_mobile_feedback();
    }

    pub fn detach_external(&mut self) {
        self.applied = None;
        self.update_mobile_feedback();
    }

    fn update_mobile_feedback(&self) {
        let Some(applied) = &self.applied else {
            for (_, entry) in &self.instances {
                if let Some(snapshot) = &entry.snapshot {
                    let mut claim_statuses = BTreeMap::new();
                    for claim_id in snapshot.claims.keys() {
                        claim_statuses.insert(*claim_id, ClaimRouteStatus::Pending);
                    }
                    entry.inputs.publish_feedback(
                        snapshot,
                        InstanceRouteStatus::Active,
                        claim_statuses,
                    );
                }
            }
            return;
        };

        for (_, entry) in &self.instances {
            let Some(snapshot) = &entry.snapshot else {
                continue;
            };
            let mut claim_statuses = BTreeMap::new();
            for (claim_id, demand) in &snapshot.claims {
                let prefixes = match demand.as_ref() {
                    RouteDemand::AutoProxy(p) => {
                        p.iter().map(|c| IpCidr::V4(*c)).collect::<Vec<_>>()
                    }
                    RouteDemand::Additional(r) => {
                        r.iter().map(|s| s.destination).collect::<Vec<_>>()
                    }
                };
                let all_in = prefixes.iter().all(|p| applied.prefixes.contains(p));
                let status = if all_in {
                    ClaimRouteStatus::Ready
                } else {
                    ClaimRouteStatus::Pending
                };
                claim_statuses.insert(*claim_id, status);
            }
            entry
                .inputs
                .publish_feedback(&snapshot, InstanceRouteStatus::Active, claim_statuses);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    #[derive(Default)]
    struct MockBackend {
        routes: Mutex<BTreeSet<OsRoute>>,
    }

    impl RouteBackend for Arc<MockBackend> {
        async fn add(&mut self, route: &OsRoute) -> Result<(), RouteError> {
            self.routes.lock().insert(route.clone());
            Ok(())
        }
        async fn remove(&mut self, route: &OsRoute) -> Result<(), RouteError> {
            self.routes.lock().remove(route);
            Ok(())
        }
        async fn existing(
            &mut self,
            routes: &BTreeSet<OsRoute>,
        ) -> Result<BTreeSet<OsRoute>, RouteError> {
            let current = self.routes.lock();
            Ok(routes.intersection(&current).cloned().collect())
        }
    }

    fn test_route(dest: &str, metric: u32, ifindex: u32) -> OsRoute {
        OsRoute {
            table: 254,
            destination: dest.parse().unwrap(),
            metric: NonZeroU32::new(metric).unwrap(),
            ifindex,
            preferred_source: None,
        }
    }

    #[tokio::test]
    async fn multi_owner_shared_same_metric() {
        let mock = Arc::new(MockBackend::default());
        let dirty = Arc::new(DirtyFlag::new(false));
        let mut controller = RouteController::new(mock.clone(), dirty);
        let if_info = InterfaceInfo {
            name: "tun0".into(),
            ifindex: 10,
        };
        controller.set_interface(Some(if_info));

        let owner_a = Uuid::new_v4();
        let owner_b = Uuid::new_v4();
        let routes_a = controller.open_instance(owner_a, "a".into()).unwrap();
        let routes_b = controller.open_instance(owner_b, "b".into()).unwrap();

        let r1 = test_route("10.14.0.0/24", 10, 10);
        let mut spec = RouteSpec::for_tun(r1.destination);
        spec.metric = 10;
        let handle_a = routes_a.handle();
        let _claim_a = handle_a
            .publish(RouteDemand::Additional(BTreeSet::from([spec.clone()])))
            .unwrap();

        controller.reconcile().await.unwrap();
        assert!(mock.routes.lock().contains(&r1));

        let handle_b = routes_b.handle();
        let _claim_b = handle_b
            .publish(RouteDemand::Additional(BTreeSet::from([spec])))
            .unwrap();

        controller.reconcile().await.unwrap();
        assert_eq!(mock.routes.lock().len(), 1);

        drop(_claim_a);
        controller.reconcile().await.unwrap();
        assert!(mock.routes.lock().contains(&r1));

        drop(_claim_b);
        controller.reconcile().await.unwrap();
        assert!(mock.routes.lock().is_empty());
    }

    #[test]
    fn metric_arbitration_and_suppression() {
        let mut slot = RouteSlot::default();
        let owner_a = Uuid::new_v4();
        let owner_b = Uuid::new_v4();
        let m10 = NonZeroU32::new(10).unwrap();
        let m20 = NonZeroU32::new(20).unwrap();

        slot.add_claim(owner_a, m10);
        slot.add_claim(owner_b, m20);

        assert_eq!(slot.winner().unwrap().0, m10);
        assert_eq!(slot.suppressed_owners(), BTreeSet::from([owner_b]));

        slot.remove_claim(&owner_a, m10);
        assert_eq!(slot.winner().unwrap().0, m20);
        assert!(slot.suppressed_owners().is_empty());
    }
}
