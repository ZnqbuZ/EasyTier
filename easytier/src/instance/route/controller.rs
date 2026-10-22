use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU32,
    sync::{Arc, Weak},
    time::Duration,
};

#[cfg(mobile)]
use cidr::IpCidr;
use easytier_core::host::route::{
    InstanceRoutes, RouteHandle, RouteSlot, RouteSlotInner, RouteSpec,
};
use parking_lot::RwLock;
use uuid::Uuid;

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

pub(crate) struct InstanceEntry {
    #[allow(dead_code)]
    pub(crate) name: String,
    pub(crate) routes: InstanceRoutes,
}

pub(crate) struct ReconcilePlan {
    pub(crate) routes_to_remove: Vec<OsRoute>,
    pub(crate) routes_to_add: Vec<OsRoute>,
    pub(crate) slots_to_mark_ready: Vec<Weak<RouteSlotInner>>,
    pub(crate) slots_to_suppress: Vec<Weak<RouteSlotInner>>,
    pub(crate) closed_instances: Vec<Uuid>,
    pub(crate) new_applied: AppliedRoutes,
}

/// Private internal routing table state, owned exclusively by RouteController
/// and protected by an RwLock. Lock is held only for microseconds; I/O happens outside the lock.
#[derive(Default)]
struct RouteControllerRuntime {
    interface: Option<InterfaceInfo>,
    slots: Vec<Weak<RouteSlotInner>>,
    instances: BTreeMap<Uuid, InstanceEntry>,
    applied: AppliedRoutes,
    shutdown: bool,
}

/// Lightweight, cloneable handle to the per-namespace RouteController.
/// Cloning this handle is cheap (Arc clone) and safe to hold across components.
#[derive(Clone)]
pub(crate) struct RouteController {
    runtime: Arc<RwLock<RouteControllerRuntime>>,
    dirty: Arc<DirtyFlag>,
}

impl RouteController {
    pub fn new(dirty: Arc<DirtyFlag>) -> Self {
        Self {
            runtime: Arc::new(RwLock::new(Default::default())),
            dirty,
        }
    }

    /// Static constructor: starts the platform backend worker in net_ns and returns a lightweight handle.
    pub fn start(
        net_ns: NetNS,
        handle: &tokio::runtime::Handle,
    ) -> anyhow::Result<Self> {
        let backend = PlatformRouteBackend::new(&net_ns, handle)?;
        let dirty = Arc::new(DirtyFlag::new(false));
        let controller = Self::new(dirty);
        let reconciler = RouteReconciler::new(controller.clone(), backend);
        handle.spawn(reconciler.run());
        Ok(controller)
    }

    /// Read the currently applied routes in memory (microsecond read lock, zero system calls).
    #[allow(dead_code)]
    pub fn applied_routes(&self) -> AppliedRoutes {
        self.runtime.read().applied.clone()
    }

    /// Allocate a new empty slot owned by Controller's exclusive registry and hand it to caller.
    pub fn add_slot(&self, run: Uuid, is_auto_proxy: bool) -> RouteSlot {
        let dirty = self.dirty.clone();
        let slot = RouteSlot::new(run, is_auto_proxy, Arc::new(move || dirty.mark()));
        let mut rt = self.runtime.write();
        rt.slots.push(slot.downgrade());
        self.dirty.mark();
        slot
    }

    pub fn set_interface(&self, info: Option<InterfaceInfo>) {
        let mut rt = self.runtime.write();
        if rt.interface != info {
            rt.interface = info;
            self.dirty.mark();
        }
    }

    #[allow(dead_code)]
    pub fn interface(&self) -> Option<InterfaceInfo> {
        self.runtime.read().interface.clone()
    }

    pub fn open_instance(&self, run: Uuid, name: String) -> anyhow::Result<InstanceRoutes> {
        anyhow::ensure!(!self.is_shutdown(), "route controller is shut down");
        let ctrl = self.clone();
        let handle = RouteHandle::new(move |is_auto_proxy| Ok(ctrl.add_slot(run, is_auto_proxy)));
        let dirty = self.dirty.clone();
        let routes = InstanceRoutes::with_handle(run, handle, Arc::new(move || dirty.mark()));
        let mut rt = self.runtime.write();
        rt.instances.insert(
            run,
            InstanceEntry {
                name,
                routes: routes.clone(),
            },
        );
        self.dirty.mark();
        Ok(routes)
    }

    pub fn ensure_instance_open(&self, run: Uuid) -> anyhow::Result<()> {
        let rt = self.runtime.read();
        anyhow::ensure!(!rt.shutdown, "route controller is shut down");
        anyhow::ensure!(
            rt.instances.get(&run).is_some_and(|e| !e.routes.is_closed()),
            "instance route capability is closed"
        );
        Ok(())
    }

    pub fn abandon_instance(&self, run: Uuid, _reason: Arc<str>) {
        let mut rt = self.runtime.write();
        if let Some(entry) = rt.instances.remove(&run) {
            entry.routes.request_close();
            self.dirty.mark();
        }
    }

    pub fn request_shutdown(&self) {
        let mut rt = self.runtime.write();
        rt.shutdown = true;
        self.dirty.mark();
    }

    pub fn is_shutdown(&self) -> bool {
        self.runtime.read().shutdown
    }

    pub fn plan_reconciliation(&self) -> Option<ReconcilePlan> {
        self.runtime.write().plan_reconciliation()
    }

    pub fn commit_plan(&self, plan: ReconcilePlan) {
        self.runtime.write().commit_plan(plan);
    }

    pub fn prune_missing_routes(&self, missing: Vec<OsRouteSlotKey>) {
        let mut rt = self.runtime.write();
        for key in missing {
            rt.applied.remove(&key);
        }
        self.dirty.mark();
    }

    pub fn invalidate_instance(&self, _run: &Uuid) {
        self.dirty.mark();
    }
}

/// Dedicated background reconciler actor: exclusively owns the RouteBackend (0 locks)
/// and drives OS route reconciliation based on plans from RouteController.
pub(crate) struct RouteReconciler<B> {
    controller: RouteController,
    backend: B,
}

impl<B: RouteBackend> RouteReconciler<B> {
    pub fn new(controller: RouteController, backend: B) -> Self {
        Self { controller, backend }
    }

    /// Background worker loop: reacts to dirty events and periodic audits without holding locks across await.
    pub async fn run(mut self) {
        loop {
            tokio::select! {
                _ = self.controller.dirty.wait() => {
                    self.controller.dirty.reset();
                    if self.controller.is_shutdown() {
                        break;
                    }
                    #[cfg(not(mobile))]
                    let _ = self.reconcile().await;
                    #[cfg(mobile)]
                    self.controller.reconcile_mobile();
                }
                _ = tokio::time::sleep(Duration::from_secs(60)) => {
                    if self.controller.is_shutdown() {
                        break;
                    }
                    #[cfg(not(mobile))]
                    let _ = self.audit().await;
                }
            }
        }
    }

    #[cfg(not(mobile))]
    pub async fn reconcile(&mut self) -> Result<(), RouteError> {
        let Some(plan) = self.controller.plan_reconciliation() else {
            return Ok(());
        };

        for r in &plan.routes_to_remove {
            if let Err(err) = self.backend.remove(r).await {
                tracing::warn!(?err, ?r, "failed to remove route from kernel");
            }
        }

        for r in &plan.routes_to_add {
            if let Err(err) = self.backend.add(r).await {
                tracing::warn!(?err, ?r, "failed to add route to kernel");
            }
        }

        self.controller.commit_plan(plan);
        Ok(())
    }

    #[cfg(not(mobile))]
    pub async fn audit(&mut self) -> Result<(), RouteError> {
        let requested: BTreeSet<OsRoute> = {
            let rt = self.controller.runtime.read();
            rt.applied.values().map(|a| a.route.clone()).collect()
        };

        if requested.is_empty() {
            return Ok(());
        }

        let existing = self.backend.existing(&requested).await?;
        let mut missing = Vec::new();
        {
            let rt = self.controller.runtime.read();
            for (slot_key, applied) in &rt.applied {
                if !existing.contains(&applied.route) {
                    missing.push(slot_key.clone());
                }
            }
        }

        if !missing.is_empty() {
            self.controller.prune_missing_routes(missing);
        }

        Ok(())
    }
}

#[cfg(not(mobile))]
impl RouteControllerRuntime {
    fn plan_reconciliation(&mut self) -> Option<ReconcilePlan> {
        self.slots
            .retain(|weak| weak.upgrade().is_some_and(|s| !s.is_closed()));

        let mut closed_instances = Vec::new();
        for (run, entry) in &self.instances {
            if entry.routes.is_closed() {
                closed_instances.push(*run);
            }
        }

        let Some(active_if) = &self.interface else {
            let to_remove = self.applied.values().map(|a| a.route.clone()).collect();
            return Some(ReconcilePlan {
                routes_to_remove: to_remove,
                routes_to_add: Vec::new(),
                slots_to_mark_ready: Vec::new(),
                slots_to_suppress: Vec::new(),
                closed_instances,
                new_applied: Default::default(),
            });
        };

        // slot_key -> claims sorted by (metric, owner, Option<Weak<Slot>>)
        let mut claims_by_key = BTreeMap::<
            OsRouteSlotKey,
            Vec<(NonZeroU32, Uuid, Option<Weak<RouteSlotInner>>)>,
        >::new();
        let mut suppressed_slots = Vec::new();

        // 1. Manual routes from instance configs
        for (run, entry) in &self.instances {
            if let Some(config) = entry.routes.config() {
                let snapshot = config.snapshot();
                if let Some(manual) = &snapshot.services.manual_routes {
                    for prefix in manual {
                        let spec = RouteSpec::for_tun((*prefix).into());
                        if let Ok(metric) = validate_tun_spec(&spec) {
                            let route = OsRoute {
                                table: spec.table.unwrap_or(254),
                                destination: spec.destination,
                                metric,
                                ifindex: active_if.ifindex,
                                preferred_source: spec.preferred_source,
                            };
                            claims_by_key
                                .entry(route.slot())
                                .or_default()
                                .push((metric, *run, None));
                        }
                    }
                }
            }
        }

        // 2. Business slots
        for weak in &self.slots {
            let Some(slot) = weak.upgrade() else {
                continue;
            };
            let run = slot.instance();
            let is_auto_suppressed = slot.is_auto_proxy()
                && self.instances.get(&run).is_some_and(|entry| {
                    entry
                        .routes
                        .config()
                        .is_some_and(|c| c.snapshot().services.manual_routes.is_some())
                });

            if is_auto_suppressed {
                suppressed_slots.push(weak.clone());
                continue;
            }

            for spec in slot.routes() {
                if let Ok(metric) = validate_tun_spec(&spec) {
                    let route = OsRoute {
                        table: spec.table.unwrap_or(254),
                        destination: spec.destination,
                        metric,
                        ifindex: active_if.ifindex,
                        preferred_source: spec.preferred_source,
                    };
                    claims_by_key
                        .entry(route.slot())
                        .or_default()
                        .push((metric, run, Some(weak.clone())));
                }
            }
        }

        // 3. Metric arbitration per slot key
        let mut desired_routes = BTreeMap::new();
        let mut winning_slots = Vec::new();

        for (slot_key, mut claims) in claims_by_key {
            claims.sort_by_key(|c| c.0);
            let min_metric = claims[0].0;
            let mut owners = BTreeSet::new();

            for (metric, owner, opt_slot) in claims {
                if metric == min_metric {
                    owners.insert(owner);
                    if let Some(slot) = opt_slot {
                        winning_slots.push(slot);
                    }
                } else if let Some(slot) = opt_slot {
                    suppressed_slots.push(slot);
                }
            }

            let os_route = OsRoute {
                table: slot_key.table,
                destination: slot_key.destination,
                metric: min_metric,
                ifindex: active_if.ifindex,
                preferred_source: None,
            };
            desired_routes.insert(slot_key, (os_route, owners));
        }

        // 4. Calculate Add / Remove diff against current applied
        let mut to_remove = Vec::new();
        let mut to_add = Vec::new();
        let mut new_applied = AppliedRoutes::default();

        let all_keys: BTreeSet<OsRouteSlotKey> = self
            .applied
            .keys()
            .chain(desired_routes.keys())
            .cloned()
            .collect();

        for slot_key in all_keys {
            let current = self.applied.get(&slot_key);
            let desired = desired_routes.get(&slot_key);

            match (desired, current) {
                (None, Some(applied)) => {
                    to_remove.push(applied.route.clone());
                }
                (Some((route, owners)), None) => {
                    to_add.push(route.clone());
                    new_applied.insert(slot_key, AppliedRoute::new(route.clone(), owners.clone()));
                }
                (Some((route, owners)), Some(applied)) => {
                    if applied.route.metric != route.metric
                        || applied.route.ifindex != active_if.ifindex
                    {
                        to_remove.push(applied.route.clone());
                        to_add.push(route.clone());
                    }
                    new_applied.insert(slot_key, AppliedRoute::new(route.clone(), owners.clone()));
                }
                (None, None) => {}
            }
        }

        Some(ReconcilePlan {
            routes_to_remove: to_remove,
            routes_to_add: to_add,
            slots_to_mark_ready: winning_slots,
            slots_to_suppress: suppressed_slots,
            closed_instances,
            new_applied,
        })
    }

    fn commit_plan(&mut self, plan: ReconcilePlan) {
        self.applied = plan.new_applied;
        for weak in plan.slots_to_mark_ready {
            if let Some(slot) = weak.upgrade() {
                slot.set_ready();
            }
        }
        for weak in plan.slots_to_suppress {
            if let Some(slot) = weak.upgrade() {
                slot.set_suppressed();
            }
        }
        for run in plan.closed_instances {
            let has_routes = self
                .slots
                .iter()
                .any(|w| w.upgrade().is_some_and(|s| s.instance() == run && !s.is_closed()));
            if !has_routes {
                self.instances.remove(&run);
            }
        }
    }
}

#[cfg(mobile)]
impl RouteController {
    pub fn reconcile_mobile(&self) {
        let mut rt = self.runtime.write();
        rt.slots
            .retain(|weak| weak.upgrade().is_some_and(|s| !s.is_closed()));

        let mut prefixes = BTreeSet::new();
        for weak in &rt.slots {
            if let Some(slot) = weak.upgrade() {
                for spec in slot.routes() {
                    prefixes.insert(spec.destination);
                }
            }
        }

        rt.applied = Some(AppliedSnapshot { prefixes });
        for weak in &rt.slots {
            if let Some(slot) = weak.upgrade() {
                slot.set_ready();
            }
        }
    }

    pub fn effective_routes_for_instance(
        &self,
        run: &Uuid,
    ) -> easytier_core::host::route::RouteSet {
        let rt = self.runtime.read();
        let mut routes = easytier_core::host::route::RouteSet::new();
        for weak in &rt.slots {
            if let Some(slot) = weak.upgrade() {
                if slot.instance() == *run {
                    routes.extend(slot.routes());
                }
            }
        }
        routes
    }

    pub fn acknowledge_external(&self, prefixes: BTreeSet<IpCidr>) {
        let mut rt = self.runtime.write();
        rt.applied = Some(AppliedSnapshot { prefixes });
        for weak in &rt.slots {
            if let Some(slot) = weak.upgrade() {
                slot.set_ready();
            }
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
        let controller = RouteController::new(dirty);
        let mut reconciler = RouteReconciler::new(controller.clone(), mock.clone());
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

        let slot_a = routes_a.handle().open_slot().unwrap();
        slot_a.set_routes(BTreeSet::from([spec.clone()])).unwrap();

        reconciler.reconcile().await.unwrap();
        assert!(mock.routes.lock().contains(&r1));

        let slot_b = routes_b.handle().open_slot().unwrap();
        slot_b.set_routes(BTreeSet::from([spec])).unwrap();

        reconciler.reconcile().await.unwrap();
        assert_eq!(mock.routes.lock().len(), 1);

        drop(slot_a);
        reconciler.reconcile().await.unwrap();
        assert!(mock.routes.lock().contains(&r1));

        drop(slot_b);
        reconciler.reconcile().await.unwrap();
        assert!(mock.routes.lock().is_empty());
    }
}
