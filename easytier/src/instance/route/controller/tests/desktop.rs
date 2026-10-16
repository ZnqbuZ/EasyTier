//! Desktop reconciler tests.

use super::super::desktop::*;
use super::super::member::*;
use super::super::*;
use crate::instance::route::{
    AppliedRoute, AppliedRoutes, InterfaceInfo, RouteBackend, RouteEffect, RouteError, RouteKey,
    normalize_route,
};
use cidr::IpCidr;
use easytier_core::host::route::{RouteAction, RouteDevice, RouteStatus};
use parking_lot::Mutex;
use std::collections::{BTreeSet, VecDeque};

#[cfg(feature = "tun")]
use crate::instance::{
    shared_virtual_nic::{SharedIpv4Route, SharedVirtualNicRegistry},
    virtual_nic::VirtualNicConfig,
};

/// One recorded backend entry, in the exact order the operation started.
#[derive(Debug, Clone, PartialEq, Eq)]
enum MockOperation {
    Add(RouteSpec<u32>),
    Remove(RouteSpec<u32>),
    Existing(BTreeSet<RouteSpec<u32>>),
}

/// A one-shot, optionally route-specific stop inside one backend call.
///
/// `Notify` keeps one permit, so a wake that happens before the other side
/// actually awaits it is not lost.
struct MockGate {
    route: Option<RouteSpec<u32>>,
    entered: Arc<Notify>,
    resume: Arc<Notify>,
}

impl MockGate {
    fn new(route: Option<RouteSpec<u32>>) -> Self {
        Self {
            route,
            entered: Arc::new(Notify::new()),
            resume: Arc::new(Notify::new()),
        }
    }

    fn matches(&self, route: &RouteSpec<u32>) -> bool {
        self.route.as_ref().is_none_or(|expected| expected == route)
    }
}

/// An entirely in-memory OS route table.
///
/// Faults and gates are taken under a short synchronous lock and used
/// after it is released, so no guard is ever held across an await.
#[derive(Default)]
struct MockBackend {
    routes: Mutex<BTreeSet<RouteSpec<u32>>>,
    operations: Mutex<Vec<MockOperation>>,
    add_calls: Mutex<Vec<RouteSpec<u32>>>,
    remove_calls: Mutex<Vec<RouteSpec<u32>>>,
    existing_batches: Mutex<Vec<BTreeSet<RouteSpec<u32>>>>,
    add_faults: Mutex<BTreeMap<RouteSpec<u32>, VecDeque<(RouteError, bool)>>>,
    remove_faults: Mutex<BTreeMap<RouteSpec<u32>, VecDeque<(RouteError, bool)>>>,
    existing_errors: Mutex<VecDeque<RouteError>>,
    add_gate: Mutex<Option<MockGate>>,
    remove_gate: Mutex<Option<MockGate>>,
    existing_gate: Mutex<Option<MockGate>>,
}

impl MockBackend {
    fn contains(&self, route: &RouteSpec<u32>) -> bool {
        self.routes.lock().contains(route)
    }

    fn add_count(&self) -> usize {
        self.add_calls.lock().len()
    }

    fn remove_count(&self) -> usize {
        self.remove_calls.lock().len()
    }

    fn existing_count(&self) -> usize {
        self.existing_batches.lock().len()
    }

    /// Queue one outcome for this exact full route. `side_effect` applies
    /// the mock OS change before the fault is returned.
    fn queue_add(&self, route: &RouteSpec<u32>, error: RouteError, side_effect: bool) {
        self.add_faults
            .lock()
            .entry(route.clone())
            .or_default()
            .push_back((error, side_effect));
    }

    fn queue_remove(&self, route: &RouteSpec<u32>, error: RouteError, side_effect: bool) {
        self.remove_faults
            .lock()
            .entry(route.clone())
            .or_default()
            .push_back((error, side_effect));
    }

    fn queue_existing_error(&self, error: RouteError) {
        self.existing_errors.lock().push_back(error);
    }

    fn gate_add(&self, route: Option<RouteSpec<u32>>) -> (Arc<Notify>, Arc<Notify>) {
        let gate = MockGate::new(route);
        let handles = (gate.entered.clone(), gate.resume.clone());
        *self.add_gate.lock() = Some(gate);
        handles
    }

    fn gate_remove(&self, route: Option<RouteSpec<u32>>) -> (Arc<Notify>, Arc<Notify>) {
        let gate = MockGate::new(route);
        let handles = (gate.entered.clone(), gate.resume.clone());
        *self.remove_gate.lock() = Some(gate);
        handles
    }

    fn gate_existing(&self, route: Option<RouteSpec<u32>>) -> (Arc<Notify>, Arc<Notify>) {
        let gate = MockGate::new(route);
        let handles = (gate.entered.clone(), gate.resume.clone());
        *self.existing_gate.lock() = Some(gate);
        handles
    }
}

fn take_gate(
    slot: &Mutex<Option<MockGate>>,
    matches: impl FnOnce(&MockGate) -> bool,
) -> Option<MockGate> {
    let mut slot = slot.lock();
    if slot.as_ref().is_some_and(matches) {
        slot.take()
    } else {
        None
    }
}

fn take_fault(
    faults: &Mutex<BTreeMap<RouteSpec<u32>, VecDeque<(RouteError, bool)>>>,
    route: &RouteSpec<u32>,
) -> Option<(RouteError, bool)> {
    faults.lock().get_mut(route).and_then(VecDeque::pop_front)
}

impl RouteBackend for Arc<MockBackend> {
    async fn add(&mut self, route: &RouteSpec<u32>) -> Result<(), RouteError> {
        self.add_calls.lock().push(route.clone());
        self.operations
            .lock()
            .push(MockOperation::Add(route.clone()));
        if let Some(gate) = take_gate(&self.add_gate, |gate| gate.matches(route)) {
            gate.entered.notify_one();
            gate.resume.notified().await;
        }
        match take_fault(&self.add_faults, route) {
            Some((error, side_effect)) => {
                if side_effect {
                    self.routes.lock().insert(route.clone());
                }
                Err(error)
            }
            None => {
                self.routes.lock().insert(route.clone());
                Ok(())
            }
        }
    }

    async fn remove(&mut self, route: &RouteSpec<u32>) -> Result<(), RouteError> {
        self.remove_calls.lock().push(route.clone());
        self.operations
            .lock()
            .push(MockOperation::Remove(route.clone()));
        if let Some(gate) = take_gate(&self.remove_gate, |gate| gate.matches(route)) {
            gate.entered.notify_one();
            gate.resume.notified().await;
        }
        match take_fault(&self.remove_faults, route) {
            Some((error, side_effect)) => {
                if side_effect {
                    self.routes.lock().remove(route);
                }
                Err(error)
            }
            None => {
                self.routes.lock().remove(route);
                Ok(())
            }
        }
    }

    async fn existing(
        &mut self,
        routes: &BTreeSet<RouteSpec<u32>>,
    ) -> Result<BTreeSet<RouteSpec<u32>>, RouteError> {
        self.existing_batches.lock().push(routes.clone());
        self.operations
            .lock()
            .push(MockOperation::Existing(routes.clone()));
        if let Some(gate) = take_gate(&self.existing_gate, |gate| {
            gate.route
                .as_ref()
                .is_none_or(|expected| routes.contains(expected))
        }) {
            gate.entered.notify_one();
            gate.resume.notified().await;
        }
        if let Some(error) = self.existing_errors.lock().pop_front() {
            return Err(error);
        }
        let current = self.routes.lock();
        Ok(routes.intersection(&current).cloned().collect())
    }
}

/// Test-only composition of the same planning stages the round drives.
///
/// Production `reconcile` orders sampling, admission, planning, OS execution
/// and feedback itself; this helper exists only because these tests observe a
/// single plan (and its feedback) without a backend.
async fn plan_stages(
    controller: &RouteController,
    synced: Option<&BTreeMap<(Uuid, Uuid), BTreeSet<IpCidr>>>,
    errors: &BTreeMap<RouteSpec<u32>, Arc<str>>,
    admission_failures: Option<&mut BTreeMap<(Uuid, Uuid), (BTreeSet<IpCidr>, RouteStatus)>>,
) -> ReconcilePlan {
    let mut admission_failures = admission_failures;
    if let Some(failures) = admission_failures.as_deref_mut() {
        failures.clear();
    }
    let inputs = controller.sample_plan_inputs();
    let candidates = resolve_plan_candidates(&inputs);
    #[cfg(feature = "tun")]
    let admissions = admit_plan_members(&inputs, &candidates).await;
    #[cfg(not(feature = "tun"))]
    let admissions = MemberAdmissions::default();
    #[cfg(feature = "tun")]
    if let Some(failures) = admission_failures.as_deref_mut() {
        for (run, failure) in &admissions.failures {
            failures.insert(
                (*run, failure.registration),
                (failure.prefixes.clone(), failure.status.clone()),
            );
        }
    }
    let plan = build_plan(&inputs, &candidates, &admissions);
    controller.update_plan_statuses(&plan, &inputs, &candidates, &admissions, synced, errors);
    plan
}

/// One reconciler; the retry records belong to the same task.
struct Harness {
    controller: RouteController,
    mock: Arc<MockBackend>,
    reconciler: RouteReconciler<Arc<MockBackend>>,
}

impl Harness {
    fn new() -> Self {
        let mock = Arc::new(MockBackend::default());
        let controller = RouteController::new(Arc::new(DirtyFlag::new(false)));
        let reconciler = RouteReconciler::new(controller.clone(), mock.clone());
        Self {
            controller,
            mock,
            reconciler,
        }
    }

    async fn round(&mut self) -> anyhow::Result<()> {
        // The real reconcile has no overall test-facing bound; this one
        // only turns a hung test into a diagnostic instead of a wait.
        tokio::time::timeout(Duration::from_secs(30), self.reconciler.reconcile())
            .await
            .expect("the reconcile round must finish within 30s")
    }

    async fn round_ok(&mut self) {
        self.round()
            .await
            .expect("the reconcile round must not fail");
    }

    fn dirty_peek(&self) -> bool {
        self.controller.dirty.peek()
    }

    fn applied(&self) -> AppliedRoutes {
        self.controller.applied_routes()
    }

    fn effect(&self, route: &RouteSpec<u32>) -> Option<RouteEffect> {
        self.applied()
            .get(&RouteKey::of(route))
            .filter(|row| row.route == *route)
            .map(|row| row.effect)
    }
}

#[test]
fn controller_only_observes_the_registry_and_keeps_the_record_for_cleanup() {
    use easytier_core::host::route::{RouteSet, RouteSource};

    let dirty = Arc::new(DirtyFlag::new(false));
    let controller = RouteController::new(dirty.clone());
    let run = Uuid::new_v4();
    let registry = controller.open_instance(run).unwrap();
    let handle = registry.handle();
    let slot = handle.open_slot(RouteSource::Additional).unwrap();

    assert!(matches!(
        controller.runtime.read().instances[&run].registry.upgrade(),
        Some(current) if Arc::ptr_eq(&current, &registry)
    ));

    dirty.reset();
    drop(registry);
    assert!(
        dirty.peek(),
        "the last registry root must wake the controller"
    );
    assert!(
        matches!(
            handle.open_slot(RouteSource::Additional),
            Err(easytier_core::host::route::RouteInputError::Closed)
        ),
        "a released registry cannot open new inputs"
    );

    let route = RouteSpec::for_tun("10.10.0.0/24".parse().unwrap());
    slot.set_routes(RouteSet::from([route.clone()]));
    assert_eq!(
        slot.statuses().get(&route),
        Some(&easytier_core::host::route::RouteStatus::Pending { error: None }),
        "an existing slot stays mutable after its registry is gone"
    );
    assert!(dirty.peek(), "the orphaned slot still wakes the controller");
    assert!(
        controller.runtime.read().instances.contains_key(&run),
        "the record stays for real cleanup"
    );
}

#[test]
fn repeated_run_and_shutdown_keep_the_existing_record() {
    let dirty = Arc::new(DirtyFlag::new(false));
    let controller = RouteController::new(dirty);
    let run = Uuid::new_v4();
    let registry = controller.open_instance(run).unwrap();

    assert!(
        controller.open_instance(run).is_err(),
        "an existing run cannot be opened twice"
    );
    let current = controller.runtime.read().instances[&run]
        .registry
        .upgrade()
        .unwrap();
    assert!(
        Arc::ptr_eq(&current, &registry),
        "the rejected open must not replace the current registry"
    );

    let other = Uuid::new_v4();
    controller.request_shutdown();
    assert!(controller.is_shutdown());
    assert!(
        controller.open_instance(other).is_err(),
        "shutdown rejects new registration"
    );
    assert!(
        controller.runtime.read().instances.contains_key(&run),
        "shutdown must not erase the existing record"
    );
    assert!(!controller.runtime.read().instances.contains_key(&other));
}

#[test]
fn config_binding_is_single_and_marks_the_shared_flag() {
    use easytier_core::config::{
        peers::PeerRuntimeSnapshot,
        runtime::{CoreRuntimeConfig, CoreRuntimeConfigStore},
    };

    let dirty = Arc::new(DirtyFlag::new(false));
    let controller = RouteController::new(dirty.clone());
    let run = Uuid::new_v4();
    let _registry = controller.open_instance(run).unwrap();
    let store = CoreRuntimeConfigStore::new(
        CoreRuntimeConfig::default(),
        Arc::new(PeerRuntimeSnapshot::default()),
    );

    dirty.reset();
    controller.bind_config(run, store.clone()).unwrap();
    assert!(
        dirty.peek(),
        "a successful binding marks the shared route flag"
    );

    dirty.reset();
    let other = CoreRuntimeConfigStore::new(
        CoreRuntimeConfig::default(),
        Arc::new(PeerRuntimeSnapshot::default()),
    );
    assert!(
        controller.bind_config(run, other.clone()).is_err(),
        "a second binding must fail"
    );
    assert!(
        !dirty.peek(),
        "a rejected binding does not mark the shared flag again"
    );

    let replacement = Arc::new(DirtyFlag::new(false));
    other
        .bind_route_dirty(replacement)
        .expect("a rejected controller binding must leave the store unclaimed");
    assert!(
        Arc::ptr_eq(
            &controller.runtime.read().instances[&run]
                .config
                .as_ref()
                .unwrap()
                .snapshot(),
            &store.snapshot()
        ),
        "the original config binding stays"
    );
}

#[tokio::test]
async fn drain_waits_for_the_record_and_not_for_the_registry() {
    let dirty = Arc::new(DirtyFlag::new(false));
    let controller = RouteController::new(dirty);
    let run = Uuid::new_v4();
    let registry = controller.open_instance(run).unwrap();
    drop(registry);

    let drain = controller.drain(run);
    tokio::pin!(drain);

    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut drain)
            .await
            .is_err(),
        "a released registry alone must not complete the drain"
    );
    assert!(
        controller.runtime.read().instances.contains_key(&run),
        "the drain wait must not remove the record"
    );

    controller.runtime.write().instances.remove(&run);
    controller.changed().notify_waiters();
    tokio::time::timeout(Duration::from_secs(1), drain)
        .await
        .expect("removing the record and notifying must complete the drain")
        .unwrap();
}

#[tokio::test]
async fn multi_owner_shared_ordinary_route_is_kept_until_the_last_owner_withdraws() {
    let mut h = Harness::new();
    let declaration = indexed("10.14.0.0/24", 10, None);
    let route = resolved(&declaration);

    let (run_a, _registry_a, slot_a) = instance_with_slot(&h.controller, RouteSource::Additional);
    let (run_b, _registry_b, slot_b) = instance_with_slot(&h.controller, RouteSource::Additional);

    slot_a.set_routes(RouteSet::from([declaration.clone()]));
    h.round_ok().await;
    assert_eq!(h.effect(&route), Some(RouteEffect::Owned));
    assert!(h.mock.contains(&route));
    assert_eq!(h.mock.add_count(), 1);

    slot_b.set_routes(RouteSet::from([declaration]));
    h.round_ok().await;
    assert_eq!(
        h.applied()[&RouteKey::of(&route)].owners,
        BTreeSet::from([run_a, run_b]),
        "both owners share the identical physical row"
    );
    assert_eq!(h.mock.routes.lock().len(), 1);
    assert_eq!(
        h.mock.add_count(),
        1,
        "the shared row is installed only once"
    );

    drop(slot_a);
    h.round_ok().await;
    assert_eq!(
        h.applied()[&RouteKey::of(&route)].owners,
        BTreeSet::from([run_b]),
        "withdrawing one declaration keeps the other owner's row"
    );
    assert!(h.mock.contains(&route));
    assert_eq!(h.mock.remove_count(), 0);

    drop(slot_b);
    h.round_ok().await;
    assert!(
        h.applied().is_empty(),
        "the last owner withdrawal retires the responsibility"
    );
    assert!(h.mock.routes.lock().is_empty());
    assert_eq!(
        h.mock.remove_calls.lock().clone(),
        vec![route],
        "the shared row is deleted exactly once"
    );
    assert!(h.reconciler.route_retries.is_empty());
}

// Planning tests. Every route below uses an explicit interface index, so
// none of them needs a real NIC or a system call.

fn indexed(destination: &str, dev: u32, via: Option<&str>) -> RouteSpec<RouteDevice> {
    RouteSpec {
        destination: destination.parse().unwrap(),
        action: RouteAction::Unicast {
            dev: RouteDevice::Index(dev),
            via: via.map(|via| via.parse().unwrap()),
        },
        #[cfg(any(target_os = "linux", windows))]
        metric: 65535,
        #[cfg(target_os = "linux")]
        table: None,
    }
}

#[cfg(target_os = "linux")]
fn indexed_with_metric(
    destination: &str,
    dev: u32,
    metric: u32,
    via: Option<&str>,
) -> RouteSpec<RouteDevice> {
    let mut route = indexed(destination, dev, via);
    route.metric = metric;
    route
}

/// The installable form of an explicit-index declaration.
fn resolved(declaration: &RouteSpec<RouteDevice>) -> RouteSpec<u32> {
    normalize_route(declaration.clone().resolve(None).unwrap()).unwrap()
}

fn installed(declaration: &RouteSpec<RouteDevice>, run: Uuid) -> AppliedRoute {
    AppliedRoute {
        route: resolved(declaration),
        owners: BTreeSet::from([run]),
        effect: RouteEffect::Owned,
        #[cfg(feature = "tun")]
        members: BTreeMap::new(),
    }
}

/// Open one instance and one slot. The registry root stays with the caller,
/// as the native instance runtime owns it in production.
fn instance_with_slot(
    controller: &RouteController,
    source: RouteSource,
) -> (Uuid, Arc<Registry>, easytier_core::host::route::RouteSlot) {
    let run = Uuid::new_v4();
    let registry = controller.open_instance(run).unwrap();
    let slot = registry.handle().open_slot(source).unwrap();
    (run, registry, slot)
}

// Pure planning tests. They resolve the sampled candidates and build the
// complete target outside an async context: no NIC lock, backend call or slot
// status update may be needed to compute it.

#[test]
fn pure_plan_builds_the_target_without_backend_nic_or_slot_feedback() {
    let controller = RouteController::new(Arc::new(DirtyFlag::new(false)));
    let declaration = indexed("10.23.0.0/24", 7, None);
    let route = resolved(&declaration);
    let (run, registry, slot) = instance_with_slot(&controller, RouteSource::Additional);
    slot.set_routes(RouteSet::from([declaration.clone()]));

    let inputs = controller.sample_plan_inputs();
    let candidates = resolve_plan_candidates(&inputs);
    let plan = build_plan(&inputs, &candidates, &MemberAdmissions::default());

    assert_eq!(
        plan.desired.get(&RouteKey::of(&route)),
        Some(&(route.clone(), BTreeSet::from([run])))
    );
    assert_eq!(plan.add, vec![route]);
    assert!(plan.remove.is_empty());
    assert_eq!(
        slot.statuses().get(&declaration),
        Some(&RouteStatus::Pending { error: None }),
        "building the plan must not report status"
    );

    drop(slot);
    drop(registry);
    assert!(
        plan.slots.iter().all(|(_, weak)| weak.strong_count() == 0),
        "sampling keeps slots only weakly"
    );
}

#[cfg(feature = "tun")]
#[test]
fn pure_plan_consumes_member_admission_without_taking_the_nic() {
    let controller = RouteController::new(Arc::new(DirtyFlag::new(false)));
    let run = Uuid::new_v4();
    let registry = controller.open_instance(run).unwrap();
    let slot = registry
        .handle()
        .open_slot(RouteSource::Additional)
        .unwrap();
    let mut fixture = ManagedNicFixture::new(run);
    let member = fixture.create_member();
    controller.bind_member(run, &member).unwrap();
    controller
        .ready(
            run,
            &member,
            InterfaceInfo {
                name: MANAGED_NIC_NAME.to_owned(),
                ifindex: 7,
            },
        )
        .unwrap();

    let declaration = indexed("10.24.0.0/24", 7, None);
    let route = resolved(&declaration);
    slot.set_routes(RouteSet::from([declaration.clone()]));

    let inputs = controller.sample_plan_inputs();
    let candidates = resolve_plan_candidates(&inputs);
    let unadmitted = build_plan(&inputs, &candidates, &MemberAdmissions::default());
    assert!(
        unadmitted.desired.is_empty() && unadmitted.add.is_empty(),
        "a managed candidate without this round's admission is not a target"
    );

    let mut admitted = MemberAdmissions::default();
    admitted.accepted.insert(
        run,
        MemberAdmission {
            registration: member.registration_id(),
            prefixes: BTreeSet::from([route.destination]),
        },
    );
    let plan = build_plan(&inputs, &candidates, &admitted);
    assert_eq!(
        plan.desired.get(&RouteKey::of(&route)),
        Some(&(route.clone(), BTreeSet::from([run])))
    );
    assert_eq!(plan.add, vec![route]);
    assert!(
        matches!(
            slot.statuses().get(&declaration),
            Some(RouteStatus::Pending { .. })
        ),
        "neither build consumes the NIC or reports status"
    );
}

// Execution tests. They use the in-memory mock above only; no platform
// backend, TUN device or system network state is touched.

#[tokio::test]
async fn a_matching_preexisting_row_is_external_and_its_withdrawal_only_clears_the_ledger() {
    let mut h = Harness::new();
    let declaration = indexed("10.16.0.0/24", 7, None);
    let route = resolved(&declaration);
    h.mock.routes.lock().insert(route.clone());

    let (_run, _registry, slot) = instance_with_slot(&h.controller, RouteSource::Additional);
    slot.set_routes(RouteSet::from([declaration.clone()]));
    h.round_ok().await;
    assert_eq!(h.effect(&route), Some(RouteEffect::External));
    assert_eq!(
        h.mock.add_count(),
        0,
        "an existing row is never installed again"
    );
    assert_eq!(h.mock.remove_count(), 0);
    assert_eq!(slot.statuses().get(&declaration), Some(&RouteStatus::Ready));
    let reads = h.mock.existing_count();

    slot.clear();
    h.round_ok().await;
    assert!(
        h.applied().is_empty(),
        "the last withdrawal releases only the ledger entry"
    );
    assert!(
        h.mock.contains(&route),
        "the external row stays physically present"
    );
    assert_eq!(h.mock.remove_count(), 0, "an external row is never deleted");
    assert_eq!(
        h.mock.existing_count(),
        reads,
        "releasing an external row needs no readback"
    );
}

#[tokio::test(start_paused = true)]
async fn a_definite_add_failure_pends_only_its_route_until_the_retry_deadline() {
    let mut h = Harness::new();
    let a = indexed("10.20.0.0/24", 7, None);
    let b = indexed("10.21.0.0/24", 7, None);
    let a_route = resolved(&a);
    let b_route = resolved(&b);
    h.mock.queue_add(
        &a_route,
        RouteError::Failed(anyhow::anyhow!("install failed")),
        false,
    );

    let (_run, _registry, slot) = instance_with_slot(&h.controller, RouteSource::Additional);
    slot.set_routes(RouteSet::from([a.clone(), b.clone()]));
    h.round_ok().await;

    assert_eq!(h.effect(&a_route), None);
    assert_eq!(h.effect(&b_route), Some(RouteEffect::Owned));
    let statuses = slot.statuses();
    assert_eq!(
        statuses.get(&a),
        Some(&RouteStatus::Pending {
            error: Some(Arc::from("route operation failed: install failed"))
        })
    );
    assert_eq!(statuses.get(&b), Some(&RouteStatus::Ready));
    let key = RouteKey::of(&a_route);
    assert_eq!(h.reconciler.route_retries[&key].route, a_route);
    assert!(
        h.reconciler.route_retries[&key].add,
        "the retry belongs to the addition"
    );
    assert!(h.reconciler.route_retries[&key].retry_at > tokio::time::Instant::now());
    assert_eq!(
        h.mock
            .add_calls
            .lock()
            .iter()
            .filter(|route| *route == &a_route)
            .count(),
        1
    );
    let reads = h.mock.existing_count();

    h.controller.dirty.mark();
    tokio::time::advance(Duration::from_millis(100)).await;
    h.round_ok().await;
    assert_eq!(
        h.mock
            .add_calls
            .lock()
            .iter()
            .filter(|route| *route == &a_route)
            .count(),
        1,
        "an unrelated dirty mark must not retry the failed addition early"
    );
    assert_eq!(
        h.mock.existing_count(),
        reads,
        "no readback is issued before the deadline"
    );
    assert!(matches!(
        slot.statuses().get(&a),
        Some(RouteStatus::Pending { error: Some(_) })
    ));

    tokio::time::advance(Duration::from_millis(100)).await;
    h.round_ok().await;
    assert_eq!(h.effect(&a_route), Some(RouteEffect::Owned));
    assert_eq!(slot.statuses().get(&a), Some(&RouteStatus::Ready));
    assert_eq!(
        h.mock
            .add_calls
            .lock()
            .iter()
            .filter(|route| *route == &a_route)
            .count(),
        2,
        "the retry runs once the deadline really passed"
    );
    assert!(h.reconciler.route_retries.is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_definite_remove_failure_restores_owned_until_its_retry_deadline() {
    let mut h = Harness::new();
    let declaration = indexed("10.22.0.0/24", 7, None);
    let route = resolved(&declaration);
    let (_run, _registry, slot) = instance_with_slot(&h.controller, RouteSource::Additional);
    slot.set_routes(RouteSet::from([declaration]));
    h.round_ok().await;
    assert_eq!(h.effect(&route), Some(RouteEffect::Owned));

    h.mock.queue_remove(
        &route,
        RouteError::Failed(anyhow::anyhow!("delete failed")),
        false,
    );
    slot.clear();
    h.round_ok().await;
    assert_eq!(
        h.effect(&route),
        Some(RouteEffect::Owned),
        "a definite failure restores the owned effect"
    );
    assert!(h.mock.contains(&route));
    assert_eq!(h.mock.remove_count(), 1);
    let key = RouteKey::of(&route);
    assert_eq!(h.reconciler.route_retries[&key].route, route);
    assert!(
        !h.reconciler.route_retries[&key].add,
        "the retry belongs to the removal"
    );
    assert!(h.reconciler.route_retries[&key].retry_at > tokio::time::Instant::now());

    h.controller.dirty.mark();
    tokio::time::advance(Duration::from_millis(100)).await;
    h.round_ok().await;
    assert_eq!(
        h.mock.remove_count(),
        1,
        "dirty alone cannot bypass the delete backoff"
    );
    assert_eq!(h.effect(&route), Some(RouteEffect::Owned));

    tokio::time::advance(Duration::from_millis(100)).await;
    h.round_ok().await;
    assert_eq!(h.mock.remove_count(), 2);
    assert_eq!(h.effect(&route), None);
    assert!(!h.mock.contains(&route));
    assert!(h.reconciler.route_retries.is_empty());
}

#[tokio::test(start_paused = true)]
async fn an_unknown_removal_stays_removing_and_completes_at_the_retry() {
    let mut h = Harness::new();
    let declaration = indexed("10.23.0.0/24", 7, None);
    let route = resolved(&declaration);
    let (_run, _registry, slot) = instance_with_slot(&h.controller, RouteSource::Additional);
    slot.set_routes(RouteSet::from([declaration]));
    h.round_ok().await;
    assert_eq!(h.effect(&route), Some(RouteEffect::Owned));

    h.mock.queue_remove(
        &route,
        RouteError::Unknown(anyhow::anyhow!("unknown delete")),
        false,
    );
    slot.clear();
    h.round_ok().await;
    assert_eq!(h.effect(&route), Some(RouteEffect::Removing));
    assert!(h.mock.contains(&route));
    assert_eq!(h.mock.remove_count(), 1);
    let key = RouteKey::of(&route);

    tokio::time::advance(Duration::from_millis(200)).await;
    h.mock.queue_remove(
        &route,
        RouteError::Unknown(anyhow::anyhow!("unknown delete again")),
        false,
    );
    h.round_ok().await;
    assert_eq!(
        h.effect(&route),
        Some(RouteEffect::Removing),
        "a present readback must not promote the uncertain removal back to Owned"
    );
    assert_eq!(h.mock.remove_count(), 2);
    assert!(!h.reconciler.route_retries[&key].add);
    assert!(h.reconciler.route_retries[&key].retry_at > tokio::time::Instant::now());

    tokio::time::advance(Duration::from_millis(400)).await;
    h.round_ok().await;
    assert_eq!(h.effect(&route), None);
    assert!(!h.mock.contains(&route));
    assert_eq!(h.mock.remove_count(), 3);
    assert!(h.reconciler.route_retries.is_empty());
}

#[tokio::test(start_paused = true)]
async fn an_unknown_removal_with_an_absent_readback_retires_the_record() {
    let mut h = Harness::new();
    let declaration = indexed("10.24.0.0/24", 7, None);
    let route = resolved(&declaration);
    let (_run, _registry, slot) = instance_with_slot(&h.controller, RouteSource::Additional);
    slot.set_routes(RouteSet::from([declaration]));
    h.round_ok().await;
    assert_eq!(h.effect(&route), Some(RouteEffect::Owned));

    h.mock.queue_remove(
        &route,
        RouteError::Unknown(anyhow::anyhow!("unknown delete")),
        true,
    );
    slot.clear();
    h.round_ok().await;
    assert_eq!(h.effect(&route), Some(RouteEffect::Removing));
    assert!(!h.mock.contains(&route));
    assert_eq!(h.mock.remove_count(), 1);
    assert!(
        h.reconciler
            .route_retries
            .contains_key(&RouteKey::of(&route))
    );

    tokio::time::advance(Duration::from_millis(200)).await;
    h.round_ok().await;
    assert_eq!(h.effect(&route), None);
    assert!(h.reconciler.route_retries.is_empty());
    assert_eq!(
        h.mock.remove_count(),
        1,
        "a confirmed absence needs no second delete"
    );
}

#[tokio::test(start_paused = true)]
async fn an_unknown_add_with_an_installed_row_stays_adding_and_is_never_deleted() {
    let mut h = Harness::new();
    let declaration = indexed("10.25.0.0/24", 7, None);
    let route = resolved(&declaration);
    let (_run, _registry, slot) = instance_with_slot(&h.controller, RouteSource::Additional);
    slot.set_routes(RouteSet::from([declaration.clone()]));
    h.mock.queue_add(
        &route,
        RouteError::Unknown(anyhow::anyhow!("unknown add")),
        true,
    );
    h.round_ok().await;

    assert_eq!(h.effect(&route), Some(RouteEffect::Adding));
    assert!(h.mock.contains(&route));
    assert_eq!(h.mock.add_count(), 1);
    assert_eq!(h.mock.remove_count(), 0);
    assert_eq!(
        slot.statuses().get(&declaration),
        Some(&RouteStatus::Pending {
            error: Some(Arc::from("route operation outcome is unknown: unknown add"))
        })
    );

    tokio::time::advance(Duration::from_millis(200)).await;
    h.round_ok().await;
    assert_eq!(h.effect(&route), Some(RouteEffect::Adding));
    assert_eq!(h.mock.add_count(), 1);
    assert!(matches!(
        slot.statuses().get(&declaration),
        Some(RouteStatus::Pending { error: Some(error) })
            if error.as_ref() == "route addition is still unconfirmed"
    ));

    slot.clear();
    tokio::time::advance(Duration::from_millis(400)).await;
    h.round_ok().await;
    assert_eq!(
        h.effect(&route),
        Some(RouteEffect::Adding),
        "a withdrawn declaration must not delete an uncertain installation"
    );
    assert!(h.mock.contains(&route));
    assert_eq!(h.mock.add_count(), 1);
    assert_eq!(h.mock.remove_count(), 0);
    assert!(
        slot.statuses().is_empty(),
        "no withdrawn entry is resurrected"
    );
}

#[tokio::test(start_paused = true)]
async fn an_unknown_add_retires_on_confirmed_absence_and_only_a_current_declaration_readds() {
    let mut h = Harness::new();
    let declaration = indexed("10.26.0.0/24", 7, None);
    let route = resolved(&declaration);
    let (_run, _registry, slot) = instance_with_slot(&h.controller, RouteSource::Additional);
    slot.set_routes(RouteSet::from([declaration.clone()]));
    h.mock.queue_add(
        &route,
        RouteError::Unknown(anyhow::anyhow!("unknown add")),
        false,
    );
    h.round_ok().await;
    assert_eq!(h.effect(&route), Some(RouteEffect::Adding));
    assert!(!h.mock.contains(&route));
    assert_eq!(h.mock.add_count(), 1);

    slot.clear();
    tokio::time::advance(Duration::from_millis(200)).await;
    h.round_ok().await;
    assert_eq!(h.effect(&route), None);
    assert!(h.reconciler.route_retries.is_empty());
    assert_eq!(
        h.mock.add_count(),
        1,
        "the withdrawn goal is not resurrected by the confirmed absence"
    );
    assert_eq!(h.mock.remove_count(), 0);
    assert!(slot.statuses().is_empty());

    slot.set_routes(RouteSet::from([declaration.clone()]));
    h.round_ok().await;
    assert_eq!(h.effect(&route), Some(RouteEffect::Owned));
    assert_eq!(
        h.mock.add_count(),
        2,
        "the current declaration may add again"
    );
    assert_eq!(slot.statuses().get(&declaration), Some(&RouteStatus::Ready));
}

/// A declaration that stays in its slot through an unknown addition is
/// confirmed absent at the retry deadline and only then really added by a
/// later round. The slot is never cleared or refilled to force that
/// wakeup.
#[tokio::test(start_paused = true)]
async fn an_unknown_add_with_a_retained_declaration_is_confirmed_absent_and_readded() {
    let mut h = Harness::new();
    let declaration = indexed("10.43.0.0/24", 7, None);
    let route = resolved(&declaration);
    let (_run, _registry, slot) = instance_with_slot(&h.controller, RouteSource::Additional);
    slot.set_routes(RouteSet::from([declaration.clone()]));
    h.mock.queue_add(
        &route,
        RouteError::Unknown(anyhow::anyhow!("unknown add")),
        false,
    );
    h.round_ok().await;

    assert_eq!(h.effect(&route), Some(RouteEffect::Adding));
    assert!(
        !h.mock.contains(&route),
        "the unknown add left no physical row"
    );
    assert_eq!(h.mock.add_count(), 1);
    assert_eq!(h.mock.remove_count(), 0);
    assert_eq!(
        slot.statuses().get(&declaration),
        Some(&RouteStatus::Pending {
            error: Some(Arc::from("route operation outcome is unknown: unknown add"))
        }),
        "the retained declaration carries the unconfirmed outcome"
    );
    let key = RouteKey::of(&route);
    assert_eq!(h.reconciler.route_retries[&key].route, route);
    assert!(
        h.reconciler.route_retries[&key].add,
        "the retry belongs to the addition"
    );
    assert!(h.reconciler.route_retries[&key].retry_at > tokio::time::Instant::now());

    h.controller.dirty.reset();
    tokio::time::advance(Duration::from_millis(200)).await;
    h.round_ok().await;
    assert_eq!(
        h.effect(&route),
        None,
        "the retry deadline confirms the absence and retires the Adding record"
    );
    assert!(!h.mock.contains(&route));
    assert!(h.reconciler.route_retries.is_empty());
    assert_eq!(
        h.mock.add_count(),
        1,
        "the confirmation round keeps the production batch policy"
    );
    assert_eq!(
        slot.statuses().get(&declaration),
        Some(&RouteStatus::Pending { error: None }),
        "the retained declaration waits for the next round"
    );
    assert!(
        h.dirty_peek(),
        "the production round marks the still-actionable addition"
    );

    h.round_ok().await;
    assert_eq!(h.effect(&route), Some(RouteEffect::Owned));
    assert!(h.mock.contains(&route));
    assert_eq!(slot.statuses().get(&declaration), Some(&RouteStatus::Ready));
    assert_eq!(
        h.mock.add_count(),
        2,
        "the retained declaration was really added once more"
    );
    assert_eq!(h.mock.remove_count(), 0);
}

#[tokio::test]
async fn a_real_already_exists_with_a_matching_full_row_becomes_external() {
    let mut h = Harness::new();
    let declaration = indexed("10.27.0.0/24", 7, None);
    let route = resolved(&declaration);
    h.mock.queue_add(
        &route,
        RouteError::Failed(anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "already present",
        ))),
        true,
    );

    let (_run, _registry, slot) = instance_with_slot(&h.controller, RouteSource::Additional);
    slot.set_routes(RouteSet::from([declaration.clone()]));
    h.round_ok().await;
    assert_eq!(h.effect(&route), Some(RouteEffect::External));
    assert!(h.mock.contains(&route));
    assert_eq!(h.mock.add_count(), 1);
    assert_eq!(h.mock.remove_count(), 0);
    assert_eq!(slot.statuses().get(&declaration), Some(&RouteStatus::Ready));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_real_already_exists_with_a_different_full_row_of_the_same_key_is_not_external() {
    let mut h = Harness::new();
    let declaration = indexed_with_metric("10.28.0.0/24", 7, 77, Some("192.0.2.1"));
    let other = indexed_with_metric("10.28.0.0/24", 7, 77, Some("192.0.2.9"));
    let route = resolved(&declaration);
    let other_route = resolved(&other);
    assert_eq!(
        RouteKey::of(&route),
        RouteKey::of(&other_route),
        "the two rows share the exclusive key"
    );
    assert_ne!(route, other_route);
    h.mock.routes.lock().insert(other_route.clone());
    h.mock.queue_add(
        &route,
        RouteError::Failed(anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "already present",
        ))),
        false,
    );

    let (_run, _registry, slot) = instance_with_slot(&h.controller, RouteSource::Additional);
    slot.set_routes(RouteSet::from([declaration.clone()]));
    h.round_ok().await;
    assert!(
        h.applied().get(&RouteKey::of(&route)).is_none(),
        "another full row of the same key is not the requested row"
    );
    assert_eq!(h.effect(&route), None);
    assert!(h.mock.contains(&other_route));
    assert!(!h.mock.contains(&route));
    assert_eq!(h.mock.add_count(), 1);
    assert_eq!(h.mock.remove_count(), 0);
    assert!(matches!(
        slot.statuses().get(&declaration),
        Some(RouteStatus::Pending { error: Some(_) })
    ));
}

#[tokio::test]
async fn an_unrelated_definite_failure_is_not_read_back_as_an_existing_row() {
    let mut h = Harness::new();
    let declaration = indexed("10.29.0.0/24", 7, None);
    let route = resolved(&declaration);
    h.mock.queue_add(
        &route,
        RouteError::Failed(anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "denied",
        ))),
        false,
    );
    let (_run, _registry, slot) = instance_with_slot(&h.controller, RouteSource::Additional);
    slot.set_routes(RouteSet::from([declaration]));

    let mock = h.mock.clone();
    let (entered, resume) = mock.gate_add(Some(route.clone()));
    let mut round = Box::pin(h.round());
    tokio::select! {
        result = round.as_mut() => panic!("the failed addition finished before the gate: {result:?}"),
        _ = entered.notified() => {}
    }
    // The row appears while the definite, non-AlreadyExists failure is in
    // flight. The controller must not turn that into an External success.
    mock.routes.lock().insert(route.clone());
    resume.notify_one();
    round.await.unwrap();

    assert_eq!(
        h.effect(&route),
        None,
        "only an AlreadyExists chain may adopt a readback"
    );
    assert!(h.mock.contains(&route));
    assert_eq!(h.mock.add_count(), 1);
    assert_eq!(
        h.mock.existing_count(),
        1,
        "only the pre-add candidate readback ran; there is no post-failure probe"
    );
    assert_eq!(h.mock.remove_count(), 0);
}

#[cfg(target_os = "linux")]
#[tokio::test(start_paused = true)]
async fn replacing_an_exclusive_key_waits_for_the_old_delete_and_keeps_its_retry() {
    let mut h = Harness::new();
    let old = indexed_with_metric("10.30.0.0/24", 7, 91, Some("192.0.2.1"));
    let new = indexed_with_metric("10.30.0.0/24", 7, 91, Some("192.0.2.9"));
    let old_route = resolved(&old);
    let new_route = resolved(&new);
    assert_eq!(RouteKey::of(&old_route), RouteKey::of(&new_route));
    assert_ne!(old_route, new_route);

    let (_run, _registry, slot) = instance_with_slot(&h.controller, RouteSource::Additional);
    slot.set_routes(RouteSet::from([old]));
    h.round_ok().await;
    assert_eq!(h.effect(&old_route), Some(RouteEffect::Owned));
    let adds = h.mock.add_count();
    let reads = h.mock.existing_count();

    slot.set_routes(RouteSet::from([new]));
    h.mock.queue_remove(
        &old_route,
        RouteError::Unknown(anyhow::anyhow!("delete outcome unknown")),
        false,
    );
    h.round_ok().await;
    let key = RouteKey::of(&old_route);
    assert_eq!(h.effect(&old_route), Some(RouteEffect::Removing));
    assert_eq!(
        h.mock.add_count(),
        adds,
        "the new row must not be added while the old one still occupies the key"
    );
    assert_eq!(
        h.mock.existing_count(),
        reads,
        "no readback is issued for the occupied key"
    );
    assert_eq!(h.mock.remove_count(), 1);
    assert_eq!(h.reconciler.route_retries[&key].route, old_route);
    assert!(!h.reconciler.route_retries[&key].add);

    tokio::time::advance(Duration::from_millis(200)).await;
    h.mock
        .queue_existing_error(RouteError::Failed(anyhow::anyhow!("readback failed")));
    h.round_ok().await;
    assert_eq!(h.effect(&old_route), Some(RouteEffect::Removing));
    assert_eq!(
        h.reconciler.route_retries[&key].route, old_route,
        "the failed confirmation keeps the old row's retry"
    );
    assert!(
        !h.reconciler.route_retries[&key].add,
        "it stays a removal retry and is not overwritten by a new addition"
    );
    assert_eq!(
        h.reconciler.route_retries[&key].error.as_ref(),
        "route operation failed: readback failed"
    );
    assert_eq!(h.mock.add_count(), adds);
    assert_eq!(
        h.mock.remove_count(),
        1,
        "a failed batch confirmation does not delete again"
    );
    assert!(
        h.mock
            .existing_batches
            .lock()
            .iter()
            .all(|batch| !batch.contains(&new_route)),
        "no candidate readback ever asks for the new row while the key is occupied"
    );

    tokio::time::advance(Duration::from_millis(400)).await;
    h.round_ok().await;
    assert_eq!(h.effect(&old_route), None);
    assert!(!h.mock.contains(&old_route));
    assert_eq!(h.mock.remove_count(), 2);
    assert!(
        h.mock
            .add_calls
            .lock()
            .iter()
            .all(|route| route != &new_route),
        "the old delete must be confirmed before the new add starts"
    );

    h.round_ok().await;
    assert_eq!(h.effect(&new_route), Some(RouteEffect::Owned));
    assert!(h.mock.contains(&new_route));
    assert!(!h.mock.contains(&old_route));
    assert_eq!(h.mock.add_count(), adds + 1);
    let operations = h.mock.operations.lock().clone();
    let last_old_remove = operations
        .iter()
        .rposition(
            |operation| matches!(operation, MockOperation::Remove(route) if route == &old_route),
        )
        .expect("the old row was removed");
    let new_add = operations
        .iter()
        .position(|operation| matches!(operation, MockOperation::Add(route) if route == &new_route))
        .expect("the new row was added");
    assert!(
        last_old_remove < new_add,
        "the old row's actual deletion precedes the new row's addition"
    );
}

#[tokio::test]
async fn an_in_flight_addition_survives_a_withdrawal_and_is_cleaned_up_next_round() {
    let mut h = Harness::new();
    let declaration = indexed("10.31.0.0/24", 7, None);
    let route = resolved(&declaration);
    let (_run, _registry, slot) = instance_with_slot(&h.controller, RouteSource::Additional);
    slot.set_routes(RouteSet::from([declaration]));

    let controller = h.controller.clone();
    let mock = h.mock.clone();
    let dirty = controller.dirty.clone();
    let slot_handle = slot.clone();
    let (entered, resume) = mock.gate_add(Some(route.clone()));
    dirty.reset();
    let mut round = Box::pin(h.round());
    tokio::select! {
        result = round.as_mut() => panic!("the addition finished before the gate: {result:?}"),
        _ = entered.notified() => {}
    }
    assert!(
        !dirty.peek(),
        "the round itself has not changed the inputs yet"
    );
    slot_handle.clear();
    assert!(
        dirty.peek(),
        "the withdrawal during the awaited addition marks the flag"
    );
    resume.notify_one();
    round.await.unwrap();

    assert_eq!(
        h.effect(&route),
        Some(RouteEffect::Owned),
        "the real successful addition is recorded as Owned first"
    );
    assert!(h.mock.contains(&route));
    assert_eq!(
        h.mock.remove_count(),
        0,
        "no compensating delete happens in the same round"
    );
    assert!(
        slot_handle.statuses().is_empty(),
        "the withdrawn declaration is not resurrected"
    );
    assert!(
        h.dirty_peek(),
        "the mark produced during the awaited addition survived the round"
    );

    h.round_ok().await;
    assert_eq!(h.effect(&route), None);
    assert!(!h.mock.contains(&route));
    assert_eq!(h.mock.remove_count(), 1);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn an_in_flight_addition_cannot_mark_a_replacement_row_ready() {
    let mut h = Harness::new();
    let old = indexed_with_metric("10.32.0.0/24", 7, 92, Some("192.0.2.1"));
    let new = indexed_with_metric("10.32.0.0/24", 7, 92, Some("192.0.2.9"));
    let old_route = resolved(&old);
    let new_route = resolved(&new);
    assert_eq!(RouteKey::of(&old_route), RouteKey::of(&new_route));
    let (_run, _registry, slot) = instance_with_slot(&h.controller, RouteSource::Additional);
    slot.set_routes(RouteSet::from([old.clone()]));

    let controller = h.controller.clone();
    let mock = h.mock.clone();
    let dirty = controller.dirty.clone();
    let slot_handle = slot.clone();
    let (entered, resume) = mock.gate_add(Some(old_route.clone()));
    dirty.reset();
    let mut round = Box::pin(h.round());
    tokio::select! {
        result = round.as_mut() => panic!("the addition finished before the gate: {result:?}"),
        _ = entered.notified() => {}
    }
    slot_handle.set_routes(RouteSet::from([new.clone()]));
    assert!(dirty.peek());
    resume.notify_one();
    round.await.unwrap();

    assert_eq!(h.effect(&old_route), Some(RouteEffect::Owned));
    assert!(
        h.mock.remove_calls.lock().is_empty(),
        "no inline compensating delete happens in the same round"
    );
    assert_eq!(
        slot_handle.statuses().get(&new),
        Some(&RouteStatus::Pending { error: None }),
        "the old row cannot mark the replacement row ready"
    );
    assert!(slot_handle.statuses().get(&old).is_none());
    assert!(h.dirty_peek());

    h.round_ok().await;
    assert_eq!(h.effect(&old_route), None);
    assert!(!h.mock.contains(&old_route));
    assert_eq!(h.mock.remove_count(), 1);
    h.round_ok().await;
    assert_eq!(h.effect(&new_route), Some(RouteEffect::Owned));
    assert!(h.mock.contains(&new_route));
    assert_eq!(slot_handle.statuses().get(&new), Some(&RouteStatus::Ready));
}

#[tokio::test]
async fn an_in_flight_addition_can_be_ready_when_the_same_row_is_redeclared() {
    let mut h = Harness::new();
    let declaration = indexed("10.33.0.0/24", 7, None);
    let route = resolved(&declaration);
    let (_run, _registry, slot) = instance_with_slot(&h.controller, RouteSource::Additional);
    slot.set_routes(RouteSet::from([declaration.clone()]));

    let controller = h.controller.clone();
    let mock = h.mock.clone();
    let dirty = controller.dirty.clone();
    let slot_handle = slot.clone();
    let (entered, resume) = mock.gate_add(Some(route.clone()));
    dirty.reset();
    let mut round = Box::pin(h.round());
    tokio::select! {
        result = round.as_mut() => panic!("the addition finished before the gate: {result:?}"),
        _ = entered.notified() => {}
    }
    slot_handle.clear();
    slot_handle.set_routes(RouteSet::from([declaration.clone()]));
    assert!(dirty.peek());
    resume.notify_one();
    round.await.unwrap();

    assert_eq!(h.effect(&route), Some(RouteEffect::Owned));
    assert_eq!(
        slot_handle.statuses().get(&declaration),
        Some(&RouteStatus::Ready),
        "a remove-and-readd of the same row may reuse the new effect"
    );
    assert_eq!(h.mock.remove_count(), 0);
    assert!(h.dirty_peek());

    h.round_ok().await;
    assert_eq!(h.effect(&route), Some(RouteEffect::Owned));
    assert_eq!(h.mock.add_count(), 1);
    assert_eq!(h.mock.remove_count(), 0);
}

#[tokio::test]
async fn an_in_flight_addition_leaves_an_unrelated_change_dirty_and_converges_next_round() {
    let mut h = Harness::new();
    let a = indexed("10.34.0.0/24", 7, None);
    let b_old = indexed("10.35.0.0/24", 7, None);
    let b_new = indexed("10.36.0.0/24", 7, None);
    let a_route = resolved(&a);
    let b_old_route = resolved(&b_old);
    let b_new_route = resolved(&b_new);
    let (_run, _registry, slot) = instance_with_slot(&h.controller, RouteSource::Additional);

    slot.set_routes(RouteSet::from([b_old.clone()]));
    h.round_ok().await;
    assert_eq!(h.effect(&b_old_route), Some(RouteEffect::Owned));

    slot.set_routes(RouteSet::from([a.clone(), b_old.clone()]));
    let controller = h.controller.clone();
    let mock = h.mock.clone();
    let dirty = controller.dirty.clone();
    let slot_handle = slot.clone();
    let (entered, resume) = mock.gate_add(Some(a_route.clone()));
    dirty.reset();
    let mut round = Box::pin(h.round());
    tokio::select! {
        result = round.as_mut() => panic!("the addition finished before the gate: {result:?}"),
        _ = entered.notified() => {}
    }
    slot_handle.set_routes(RouteSet::from([a.clone(), b_new.clone()]));
    assert!(dirty.peek());
    resume.notify_one();
    round.await.unwrap();

    assert_eq!(h.effect(&a_route), Some(RouteEffect::Owned));
    assert_eq!(
        slot_handle.statuses().get(&a),
        Some(&RouteStatus::Ready),
        "the unchanged in-flight row can be ready"
    );
    assert_eq!(
        h.effect(&b_old_route),
        Some(RouteEffect::Owned),
        "an unrelated change does not delete the old row in the same round"
    );
    assert!(h.mock.remove_calls.lock().is_empty());
    assert_eq!(
        slot_handle.statuses().get(&b_new),
        Some(&RouteStatus::Pending { error: None })
    );
    assert!(h.dirty_peek());

    h.round_ok().await;
    assert_eq!(h.effect(&b_old_route), None);
    assert_eq!(h.effect(&b_new_route), Some(RouteEffect::Owned));
    assert_eq!(h.mock.remove_count(), 1);
    assert_eq!(h.mock.add_count(), 3);
    assert_eq!(
        slot_handle.statuses().get(&b_new),
        Some(&RouteStatus::Ready)
    );
}

#[tokio::test]
async fn an_in_flight_addition_survives_a_released_root_and_gets_no_ready_feedback() {
    use easytier_core::config::{
        peers::PeerRuntimeSnapshot,
        runtime::{CoreRuntimeConfig, CoreRuntimeConfigStore},
    };

    let mut h = Harness::new();
    let declaration = indexed("10.37.0.0/24", 7, None);
    let route = resolved(&declaration);
    let run = Uuid::new_v4();
    let registry = h.controller.open_instance(run).unwrap();
    let store = CoreRuntimeConfigStore::new(
        CoreRuntimeConfig::default(),
        Arc::new(PeerRuntimeSnapshot::default()),
    );
    // A real, nonempty manual policy stays held by the live store. Its TUN
    // declaration is never installed in this test; it only proves that
    // released inputs cannot be resurrected even while this policy exists.
    let held_manual = BTreeSet::from(["10.237.0.0/24".parse().unwrap()]);
    store.update_services(|services| services.manual_routes = Some(held_manual.clone()));
    h.controller.bind_config(run, store.clone()).unwrap();
    let slot = registry
        .handle()
        .open_slot(RouteSource::Additional)
        .unwrap();
    slot.set_routes(RouteSet::from([declaration.clone()]));

    let controller = h.controller.clone();
    let mock = h.mock.clone();
    let dirty = controller.dirty.clone();
    let slot_handle = slot.clone();
    let (entered, resume) = mock.gate_add(Some(route.clone()));
    dirty.reset();
    let mut round = Box::pin(h.round());
    tokio::select! {
        result = round.as_mut() => panic!("the addition finished before the gate: {result:?}"),
        _ = entered.notified() => {}
    }
    drop(registry);
    assert!(
        dirty.peek(),
        "releasing the root during the awaited addition marks the flag"
    );
    resume.notify_one();
    round.await.unwrap();

    assert_eq!(h.effect(&route), Some(RouteEffect::Owned));
    assert!(h.mock.contains(&route));
    assert_eq!(
        slot_handle.statuses().get(&declaration),
        Some(&RouteStatus::Pending { error: None }),
        "a released root gets no ready feedback"
    );
    assert!(h.dirty_peek());
    assert_eq!(
        controller.effective_routes_for_instance(&run),
        RouteSet::new(),
        "the held nonempty manual configuration cannot recreate a released input"
    );
    assert_eq!(
        store.snapshot().services.manual_routes,
        Some(held_manual),
        "the store still holds the real nonempty manual policy"
    );

    h.round_ok().await;
    assert_eq!(h.effect(&route), None);
    assert!(!h.mock.contains(&route));
    assert_eq!(h.mock.remove_count(), 1);
    assert!(
        !controller.runtime.read().instances.contains_key(&run),
        "the released record is eventually removed"
    );
}

/// A manual policy committed while an AutoProxy addition is awaited must be
/// acted on by later production rounds, not by the in-flight addition.
#[tokio::test]
async fn manual_policy_commit_during_awaited_add_keeps_owned_row_until_next_round() {
    use easytier_core::config::{
        peers::PeerRuntimeSnapshot,
        runtime::{CoreRuntimeConfig, CoreRuntimeConfigStore},
    };

    let mut h = Harness::new();
    let declaration = indexed("10.44.0.0/24", 7, None);
    let route = resolved(&declaration);
    let run = Uuid::new_v4();
    let registry = h.controller.open_instance(run).unwrap();
    let store = CoreRuntimeConfigStore::new(
        CoreRuntimeConfig::default(),
        Arc::new(PeerRuntimeSnapshot::default()),
    );
    h.controller.bind_config(run, store.clone()).unwrap();
    assert!(
        store.snapshot().services.manual_routes.is_none(),
        "the fixture starts in automatic mode"
    );
    let slot = registry.handle().open_slot(RouteSource::AutoProxy).unwrap();
    slot.set_routes(RouteSet::from([declaration.clone()]));

    let controller = h.controller.clone();
    let mock = h.mock.clone();
    let dirty = controller.dirty.clone();
    let (entered, resume) = mock.gate_add(Some(route.clone()));
    dirty.reset();
    let mut round = Box::pin(h.round());
    tokio::select! {
        result = round.as_mut() => panic!("the addition finished before the gate: {result:?}"),
        _ = entered.notified() => {}
    }
    // The live store commits the policy the way production configuration
    // does; that commit must mark the shared flag by itself.
    store.update_services(|services| services.manual_routes = Some(BTreeSet::new()));
    assert!(
        dirty.peek(),
        "the configuration commit marks the shared route flag itself"
    );
    assert_eq!(
        store.snapshot().services.manual_routes,
        Some(BTreeSet::new())
    );
    resume.notify_one();
    round.await.unwrap();

    assert_eq!(
        h.effect(&route),
        Some(RouteEffect::Owned),
        "the real successful addition is recorded before the policy is applied"
    );
    assert!(h.mock.contains(&route));
    assert_eq!(
        h.mock.remove_count(),
        0,
        "the awaited addition is not compensated in the same round"
    );
    assert!(
        matches!(
            slot.statuses().get(&declaration),
            Some(RouteStatus::Suppressed(_))
        ),
        "the current manual policy suppresses the AutoProxy declaration instead of reporting ready"
    );
    assert!(
        h.dirty_peek(),
        "the configuration mark survives the awaited round"
    );

    h.round_ok().await;
    assert_eq!(
        h.effect(&route),
        None,
        "the next round applies the current empty manual policy"
    );
    assert!(!h.mock.contains(&route));
    assert_eq!(
        h.mock.add_count(),
        1,
        "the suppressed declaration is not added again"
    );
    assert_eq!(h.mock.remove_count(), 1);
    assert!(
        matches!(
            slot.statuses().get(&declaration),
            Some(RouteStatus::Suppressed(_))
        ),
        "the slot stays suppressed after its installed row is deleted"
    );
    assert_eq!(
        store.snapshot().services.manual_routes,
        Some(BTreeSet::new()),
        "the store stayed alive and kept the committed policy"
    );
}

#[tokio::test]
async fn an_awaited_removal_rechecks_fresh_declarations_before_deleting_a_later_row() {
    let mut h = Harness::new();
    let a = indexed("10.38.0.0/24", 7, None);
    let b = indexed("10.39.0.0/24", 7, None);
    let a_route = resolved(&a);
    let b_route = resolved(&b);
    let (_run, _registry, slot) = instance_with_slot(&h.controller, RouteSource::Additional);
    slot.set_routes(RouteSet::from([a, b.clone()]));
    h.round_ok().await;
    assert_eq!(h.effect(&a_route), Some(RouteEffect::Owned));
    assert_eq!(h.effect(&b_route), Some(RouteEffect::Owned));

    slot.clear();
    let controller = h.controller.clone();
    let mock = h.mock.clone();
    let dirty = controller.dirty.clone();
    let slot_handle = slot.clone();
    let (entered, resume) = mock.gate_remove(Some(a_route.clone()));
    dirty.reset();
    let mut round = Box::pin(h.round());
    tokio::select! {
        result = round.as_mut() => panic!("the removals finished before the gate: {result:?}"),
        _ = entered.notified() => {}
    }
    slot_handle.set_routes(RouteSet::from([b.clone()]));
    assert!(dirty.peek());
    resume.notify_one();
    round.await.unwrap();

    assert_eq!(h.effect(&a_route), None, "the awaited removal completed");
    assert_eq!(
        h.effect(&b_route),
        Some(RouteEffect::Owned),
        "the fresh check at execution time keeps the redeclared row"
    );
    assert!(
        !h.mock
            .remove_calls
            .lock()
            .iter()
            .any(|route| route == &b_route),
        "the collection-time decision must not delete the redeclared row"
    );
    assert_eq!(h.mock.remove_count(), 1);
    assert!(h.mock.contains(&b_route));
    assert!(!h.mock.contains(&a_route));
    assert_eq!(slot_handle.statuses().get(&b), Some(&RouteStatus::Ready));
    assert!(
        h.dirty_peek(),
        "the slot mark made during the awaited removal survived the round"
    );

    h.round_ok().await;
    assert_eq!(h.effect(&b_route), Some(RouteEffect::Owned));
    assert_eq!(h.mock.remove_count(), 1);
}

#[cfg(all(target_os = "linux", feature = "tun"))]
#[tokio::test]
async fn device_less_actions_stay_ordinary_for_a_bound_member_without_an_interface() {
    let mut h = Harness::new();
    let run = Uuid::new_v4();
    let mut fixture = ManagedNicFixture::new(run);
    let member = fixture.create_member();
    let registry = h.controller.open_instance(run).unwrap();
    h.controller.bind_member(run, &member).unwrap();
    let slot = registry
        .handle()
        .open_slot(RouteSource::Additional)
        .unwrap();
    let blackhole = RouteSpec::<RouteDevice> {
        destination: "10.40.0.0/24".parse().unwrap(),
        action: RouteAction::Blackhole,
        metric: 5,
        table: None,
    };
    let unreachable = RouteSpec::<RouteDevice> {
        destination: "10.41.0.0/24".parse().unwrap(),
        action: RouteAction::Unreachable,
        metric: 5,
        table: None,
    };
    let unresolved_tun = RouteSpec::for_tun("10.42.0.0/24".parse().unwrap());
    slot.set_routes(RouteSet::from([
        blackhole.clone(),
        unreachable.clone(),
        unresolved_tun.clone(),
    ]));
    h.round_ok().await;

    let blackhole_route = resolved(&blackhole);
    let unreachable_route = resolved(&unreachable);
    assert_eq!(h.effect(&blackhole_route), Some(RouteEffect::Owned));
    assert_eq!(h.effect(&unreachable_route), Some(RouteEffect::Owned));
    assert!(h.mock.contains(&blackhole_route));
    assert!(h.mock.contains(&unreachable_route));
    assert_eq!(slot.statuses().get(&blackhole), Some(&RouteStatus::Ready));
    assert_eq!(slot.statuses().get(&unreachable), Some(&RouteStatus::Ready));
    assert_eq!(
        slot.statuses().get(&unresolved_tun),
        Some(&RouteStatus::Pending { error: None }),
        "a tun declaration without a bound interface stays unresolved"
    );
    assert_eq!(h.mock.add_count(), 2);
    assert!(
        h.controller.runtime.read().instances[&run]
            .interface
            .is_none(),
        "no device was ever recorded for the bound member"
    );
}

#[tokio::test]
async fn planning_merges_the_same_row_and_drops_the_withdrawn_declaration() {
    let controller = RouteController::new(Arc::new(DirtyFlag::new(false)));
    let (p_run, _p_registry, p_slot) = instance_with_slot(&controller, RouteSource::AutoProxy);
    let (q_run, _q_registry, q_slot) = instance_with_slot(&controller, RouteSource::AutoProxy);

    let a = indexed("10.1.0.0/24", 7, None);
    let b = indexed("10.2.0.0/24", 7, None);
    let c = indexed("10.3.0.0/24", 7, None);
    p_slot.set_routes(RouteSet::from([a.clone(), b.clone()]));
    q_slot.set_routes(RouteSet::from([b.clone()]));

    let b_route = resolved(&b);
    let c_route = resolved(&c);
    let a_route = resolved(&a);

    let plan = plan_stages(&controller, None, &BTreeMap::new(), None).await;
    assert_eq!(
        plan.desired.get(&RouteKey::of(&b_route)),
        Some(&(b_route.clone(), BTreeSet::from([p_run, q_run]))),
        "the same complete row merges its owners"
    );
    assert!(plan.add.contains(&a_route) && plan.add.contains(&b_route));
    assert!(plan.remove.is_empty());

    // P replaces {A, B} with {C}; Q still declares B. A disappears only
    // because no current input needs it, and B keeps Q as its owner.
    p_slot.set_routes(RouteSet::from([c.clone()]));
    let plan = plan_stages(&controller, None, &BTreeMap::new(), None).await;
    assert_eq!(plan.desired.len(), 2, "only the current B and C remain");
    assert_eq!(
        plan.desired.get(&RouteKey::of(&b_route)),
        Some(&(b_route.clone(), BTreeSet::from([q_run])))
    );
    assert_eq!(
        plan.desired
            .get(&RouteKey::of(&c_route))
            .map(|(route, _)| route),
        Some(&c_route)
    );
    assert!(!plan.add.contains(&a_route), "A is no longer a target");
    assert!(plan.remove.is_empty(), "nothing was installed yet");
    assert_eq!(
        p_slot.statuses().get(&a),
        None,
        "the withdrawn declaration holds no feedback entry"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn different_linux_metrics_coexist_and_keep_the_installed_occupant() {
    let controller = RouteController::new(Arc::new(DirtyFlag::new(false)));
    let (run, _registry, slot) = instance_with_slot(&controller, RouteSource::Additional);

    let zero = indexed_with_metric("10.5.0.0/24", 7, 0, None);
    let ten = indexed_with_metric("10.5.0.0/24", 7, 10, None);
    slot.set_routes(RouteSet::from([zero.clone(), ten.clone()]));
    let plan = plan_stages(&controller, None, &BTreeMap::new(), None).await;
    assert_eq!(
        plan.desired.len(),
        2,
        "different legal metrics are different keys and coexist"
    );
    assert!(plan.desired.contains_key(&RouteKey::of(&resolved(&zero))));
    assert!(plan.desired.contains_key(&RouteKey::of(&resolved(&ten))));

    // Two declarations of one key differ in their gateway. The row already
    // installed wins while it is still a candidate.
    let first = indexed("10.6.0.0/24", 7, Some("192.0.2.1"));
    let second = indexed("10.6.0.0/24", 7, Some("192.0.2.9"));
    slot.set_routes(RouteSet::from([first.clone(), second.clone()]));
    let row = installed(&first, run);
    let stable_route = row.route.clone();
    controller
        .runtime
        .write()
        .applied
        .insert(RouteKey::of(&stable_route), row);

    let plan = plan_stages(&controller, None, &BTreeMap::new(), None).await;
    assert_eq!(
        plan.desired
            .get(&RouteKey::of(&stable_route))
            .map(|(route, _)| route),
        Some(&stable_route),
        "an installed candidate stays the occupant"
    );
    assert!(plan.add.is_empty(), "the installed row needs no addition");
    assert!(plan.remove.is_empty(), "the installed row stays");
    let statuses = slot.statuses();
    assert_eq!(statuses.get(&first), Some(&RouteStatus::Ready));
    assert!(
        matches!(statuses.get(&second), Some(RouteStatus::Suppressed(_))),
        "the competing declaration is suppressed"
    );

    // Once the installed row is withdrawn, the stable first candidate wins
    // and the complete parameter change yields both remove and add.
    slot.set_routes(RouteSet::from([second.clone()]));
    let plan = plan_stages(&controller, None, &BTreeMap::new(), None).await;
    let second_route = resolved(&second);
    assert_eq!(
        plan.desired
            .get(&RouteKey::of(&stable_route))
            .map(|(route, _)| route),
        Some(&second_route)
    );
    assert!(
        plan.remove.contains(&stable_route),
        "the changed row is removed"
    );
    assert!(plan.add.contains(&second_route), "the new row is added");
}

#[tokio::test]
async fn manual_policy_decides_auto_proxy_and_keeps_additional() {
    use easytier_core::config::{
        peers::PeerRuntimeSnapshot,
        runtime::{CoreRuntimeConfig, CoreRuntimeConfigStore},
    };

    let controller = RouteController::new(Arc::new(DirtyFlag::new(false)));
    let run = Uuid::new_v4();
    let registry = controller.open_instance(run).unwrap();
    let store = CoreRuntimeConfigStore::new(
        CoreRuntimeConfig::default(),
        Arc::new(PeerRuntimeSnapshot::default()),
    );
    controller.bind_config(run, store.clone()).unwrap();
    let auto = registry.handle().open_slot(RouteSource::AutoProxy).unwrap();
    let additional = registry
        .handle()
        .open_slot(RouteSource::Additional)
        .unwrap();
    let auto_route = indexed("10.7.0.0/24", 7, None);
    let additional_route = indexed("10.8.0.0/24", 7, None);
    auto.set_routes(RouteSet::from([auto_route.clone()]));
    additional.set_routes(RouteSet::from([additional_route.clone()]));

    // None: AutoProxy contributes, so the exported candidates hold both,
    // even though no NIC is bound.
    let exported = controller.effective_routes_for_instance(&run);
    assert_eq!(
        exported,
        RouteSet::from([auto_route.clone(), additional_route.clone()])
    );
    let plan = plan_stages(&controller, None, &BTreeMap::new(), None).await;
    assert_eq!(plan.desired.len(), 2);

    // Some(empty): no manual route is generated and AutoProxy is
    // suppressed without touching any slot.
    store.update_services(|services| services.manual_routes = Some(BTreeSet::new()));
    assert_eq!(
        controller.effective_routes_for_instance(&run),
        RouteSet::from([additional_route.clone()]),
        "a configured manual policy suppresses every AutoProxy declaration"
    );
    let plan = plan_stages(&controller, None, &BTreeMap::new(), None).await;
    assert_eq!(plan.desired.len(), 1, "AutoProxy is no longer a target");
    assert!(matches!(
        auto.statuses().get(&auto_route),
        Some(RouteStatus::Suppressed(_))
    ));
    assert!(!matches!(
        additional.statuses().get(&additional_route),
        Some(RouteStatus::Suppressed(_))
    ));

    // Some(nonempty): the manual list itself becomes the TUN target. Its
    // `Tun` device stays unresolved without a binding, so only the normal
    // indexed route reaches this round's target.
    store.update_services(|services| {
        services.manual_routes = Some(BTreeSet::from(["10.9.0.0/24".parse().unwrap()]));
    });
    assert_eq!(
        controller.effective_routes_for_instance(&run),
        RouteSet::from([
            RouteSpec::for_tun("10.9.0.0/24".parse().unwrap()),
            additional_route.clone(),
        ]),
        "manual routes replace auto proxy and Additional stays"
    );
    assert_eq!(
        controller.effective_routes_for_instance(&Uuid::new_v4()),
        RouteSet::new(),
        "an unknown run contributes nothing"
    );
}

#[tokio::test]
async fn dropped_registry_plans_nothing_and_keeps_the_ledger() {
    let controller = RouteController::new(Arc::new(DirtyFlag::new(false)));
    let run = Uuid::new_v4();
    let registry = controller.open_instance(run).unwrap();
    let slot = registry
        .handle()
        .open_slot(RouteSource::Additional)
        .unwrap();
    let declaration = indexed("10.11.0.0/24", 7, None);
    slot.set_routes(RouteSet::from([declaration.clone()]));
    let row = installed(&declaration, run);
    let planned = row.route.clone();
    controller
        .runtime
        .write()
        .applied
        .insert(RouteKey::of(&planned), row);

    drop(registry);
    slot.set_routes(RouteSet::from([indexed("10.12.0.0/24", 7, None)]));
    let plan = plan_stages(&controller, None, &BTreeMap::new(), None).await;
    assert!(plan.desired.is_empty(), "a released registry plans nothing");
    assert!(plan.slots.is_empty());
    assert_eq!(plan.remove, vec![planned.clone()]);
    assert!(plan.add.is_empty());
    assert_eq!(
        controller
            .applied_routes()
            .get(&RouteKey::of(&planned))
            .map(|row| (&row.route, row.effect)),
        Some((&planned, RouteEffect::Owned)),
        "planning never replaces or clears the applied ledger"
    );

    controller.request_shutdown();
    let plan = plan_stages(&controller, None, &BTreeMap::new(), None).await;
    assert!(plan.desired.is_empty(), "shutdown clears every target");
    assert!(!controller.applied_routes().is_empty());
    assert_eq!(
        controller.effective_routes_for_instance(&run),
        RouteSet::new()
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn feedback_reports_each_row_of_one_slot_separately() {
    let controller = RouteController::new(Arc::new(DirtyFlag::new(false)));
    let (run, _registry, slot) = instance_with_slot(&controller, RouteSource::Additional);

    let ready = indexed("10.13.0.0/24", 7, None);
    let pending = indexed("10.14.0.0/24", 7, None);
    let winner = indexed("10.15.0.0/24", 7, Some("192.0.2.1"));
    let loser = indexed("10.15.0.0/24", 7, Some("192.0.2.2"));
    slot.set_routes(RouteSet::from([
        ready.clone(),
        pending.clone(),
        winner.clone(),
        loser.clone(),
    ]));
    let ready_row = installed(&ready, run);
    let ready_route = ready_row.route.clone();
    controller
        .runtime
        .write()
        .applied
        .insert(RouteKey::of(&ready_route), ready_row);

    let plan = plan_stages(&controller, None, &BTreeMap::new(), None).await;
    assert_eq!(
        plan.desired
            .get(&RouteKey::of(&ready_route))
            .map(|(route, _)| route),
        Some(&ready_route)
    );
    // The stable first candidate owns the key but has no confirmed effect
    // yet; the other declaration of that key loses the competition.
    let statuses = slot.statuses();
    assert_eq!(statuses.get(&ready), Some(&RouteStatus::Ready));
    assert_eq!(
        statuses.get(&pending),
        Some(&RouteStatus::Pending { error: None })
    );
    assert_eq!(
        statuses.get(&winner),
        Some(&RouteStatus::Pending { error: None })
    );
    assert!(matches!(
        statuses.get(&loser),
        Some(RouteStatus::Suppressed(_))
    ));

    // A failure for the exact same complete row is reported on that row
    // only; it cannot override the confirmed row.
    let pending_route = resolved(&pending);
    let mut errors = BTreeMap::new();
    errors.insert(pending_route, Arc::<str>::from("install failed"));
    plan_stages(&controller, None, &errors, None).await;
    let statuses = slot.statuses();
    assert_eq!(
        statuses.get(&pending),
        Some(&RouteStatus::Pending {
            error: Some(Arc::<str>::from("install failed"))
        })
    );
    assert_eq!(statuses.get(&ready), Some(&RouteStatus::Ready));

    // A different complete row never inherits another row's error.
    let mut errors = BTreeMap::new();
    errors.insert(
        resolved(&indexed("10.99.0.0/24", 7, None)),
        Arc::<str>::from("unrelated"),
    );
    plan_stages(&controller, None, &errors, None).await;
    assert_eq!(
        slot.statuses().get(&pending),
        Some(&RouteStatus::Pending { error: None })
    );
}

// The managed-routes NIC fixture is entirely in memory: the registry only
// builds a NIC descriptor that its members share, so nothing here creates
// a TUN device or touches a system address or route. The namespace handle
// is an opaque external reference that no code path here enters, and the
// dispatcher stays absent because no device is ever created.
#[cfg(feature = "tun")]
const MANAGED_NIC_NAME: &str = "et-route-test";

#[cfg(feature = "tun")]
fn managed_virtual_nic_config() -> VirtualNicConfig {
    VirtualNicConfig::new(
        MANAGED_NIC_NAME.to_owned(),
        1500,
        NetNS::from_host_reference("route-controller-test"),
    )
    .with_routes_managed(true)
}

#[cfg(feature = "tun")]
struct ManagedNicFixture {
    run: Uuid,
    registry: SharedVirtualNicRegistry,
}

#[cfg(feature = "tun")]
impl ManagedNicFixture {
    fn new(run: Uuid) -> Self {
        Self {
            run,
            registry: SharedVirtualNicRegistry::new(),
        }
    }

    /// A fresh registration for this run. Both members share one NIC;
    /// only the registration identity differs.
    fn create_member(&mut self) -> SharedVirtualNicMember {
        self.registry
            .try_create_member(
                MANAGED_NIC_NAME.to_owned(),
                managed_virtual_nic_config(),
                self.run,
                Arc::new(Notify::new()),
            )
            .unwrap()
    }
}

/// Attach the member's registration under the NIC lock, as device creation
/// does. No device is created here.
#[cfg(feature = "tun")]
async fn attach_member(member: &SharedVirtualNicMember) {
    let shared_nic = member.shared_nic();
    let mut nic = shared_nic.lock().await;
    nic.attach_member_registration(member.member_id(), member.registration_id())
        .await
        .unwrap();
}

/// A registration replaced by a newer one for the same run cannot confirm
/// a sync, and that refusal must leave the current registration's claims
/// alone. The current claims start nonempty so a mistaken withdrawal is
/// observable.
#[cfg(feature = "tun")]
#[tokio::test]
async fn superseded_registration_sync_reports_false_and_keeps_current_claims() {
    let mut fixture = ManagedNicFixture::new(Uuid::new_v4());
    let old_member = fixture.create_member();
    attach_member(&old_member).await;
    let new_member = fixture.create_member();
    attach_member(&new_member).await;

    let prefix: IpCidr = "10.42.0.0/24".parse().unwrap();
    let expected_claims =
        BTreeSet::from([SharedIpv4Route::new("10.42.0.0".parse().unwrap(), 24, None)]);
    assert!(
        sync_member_routes(&new_member, &BTreeSet::from([prefix]))
            .await
            .unwrap(),
        "the current registration commits and acknowledges"
    );
    assert_eq!(
        new_member.claims().await.ipv4_routes,
        expected_claims,
        "the fixture must start from a nonempty claim set"
    );

    assert!(
        !sync_member_routes(&old_member, &BTreeSet::new())
            .await
            .unwrap(),
        "a superseded registration must not confirm a sync"
    );
    assert_eq!(
        new_member.claims().await.ipv4_routes,
        expected_claims,
        "the stale sync must not clear the current registration's claims"
    );
}

/// Closing marks the member before it can take the NIC lock, yet an empty
/// sync still withdraws through it. Both finish once the lock is released;
/// the test never waits while holding the lock.
#[cfg(feature = "tun")]
#[tokio::test]
async fn closed_member_can_still_sync_an_empty_route_set() {
    let mut fixture = ManagedNicFixture::new(Uuid::new_v4());
    let member = fixture.create_member();
    attach_member(&member).await;

    let shared_nic = member.shared_nic();
    let guard = shared_nic.lock().await;

    let empty = BTreeSet::new();
    let sync = sync_member_routes(&member, &empty);
    tokio::pin!(sync);
    assert!(
        futures::poll!(&mut sync).is_pending(),
        "the sync waits for the held NIC lock"
    );

    let close = member.close();
    tokio::pin!(close);
    assert!(
        futures::poll!(&mut close).is_pending(),
        "close sets the flag and then waits for the same NIC lock"
    );
    assert!(
        member.ensure_open().is_err(),
        "close marks the member closed before it touches the NIC"
    );

    drop(guard);

    assert!(
        tokio::time::timeout(Duration::from_secs(1), sync)
            .await
            .expect("the empty sync must not wait for the NIC forever")
            .expect("an empty sync may withdraw through an already closed member"),
        "the withdrawal commit still completed"
    );
    tokio::time::timeout(Duration::from_secs(1), close)
        .await
        .expect("close must finish once the NIC lock is free")
        .expect("closing the member must not fail");
}

/// The bounded NIC lock wait of the sync helper reports the exact member it
/// timed out on instead of waiting forever.
#[cfg(feature = "tun")]
#[tokio::test(start_paused = true)]
async fn nic_lock_timeout_is_reported_by_the_sync_helper() {
    let mut fixture = ManagedNicFixture::new(Uuid::new_v4());
    let member = fixture.create_member();
    attach_member(&member).await;

    let shared_nic = member.shared_nic();
    let guard = shared_nic.lock().await;

    let empty = BTreeSet::new();
    let sync = sync_member_routes(&member, &empty);
    tokio::pin!(sync);
    assert!(
        futures::poll!(&mut sync).is_pending(),
        "the helper waits for the held NIC lock"
    );

    tokio::time::advance(Duration::from_secs(5)).await;

    let error = tokio::time::timeout(Duration::from_secs(1), sync)
        .await
        .expect("the helper must not wait past its own NIC lock timeout")
        .expect_err("the bounded NIC lock wait must expire");
    assert_eq!(
        error.to_string(),
        format!("timed out locking shared NIC for member {}", fixture.run)
    );
    drop(guard);
}

/// One member admission waiting on the NIC lock must not stall the rest of
/// the round. After the wait expires, the affected managed declaration
/// reports that timeout while an ordinary declaration on another device
/// still reaches the target.
#[cfg(feature = "tun")]
#[tokio::test(start_paused = true)]
async fn nic_lock_timeout_only_pends_the_managed_declaration() {
    let run = Uuid::new_v4();
    let mut fixture = ManagedNicFixture::new(run);
    let member = fixture.create_member();
    attach_member(&member).await;

    let controller = RouteController::new(Arc::new(DirtyFlag::new(false)));
    let registry = controller.open_instance(run).unwrap();
    controller.bind_member(run, &member).unwrap();
    assert!(
        controller
            .ready(
                run,
                &member,
                InterfaceInfo {
                    name: MANAGED_NIC_NAME.into(),
                    ifindex: 7,
                },
            )
            .unwrap(),
        "the fixture interface is the bound member's device"
    );
    let slot = registry
        .handle()
        .open_slot(RouteSource::Additional)
        .unwrap();
    let managed = RouteSpec::for_tun("10.61.0.0/24".parse().unwrap());
    let ordinary = indexed("10.62.0.0/24", 9, None);
    slot.set_routes(RouteSet::from([managed.clone(), ordinary.clone()]));

    let shared_nic = member.shared_nic();
    let guard = shared_nic.lock().await;

    let errors = BTreeMap::new();
    let plan = plan_stages(&controller, None, &errors, None);
    tokio::pin!(plan);
    assert!(
        futures::poll!(&mut plan).is_pending(),
        "the managed admission waits for the held NIC lock"
    );

    tokio::time::advance(Duration::from_secs(5)).await;
    let plan = tokio::time::timeout(Duration::from_secs(1), plan)
        .await
        .expect("the round must finish after the bounded NIC lock wait");

    let ordinary_route = resolved(&ordinary);
    assert_eq!(
        plan.desired.get(&RouteKey::of(&ordinary_route)),
        Some(&(ordinary_route.clone(), BTreeSet::from([run]))),
        "the ordinary declaration is not blocked by the NIC lock"
    );
    assert_eq!(
        plan.desired.len(),
        1,
        "the timed out managed declaration is not a target"
    );
    assert_eq!(
        slot.statuses().get(&managed),
        Some(&RouteStatus::Pending {
            error: Some(Arc::<str>::from(format!(
                "timed out locking shared NIC for member {run}"
            )))
        }),
        "the managed declaration reports the NIC lock timeout"
    );
    drop(guard);
}

// Planning-await tests. Each one uses the shared NIC's async lock as a
// controlled pause: the real planner is polled until it is suspended in
// member admission, exactly the state the post-await feedback rechecks is
// changed, and only then is the lock released. No controller, slot or
// registry synchronous guard is held across an await, and every wait is
// bounded.

/// The applied row of a managed declaration, including the registration
/// that really acknowledged it.
#[cfg(feature = "tun")]
fn managed_installed(
    declaration: &RouteSpec<RouteDevice>,
    ifindex: u32,
    run: Uuid,
    member: &SharedVirtualNicMember,
) -> AppliedRoute {
    AppliedRoute {
        route: normalize_route(declaration.clone().resolve(Some(ifindex)).unwrap()).unwrap(),
        owners: BTreeSet::from([run]),
        effect: RouteEffect::Owned,
        members: BTreeMap::from([(run, member.clone())]),
    }
}

/// The real prefix set a member currently claims, read through its NIC.
#[cfg(feature = "tun")]
async fn member_claim_prefixes(member: &SharedVirtualNicMember) -> BTreeSet<IpCidr> {
    claim_prefixes(&member.claims().await)
}

/// Dropping the only registry root while a managed admission waits on the
/// NIC lock must not let the suspended plan write ready feedback when it
/// resumes. The held manual policy proves the empty input is the released
/// root, not a configuration change.
#[cfg(feature = "tun")]
#[tokio::test]
async fn a_dropped_registry_during_nic_admission_gets_no_ready_feedback() {
    use easytier_core::config::{
        peers::PeerRuntimeSnapshot,
        runtime::{CoreRuntimeConfig, CoreRuntimeConfigStore},
    };

    let controller = RouteController::new(Arc::new(DirtyFlag::new(false)));
    let run = Uuid::new_v4();
    let registry = controller.open_instance(run).unwrap();
    let store = CoreRuntimeConfigStore::new(
        CoreRuntimeConfig::default(),
        Arc::new(PeerRuntimeSnapshot::default()),
    );
    let held_manual = BTreeSet::from(["10.70.0.0/24".parse().unwrap()]);
    store.update_services(|services| services.manual_routes = Some(held_manual.clone()));
    controller.bind_config(run, store.clone()).unwrap();

    let mut fixture = ManagedNicFixture::new(run);
    let member = fixture.create_member();
    attach_member(&member).await;
    controller.bind_member(run, &member).unwrap();
    assert!(
        controller
            .ready(
                run,
                &member,
                InterfaceInfo {
                    name: MANAGED_NIC_NAME.into(),
                    ifindex: 7,
                },
            )
            .unwrap(),
        "the fixture interface is the bound member's device"
    );

    let slot = registry
        .handle()
        .open_slot(RouteSource::Additional)
        .unwrap();
    let managed = RouteSpec::for_tun("10.71.0.0/24".parse().unwrap());
    let ordinary = indexed("10.72.0.0/24", 9, None);
    slot.set_routes(RouteSet::from([managed.clone(), ordinary.clone()]));
    let ordinary_route = resolved(&ordinary);
    controller
        .runtime
        .write()
        .applied
        .insert(RouteKey::of(&ordinary_route), installed(&ordinary, run));

    let shared_nic = member.shared_nic();
    let guard = shared_nic.lock().await;
    controller.dirty.reset();
    let errors = BTreeMap::new();
    let plan = plan_stages(&controller, None, &errors, None);
    tokio::pin!(plan);
    assert!(
        futures::poll!(&mut plan).is_pending(),
        "the managed admission waits for the held NIC lock"
    );

    drop(registry);
    assert!(
        controller.runtime.read().instances[&run]
            .registry
            .upgrade()
            .is_none(),
        "the test held the only strong root"
    );
    assert!(
        controller.dirty.peek(),
        "dropping the last root marks the route inputs dirty before the wait ends"
    );

    drop(guard);
    let plan = tokio::time::timeout(Duration::from_secs(10), plan)
        .await
        .expect("the paused plan must finish once the NIC lock is free");

    assert_eq!(
        slot.statuses().get(&ordinary),
        Some(&RouteStatus::Pending { error: None }),
        "the old plan must not write ready feedback for a released input"
    );
    assert_eq!(
        slot.statuses().get(&managed),
        Some(&RouteStatus::Pending { error: None }),
        "the managed declaration keeps its original pending status"
    );
    assert!(
        plan.desired.contains_key(&RouteKey::of(&ordinary_route)),
        "the plan still carries the rows it copied before the wait"
    );
    assert_eq!(
        controller.effective_routes_for_instance(&run),
        RouteSet::new(),
        "a released registry has no current inputs, even with retained manual policy"
    );
    assert_eq!(
        store.snapshot().services.manual_routes,
        Some(held_manual),
        "the store really still holds the nonempty manual policy"
    );

    let fresh = plan_stages(&controller, None, &errors, None).await;
    assert!(
        fresh.desired.is_empty(),
        "the next round plans from the now-empty input directory"
    );
    assert!(
        controller
            .applied_routes()
            .get(&RouteKey::of(&ordinary_route))
            .is_some_and(|row| row.effect == RouteEffect::Owned && row.owners.contains(&run)),
        "planning never clears or replaces the actual owned ledger row"
    );
}

/// Run the old admission to completion against a binding and ledger that
/// changed while it waited, then check the fresh round is really ready.
#[cfg(feature = "tun")]
async fn assert_stale_admission_pends_for_the_new_registration(old_rejects: bool) {
    let run = Uuid::new_v4();
    let mut old_fixture = ManagedNicFixture::new(run);
    let old_member = old_fixture.create_member();
    attach_member(&old_member).await;
    let mut new_fixture = ManagedNicFixture::new(run);
    let new_member = new_fixture.create_member();
    attach_member(&new_member).await;

    let managed = RouteSpec::for_tun("10.80.0.0/24".parse().unwrap());
    let prefix: IpCidr = managed.destination;

    // Dropping a member withdraws its claims asynchronously, so the
    // conflict must be held past the old plan and its feedback: otherwise
    // the admission under test would really succeed and this variant would
    // prove nothing.
    let mut conflicting_member: Option<SharedVirtualNicMember> = None;
    if old_rejects {
        // The old NIC has a real overlapping claim from another run, so
        // the prepare that runs after the release really fails. The new
        // NIC has no such conflict.
        let other_run = Uuid::new_v4();
        let other_member = old_fixture
            .registry
            .try_create_member(
                MANAGED_NIC_NAME.to_owned(),
                managed_virtual_nic_config(),
                other_run,
                Arc::new(Notify::new()),
            )
            .unwrap();
        attach_member(&other_member).await;
        assert!(
            sync_member_routes(
                &other_member,
                &BTreeSet::from(["10.80.0.0/25".parse::<IpCidr>().unwrap()]),
            )
            .await
            .unwrap(),
            "the conflicting member commits a claim that overlaps the prefix"
        );
        conflicting_member = Some(other_member);
    }

    assert!(
        sync_member_routes(&new_member, &BTreeSet::from([prefix]))
            .await
            .unwrap(),
        "the new registration really acknowledges the managed prefix"
    );

    let controller = RouteController::new(Arc::new(DirtyFlag::new(false)));
    let registry = controller.open_instance(run).unwrap();
    controller.bind_member(run, &old_member).unwrap();
    assert!(
        controller
            .ready(
                run,
                &old_member,
                InterfaceInfo {
                    name: MANAGED_NIC_NAME.into(),
                    ifindex: 7,
                },
            )
            .unwrap()
    );
    let slot = registry
        .handle()
        .open_slot(RouteSource::Additional)
        .unwrap();
    slot.set_routes(RouteSet::from([managed.clone()]));

    let row = managed_installed(&managed, 7, run, &new_member);
    let route = row.route.clone();
    let synced = BTreeMap::from([(
        (run, new_member.registration_id()),
        BTreeSet::from([prefix]),
    )]);

    let shared_nic = old_member.shared_nic();
    let guard = shared_nic.lock().await;
    let errors = BTreeMap::new();
    let mut admission_failures = BTreeMap::new();
    let mut plan = Box::pin(plan_stages(
        &controller,
        Some(&synced),
        &errors,
        Some(&mut admission_failures),
    ));
    assert!(
        futures::poll!(&mut plan).is_pending(),
        "the old admission waits for the held old NIC lock"
    );

    // The binding and the actual ledger change while the old admission is
    // suspended. Neither may be borrowed to confirm the old result.
    controller.bind_member(run, &new_member).unwrap();
    assert!(
        controller
            .ready(
                run,
                &new_member,
                InterfaceInfo {
                    name: MANAGED_NIC_NAME.into(),
                    ifindex: 7,
                },
            )
            .unwrap(),
        "the new registration owns the same interface index"
    );
    controller
        .runtime
        .write()
        .applied
        .insert(RouteKey::of(&route), row);

    drop(guard);
    let plan = tokio::time::timeout(Duration::from_secs(10), plan)
        .await
        .expect("the paused plan must finish once the old NIC lock is free");

    // The timeout consumed and dropped the pinned future, so this is the
    // old plan's own record of what really happened on its captured member.
    if old_rejects {
        let (failed_prefixes, failed_status) = admission_failures
            .get(&(run, old_member.registration_id()))
            .expect("the old plan really failed admission for the old registration");
        assert_eq!(
            failed_prefixes,
            &BTreeSet::from([prefix]),
            "the old plan reports exactly the prefix it captured"
        );
        assert!(
            matches!(failed_status, RouteStatus::Rejected(_)),
            "the conflicting member's claim is a real rejection"
        );
    } else {
        assert!(
            admission_failures.is_empty(),
            "a successful old admission reports no failure"
        );
        assert!(
            plan.desired.contains_key(&RouteKey::of(&route)),
            "the old plan really admitted and captured the managed prefix"
        );
    }

    let status = slot.statuses().get(&managed).cloned();
    assert_eq!(
        status,
        Some(RouteStatus::Pending { error: None }),
        "an old admission result cannot answer for the new registration"
    );
    assert!(
        !matches!(status, Some(RouteStatus::Rejected(_))),
        "an old rejection must not be reported on the new registration"
    );

    let fresh = plan_stages(&controller, Some(&synced), &errors, None).await;
    assert_eq!(
        slot.statuses().get(&managed),
        Some(&RouteStatus::Ready),
        "the same acknowledgement is valid for the current registration"
    );
    assert!(
        fresh.desired.contains_key(&RouteKey::of(&route)),
        "the current registration still targets the managed prefix"
    );

    // Release the conflict only now that the old plan and the fresh round
    // have both been observed.
    drop(conflicting_member);
}

/// An old successful admission cannot confirm the new registration's row.
#[cfg(feature = "tun")]
#[tokio::test]
async fn an_old_successful_admission_pends_for_the_new_registration() {
    assert_stale_admission_pends_for_the_new_registration(false).await;
}

/// An old rejected admission cannot report its conflict on the new one.
#[cfg(feature = "tun")]
#[tokio::test]
async fn an_old_rejected_admission_pends_for_the_new_registration() {
    assert_stale_admission_pends_for_the_new_registration(true).await;
}

/// The whole-set admission really fails on the captured P+Q set, but the
/// slot shrank to P while it waited. That failure describes inputs that no
/// longer exist and must only wait for the next round, not reject P.
#[cfg(feature = "tun")]
#[tokio::test]
async fn a_whole_set_admission_failure_goes_stale_with_its_captured_set() {
    let run = Uuid::new_v4();
    let other_run = Uuid::new_v4();
    let mut fixture = ManagedNicFixture::new(run);
    let member = fixture.create_member();
    attach_member(&member).await;
    let other_member = fixture
        .registry
        .try_create_member(
            MANAGED_NIC_NAME.to_owned(),
            managed_virtual_nic_config(),
            other_run,
            Arc::new(Notify::new()),
        )
        .unwrap();
    attach_member(&other_member).await;

    let p = RouteSpec::for_tun("10.90.0.0/24".parse().unwrap());
    let q = RouteSpec::for_tun("10.91.0.0/24".parse().unwrap());
    let p_prefix: IpCidr = p.destination;
    let q_prefix: IpCidr = q.destination;
    assert!(
        sync_member_routes(&member, &BTreeSet::from([p_prefix]))
            .await
            .unwrap(),
        "the current NIC member owns P"
    );
    assert!(
        sync_member_routes(&other_member, &BTreeSet::from([q_prefix]))
            .await
            .unwrap(),
        "the other member owns the disjoint Q"
    );

    let controller = RouteController::new(Arc::new(DirtyFlag::new(false)));
    let registry = controller.open_instance(run).unwrap();
    controller.bind_member(run, &member).unwrap();
    assert!(
        controller
            .ready(
                run,
                &member,
                InterfaceInfo {
                    name: MANAGED_NIC_NAME.into(),
                    ifindex: 7,
                },
            )
            .unwrap()
    );
    let slot = registry
        .handle()
        .open_slot(RouteSource::Additional)
        .unwrap();
    slot.set_routes(RouteSet::from([p.clone(), q.clone()]));
    let row = managed_installed(&p, 7, run, &member);
    let route = row.route.clone();
    controller
        .runtime
        .write()
        .applied
        .insert(RouteKey::of(&route), row);

    let shared_nic = member.shared_nic();
    let guard = shared_nic.lock().await;
    let errors = BTreeMap::new();
    let mut admission_failures = BTreeMap::new();
    let mut plan = Box::pin(plan_stages(
        &controller,
        None,
        &errors,
        Some(&mut admission_failures),
    ));
    assert!(
        futures::poll!(&mut plan).is_pending(),
        "the whole-set admission waits for the held NIC lock"
    );

    // The captured set was P+Q, and Q really conflicts with the other
    // member. Shrinking the current declaration set makes that result
    // stale without touching the other member or the captured candidates.
    slot.set_routes(RouteSet::from([p.clone()]));

    drop(guard);
    let _plan = tokio::time::timeout(Duration::from_secs(10), plan)
        .await
        .expect("the paused plan must finish once the NIC lock is free");

    let (failed_prefixes, failed_status) = admission_failures
        .get(&(run, member.registration_id()))
        .expect("the captured whole-set admission really failed for this registration");
    assert_eq!(
        failed_prefixes,
        &BTreeSet::from([p_prefix, q_prefix]),
        "the observed failure describes exactly the captured P+Q set"
    );
    assert!(
        matches!(failed_status, RouteStatus::Rejected(_)),
        "the overlap with the other member's Q is a real rejection"
    );

    assert_eq!(
        slot.statuses().get(&p),
        Some(&RouteStatus::Pending { error: None }),
        "a failure of the captured whole set cannot reject the current input"
    );
    assert!(
        !matches!(slot.statuses().get(&p), Some(RouteStatus::Rejected(_))),
        "the stale whole-set failure must not surface as a rejection"
    );
    assert!(
        slot.statuses().get(&q).is_none(),
        "the withdrawn Q has no status entry to resurrect"
    );

    let synced = BTreeMap::from([((run, member.registration_id()), BTreeSet::from([p_prefix]))]);
    let fresh = plan_stages(&controller, Some(&synced), &errors, None).await;
    assert_eq!(
        slot.statuses().get(&p),
        Some(&RouteStatus::Ready),
        "the fresh single-prefix admission is disjoint from the other member"
    );
    assert!(
        fresh.desired.contains_key(&RouteKey::of(&route)),
        "the fresh plan still targets P"
    );
}

/// A valid managed acknowledgement survives an unrelated run's input
/// change; that other run's new row has no actual effect and stays
/// pending.
#[cfg(feature = "tun")]
#[tokio::test]
async fn an_unrelated_run_change_preserves_a_valid_managed_feedback() {
    let run = Uuid::new_v4();
    let mut fixture = ManagedNicFixture::new(run);
    let member = fixture.create_member();
    attach_member(&member).await;
    let managed = RouteSpec::for_tun("10.100.0.0/24".parse().unwrap());
    let prefix: IpCidr = managed.destination;
    assert!(
        sync_member_routes(&member, &BTreeSet::from([prefix]))
            .await
            .unwrap(),
        "the member really acknowledges P"
    );

    let controller = RouteController::new(Arc::new(DirtyFlag::new(false)));
    let registry = controller.open_instance(run).unwrap();
    controller.bind_member(run, &member).unwrap();
    assert!(
        controller
            .ready(
                run,
                &member,
                InterfaceInfo {
                    name: MANAGED_NIC_NAME.into(),
                    ifindex: 7,
                },
            )
            .unwrap()
    );
    let slot = registry
        .handle()
        .open_slot(RouteSource::Additional)
        .unwrap();
    slot.set_routes(RouteSet::from([managed.clone()]));
    let row = managed_installed(&managed, 7, run, &member);
    let route = row.route.clone();
    controller
        .runtime
        .write()
        .applied
        .insert(RouteKey::of(&route), row);

    let other_run = Uuid::new_v4();
    let other_registry = controller.open_instance(other_run).unwrap();
    let other_slot = other_registry
        .handle()
        .open_slot(RouteSource::Additional)
        .unwrap();
    let before = indexed("10.101.0.0/24", 9, None);
    let after = indexed("10.102.0.0/24", 9, None);
    other_slot.set_routes(RouteSet::from([before.clone()]));
    let after_route = resolved(&after);

    let synced = BTreeMap::from([((run, member.registration_id()), BTreeSet::from([prefix]))]);

    let shared_nic = member.shared_nic();
    let guard = shared_nic.lock().await;
    let errors = BTreeMap::new();
    let plan = plan_stages(&controller, Some(&synced), &errors, None);
    tokio::pin!(plan);
    assert!(
        futures::poll!(&mut plan).is_pending(),
        "the managed admission waits for the held NIC lock"
    );

    other_slot.set_routes(RouteSet::from([after.clone()]));

    drop(guard);
    let _plan = tokio::time::timeout(Duration::from_secs(10), plan)
        .await
        .expect("the paused plan must finish once the NIC lock is free");

    assert_eq!(
        slot.statuses().get(&managed),
        Some(&RouteStatus::Ready),
        "an unrelated run's change cannot invalidate this acknowledgement"
    );
    assert_eq!(
        other_slot.statuses().get(&after),
        Some(&RouteStatus::Pending { error: None }),
        "the new unrelated row has no actual effect and is not ready"
    );
    assert!(
        other_slot.statuses().get(&before).is_none(),
        "the replaced declaration leaves no status entry"
    );
    assert!(
        !controller
            .applied_routes()
            .contains_key(&RouteKey::of(&after_route)),
        "the new unrelated row was never installed"
    );
}

/// Two instances share one managed NIC and one MagicDNS row, but each
/// member acknowledges independently. A backoff on one member neither
/// blocks the other's real withdrawal nor lets the intersection stage
/// clear the final target; once its deadline passes the second member
/// commits the same shared row and only then becomes ready.
#[cfg(feature = "tun")]
#[tokio::test(start_paused = true)]
async fn shared_magic_dns_row_keeps_independent_member_confirmations() {
    use crate::instance::dns_server::MAGIC_DNS_FAKE_IP;

    let mut h = Harness::new();
    let run_a = Uuid::new_v4();
    let run_b = Uuid::new_v4();
    let mut fixture = ManagedNicFixture::new(run_a);
    let member_a = fixture.create_member();
    attach_member(&member_a).await;
    let member_b = fixture
        .registry
        .try_create_member(
            MANAGED_NIC_NAME.to_owned(),
            managed_virtual_nic_config(),
            run_b,
            Arc::new(Notify::new()),
        )
        .unwrap();
    attach_member(&member_b).await;

    let registry_a = h.controller.open_instance(run_a).unwrap();
    let registry_b = h.controller.open_instance(run_b).unwrap();
    h.controller.bind_member(run_a, &member_a).unwrap();
    h.controller.bind_member(run_b, &member_b).unwrap();
    for (run, member) in [(run_a, &member_a), (run_b, &member_b)] {
        assert!(
            h.controller
                .ready(
                    run,
                    member,
                    InterfaceInfo {
                        name: MANAGED_NIC_NAME.into(),
                        ifindex: 7,
                    },
                )
                .unwrap(),
            "both members bind the same managed device"
        );
    }

    let fake: RouteSpec<RouteDevice> =
        RouteSpec::for_tun(format!("{MAGIC_DNS_FAKE_IP}/32").parse().unwrap());
    let prefix: IpCidr = fake.destination;
    let route = normalize_route(fake.clone().resolve(Some(7)).unwrap()).unwrap();
    let slot_a = registry_a
        .handle()
        .open_slot(RouteSource::Additional)
        .unwrap();
    let slot_b = registry_b
        .handle()
        .open_slot(RouteSource::Additional)
        .unwrap();
    slot_a.set_routes(RouteSet::from([fake.clone()]));
    slot_b.set_routes(RouteSet::from([fake.clone()]));

    // The ordinary member retry of B: a real earlier ACK failure for its
    // full final target. No per-route Ready state is fabricated.
    let retry_deadline = tokio::time::Instant::now() + Duration::from_millis(200);
    h.reconciler.member_retries.insert(
        (run_b, member_b.registration_id()),
        MemberRetry {
            member: member_b.clone(),
            target: BTreeSet::from([prefix]),
            retry_at: retry_deadline,
            attempts: 1,
            error: Arc::from("previous member acknowledgement failed"),
        },
    );

    h.round_ok().await;

    assert_eq!(h.effect(&route), Some(RouteEffect::Owned));
    assert!(h.mock.contains(&route));
    assert_eq!(
        h.mock.add_count(),
        1,
        "the two members share one physical row"
    );
    let row = h
        .applied()
        .get(&RouteKey::of(&route))
        .cloned()
        .expect("the shared row is in the actual ledger");
    assert_eq!(row.owners, BTreeSet::from([run_a, run_b]));
    assert_eq!(
        row.members.keys().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([run_a]),
        "only the member that really acknowledged is recorded"
    );
    assert_eq!(
        row.members[&run_a].registration_id(),
        member_a.registration_id()
    );
    assert_eq!(slot_a.statuses().get(&fake), Some(&RouteStatus::Ready));
    assert!(
        matches!(
            slot_b.statuses().get(&fake),
            Some(RouteStatus::Pending { error: Some(_) })
        ),
        "the backed-off member stays pending with its real error"
    );
    assert_eq!(
        member_claim_prefixes(&member_a).await,
        BTreeSet::from([prefix])
    );
    assert!(
        member_claim_prefixes(&member_b).await.is_empty(),
        "the backed-off member has not confirmed anything"
    );
    {
        let MemberRetry {
            target,
            retry_at: deadline,
            attempts: attempt,
            ..
        } = &h.reconciler.member_retries[&(run_b, member_b.registration_id())];
        assert_eq!(target, &BTreeSet::from([prefix]));
        assert_eq!(*deadline, retry_deadline);
        assert_eq!(*attempt, 1);
    }

    // Only A's input root disappears. Its fixture member stays alive, so
    // the claims survive until the controller really acknowledges them.
    drop(registry_a);
    assert!(
        h.controller.runtime.read().instances[&run_a]
            .registry
            .upgrade()
            .is_none(),
        "the test held A's only registry root"
    );

    h.round_ok().await;

    let row = h
        .applied()
        .get(&RouteKey::of(&route))
        .cloned()
        .expect("the shared physical row stays for B");
    assert_eq!(row.effect, RouteEffect::Owned);
    assert_eq!(
        row.owners,
        BTreeSet::from([run_b]),
        "A's owner responsibility is really released"
    );
    assert!(
        row.members.is_empty(),
        "B has no acknowledgement and must not be recorded as a member"
    );
    assert_eq!(
        h.mock.add_count(),
        1,
        "the unchanged intersection must not add the row again"
    );
    assert_eq!(h.mock.remove_count(), 0, "the row is still B's target");
    assert!(h.mock.contains(&route));
    assert!(
        matches!(
            slot_b.statuses().get(&fake),
            Some(RouteStatus::Pending { error: Some(_) })
        ),
        "B is still waiting for its own ACK"
    );
    {
        let MemberRetry {
            target,
            retry_at: deadline,
            attempts: attempt,
            ..
        } = &h.reconciler.member_retries[&(run_b, member_b.registration_id())];
        assert_eq!(target, &BTreeSet::from([prefix]));
        assert_eq!(
            *deadline, retry_deadline,
            "the intersection stage must not replace the final target's deadline"
        );
        assert_eq!(*attempt, 1, "no attempt was started while backing off");
    }
    assert!(
        member_claim_prefixes(&member_a).await.is_empty(),
        "A's empty ACK really withdrew its shared prefix"
    );
    assert!(
        member_claim_prefixes(&member_b).await.is_empty(),
        "B still has no confirmed claim"
    );
    assert!(
        !h.controller.runtime.read().instances.contains_key(&run_a),
        "A's finished record is pruned"
    );
    tokio::time::timeout(Duration::from_secs(1), h.controller.drain(run_a))
        .await
        .expect("drain A must complete once its record is gone")
        .expect("drain A must not fail");

    let remaining = retry_deadline.saturating_duration_since(tokio::time::Instant::now());
    tokio::time::advance(remaining).await;
    h.round_ok().await;

    let row = h
        .applied()
        .get(&RouteKey::of(&route))
        .cloned()
        .expect("the shared row is still owned");
    assert_eq!(row.effect, RouteEffect::Owned);
    assert_eq!(row.owners, BTreeSet::from([run_b]));
    assert_eq!(
        row.members
            .get(&run_b)
            .map(SharedVirtualNicMember::registration_id),
        Some(member_b.registration_id()),
        "the due member commit confirms B's own registration"
    );
    assert_eq!(slot_b.statuses().get(&fake), Some(&RouteStatus::Ready));
    assert!(
        h.reconciler.member_retries.is_empty(),
        "the confirmed member goal clears its retry"
    );
    assert_eq!(
        h.mock.add_count(),
        1,
        "B's confirmation reuses the already installed physical row"
    );
    assert_eq!(h.mock.remove_count(), 0);
    assert_eq!(
        member_claim_prefixes(&member_b).await,
        BTreeSet::from([prefix])
    );
}

/// The old registration really acknowledged its prefix before the backend
/// readback, then the run rebinds to another NIC while that readback is
/// still in flight. The old candidate cannot add through the new binding,
/// and the old nonempty acknowledgement must survive as an orphan
/// withdrawal retry that the next round really completes.
#[cfg(feature = "tun")]
#[tokio::test(start_paused = true)]
async fn replaced_member_after_ack_keeps_an_orphan_withdrawal_retry() {
    let mut h = Harness::new();
    let run = Uuid::new_v4();
    let mut old_fixture = ManagedNicFixture::new(run);
    let old_member = old_fixture.create_member();
    attach_member(&old_member).await;
    let mut new_fixture = ManagedNicFixture::new(run);
    let new_member = new_fixture.create_member();
    attach_member(&new_member).await;

    let registry = h.controller.open_instance(run).unwrap();
    h.controller.bind_member(run, &old_member).unwrap();
    assert!(
        h.controller
            .ready(
                run,
                &old_member,
                InterfaceInfo {
                    name: MANAGED_NIC_NAME.into(),
                    ifindex: 7,
                },
            )
            .unwrap()
    );
    let slot = registry
        .handle()
        .open_slot(RouteSource::Additional)
        .unwrap();
    let p: RouteSpec<RouteDevice> = RouteSpec::for_tun("10.110.0.0/24".parse().unwrap());
    let prefix: IpCidr = p.destination;
    slot.set_routes(RouteSet::from([p.clone()]));
    let old_route = normalize_route(p.clone().resolve(Some(7)).unwrap()).unwrap();
    let new_route = normalize_route(p.clone().resolve(Some(8)).unwrap()).unwrap();
    assert_ne!(old_route, new_route);

    let controller = h.controller.clone();
    let mock = h.mock.clone();
    let dirty = controller.dirty.clone();
    let slot_handle = slot.clone();
    let (entered, resume) = mock.gate_existing(Some(old_route.clone()));
    dirty.reset();
    let mut round = Box::pin(h.round());
    tokio::select! {
        result = round.as_mut() => panic!("the candidate readback finished before the gate: {result:?}"),
        _ = entered.notified() => {}
    }

    assert_eq!(
        member_claim_prefixes(&old_member).await,
        BTreeSet::from([prefix]),
        "reaching the readback proves the old prefix ACK really completed"
    );
    assert!(
        old_member.ensure_open().is_ok(),
        "the old NIC and registration stay valid while the rebind happens"
    );

    // A new registration on a different NIC replaces the binding while
    // the old readback waits. The old NIC is deliberately left untouched,
    // so its nonempty claims are still real cleanup work.
    controller.bind_member(run, &new_member).unwrap();
    assert!(
        controller
            .ready(
                run,
                &new_member,
                InterfaceInfo {
                    name: MANAGED_NIC_NAME.into(),
                    ifindex: 8,
                },
            )
            .unwrap()
    );
    // Only the production work of this round may remain marked.
    dirty.reset();
    resume.notify_one();
    round.await.unwrap();

    assert_eq!(
        h.mock.add_count(),
        0,
        "the old candidate cannot add through the new binding"
    );
    assert!(!h.mock.contains(&old_route), "no old physical row exists");
    assert!(h.applied().is_empty());
    assert!(matches!(
        slot_handle.statuses().get(&p),
        Some(RouteStatus::Pending { .. })
    ));

    let orphan_key = (run, old_member.registration_id());
    {
        let MemberRetry {
            member: retained,
            target,
            attempts: attempt,
            ..
        } = h
            .reconciler
            .member_retries
            .get(&orphan_key)
            .expect("the old registration is retained for its real withdrawal");
        assert_eq!(
            retained.registration_id(),
            old_member.registration_id(),
            "the cleanup handle is the old registration"
        );
        assert!(
            target.is_empty(),
            "the orphan target is empty; the nonempty ACK belongs to the withdrawal"
        );
        assert_eq!(*attempt, 0, "an orphan cleanup starts no failed attempt");
    }
    assert!(
        dirty.peek(),
        "the remaining orphan withdrawal is actionable in this round"
    );
    assert_eq!(
        member_claim_prefixes(&old_member).await,
        BTreeSet::from([prefix]),
        "the old prefix is not withdrawn until the retry really runs"
    );

    h.controller.dirty.reset();
    h.round_ok().await;

    assert_eq!(h.effect(&new_route), Some(RouteEffect::Owned));
    assert!(h.mock.contains(&new_route));
    assert!(!h.mock.contains(&old_route));
    assert_eq!(h.mock.add_count(), 1);
    assert_eq!(h.mock.remove_count(), 0);
    assert_eq!(slot_handle.statuses().get(&p), Some(&RouteStatus::Ready));
    assert!(
        h.reconciler.member_retries.is_empty(),
        "the old withdrawal completed and removed the orphan retry"
    );
    assert!(
        member_claim_prefixes(&old_member).await.is_empty(),
        "the old registration really withdrew its prefix"
    );
    assert_eq!(
        member_claim_prefixes(&new_member).await,
        BTreeSet::from([prefix]),
        "the new registration confirms the prefix itself"
    );
}

/// A whole-member rejection makes its owner give up the old full row of a
/// shared physical key. The fresh negative proof deletes that row first;
/// only the next normal pass may add the other member's full row of the
/// same key.
#[cfg(all(feature = "tun", target_os = "linux"))]
#[tokio::test]
async fn rejected_owner_releases_its_same_key_row_before_the_other_full_row_is_added() {
    let mut h = Harness::new();
    let run_a = Uuid::new_v4();
    let run_b = Uuid::new_v4();
    let run_c = Uuid::new_v4();
    let mut fixture = ManagedNicFixture::new(run_a);
    let member_a = fixture.create_member();
    attach_member(&member_a).await;
    let member_c = fixture
        .registry
        .try_create_member(
            MANAGED_NIC_NAME.to_owned(),
            managed_virtual_nic_config(),
            run_c,
            Arc::new(Notify::new()),
        )
        .unwrap();
    attach_member(&member_c).await;

    let p: RouteSpec<RouteDevice> = RouteSpec::for_tun("10.112.0.0/24".parse().unwrap());
    let q: RouteSpec<RouteDevice> = RouteSpec::for_tun("10.113.0.0/24".parse().unwrap());
    let p_prefix: IpCidr = p.destination;
    let q_prefix: IpCidr = q.destination;
    assert!(
        sync_member_routes(&member_a, &BTreeSet::from([p_prefix]))
            .await
            .unwrap(),
        "A really claims P"
    );
    assert!(
        sync_member_routes(&member_c, &BTreeSet::from([q_prefix]))
            .await
            .unwrap(),
        "the fixture blocker C really claims Q"
    );

    let registry_a = h.controller.open_instance(run_a).unwrap();
    h.controller.bind_member(run_a, &member_a).unwrap();
    assert!(
        h.controller
            .ready(
                run_a,
                &member_a,
                InterfaceInfo {
                    name: MANAGED_NIC_NAME.into(),
                    ifindex: 7,
                },
            )
            .unwrap()
    );
    let slot_a = registry_a
        .handle()
        .open_slot(RouteSource::Additional)
        .unwrap();
    slot_a.set_routes(RouteSet::from([p.clone()]));

    let registry_b = h.controller.open_instance(run_b).unwrap();
    let slot_b = registry_b
        .handle()
        .open_slot(RouteSource::Additional)
        .unwrap();
    let row2_declaration = indexed("10.112.0.0/24", 8, None);
    let row2_route = resolved(&row2_declaration);
    slot_b.set_routes(RouteSet::from([row2_declaration.clone()]));

    let row1 = managed_installed(&p, 7, run_a, &member_a);
    let row1_route = row1.route.clone();
    assert_eq!(
        RouteKey::of(&row1_route),
        RouteKey::of(&row2_route),
        "the two full rows share the exclusive key"
    );
    assert_ne!(row1_route, row2_route);
    h.mock.routes.lock().insert(row1_route.clone());
    h.controller
        .runtime
        .write()
        .applied
        .insert(RouteKey::of(&row1_route), row1);

    h.round_ok().await;
    assert_eq!(slot_a.statuses().get(&p), Some(&RouteStatus::Ready));
    assert!(
        matches!(
            slot_b.statuses().get(&row2_declaration),
            Some(RouteStatus::Suppressed(_))
        ),
        "the installed row still occupies the shared key"
    );
    assert_eq!(h.mock.add_count(), 0);
    assert_eq!(h.mock.remove_count(), 0);

    // Adding Q makes A's whole candidate set conflict with C's Q. A raw P
    // declaration no longer proves ownership of row 1.
    slot_a.set_routes(RouteSet::from([p.clone(), q.clone()]));
    h.round_ok().await;

    assert!(matches!(
        slot_a.statuses().get(&p),
        Some(RouteStatus::Rejected(_))
    ));
    assert!(matches!(
        slot_a.statuses().get(&q),
        Some(RouteStatus::Rejected(_))
    ));
    assert_eq!(
        h.effect(&row1_route),
        None,
        "the rejected owner's old full row is really deleted"
    );
    assert!(!h.mock.contains(&row1_route));
    assert_eq!(h.mock.remove_count(), 1);
    assert_eq!(
        h.mock.add_count(),
        0,
        "the other full row waits for a normal pass after the deletion"
    );
    assert!(
        member_claim_prefixes(&member_a).await.is_empty(),
        "the whole-member rejection still acknowledges the real withdrawal"
    );
    assert_eq!(
        member_claim_prefixes(&member_c).await,
        BTreeSet::from([q_prefix]),
        "the fixture blocker outside the controller is untouched"
    );

    h.round_ok().await;

    assert_eq!(h.effect(&row2_route), Some(RouteEffect::Owned));
    assert!(h.mock.contains(&row2_route));
    assert_eq!(h.mock.add_count(), 1);
    let row = h
        .applied()
        .get(&RouteKey::of(&row2_route))
        .cloned()
        .expect("the other full row is installed");
    assert_eq!(
        row.owners,
        BTreeSet::from([run_b]),
        "the rejected owner does not steal the new row"
    );
    assert!(row.members.is_empty());
    assert_eq!(
        slot_b.statuses().get(&row2_declaration),
        Some(&RouteStatus::Ready)
    );
    assert!(matches!(
        slot_a.statuses().get(&p),
        Some(RouteStatus::Rejected(_))
    ));
    assert!(matches!(
        slot_a.statuses().get(&q),
        Some(RouteStatus::Rejected(_))
    ));

    let operations = h.mock.operations.lock().clone();
    let removed = operations
        .iter()
        .position(
            |operation| matches!(operation, MockOperation::Remove(route) if route == &row1_route),
        )
        .expect("the old same-key row was really removed");
    let added = operations
        .iter()
        .position(
            |operation| matches!(operation, MockOperation::Add(route) if route == &row2_route),
        )
        .expect("the other same-key row was really added");
    assert!(
        removed < added,
        "the old same-key row must be deleted before the new one is added"
    );
}

/// Transient admission failures keep the member's real claims, record one
/// retry for the full target and never turn into an empty withdrawal. A
/// dirty round before that deadline cannot bypass it; the due round then
/// commits the current prefix, installs the row and becomes ready.
#[cfg(feature = "tun")]
#[tokio::test(start_paused = true)]
async fn transient_admission_failure_preserves_claims_and_schedules_progress() {
    let mut h = Harness::new();
    let run_a = Uuid::new_v4();
    let mut fixture = ManagedNicFixture::new(run_a);
    let member = fixture.create_member();
    attach_member(&member).await;

    let p: RouteSpec<RouteDevice> = RouteSpec::for_tun("10.114.0.0/24".parse().unwrap());
    let prefix: IpCidr = p.destination;
    let p_route = normalize_route(p.clone().resolve(Some(7)).unwrap()).unwrap();
    assert!(
        sync_member_routes(&member, &BTreeSet::from([prefix]))
            .await
            .unwrap(),
        "the fixture starts from a real current claim"
    );

    let registry_a = h.controller.open_instance(run_a).unwrap();
    h.controller.bind_member(run_a, &member).unwrap();
    assert!(
        h.controller
            .ready(
                run_a,
                &member,
                InterfaceInfo {
                    name: MANAGED_NIC_NAME.into(),
                    ifindex: 7,
                },
            )
            .unwrap()
    );
    let slot_a = registry_a
        .handle()
        .open_slot(RouteSource::Additional)
        .unwrap();
    slot_a.set_routes(RouteSet::from([p.clone()]));

    let run_b = Uuid::new_v4();
    let registry_b = h.controller.open_instance(run_b).unwrap();
    let slot_b = registry_b
        .handle()
        .open_slot(RouteSource::Additional)
        .unwrap();
    let b_declaration = indexed("10.115.0.0/24", 9, None);
    let b_route = resolved(&b_declaration);
    slot_b.set_routes(RouteSet::from([b_declaration.clone()]));

    let shared_nic = member.shared_nic();
    let guard = shared_nic.lock().await;
    {
        let mut round = Box::pin(h.round());
        let mut advances = 0;
        loop {
            match futures::poll!(&mut round) {
                std::task::Poll::Ready(result) => {
                    result.expect("the reconcile round must not fail");
                    break;
                }
                std::task::Poll::Pending => {
                    assert!(
                        advances < 4,
                        "the round must finish after its bounded planning attempts"
                    );
                    advances += 1;
                    // Each held-NIC admission has its own bounded wait;
                    // advancing the paused clock expires the current one.
                    tokio::time::advance(Duration::from_secs(5)).await;
                }
            }
        }
    }
    drop(guard);

    assert!(
        matches!(
            slot_a.statuses().get(&p),
            Some(RouteStatus::Pending { error: Some(error) })
                if error.contains("timed out locking shared NIC")
        ),
        "the held NIC reports its bounded admission timeout"
    );
    assert_eq!(h.effect(&p_route), None);
    assert!(
        !h.mock
            .add_calls
            .lock()
            .iter()
            .any(|route| route == &p_route),
        "a timed-out admission never installs its row"
    );
    assert_eq!(
        slot_b.statuses().get(&b_declaration),
        Some(&RouteStatus::Ready)
    );
    assert_eq!(h.effect(&b_route), Some(RouteEffect::Owned));
    assert_eq!(
        member_claim_prefixes(&member).await,
        BTreeSet::from([prefix]),
        "the failed admission must not withdraw the real claim"
    );
    let member_key = (run_a, member.registration_id());
    let deadline = {
        let MemberRetry {
            target,
            retry_at: deadline,
            attempts: attempt,
            ..
        } = h
            .reconciler
            .member_retries
            .get(&member_key)
            .expect("the failed admission records its retry");
        assert_eq!(target, &BTreeSet::from([prefix]));
        assert!(*attempt >= 1);
        assert!(*deadline > tokio::time::Instant::now());
        *deadline
    };
    let attempt_before = h.reconciler.member_retries[&member_key].attempts;

    // A dirty round before the deadline must not start the member commit.
    h.controller.dirty.mark();
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    tokio::time::advance(remaining / 2).await;
    h.round_ok().await;

    assert_eq!(
        h.effect(&p_route),
        None,
        "the member backoff still owns this row"
    );
    assert!(
        !h.mock
            .add_calls
            .lock()
            .iter()
            .any(|route| route == &p_route)
    );
    assert_eq!(
        member_claim_prefixes(&member).await,
        BTreeSet::from([prefix]),
        "no false empty withdrawal before the deadline"
    );
    {
        let MemberRetry {
            retry_at: deadline_now,
            attempts: attempt_now,
            ..
        } = &h.reconciler.member_retries[&member_key];
        assert_eq!(*deadline_now, deadline);
        assert_eq!(*attempt_now, attempt_before);
    }

    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    tokio::time::advance(remaining + Duration::from_millis(1)).await;
    h.round_ok().await;

    assert_eq!(h.effect(&p_route), Some(RouteEffect::Owned));
    assert!(h.mock.contains(&p_route));
    assert_eq!(slot_a.statuses().get(&p), Some(&RouteStatus::Ready));
    assert!(
        h.reconciler.member_retries.is_empty(),
        "the due commit clears the member retry"
    );
    assert_eq!(
        member_claim_prefixes(&member).await,
        BTreeSet::from([prefix]),
        "the committed prefix is still the current one"
    );
}

/// A rejected owner keeps the physical row absent, and the round ends with
/// an empty ACK for its member. When the conflicting fixture member
/// releases its claim during that same round, the fresh planning admits
/// the member again. Since this round's ACK was empty it cannot be ready,
/// but the remaining member goal must leave the controller dirty so the
/// next round runs without waiting for another input mark.
#[cfg(feature = "tun")]
#[tokio::test]
async fn admission_recovery_after_empty_ack_keeps_actionable_dirty() {
    let mut h = Harness::new();
    let run_a = Uuid::new_v4();
    let run_c = Uuid::new_v4();
    let mut fixture = ManagedNicFixture::new(run_a);
    let member_a = fixture.create_member();
    attach_member(&member_a).await;
    let member_c = fixture
        .registry
        .try_create_member(
            MANAGED_NIC_NAME.to_owned(),
            managed_virtual_nic_config(),
            run_c,
            Arc::new(Notify::new()),
        )
        .unwrap();
    attach_member(&member_c).await;

    let p: RouteSpec<RouteDevice> = RouteSpec::for_tun("10.116.0.0/24".parse().unwrap());
    let q: RouteSpec<RouteDevice> = RouteSpec::for_tun("10.117.0.0/24".parse().unwrap());
    let p_prefix: IpCidr = p.destination;
    let q_prefix: IpCidr = q.destination;
    let p_route = normalize_route(p.clone().resolve(Some(7)).unwrap()).unwrap();
    let q_route = normalize_route(q.clone().resolve(Some(7)).unwrap()).unwrap();
    assert!(
        sync_member_routes(&member_a, &BTreeSet::from([p_prefix]))
            .await
            .unwrap()
    );
    assert!(
        sync_member_routes(&member_c, &BTreeSet::from([q_prefix]))
            .await
            .unwrap(),
        "the fixture blocker really claims Q"
    );

    let registry_a = h.controller.open_instance(run_a).unwrap();
    h.controller.bind_member(run_a, &member_a).unwrap();
    assert!(
        h.controller
            .ready(
                run_a,
                &member_a,
                InterfaceInfo {
                    name: MANAGED_NIC_NAME.into(),
                    ifindex: 7,
                },
            )
            .unwrap()
    );
    let slot_a = registry_a
        .handle()
        .open_slot(RouteSource::Additional)
        .unwrap();
    slot_a.set_routes(RouteSet::from([p.clone(), q.clone()]));

    let run_b = Uuid::new_v4();
    let registry_b = h.controller.open_instance(run_b).unwrap();
    let slot_b = registry_b
        .handle()
        .open_slot(RouteSource::Additional)
        .unwrap();
    let b_declaration = indexed("10.118.0.0/24", 9, None);
    let b_route = resolved(&b_declaration);
    slot_b.set_routes(RouteSet::from([b_declaration.clone()]));

    let controller = h.controller.clone();
    let dirty = controller.dirty.clone();
    let mock = h.mock.clone();
    let (entered, resume) = mock.gate_add(Some(b_route.clone()));
    dirty.reset();
    let mut round = Box::pin(h.round());
    tokio::select! {
        result = round.as_mut() => panic!("the ordinary addition finished before the gate: {result:?}"),
        _ = entered.notified() => {}
    }

    assert!(
        member_claim_prefixes(&member_a).await.is_empty(),
        "the rejected whole member still acknowledged the empty target"
    );
    assert_eq!(
        member_claim_prefixes(&member_c).await,
        BTreeSet::from([q_prefix])
    );
    assert!(
        !dirty.peek(),
        "the member withdrawal and the fixture claims mark no controller input"
    );

    // The fixture blocker releases its claim while the ordinary addition
    // waits. No controller slot or configuration changes, so no input mark
    // is produced by this recovery.
    assert!(
        sync_member_routes(&member_c, &BTreeSet::new())
            .await
            .unwrap()
    );
    assert!(
        !dirty.peek(),
        "the fixture-only claim release marks no controller input"
    );

    resume.notify_one();
    round.await.unwrap();

    assert_eq!(
        slot_b.statuses().get(&b_declaration),
        Some(&RouteStatus::Ready)
    );
    assert_eq!(h.effect(&b_route), Some(RouteEffect::Owned));
    assert!(
        matches!(slot_a.statuses().get(&p), Some(RouteStatus::Pending { .. })),
        "the recovered admission has no row in this round"
    );
    assert!(
        matches!(slot_a.statuses().get(&q), Some(RouteStatus::Pending { .. })),
        "the empty ACK of this round cannot make the recovered member ready"
    );
    assert!(
        !h.applied().contains_key(&RouteKey::of(&p_route)),
        "the fresh final planning never installs during this round"
    );
    assert!(!h.applied().contains_key(&RouteKey::of(&q_route)));
    assert!(
        dirty.peek(),
        "the unconfirmed recovered member goal is actionable without another input mark"
    );

    h.controller.dirty.reset();
    h.round_ok().await;

    assert_eq!(h.effect(&p_route), Some(RouteEffect::Owned));
    assert_eq!(h.effect(&q_route), Some(RouteEffect::Owned));
    assert_eq!(slot_a.statuses().get(&p), Some(&RouteStatus::Ready));
    assert_eq!(slot_a.statuses().get(&q), Some(&RouteStatus::Ready));
    assert_eq!(
        member_claim_prefixes(&member_a).await,
        BTreeSet::from([p_prefix, q_prefix]),
        "the next round commits the whole current member target"
    );
}

// Audit tests. Every one drives the real `RouteReconciler::audit` through
// the mock backend and the same retry maps of the worker loop; none of
// them starts the platform backend or enters a real namespace.

impl Harness {
    /// One real audit with a test-only overall bound. It only turns a hung
    /// test into a diagnostic; the production I/O bounds are inside.
    async fn audit(&mut self) -> anyhow::Result<bool> {
        tokio::time::timeout(Duration::from_secs(10), self.reconciler.audit())
            .await
            .expect("the audit must finish within 10s")
    }
}

/// Every actual fact an audit must not clear: key, full route, effect,
/// owners and the registration behind each recorded member.
#[cfg(feature = "tun")]
fn applied_evidence(
    applied: &AppliedRoutes,
) -> Vec<(
    RouteKey,
    RouteSpec<u32>,
    RouteEffect,
    BTreeSet<Uuid>,
    Vec<(Uuid, Uuid)>,
)> {
    applied
        .iter()
        .map(|(key, row)| {
            let members = row
                .members
                .iter()
                .map(|(run, member)| (*run, member.registration_id()))
                .collect();
            (
                key.clone(),
                row.route.clone(),
                row.effect,
                row.owners.clone(),
                members,
            )
        })
        .collect()
}

/// A healthy managed row and an absent ordinary row are read back in one
/// batch. The audit must not drive the planner or touch the healthy
/// member's NIC: only the next normal round restores the missing row.
#[cfg(feature = "tun")]
#[tokio::test(start_paused = true)]
async fn a_batch_audit_retires_only_the_absent_row_without_waiting_for_the_healthy_nic() {
    let mut h = Harness::new();
    let run = Uuid::new_v4();
    let mut fixture = ManagedNicFixture::new(run);
    let member = fixture.create_member();
    attach_member(&member).await;

    let registry = h.controller.open_instance(run).unwrap();
    h.controller.bind_member(run, &member).unwrap();
    assert!(
        h.controller
            .ready(
                run,
                &member,
                InterfaceInfo {
                    name: MANAGED_NIC_NAME.into(),
                    ifindex: 7,
                },
            )
            .unwrap()
    );
    let slot = registry
        .handle()
        .open_slot(RouteSource::Additional)
        .unwrap();

    let managed: RouteSpec<RouteDevice> = RouteSpec::for_tun("10.130.0.0/24".parse().unwrap());
    let managed_route = normalize_route(managed.clone().resolve(Some(7)).unwrap()).unwrap();
    let ordinary_declaration = indexed("10.131.0.0/24", 9, None);
    let ordinary_route = resolved(&ordinary_declaration);
    h.mock.routes.lock().insert(ordinary_route.clone());
    slot.set_routes(RouteSet::from([
        managed.clone(),
        ordinary_declaration.clone(),
    ]));

    h.round_ok().await;
    assert_eq!(h.effect(&managed_route), Some(RouteEffect::Owned));
    assert_eq!(h.effect(&ordinary_route), Some(RouteEffect::External));
    assert_eq!(slot.statuses().get(&managed), Some(&RouteStatus::Ready));
    assert_eq!(
        slot.statuses().get(&ordinary_declaration),
        Some(&RouteStatus::Ready)
    );
    assert_eq!(
        member_claim_prefixes(&member).await,
        BTreeSet::from([managed.destination])
    );
    let evidence_before = applied_evidence(&h.applied());
    let managed_evidence = evidence_before
        .iter()
        .find(|row| row.0 == RouteKey::of(&managed_route))
        .cloned()
        .expect("the managed row is installed");
    let add_calls = h.mock.add_count();
    let remove_calls = h.mock.remove_count();

    // Only the ordinary row is physically gone. The managed member's NIC
    // lock is held for the whole audit: a planner call inside the audit
    // would wait on member admission instead of returning immediately.
    h.mock.routes.lock().remove(&ordinary_route);
    let shared_nic = member.shared_nic();
    let guard = shared_nic.lock().await;
    h.controller.dirty.reset();
    let removed = tokio::time::timeout(Duration::from_millis(100), h.audit())
        .await
        .expect("the audit must not wait for the healthy member's NIC")
        .expect("the audit readback is complete");
    assert!(removed);

    assert_eq!(
        h.mock.existing_batches.lock().last().cloned(),
        Some(BTreeSet::from([
            managed_route.clone(),
            ordinary_route.clone()
        ])),
        "one batch contains the exact full rows of both effects"
    );
    assert_eq!(
        applied_evidence(&h.applied()),
        vec![managed_evidence],
        "the healthy row and its member registration are untouched"
    );
    assert_eq!(slot.statuses().get(&managed), Some(&RouteStatus::Ready));
    assert_eq!(
        slot.statuses().get(&ordinary_declaration),
        Some(&RouteStatus::Pending { error: None }),
        "the missing ordinary declaration waits for the normal round"
    );
    assert!(h.dirty_peek());
    assert_eq!(h.mock.add_count(), add_calls);
    assert_eq!(h.mock.remove_count(), remove_calls);
    drop(guard);

    h.round_ok().await;
    assert_eq!(h.effect(&ordinary_route), Some(RouteEffect::Owned));
    assert!(h.mock.contains(&ordinary_route));
    assert_eq!(
        slot.statuses().get(&ordinary_declaration),
        Some(&RouteStatus::Ready)
    );
    assert_eq!(
        h.mock.add_count(),
        add_calls + 1,
        "the normal round, not the audit, really adds the missing row"
    );
    assert_eq!(h.mock.remove_count(), remove_calls);
}

/// A failed or timed-out batch readback proves nothing: every actual row,
/// effect, owner, member registration and status stays exactly as it was,
/// and the audit itself performs no CRUD. Only a complete present readback
/// ends the audit without changing the ledger.
#[cfg(feature = "tun")]
#[tokio::test(start_paused = true)]
async fn a_failed_or_timed_out_readback_keeps_every_actual_fact() {
    let mut h = Harness::new();
    let run = Uuid::new_v4();
    let mut fixture = ManagedNicFixture::new(run);
    let member = fixture.create_member();
    attach_member(&member).await;

    let registry = h.controller.open_instance(run).unwrap();
    h.controller.bind_member(run, &member).unwrap();
    assert!(
        h.controller
            .ready(
                run,
                &member,
                InterfaceInfo {
                    name: MANAGED_NIC_NAME.into(),
                    ifindex: 7,
                },
            )
            .unwrap()
    );
    let slot = registry
        .handle()
        .open_slot(RouteSource::Additional)
        .unwrap();

    let owned: RouteSpec<RouteDevice> = RouteSpec::for_tun("10.132.0.0/24".parse().unwrap());
    let owned_route = normalize_route(owned.clone().resolve(Some(7)).unwrap()).unwrap();
    let external_declaration = indexed("10.133.0.0/24", 8, None);
    let external_route = resolved(&external_declaration);
    h.mock.routes.lock().insert(external_route.clone());
    slot.set_routes(RouteSet::from([
        owned.clone(),
        external_declaration.clone(),
    ]));

    h.round_ok().await;
    assert_eq!(h.effect(&owned_route), Some(RouteEffect::Owned));
    assert_eq!(h.effect(&external_route), Some(RouteEffect::External));
    assert_eq!(slot.statuses().get(&owned), Some(&RouteStatus::Ready));
    assert_eq!(
        slot.statuses().get(&external_declaration),
        Some(&RouteStatus::Ready)
    );
    assert_eq!(
        member_claim_prefixes(&member).await,
        BTreeSet::from([owned.destination])
    );

    let evidence = applied_evidence(&h.applied());
    assert!(
        evidence
            .iter()
            .any(|row| row.0 == RouteKey::of(&owned_route) && !row.4.is_empty()),
        "the evidence really includes the acknowledged member registration"
    );
    let statuses = slot.statuses();
    let add_calls = h.mock.add_count();
    let remove_calls = h.mock.remove_count();

    // A complete readback error is an audit error, not an empty table.
    h.mock
        .queue_existing_error(RouteError::Failed(anyhow::anyhow!("readback failed")));
    h.controller.dirty.reset();
    assert!(h.audit().await.is_err());
    assert_eq!(applied_evidence(&h.applied()), evidence);
    assert_eq!(slot.statuses(), statuses);
    assert_eq!(h.mock.add_count(), add_calls);
    assert_eq!(h.mock.remove_count(), remove_calls);
    assert!(!h.dirty_peek(), "a failed read is not progress");
    assert!(h.reconciler.route_retries.is_empty());

    // A readback that never completes is also not an absence. The gate is
    // entered and then the audit's real 5s I/O bound expires under paused
    // time; the test's own outer bound keeps the wait finite.
    let (entered, resume) = h.mock.gate_existing(None);
    h.controller.dirty.reset();
    let mut audit = Box::pin(h.audit());
    tokio::select! {
        result = audit.as_mut() => panic!("the gated readback finished before the gate: {result:?}"),
        _ = entered.notified() => {}
    }
    tokio::time::advance(Duration::from_secs(5)).await;
    let error = tokio::time::timeout(Duration::from_secs(1), audit)
        .await
        .expect("the audit's own I/O bound must stop the wait")
        .expect_err("an incomplete readback is an audit error");
    assert!(
        error
            .to_string()
            .contains("timed out reading existing routes"),
        "the honest timeout stays the audit error: {error}"
    );
    resume.notify_one();
    assert_eq!(applied_evidence(&h.applied()), evidence);
    assert_eq!(slot.statuses(), statuses);
    assert_eq!(h.mock.add_count(), add_calls);
    assert_eq!(h.mock.remove_count(), remove_calls);
    assert!(!h.dirty_peek());
    assert!(h.reconciler.route_retries.is_empty());

    assert!(
        !h.audit().await.expect("a complete readback succeeds"),
        "present rows need no repair"
    );
    assert_eq!(applied_evidence(&h.applied()), evidence);
    assert_eq!(slot.statuses(), statuses);
    assert_eq!(h.mock.add_count(), add_calls);
    assert_eq!(h.mock.remove_count(), remove_calls);
    assert!(!h.dirty_peek());
}

/// The root is released while a batch readback is gated. The confirmed
/// absence may retire the old row, but neither the audit nor the next
/// normal round may recreate it from the still-held slot or manual policy.
#[tokio::test(start_paused = true)]
async fn a_released_root_during_a_gated_audit_is_never_revived_by_old_inputs() {
    use easytier_core::config::{
        peers::PeerRuntimeSnapshot,
        runtime::{CoreRuntimeConfig, CoreRuntimeConfigStore},
    };

    let mut h = Harness::new();
    let declaration = indexed("10.134.0.0/24", 7, None);
    let route = resolved(&declaration);
    let run = Uuid::new_v4();
    let registry = h.controller.open_instance(run).unwrap();
    let store = CoreRuntimeConfigStore::new(
        CoreRuntimeConfig::default(),
        Arc::new(PeerRuntimeSnapshot::default()),
    );
    let held_manual = BTreeSet::from(["10.135.0.0/24".parse().unwrap()]);
    store.update_services(|services| services.manual_routes = Some(held_manual.clone()));
    h.controller.bind_config(run, store.clone()).unwrap();
    let slot = registry
        .handle()
        .open_slot(RouteSource::Additional)
        .unwrap();
    slot.set_routes(RouteSet::from([declaration.clone()]));

    h.round_ok().await;
    assert_eq!(h.effect(&route), Some(RouteEffect::Owned));
    assert_eq!(slot.statuses().get(&declaration), Some(&RouteStatus::Ready));
    assert!(h.mock.contains(&route));
    let add_calls = h.mock.add_count();
    let status_before = slot.statuses();

    h.mock.routes.lock().remove(&route);
    let (entered, resume) = h.mock.gate_existing(Some(route.clone()));
    let controller = h.controller.clone();
    let dirty = controller.dirty.clone();
    let slot_handle = slot.clone();
    dirty.reset();
    let mut audit = Box::pin(h.audit());
    tokio::select! {
        result = audit.as_mut() => panic!("the gated readback finished before the gate: {result:?}"),
        _ = entered.notified() => {}
    }

    // Only the root is released. The slot and the nonempty manual policy
    // stay held, so they are the stale inputs that must not resurrect.
    drop(registry);
    assert!(
        controller.runtime.read().instances[&run]
            .registry
            .upgrade()
            .is_none(),
        "the controller only observes the released root weakly"
    );
    assert!(dirty.peek(), "releasing the root marks the route inputs");
    assert_eq!(
        controller.effective_routes_for_instance(&run),
        RouteSet::new(),
        "the held manual policy cannot outlive the released input directory"
    );

    resume.notify_one();
    let removed = tokio::time::timeout(Duration::from_secs(1), audit)
        .await
        .expect("the audit must finish once the readback is released")
        .expect("a complete absence readback succeeds");
    assert!(removed);

    assert_eq!(
        h.effect(&route),
        None,
        "the confirmed absence retires the old Owned row"
    );
    assert!(!h.mock.contains(&route));
    assert_eq!(
        slot_handle.statuses().get(&declaration),
        status_before.get(&declaration),
        "feedback for the released root is skipped, not rewritten"
    );
    assert_eq!(h.mock.add_count(), add_calls, "the audit never adds");
    assert_eq!(h.mock.remove_count(), 0, "the audit never deletes");
    assert_eq!(
        store.snapshot().services.manual_routes,
        Some(held_manual),
        "the real nonempty manual policy is still there"
    );

    h.controller.dirty.reset();
    h.round_ok().await;

    assert!(
        !h.mock.contains(&route),
        "the normal round must not recreate the released input"
    );
    assert_eq!(
        h.mock.add_count(),
        add_calls,
        "neither the old slot nor the manual policy becomes a target"
    );
    assert!(h.applied().is_empty());
    assert!(
        !h.controller.runtime.read().instances.contains_key(&run),
        "a released record is pruned once no cleanup is owed"
    );
    tokio::time::timeout(Duration::from_secs(1), h.controller.drain(run))
        .await
        .expect("the released record's drain completes after cleanup")
        .expect("drain must not fail");
}

/// A present readback never promotes an unconfirmed addition, and a
/// complete absence retires exactly that record and its retry. The audit
/// never performs the add; the next normal round decides from current
/// input.
#[tokio::test]
async fn a_present_adding_row_stays_unconfirmed_and_a_confirmed_absence_retires_it() {
    let mut h = Harness::new();
    let declaration = indexed("10.136.0.0/24", 7, None);
    let route = resolved(&declaration);
    let (_run, _registry, slot) = instance_with_slot(&h.controller, RouteSource::Additional);
    slot.set_routes(RouteSet::from([declaration.clone()]));
    h.mock.queue_add(
        &route,
        RouteError::Unknown(anyhow::anyhow!("unknown add")),
        false,
    );
    h.round_ok().await;

    assert_eq!(h.effect(&route), Some(RouteEffect::Adding));
    assert!(!h.mock.contains(&route));
    let key = RouteKey::of(&route);
    let retry_before = h.reconciler.route_retries[&key].clone();
    let add_calls = h.mock.add_count();
    let remove_calls = h.mock.remove_count();
    let unknown_status = RouteStatus::Pending {
        error: Some(Arc::from("route operation outcome is unknown: unknown add")),
    };
    assert_eq!(slot.statuses().get(&declaration), Some(&unknown_status));

    // The row is physically there now, yet the effect is still unconfirmed.
    h.mock.routes.lock().insert(route.clone());
    h.controller.dirty.reset();
    assert!(!h.audit().await.expect("the present readback is complete"));
    assert_eq!(
        h.effect(&route),
        Some(RouteEffect::Adding),
        "a present row is not proof that this addition completed"
    );
    assert_eq!(slot.statuses().get(&declaration), Some(&unknown_status));
    assert_eq!(h.reconciler.route_retries[&key], retry_before);
    assert_eq!(h.mock.add_count(), add_calls);
    assert_eq!(h.mock.remove_count(), remove_calls);
    assert!(!h.dirty_peek());

    // A complete absence is real progress for exactly this addition.
    h.mock.routes.lock().remove(&route);
    h.controller.dirty.reset();
    assert!(h.audit().await.expect("the absence readback is complete"));
    assert_eq!(h.effect(&route), None);
    assert!(!h.reconciler.route_retries.contains_key(&key));
    assert_eq!(
        slot.statuses().get(&declaration),
        Some(&RouteStatus::Pending { error: None })
    );
    assert!(h.dirty_peek());
    assert_eq!(h.mock.add_count(), add_calls, "the audit never adds");
    assert_eq!(h.mock.remove_count(), remove_calls);

    // The current declaration is still a target; the next normal round
    // really installs it from the fresh input.
    h.round_ok().await;
    assert_eq!(h.effect(&route), Some(RouteEffect::Owned));
    assert_eq!(slot.statuses().get(&declaration), Some(&RouteStatus::Ready));
    assert_eq!(h.mock.add_count(), add_calls + 1);
}

/// A present readback keeps an uncertain removal and its delete retry; a
/// complete absence retires exactly that record and retry. The audit never
/// performs the delete.
#[tokio::test]
async fn a_present_removing_row_keeps_its_delete_responsibility_until_the_absence_proof() {
    let mut h = Harness::new();
    let declaration = indexed("10.137.0.0/24", 7, None);
    let route = resolved(&declaration);
    let (_run, _registry, slot) = instance_with_slot(&h.controller, RouteSource::Additional);
    slot.set_routes(RouteSet::from([declaration]));
    h.round_ok().await;
    assert_eq!(h.effect(&route), Some(RouteEffect::Owned));

    h.mock.queue_remove(
        &route,
        RouteError::Unknown(anyhow::anyhow!("unknown delete")),
        false,
    );
    slot.clear();
    h.round_ok().await;
    assert_eq!(h.effect(&route), Some(RouteEffect::Removing));
    assert!(
        h.mock.contains(&route),
        "the unknown delete left the physical row"
    );
    let key = RouteKey::of(&route);
    let retry_before = h.reconciler.route_retries[&key].clone();
    let add_calls = h.mock.add_count();
    let remove_calls = h.mock.remove_count();
    assert!(slot.statuses().is_empty());

    // Present readback: the delete is not confirmed and its retry and
    // cleanup responsibility stay.
    h.controller.dirty.reset();
    assert!(!h.audit().await.expect("the present readback is complete"));
    assert_eq!(
        h.effect(&route),
        Some(RouteEffect::Removing),
        "a present row must not promote an uncertain removal to Owned"
    );
    assert_eq!(h.reconciler.route_retries[&key], retry_before);
    assert_eq!(
        h.mock.remove_count(),
        remove_calls,
        "the audit never deletes"
    );
    assert_eq!(h.mock.add_count(), add_calls);
    assert!(!h.dirty_peek());

    // Only the positive absence proof retires the record and its retry.
    h.mock.routes.lock().remove(&route);
    h.controller.dirty.reset();
    assert!(h.audit().await.expect("the absence readback is complete"));
    assert_eq!(h.effect(&route), None);
    assert!(!h.reconciler.route_retries.contains_key(&key));
    assert!(h.dirty_peek());
    assert_eq!(h.mock.remove_count(), remove_calls);
    assert_eq!(h.mock.add_count(), add_calls);

    h.round_ok().await;
    assert!(h.applied().is_empty());
    assert_eq!(h.mock.remove_count(), remove_calls);
    assert_eq!(h.mock.add_count(), add_calls);
}

/// The audit's absence proof retires an old managed row while the run
/// rebinds. The old registration and its real prefix stay in the retry map
/// as an empty-goal cleanup; the new binding is ready only after its own
/// acknowledgement and installation, never from the old read or ACK.
#[cfg(feature = "tun")]
#[tokio::test(start_paused = true)]
async fn an_audit_keeps_the_old_member_cleanup_across_a_rebind() {
    let mut h = Harness::new();
    let run = Uuid::new_v4();
    let mut old_fixture = ManagedNicFixture::new(run);
    let old_member = old_fixture.create_member();
    attach_member(&old_member).await;
    let mut new_fixture = ManagedNicFixture::new(run);
    let new_member = new_fixture.create_member();
    attach_member(&new_member).await;

    let registry = h.controller.open_instance(run).unwrap();
    h.controller.bind_member(run, &old_member).unwrap();
    assert!(
        h.controller
            .ready(
                run,
                &old_member,
                InterfaceInfo {
                    name: MANAGED_NIC_NAME.into(),
                    ifindex: 7,
                },
            )
            .unwrap()
    );
    let slot = registry
        .handle()
        .open_slot(RouteSource::Additional)
        .unwrap();
    let p: RouteSpec<RouteDevice> = RouteSpec::for_tun("10.138.0.0/24".parse().unwrap());
    let prefix: IpCidr = p.destination;
    slot.set_routes(RouteSet::from([p.clone()]));

    h.round_ok().await;
    let old_route = normalize_route(p.clone().resolve(Some(7)).unwrap()).unwrap();
    let new_route = normalize_route(p.clone().resolve(Some(8)).unwrap()).unwrap();
    assert_ne!(old_route, new_route);
    assert_eq!(h.effect(&old_route), Some(RouteEffect::Owned));
    assert!(
        h.applied()[&RouteKey::of(&old_route)]
            .members
            .get(&run)
            .is_some_and(|member| member.registration_id() == old_member.registration_id())
    );
    assert_eq!(slot.statuses().get(&p), Some(&RouteStatus::Ready));
    assert_eq!(
        member_claim_prefixes(&old_member).await,
        BTreeSet::from([prefix])
    );

    // The old physical row disappears and its readback is held. The new
    // registration is bound to a different NIC and device while the audit
    // awaits; the old NIC is deliberately not attached to it.
    h.mock.routes.lock().remove(&old_route);
    let (entered, resume) = h.mock.gate_existing(Some(old_route.clone()));
    let controller = h.controller.clone();
    let dirty = controller.dirty.clone();
    let slot_handle = slot.clone();
    let mock = h.mock.clone();
    dirty.reset();
    let mut audit = Box::pin(h.audit());
    tokio::select! {
        result = audit.as_mut() => panic!("the old row readback finished before the gate: {result:?}"),
        _ = entered.notified() => {}
    }

    controller.bind_member(run, &new_member).unwrap();
    assert!(
        controller
            .ready(
                run,
                &new_member,
                InterfaceInfo {
                    name: MANAGED_NIC_NAME.into(),
                    ifindex: 8,
                },
            )
            .unwrap()
    );
    // The rebind's own marks must not hide the audit outcome; the audit
    // marks dirty again when it retires the row.
    dirty.reset();
    resume.notify_one();
    let removed = tokio::time::timeout(Duration::from_secs(1), audit)
        .await
        .expect("the audit must finish once the readback is released")
        .expect("the complete absence readback succeeds");
    assert!(removed);

    assert!(!h.mock.contains(&old_route));
    assert!(
        h.applied().get(&RouteKey::of(&new_route)).is_none(),
        "the old readback or ACK cannot install the new binding's row"
    );
    assert!(h.applied().is_empty());
    assert!(
        member_claim_prefixes(&new_member).await.is_empty(),
        "the new registration has no claim before its own acknowledgement"
    );
    assert_eq!(
        member_claim_prefixes(&old_member).await,
        BTreeSet::from([prefix]),
        "the old registration really still owns the prefix it must withdraw"
    );
    let orphan_key = (run, old_member.registration_id());
    {
        let MemberRetry {
            member: retained,
            target,
            retry_at: deadline,
            attempts: attempt,
            ..
        } = h
            .reconciler
            .member_retries
            .get(&orphan_key)
            .expect("the old registration is retained for its real withdrawal");
        assert_eq!(retained.registration_id(), old_member.registration_id());
        assert!(target.is_empty(), "the orphan goal is empty");
        assert_eq!(*attempt, 0, "an orphan cleanup starts no failed attempt");
        assert!(
            *deadline <= tokio::time::Instant::now(),
            "the orphan withdrawal is due immediately"
        );
    }
    assert!(h.dirty_peek());

    // The next normal round first withdraws the old registration's prefix
    // and only then installs the new binding's own row.
    let (add_entered, add_resume) = mock.gate_add(Some(new_route.clone()));
    let mut round = Box::pin(h.round());
    tokio::select! {
        result = round.as_mut() => panic!("the new addition finished before the gate: {result:?}"),
        _ = add_entered.notified() => {}
    }
    assert!(
        member_claim_prefixes(&new_member).await.contains(&prefix),
        "the new registration's own acknowledgement precedes its addition"
    );
    assert!(
        member_claim_prefixes(&old_member).await.is_empty(),
        "the old registration really withdrew the prefix before the addition"
    );
    // Feedback runs after the OS facts, so the slot still carries its earlier
    // status while this row is only Adding. The round can report Ready only
    // after the real installation (asserted below).
    assert_eq!(
        controller
            .applied_routes()
            .get(&RouteKey::of(&new_route))
            .map(|row| row.effect),
        Some(RouteEffect::Adding)
    );
    add_resume.notify_one();
    round.await.unwrap();

    assert_eq!(h.effect(&new_route), Some(RouteEffect::Owned));
    assert_eq!(slot_handle.statuses().get(&p), Some(&RouteStatus::Ready));
    assert!(
        h.reconciler.member_retries.is_empty(),
        "the old cleanup completed"
    );
    assert!(
        member_claim_prefixes(&old_member).await.is_empty(),
        "the old registration's prefix was really withdrawn"
    );
    assert_eq!(
        member_claim_prefixes(&new_member).await,
        BTreeSet::from([prefix])
    );
    assert_eq!(h.mock.remove_count(), 0);
    assert!(!h.mock.contains(&old_route));
    assert!(h.mock.contains(&new_route));
}

// Scheduler tests. They drive the real `RouteReconciler::run` worker on the
// in-memory backend, so no platform backend, TUN device or system route
// state is touched. They never call the static `RouteController::start`.

/// Wait for an observable condition for a fixed number of scheduler turns.
///
/// A paused-clock test cannot make progress while a task spins on
/// `yield_now`, so wrapping an unbounded yield loop in a paused timeout
/// would hang instead of failing. The bound is finite and the condition is
/// asserted once it is exhausted.
async fn yield_until(mut condition: impl FnMut() -> bool) {
    for _ in 0..1000 {
        if condition() {
            return;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        condition(),
        "the observable condition did not appear within 1000 scheduler turns"
    );
}

/// Continuous dirty input never moves or starves the fixed audit grid.
///
/// Dirty marks at every second before the first grid point may run normal
/// rounds, but only the real 60s deadline performs the one full readback of
/// the actual row, and neither CRUD nor the reported status flaps.
#[tokio::test(start_paused = true)]
async fn continuous_dirty_input_never_moves_the_fixed_audit_grid() {
    let Harness {
        controller,
        mock,
        reconciler,
        ..
    } = Harness::new();
    let declaration = indexed("10.150.0.0/24", 7, None);
    let route = resolved(&declaration);
    let (_run, _registry, slot) = instance_with_slot(&controller, RouteSource::Additional);
    slot.set_routes(RouteSet::from([declaration.clone()]));

    let mut task = tokio::spawn(reconciler.run());
    yield_until(|| {
        slot.statuses().get(&declaration) == Some(&RouteStatus::Ready)
            && controller
                .applied_routes()
                .get(&RouteKey::of(&route))
                .is_some_and(|row| row.effect == RouteEffect::Owned)
    })
    .await;
    assert!(mock.contains(&route), "the real mock row stays present");
    let baseline_readbacks = mock.existing_count();
    assert_eq!(mock.add_count(), 1);
    assert_eq!(mock.remove_count(), 0);

    for second in 1..=59 {
        tokio::time::advance(Duration::from_secs(1)).await;
        controller.dirty.mark();
        yield_until(|| !controller.dirty.peek()).await;
        assert_eq!(
            mock.existing_count(),
            baseline_readbacks,
            "the audit read the table before 60s at second {second}"
        );
        assert_eq!(
            mock.add_count(),
            1,
            "no addition is repeated at second {second}"
        );
        assert_eq!(
            mock.remove_count(),
            0,
            "no deletion is issued at second {second}"
        );
        assert_eq!(slot.statuses().get(&declaration), Some(&RouteStatus::Ready));
    }

    // The grid point is due while an ordinary dirty mark is still set: the
    // fixed audit must still win and read the exact full actual row once.
    controller.dirty.mark();
    tokio::time::advance(Duration::from_secs(1)).await;
    yield_until(|| mock.existing_count() > baseline_readbacks).await;

    assert_eq!(
        mock.existing_count(),
        baseline_readbacks + 1,
        "exactly one full audit readback after 60s"
    );
    assert_eq!(
        mock.existing_batches.lock().last().cloned(),
        Some(BTreeSet::from([route.clone()])),
        "the audit requests exactly the actual full row"
    );
    assert_eq!(mock.add_count(), 1, "the audit never adds");
    assert_eq!(mock.remove_count(), 0, "the audit never deletes");
    assert_eq!(
        controller
            .applied_routes()
            .get(&RouteKey::of(&route))
            .map(|row| row.effect),
        Some(RouteEffect::Owned)
    );
    assert_eq!(
        slot.statuses().get(&declaration),
        Some(&RouteStatus::Ready),
        "a present full row keeps Ready without a status flap"
    );

    controller.request_shutdown();
    let joined = tokio::time::timeout(Duration::from_secs(5), &mut task)
        .await
        .expect("the real worker must finish its cleanup")
        .expect("the worker task must not panic");
    joined.expect("a genuine shutdown returns Ok");
    assert!(controller.runtime.read().instances.is_empty());
    assert!(controller.applied_routes().is_empty());
    assert!(!mock.contains(&route));
    assert_eq!(mock.remove_count(), 1);
}

/// An unrelated dirty mark cannot jump a failed addition's backoff. Only
/// the real 200ms deadline retries the operation, and that retry succeeds
/// without any manual wake.
#[tokio::test(start_paused = true)]
async fn unrelated_dirty_marks_cannot_bypass_the_failed_add_backoff() {
    let Harness {
        controller,
        mock,
        reconciler,
        ..
    } = Harness::new();
    let declaration = indexed("10.151.0.0/24", 7, None);
    let route = resolved(&declaration);
    mock.queue_add(
        &route,
        RouteError::Failed(anyhow::anyhow!("install failed")),
        false,
    );
    let (_run, _registry, slot) = instance_with_slot(&controller, RouteSource::Additional);
    slot.set_routes(RouteSet::from([declaration.clone()]));

    let mut task = tokio::spawn(reconciler.run());
    yield_until(|| {
        matches!(
            slot.statuses().get(&declaration),
            Some(RouteStatus::Pending { error: Some(_) })
        )
    })
    .await;
    let adds_for_route = || {
        mock.add_calls
            .lock()
            .iter()
            .filter(|called| *called == &route)
            .count()
    };
    assert_eq!(adds_for_route(), 1);
    assert_eq!(
        controller
            .applied_routes()
            .get(&RouteKey::of(&route))
            .map(|row| row.effect),
        None
    );

    for _ in 0..3 {
        controller.dirty.mark();
        yield_until(|| !controller.dirty.peek()).await;
        tokio::time::advance(Duration::from_millis(50)).await;
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            adds_for_route(),
            1,
            "dirty input before 200ms must not retry the addition"
        );
        assert!(
            matches!(
                slot.statuses().get(&declaration),
                Some(RouteStatus::Pending { error: Some(_) })
            ),
            "the failed addition stays pending before its deadline"
        );
    }

    // 200ms after the real failure, the worker's own deadline is due. No
    // dirty mark is issued here: the retry wakes by time alone.
    tokio::time::advance(Duration::from_millis(50)).await;
    yield_until(|| slot.statuses().get(&declaration) == Some(&RouteStatus::Ready)).await;
    assert_eq!(adds_for_route(), 2, "the real retry runs once due");
    assert_eq!(
        controller
            .applied_routes()
            .get(&RouteKey::of(&route))
            .map(|row| row.effect),
        Some(RouteEffect::Owned)
    );

    controller.request_shutdown();
    let joined = tokio::time::timeout(Duration::from_secs(5), &mut task)
        .await
        .expect("the real worker must finish its cleanup")
        .expect("the worker task must not panic");
    joined.expect("a genuine shutdown returns Ok");
    assert!(controller.runtime.read().instances.is_empty());
    assert!(controller.applied_routes().is_empty());
    assert!(!mock.contains(&route));
}

/// A shutdown during a real addition keeps waiting for that operation.
///
/// The in-flight record is not cancelled or pretend-never-happened: the
/// completed addition is recorded, and the same run's next round really
/// deletes it before the task returns.
#[tokio::test(start_paused = true)]
async fn a_shutdown_during_a_real_add_await_keeps_the_actual_operation() {
    let Harness {
        controller,
        mock,
        reconciler,
        ..
    } = Harness::new();
    let declaration = indexed("10.152.0.0/24", 7, None);
    let route = resolved(&declaration);
    let (_run, _registry, slot) = instance_with_slot(&controller, RouteSource::Additional);
    slot.set_routes(RouteSet::from([declaration.clone()]));
    let (entered, resume) = mock.gate_add(Some(route.clone()));

    let mut task = tokio::spawn(reconciler.run());
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .expect("the real addition must reach the held backend call");
    assert_eq!(mock.add_count(), 1);
    assert!(
        !task.is_finished(),
        "the worker is still inside the real OS call"
    );
    assert_eq!(
        controller
            .applied_routes()
            .get(&RouteKey::of(&route))
            .map(|row| row.effect),
        Some(RouteEffect::Adding),
        "the in-flight addition is recorded before its result"
    );

    slot.clear();
    controller.request_shutdown();
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
    assert!(controller.is_shutdown());
    assert_eq!(
        mock.add_count(),
        1,
        "shutdown must not start another addition"
    );
    assert_eq!(
        mock.remove_count(),
        0,
        "shutdown must not pretend the blocked addition never happened"
    );
    assert!(!task.is_finished());
    assert_eq!(
        controller
            .applied_routes()
            .get(&RouteKey::of(&route))
            .map(|row| row.effect),
        Some(RouteEffect::Adding),
        "the blocked call keeps its in-flight record"
    );

    resume.notify_one();
    let joined = tokio::time::timeout(Duration::from_secs(5), &mut task)
        .await
        .expect("the completed addition must lead to genuine cleanup")
        .expect("the worker task must not panic");
    joined.expect("a genuine shutdown returns Ok after real cleanup");

    let effect_operations: Vec<MockOperation> = mock
        .operations
        .lock()
        .iter()
        .filter(|operation| matches!(operation, MockOperation::Add(_) | MockOperation::Remove(_)))
        .cloned()
        .collect();
    assert_eq!(
        effect_operations,
        vec![
            MockOperation::Add(route.clone()),
            MockOperation::Remove(route.clone())
        ],
        "the completed addition is recorded and only then really deleted"
    );
    assert_eq!(mock.add_count(), 1);
    assert_eq!(mock.remove_count(), 1);
    assert!(!mock.contains(&route));
    assert!(controller.applied_routes().is_empty());
    assert!(controller.runtime.read().instances.is_empty());
}

/// A failed delete during shutdown waits for its real retry deadline.
///
/// The failed removal restores the actual Owned row; neither shutdown nor
/// the retry before 200ms may drop it. The due retry deletes it for real,
/// and only then does the worker return.
#[tokio::test(start_paused = true)]
async fn shutdown_delete_failure_waits_for_its_real_retry() {
    let Harness {
        controller,
        mock,
        reconciler,
        ..
    } = Harness::new();
    let declaration = indexed("10.153.0.0/24", 7, None);
    let route = resolved(&declaration);
    let (run, _registry, slot) = instance_with_slot(&controller, RouteSource::Additional);
    slot.set_routes(RouteSet::from([declaration.clone()]));

    let mut task = tokio::spawn(reconciler.run());
    yield_until(|| {
        slot.statuses().get(&declaration) == Some(&RouteStatus::Ready) && mock.contains(&route)
    })
    .await;
    let add_calls = mock.add_count();

    mock.queue_remove(
        &route,
        RouteError::Failed(anyhow::anyhow!("delete failed")),
        false,
    );
    controller.request_shutdown();
    yield_until(|| {
        mock.remove_count() == 1
            && controller
                .applied_routes()
                .get(&RouteKey::of(&route))
                .is_some_and(|row| row.effect == RouteEffect::Owned)
    })
    .await;

    tokio::time::advance(Duration::from_millis(100)).await;
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
    assert!(
        !task.is_finished(),
        "the worker must wait for the actual retry deadline"
    );
    assert!(
        mock.contains(&route),
        "a failed delete leaves the real row present"
    );
    assert_eq!(
        mock.remove_count(),
        1,
        "nothing before the deadline retries the deletion"
    );
    assert_eq!(
        controller
            .applied_routes()
            .get(&RouteKey::of(&route))
            .map(|row| row.effect),
        Some(RouteEffect::Owned),
        "the definite failure restores the actual Owned record"
    );
    assert!(controller.runtime.read().instances.contains_key(&run));

    // No dirty mark and no local retry map injection: the worker's own
    // 200ms deadline wakes it, and the real deletion then succeeds.
    tokio::time::advance(Duration::from_millis(100)).await;
    let joined = tokio::time::timeout(Duration::from_secs(5), &mut task)
        .await
        .expect("the due retry must finish the real cleanup")
        .expect("the worker task must not panic");
    joined.expect("a genuine shutdown returns Ok after cleanup");

    assert_eq!(mock.remove_count(), 2, "the deletion is really retried");
    assert_eq!(mock.add_count(), add_calls);
    assert!(!mock.contains(&route));
    assert!(controller.applied_routes().is_empty());
    assert!(controller.runtime.read().instances.is_empty());
}

/// An unknown deletion stays outstanding past the drain timeout.
///
/// Many unknown outcomes keep the real row and Removing record alive for
/// longer than 30s. `drain` reports its real timeout and residual detail
/// while the worker still runs; only a real absence proof retires the
/// responsibility and lets the worker return.
#[tokio::test(start_paused = true)]
async fn an_unknown_deletion_survives_the_drain_timeout_until_absence_is_proven() {
    let Harness {
        controller,
        mock,
        reconciler,
        ..
    } = Harness::new();
    let declaration = indexed("10.154.0.0/24", 7, None);
    let route = resolved(&declaration);
    let (run, _registry, slot) = instance_with_slot(&controller, RouteSource::Additional);
    slot.set_routes(RouteSet::from([declaration.clone()]));

    let mut task = tokio::spawn(reconciler.run());
    yield_until(|| {
        slot.statuses().get(&declaration) == Some(&RouteStatus::Ready) && mock.contains(&route)
    })
    .await;

    for _ in 0..32 {
        mock.queue_remove(
            &route,
            RouteError::Unknown(anyhow::anyhow!("unknown delete")),
            false,
        );
    }
    controller.request_shutdown();

    let error = controller
        .drain(run)
        .await
        .expect_err("an outstanding unknown deletion keeps drain incomplete");
    assert!(
        error
            .downcast_ref::<tokio::time::error::Elapsed>()
            .is_some(),
        "the real 30s drain timeout stays in the chain: {error:#}"
    );
    let detail = format!("{error:#}");
    assert!(
        detail.contains("timed out waiting for route cleanup of instance"),
        "the residual record is reported: {detail}"
    );
    assert!(
        detail.contains("effect Removing"),
        "the row is still Removing in the residual detail: {detail}"
    );
    assert!(controller.runtime.read().instances.contains_key(&run));
    assert_eq!(
        controller
            .applied_routes()
            .get(&RouteKey::of(&route))
            .map(|row| row.effect),
        Some(RouteEffect::Removing)
    );
    assert!(
        mock.contains(&route),
        "the real OS row is still present at the timeout"
    );
    assert!(
        !task.is_finished(),
        "the real worker is still cleaning up after the drain timeout"
    );
    let remove_calls_at_timeout = mock.remove_count();

    // Delete the Mock OS row directly to simulate an external change to
    // the OS table. The Controller ledger is not manually cleared here:
    // the next ordinary retry/audit must prove the complete absence, and
    // no completion is faked.
    mock.routes.lock().remove(&route);
    tokio::time::advance(Duration::from_secs(30)).await;
    let joined = tokio::time::timeout(Duration::from_secs(5), &mut task)
        .await
        .expect("the absence proof must finish the real cleanup")
        .expect("the worker task must not panic");
    joined.expect("genuine cleanup returns Ok");

    assert_eq!(
        mock.remove_count(),
        remove_calls_at_timeout,
        "the absence proof retires the row without another delete"
    );
    assert!(!mock.contains(&route));
    assert!(controller.applied_routes().is_empty());
    assert!(controller.runtime.read().instances.is_empty());
}

// Deadline-crossing scheduler tests. Each one drives the real
// `RouteReconciler::run` worker with the paused Tokio clock, so both the
// audit grid and every retry deadline belong to the production loop. No
// local retry map is injected and no operation is completed by hand.

/// Real backend calls for one exact route.
fn backend_calls(calls: &Mutex<Vec<RouteSpec<u32>>>, route: &RouteSpec<u32>) -> usize {
    calls
        .lock()
        .iter()
        .filter(|called| *called == route)
        .count()
}

/// Give the real worker a bounded number of scheduler turns without
/// moving the paused clock.
async fn yield_turns(turns: usize) {
    for _ in 0..turns {
        tokio::task::yield_now().await;
    }
}

/// Poll a one-shot backend gate without moving the paused clock.
async fn wait_for_gate(entered: Arc<Notify>) {
    let notified = entered.notified();
    tokio::pin!(notified);
    for _ in 0..1000 {
        if futures::poll!(&mut notified).is_ready() {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("the backend gate was not reached within 1000 scheduler turns");
}

/// A retry that becomes due while an unrelated addition is held must be
/// retried by the next ordinary pass, not stranded until the next audit.
///
/// B really fails at t=0. At t=100ms the later-sorted A is declared and its
/// addition held; this pass checks B first and skips it as still backed
/// off. The clock then passes B's 200ms deadline while A is still held, so
/// resuming A must leave B's now-due retry actionable without any new
/// input mark.
#[tokio::test(start_paused = true)]
async fn a_retry_that_becomes_due_during_a_held_addition_runs_in_the_next_pass() {
    let Harness {
        controller,
        mock,
        reconciler,
        ..
    } = Harness::new();
    let b_declaration = indexed("10.200.0.0/24", 9, None);
    let b_route = resolved(&b_declaration);
    mock.queue_add(
        &b_route,
        RouteError::Failed(anyhow::anyhow!("install failed")),
        false,
    );
    let (_run_b, _registry_b, slot_b) = instance_with_slot(&controller, RouteSource::Additional);
    slot_b.set_routes(RouteSet::from([b_declaration.clone()]));

    let mut task = tokio::spawn(reconciler.run());
    yield_until(|| {
        matches!(
            slot_b.statuses().get(&b_declaration),
            Some(RouteStatus::Pending { error: Some(_) })
        )
    })
    .await;
    assert_eq!(
        backend_calls(&mock.add_calls, &b_route),
        1,
        "the first real attempt fails"
    );
    assert_eq!(
        controller
            .applied_routes()
            .get(&RouteKey::of(&b_route))
            .map(|row| row.effect),
        None,
        "a definite failure leaves no actual effect"
    );

    // t=100ms: A sorts after B, so this pass considers B first and skips it
    // inside its backoff before reaching A's held addition.
    tokio::time::advance(Duration::from_millis(100)).await;
    let a_declaration = indexed("10.201.0.0/24", 9, None);
    let a_route = resolved(&a_declaration);
    let (_run_a, _registry_a, slot_a) = instance_with_slot(&controller, RouteSource::Additional);
    let (a_entered, a_resume) = mock.gate_add(Some(a_route.clone()));
    slot_a.set_routes(RouteSet::from([a_declaration.clone()]));
    wait_for_gate(a_entered).await;
    assert_eq!(
        backend_calls(&mock.add_calls, &b_route),
        1,
        "B was checked before A and is still inside its backoff"
    );

    // The deadline passes while A's addition is still held. No extra dirty
    // mark is issued: the due retry must survive A's completion and run in
    // the immediately following pass.
    tokio::time::advance(Duration::from_millis(100)).await;
    a_resume.notify_one();
    yield_until(|| {
        slot_a.statuses().get(&a_declaration) == Some(&RouteStatus::Ready)
            && slot_b.statuses().get(&b_declaration) == Some(&RouteStatus::Ready)
    })
    .await;

    assert_eq!(
        backend_calls(&mock.add_calls, &b_route),
        2,
        "the due retry is really retried right after the held addition"
    );
    assert_eq!(backend_calls(&mock.add_calls, &a_route), 1);
    assert_eq!(
        controller
            .applied_routes()
            .get(&RouteKey::of(&b_route))
            .map(|row| row.effect),
        Some(RouteEffect::Owned),
        "the retried addition is the real conflicting effect"
    );
    assert!(mock.contains(&b_route));
    assert_eq!(
        slot_b.statuses().get(&b_declaration),
        Some(&RouteStatus::Ready),
        "the retried row is really acknowledged as ready"
    );

    controller.request_shutdown();
    let joined = tokio::time::timeout(Duration::from_secs(5), &mut task)
        .await
        .expect("the real worker must finish its cleanup")
        .expect("the worker task must not panic");
    joined.expect("a genuine shutdown returns Ok");
    assert!(controller.runtime.read().instances.is_empty());
    assert!(controller.applied_routes().is_empty());
    assert!(mock.routes.lock().is_empty());
}

/// A due OS retry that cannot act in this round must wait for the member
/// acknowledgement deadline and then run, rather than being stranded by
/// the batch-start horizon.
///
/// A really acknowledges its prefix at t=0 and then its addition fails, so
/// its own retry is due at 200ms. The A NIC lock is held and the clock is
/// advanced to that deadline; the batch that starts there spends two
/// bounded admission attempts on A and then holds the real ordinary B
/// addition. B is declared during that wait, so the fresh replan sees it.
/// Releasing the NIC and B lets the final planner admit A, but this round
/// has no A acknowledgement, so nothing is added early. The old due retry
/// then runs only once the member's own backoff is due.
#[cfg(feature = "tun")]
#[tokio::test(start_paused = true)]
async fn a_due_os_retry_waits_for_the_member_deadline_and_then_runs() {
    let Harness {
        controller,
        mock,
        reconciler,
        ..
    } = Harness::new();
    let run_a = Uuid::new_v4();
    let mut fixture = ManagedNicFixture::new(run_a);
    let member = fixture.create_member();
    attach_member(&member).await;

    let p: RouteSpec<RouteDevice> = RouteSpec::for_tun("10.116.0.0/24".parse().unwrap());
    let prefix: IpCidr = p.destination;
    let p_route = normalize_route(p.clone().resolve(Some(7)).unwrap()).unwrap();
    let registry_a = controller.open_instance(run_a).unwrap();
    controller.bind_member(run_a, &member).unwrap();
    assert!(
        controller
            .ready(
                run_a,
                &member,
                InterfaceInfo {
                    name: MANAGED_NIC_NAME.into(),
                    ifindex: 7,
                },
            )
            .unwrap(),
        "the fixture interface is the bound member's device"
    );
    let slot_a = registry_a
        .handle()
        .open_slot(RouteSource::Additional)
        .unwrap();
    slot_a.set_routes(RouteSet::from([p.clone()]));
    mock.queue_add(
        &p_route,
        RouteError::Failed(anyhow::anyhow!("install failed")),
        false,
    );

    let mut task = tokio::spawn(reconciler.run());
    yield_until(|| {
        matches!(
            slot_a.statuses().get(&p),
            Some(RouteStatus::Pending { error: Some(_) })
        )
    })
    .await;
    assert_eq!(
        backend_calls(&mock.add_calls, &p_route),
        1,
        "the real addition failed after a real prefix acknowledgement"
    );

    // Hold the real NIC admission, then let the 200ms route retry become
    // due so the batch that starts at that deadline already owns it.
    let shared_nic = member.shared_nic();
    let guard = shared_nic.lock().await;
    let b_declaration = indexed("10.117.0.0/24", 9, None);
    let b_route = resolved(&b_declaration);
    let (b_entered, b_resume) = mock.gate_add(Some(b_route.clone()));
    tokio::time::advance(Duration::from_millis(200)).await;

    // Declare the independent ordinary B while A is waiting in admission.
    let (_run_b, _registry_b, slot_b) = instance_with_slot(&controller, RouteSource::Additional);
    slot_b.set_routes(RouteSet::from([b_declaration.clone()]));

    // The ordinary B gate follows the member stage: two bounded admission
    // attempts and the second failure's 400ms member backoff.
    let notified = b_entered.notified();
    tokio::pin!(notified);
    let mut advances = 0u32;
    loop {
        if futures::poll!(&mut notified).is_ready() {
            break;
        }
        assert!(
            advances < 4,
            "the ordinary B gate must be reached within four bounded admission waits"
        );
        advances += 1;
        tokio::time::advance(Duration::from_secs(5)).await;
        yield_turns(32).await;
    }
    assert_eq!(
        advances, 2,
        "the B gate follows exactly two bounded admission attempts"
    );
    // The two bounded waits above are the real timeout evidence. Feedback
    // runs after the OS facts, so A's slot still carries the previous round's
    // pending failure while this admission attempt is in flight; a timed-out
    // attempt never confirms A as ready.
    assert_ne!(
        slot_a.statuses().get(&p),
        Some(&RouteStatus::Ready),
        "A really passed its bounded NIC lock timeout without being confirmed"
    );
    assert_eq!(
        backend_calls(&mock.add_calls, &p_route),
        1,
        "the due OS retry had no acknowledged member and must not add early"
    );

    // Release the NIC and let B finish without moving the clock. The final
    // planner now admits A, but this round has no A acknowledgement.
    drop(guard);
    b_resume.notify_one();
    yield_until(|| slot_b.statuses().get(&b_declaration) == Some(&RouteStatus::Ready)).await;
    yield_turns(32).await;
    assert_eq!(
        backend_calls(&mock.add_calls, &p_route),
        1,
        "the final planner admitted A but this round had no member acknowledgement"
    );
    assert!(
        matches!(slot_a.statuses().get(&p), Some(RouteStatus::Pending { .. })),
        "A stays pending while its member retry is in the future"
    );

    // Before the member retry deadline nothing adds A.
    tokio::time::advance(Duration::from_millis(200)).await;
    yield_turns(32).await;
    assert_eq!(
        backend_calls(&mock.add_calls, &p_route),
        1,
        "no early addition before the member retry deadline"
    );
    assert!(
        matches!(slot_a.statuses().get(&p), Some(RouteStatus::Pending { .. })),
        "A stays pending before its member retry deadline"
    );

    // At the member deadline the worker wakes by itself, really
    // acknowledges the prefix and performs the long-overdue OS add.
    tokio::time::advance(Duration::from_millis(200)).await;
    yield_until(|| slot_a.statuses().get(&p) == Some(&RouteStatus::Ready)).await;
    assert_eq!(
        backend_calls(&mock.add_calls, &p_route),
        2,
        "the due old OS retry runs once the member acknowledgement succeeds"
    );
    assert_eq!(
        controller
            .applied_routes()
            .get(&RouteKey::of(&p_route))
            .map(|row| row.effect),
        Some(RouteEffect::Owned)
    );
    assert_eq!(
        member_claim_prefixes(&member).await,
        BTreeSet::from([prefix])
    );

    controller.request_shutdown();
    let joined = tokio::time::timeout(Duration::from_secs(5), &mut task)
        .await
        .expect("the real worker must finish its cleanup")
        .expect("the worker task must not panic");
    joined.expect("a genuine shutdown returns Ok");
    assert!(controller.runtime.read().instances.is_empty());
    assert!(controller.applied_routes().is_empty());
    assert!(mock.routes.lock().is_empty());
}

/// The 64-operation budget must not strand a later-sorted due deletion
/// retry. The production dirty mark from the exhausted budget, not any new
/// input, drives the passes that really finish every deletion.
#[tokio::test(start_paused = true)]
async fn the_operation_budget_cannot_strand_a_due_deletion_retry() {
    let Harness {
        controller,
        mock,
        reconciler,
        ..
    } = Harness::new();
    let ordinary: Vec<RouteSpec<RouteDevice>> = (1..=66)
        .map(|index| indexed(&format!("10.0.0.{index}/32"), 9, None))
        .collect();
    let late = indexed("10.255.255.255/32", 9, None);
    let late_route = resolved(&late);
    let first_route = resolved(&ordinary[0]);
    let all: RouteSet = ordinary
        .iter()
        .cloned()
        .chain(std::iter::once(late.clone()))
        .collect();
    let remaining: RouteSet = ordinary.iter().cloned().collect();

    let (_run, _registry, slot) = instance_with_slot(&controller, RouteSource::Additional);
    slot.set_routes(all);

    let mut task = tokio::spawn(reconciler.run());
    // The real budget splits this into several ordinary passes.
    yield_until(|| {
        let statuses = slot.statuses();
        ordinary
            .iter()
            .all(|declaration| statuses.get(declaration) == Some(&RouteStatus::Ready))
            && statuses.get(&late) == Some(&RouteStatus::Ready)
    })
    .await;
    assert_eq!(mock.add_count(), 67, "every row is really installed once");
    assert_eq!(mock.remove_count(), 0);
    assert_eq!(controller.applied_routes().len(), 67);

    // Withdraw only the last-sorted row and let its first real delete fail,
    // so the worker itself records the 200ms backoff.
    mock.queue_remove(
        &late_route,
        RouteError::Failed(anyhow::anyhow!("delete failed")),
        false,
    );
    slot.set_routes(remaining);
    yield_until(|| {
        backend_calls(&mock.remove_calls, &late_route) == 1
            && controller
                .applied_routes()
                .get(&RouteKey::of(&late_route))
                .map(|row| row.effect)
                == Some(RouteEffect::Owned)
    })
    .await;
    assert!(
        mock.contains(&late_route),
        "a failed delete leaves the real row present"
    );
    let failure_at = tokio::time::Instant::now();

    // Clear the other 66 and advance to the late retry deadline in one
    // synchronous step: no scheduler turn separates them, so the next batch
    // starts exactly at the already-due retry with 66 deletions pending.
    let (first_entered, first_resume) = mock.gate_remove(Some(first_route.clone()));
    slot.clear();
    tokio::time::advance(Duration::from_millis(200)).await;
    wait_for_gate(first_entered).await;

    assert_eq!(
        tokio::time::Instant::now(),
        failure_at + Duration::from_millis(200),
        "the batch begins exactly at the recorded retry deadline"
    );
    assert_eq!(
        backend_calls(&mock.remove_calls, &late_route),
        1,
        "the late retry is still only once attempted when the budget batch starts"
    );
    first_resume.notify_one();

    // The first batch spends its full budget; the production dirty mark
    // must finish the rest without any new input or ledger edit.
    yield_until(|| mock.routes.lock().is_empty() && controller.applied_routes().is_empty()).await;

    assert_eq!(
        backend_calls(&mock.remove_calls, &late_route),
        2,
        "the due late retry really succeeds on its second attempt"
    );
    assert_eq!(
        mock.remove_count(),
        68,
        "66 rows plus the late row's failed and successful delete"
    );
    assert_eq!(mock.add_count(), 67, "no row is added again during cleanup");

    let remove_ops: Vec<RouteSpec<u32>> = mock
        .operations
        .lock()
        .iter()
        .filter_map(|operation| match operation {
            MockOperation::Remove(route) => Some(route.clone()),
            _ => None,
        })
        .collect();
    let late_positions: Vec<usize> = remove_ops
        .iter()
        .enumerate()
        .filter(|(_, route)| **route == late_route)
        .map(|(index, _)| index)
        .collect();
    assert_eq!(late_positions.len(), 2);
    let other_before = remove_ops[..late_positions[1]]
        .iter()
        .filter(|route| **route != late_route)
        .count();
    assert!(
        other_before >= 64,
        "at least 64 other real deletions precede the retried late row, got {other_before}"
    );

    controller.request_shutdown();
    let joined = tokio::time::timeout(Duration::from_secs(5), &mut task)
        .await
        .expect("the real worker must finish its cleanup")
        .expect("the worker task must not panic");
    joined.expect("a genuine shutdown returns Ok");
    assert!(controller.runtime.read().instances.is_empty());
    assert!(controller.applied_routes().is_empty());
    assert!(mock.routes.lock().is_empty());
}

/// The audit's own failure backoff crosses the fixed grid: the nine real
/// failures retry at their own doubling deadlines, the original 120s grid
/// point does not read through a pending backoff, and the 141s retry
/// succeeds even though the next grid point is already 180s.
#[tokio::test(start_paused = true)]
async fn audit_failure_backoff_crosses_the_fixed_grid() {
    let Harness {
        controller,
        mock,
        reconciler,
        ..
    } = Harness::new();
    let declaration = indexed("10.160.0.0/24", 7, None);
    let route = resolved(&declaration);
    let (_run, _registry, slot) = instance_with_slot(&controller, RouteSource::Additional);
    slot.set_routes(RouteSet::from([declaration.clone()]));

    let mut task = tokio::spawn(reconciler.run());
    yield_until(|| {
        slot.statuses().get(&declaration) == Some(&RouteStatus::Ready) && mock.contains(&route)
    })
    .await;
    let baseline = mock.existing_count();
    assert_eq!(mock.add_count(), 1);
    assert_eq!(mock.remove_count(), 0);

    for _ in 0..9 {
        mock.queue_existing_error(RouteError::Failed(anyhow::anyhow!("audit read failed")));
    }

    // Each real failure doubles from 200ms: 60, 60.2, 60.6, 61.4, 63,
    // 66.2, 72.6, 85.4, 111. Every step requires the previous audit to have
    // really completed before the next deadline is reached.
    let steps = [
        Duration::from_secs(60),
        Duration::from_millis(200),
        Duration::from_millis(400),
        Duration::from_millis(800),
        Duration::from_millis(1600),
        Duration::from_millis(3200),
        Duration::from_millis(6400),
        Duration::from_millis(12800),
        Duration::from_millis(25600),
    ];
    for (failed, step) in steps.iter().enumerate() {
        tokio::time::advance(*step).await;
        yield_until(|| mock.existing_count() >= baseline + failed + 1).await;
        assert_eq!(
            mock.existing_count(),
            baseline + failed + 1,
            "exactly one audit readback at failure {}",
            failed + 1
        );
        assert_eq!(
            slot.statuses().get(&declaration),
            Some(&RouteStatus::Ready),
            "a failed audit keeps the reported Ready status"
        );
        assert_eq!(
            controller
                .applied_routes()
                .get(&RouteKey::of(&route))
                .map(|row| row.effect),
            Some(RouteEffect::Owned),
            "a failed audit keeps the actual ledger"
        );
        assert_eq!(mock.add_count(), 1);
        assert_eq!(mock.remove_count(), 0);
    }
    assert_eq!(mock.existing_count(), baseline + 9);

    // The original fixed 120s grid point falls inside the 141s backoff: it
    // must not read through it.
    tokio::time::advance(Duration::from_secs(9)).await;
    yield_turns(32).await;
    assert_eq!(
        mock.existing_count(),
        baseline + 9,
        "the fixed 120s grid must not read during the pending backoff"
    );
    assert_eq!(slot.statuses().get(&declaration), Some(&RouteStatus::Ready));
    assert_eq!(
        controller
            .applied_routes()
            .get(&RouteKey::of(&route))
            .map(|row| row.effect),
        Some(RouteEffect::Owned)
    );

    // The audit's own 141s retry really succeeds, although the next fixed
    // grid point is already 180s: the grid is not restarted from the retry.
    tokio::time::advance(Duration::from_secs(21)).await;
    yield_until(|| mock.existing_count() >= baseline + 10).await;
    assert_eq!(mock.existing_count(), baseline + 10);
    assert_eq!(
        mock.existing_batches.lock().last().cloned(),
        Some(BTreeSet::from([route.clone()])),
        "the successful retry reads exactly the actual full row"
    );

    // The original 180s grid still performs its own audit.
    tokio::time::advance(Duration::from_secs(39)).await;
    yield_until(|| mock.existing_count() >= baseline + 11).await;
    assert_eq!(mock.existing_count(), baseline + 11);

    controller.request_shutdown();
    let joined = tokio::time::timeout(Duration::from_secs(5), &mut task)
        .await
        .expect("the real worker must finish its cleanup")
        .expect("the worker task must not panic");
    joined.expect("a genuine shutdown returns Ok");
    assert_eq!(mock.remove_count(), 1);
    assert!(!mock.contains(&route));
    assert!(controller.runtime.read().instances.is_empty());
    assert!(controller.applied_routes().is_empty());
}
