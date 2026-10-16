//! Route controller facade: shared runtime state, instance inputs and the
//! platform reconcilers.
//!
//! Desktop planning and OS effects live in `desktop`; mobile local
//! synchronization and facts live in `mobile`; the bounded NIC synchronization
//! shared by both lives in `member`. Only this module exports the controller.

#[cfg(all(mobile, feature = "tun"))]
use std::collections::BTreeSet;
use std::{
    collections::BTreeMap,
    sync::{Arc, Weak},
    time::Duration,
};

use easytier_core::{
    config::runtime::CoreRuntimeConfigStore,
    host::route::{Registry, RouteSet, RouteSlotInner, RouteSource, RouteSpec},
};
use parking_lot::RwLock;
use tokio::sync::Notify;
use uuid::Uuid;

#[cfg(all(mobile, feature = "tun"))]
use crate::common::global_ctx::GlobalCtx;
use crate::common::net_ns::NetNS;
#[cfg(not(mobile))]
use crate::instance::route::AppliedRoutes;
#[cfg(all(feature = "tun", not(mobile)))]
use crate::instance::route::InterfaceInfo;
#[cfg(not(mobile))]
use crate::instance::route::PlatformRouteBackend;
#[cfg(feature = "tun")]
use crate::instance::shared_virtual_nic::SharedVirtualNicMember;
use crate::utils::dirty::DirtyFlag;

#[cfg(not(mobile))]
mod desktop;
#[cfg(feature = "tun")]
mod member;
#[cfg(all(mobile, feature = "tun"))]
mod mobile;
#[cfg(test)]
mod tests;

#[cfg(not(mobile))]
use self::desktop::RouteReconciler;
#[cfg(all(mobile, feature = "tun"))]
use self::mobile::{MobileInstalledRoutes, RouteReconciler};

/// One instance's input directory and current device binding.
///
/// The registry is only observed weakly: the native instance runtime owns the
/// single strong root reference.
struct InstanceRoutes {
    registry: Weak<Registry>,
    config: Option<CoreRuntimeConfigStore>,

    #[cfg(feature = "tun")]
    member: Option<SharedVirtualNicMember>,
    #[cfg(all(feature = "tun", not(mobile)))]
    interface: Option<InterfaceInfo>,
    /// The configured instance identity captured when the mobile authority
    /// was bound. It is not an address input and remains usable for local
    /// cleanup confirmation after the GlobalCtx is gone.
    #[cfg(all(mobile, feature = "tun"))]
    instance_id: Option<Uuid>,
    /// Mobile authority observation: the native instance runtime owns the
    /// context; the controller only reads its current values.
    #[cfg(all(mobile, feature = "tun"))]
    global: Option<Weak<GlobalCtx>>,
    /// The exact public-address intent shared with the native route context.
    /// Nothing here is a second address value.
    #[cfg(all(mobile, feature = "tun"))]
    public_address: Option<Arc<parking_lot::Mutex<Option<cidr::Ipv6Inet>>>>,
}

impl InstanceRoutes {
    /// This instance's current declarations under the current policy.
    ///
    /// Returns `None` once the registry root is gone: the whole instance has
    /// withdrawn its inputs, including the manual policy its config still
    /// holds. Otherwise the manual list of the current configuration decides
    /// whether AutoProxy declarations count; `Some` suppresses every AutoProxy
    /// declaration, `Some(empty)` contributes no manual routes and `None`
    /// keeps them. Additional declarations are always included. The live slot
    /// references come back too, including the suppressed ones, for feedback;
    /// every temporary registry and slot handle is released before returning.
    fn declarations(&self) -> Option<(RouteSet, Vec<Weak<RouteSlotInner>>)> {
        let registry = self.registry.upgrade()?;
        let manual = self
            .config
            .as_ref()
            .and_then(|config| config.snapshot().services.manual_routes.clone());

        let mut declarations = RouteSet::new();
        let mut slots = Vec::new();
        for weak in registry.slots() {
            if let Some(slot) = weak.upgrade() {
                if slot.source() != RouteSource::AutoProxy || manual.is_none() {
                    declarations.extend(slot.routes());
                }
            }
            slots.push(weak);
        }
        if let Some(manual) = &manual {
            declarations.extend(
                manual
                    .iter()
                    .map(|prefix| RouteSpec::for_tun((*prefix).into())),
            );
        }
        drop(registry);
        Some((declarations, slots))
    }
}

/// Private internal routing table state, owned exclusively by RouteController
/// and protected by an RwLock. Lock is held only for microseconds; I/O happens outside the lock.
#[derive(Default)]
struct RouteControllerRuntime {
    instances: BTreeMap<Uuid, InstanceRoutes>,
    #[cfg(not(mobile))]
    applied: AppliedRoutes,
    /// Local mobile attachment evidence only: which accepted prefixes were
    /// really installed for one current run/registration. It owns no FD,
    /// system VPN or NativeRuntime.
    #[cfg(all(mobile, feature = "tun"))]
    installed_routes: MobileInstalledRoutes,
    shutdown: bool,
    /// The host's participation range, keyed by configured instance id.
    /// `None` means every live instance of this domain; an empty set is an
    /// explicit empty range. This is an input, never a post-export filter.
    #[cfg(all(mobile, feature = "tun"))]
    mobile_scope: Option<BTreeSet<Uuid>>,
}

/// Lightweight, cloneable handle to the per-namespace RouteController.
/// Cloning this handle is cheap (Arc clone) and safe to hold across components.
#[derive(Clone)]
pub(crate) struct RouteController {
    runtime: Arc<RwLock<RouteControllerRuntime>>,
    dirty: Arc<DirtyFlag>,
    changed: Arc<Notify>,
}

impl RouteController {
    pub fn new(dirty: Arc<DirtyFlag>) -> Self {
        Self {
            runtime: Arc::new(RwLock::new(Default::default())),
            dirty,
            changed: Arc::new(Notify::new()),
        }
    }

    /// Notification that instance records or actual effects visibly changed.
    ///
    /// It carries no payload: a `drain` waiter rechecks cleanup conditions and
    /// the mobile host re-exports the current configuration. The handle is the
    /// controller's one `Arc<Notify>`; callers that need to keep it clone it.
    pub fn changed(&self) -> &Arc<Notify> {
        &self.changed
    }

    /// Whether both handles observe the same per-namespace controller.
    #[cfg(mobile)]
    pub(crate) fn same_controller(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.runtime, &other.runtime)
    }

    /// Static constructor: starts the platform backend worker in `net_ns` and
    /// returns a lightweight handle together with the real worker task.
    ///
    /// The caller keeps the `JoinHandle`: the worker owns the backend and the
    /// actual ledger, so detaching it would lose both the completion signal and
    /// the error of a task that really stopped.
    #[cfg(not(mobile))]
    pub fn start(
        net_ns: NetNS,
        handle: &tokio::runtime::Handle,
    ) -> anyhow::Result<(Self, tokio::task::JoinHandle<anyhow::Result<()>>)> {
        let backend = PlatformRouteBackend::new(&net_ns, handle)?;
        let dirty = Arc::new(DirtyFlag::new(false));
        let controller = Self::new(dirty);
        let reconciler = RouteReconciler::new(controller.clone(), backend);
        let task = handle.spawn(reconciler.run());
        Ok((controller, task))
    }

    /// Mobile constructor: starts the real member reconciler.
    ///
    /// Mobile has no system route backend and the external VPN owner performs
    /// the only actual installation, so the namespace handle is not retained
    /// here. The returned task is the real worker: it drives member prefix
    /// synchronization, per-route feedback and cleanup, and it returns only
    /// when the domain is genuinely drained.
    #[cfg(all(mobile, feature = "tun"))]
    pub fn start(
        _net_ns: NetNS,
        handle: &tokio::runtime::Handle,
    ) -> anyhow::Result<(Self, tokio::task::JoinHandle<anyhow::Result<()>>)> {
        let dirty = Arc::new(DirtyFlag::new(false));
        let controller = Self::new(dirty);
        let reconciler = RouteReconciler::new(controller.clone());
        let task = handle.spawn(reconciler.run());
        Ok((controller, task))
    }
    /// Allocate the instance's route input directory.
    ///
    /// The caller receives the only strong root of the new [`Registry`]; the
    /// controller keeps a weak observation of it. A repeated run does not
    /// replace a record that is still present.
    pub fn open_instance(&self, run: Uuid) -> anyhow::Result<Arc<Registry>> {
        let registry = {
            let mut rt = self.runtime.write();
            anyhow::ensure!(!rt.shutdown, "route controller is shut down");
            anyhow::ensure!(
                !rt.instances.contains_key(&run),
                "instance {run} already has route inputs"
            );
            let registry = Arc::new(Registry::new(self.dirty.clone()));
            rt.instances.insert(
                run,
                InstanceRoutes {
                    registry: Arc::downgrade(&registry),
                    config: None,
                    #[cfg(feature = "tun")]
                    member: None,
                    #[cfg(all(feature = "tun", not(mobile)))]
                    interface: None,
                    #[cfg(all(mobile, feature = "tun"))]
                    instance_id: None,
                    #[cfg(all(mobile, feature = "tun"))]
                    global: None,
                    #[cfg(all(mobile, feature = "tun"))]
                    public_address: None,
                },
            );
            registry
        };
        self.dirty.mark();
        Ok(registry)
    }
    /// Bind the instance's runtime configuration store to this controller.
    ///
    /// The store keeps the same shared dirty flag from then on; a second
    /// binding, whether on this record or on the store itself, fails without
    /// replacing the first one.
    pub fn bind_config(&self, run: Uuid, config: CoreRuntimeConfigStore) -> anyhow::Result<()> {
        {
            let mut rt = self.runtime.write();
            anyhow::ensure!(!rt.shutdown, "route controller is shut down");
            let instances = rt
                .instances
                .get_mut(&run)
                .ok_or_else(|| anyhow::anyhow!("instance {run} has no route inputs"))?;
            anyhow::ensure!(
                instances.registry.upgrade().is_some(),
                "instance {run} route registry is closed"
            );
            anyhow::ensure!(
                instances.config.is_none(),
                "route configuration is already bound for instance {run}"
            );
            config.bind_route_dirty(self.dirty.clone()).map_err(|()| {
                anyhow::anyhow!("route configuration of instance {run} is already bound")
            })?;
            instances.config = Some(config);
        }
        self.dirty.mark();
        Ok(())
    }
    /// Bind the mobile authority inputs once.
    ///
    /// The controller observes the instance's `GlobalCtx` weakly and shares the
    /// exact public-address mutex owned by the native route context; it never
    /// copies the current addresses. A closed run, a mismatched context or a
    /// second binding is rejected without replacing the first binding.
    #[cfg(all(mobile, feature = "tun"))]
    pub fn bind_mobile_inputs(
        &self,
        run: Uuid,
        global: Weak<GlobalCtx>,
        public_address: Arc<parking_lot::Mutex<Option<cidr::Ipv6Inet>>>,
    ) -> anyhow::Result<()> {
        let current = global
            .upgrade()
            .ok_or_else(|| anyhow::anyhow!("global context is closed"))?;
        anyhow::ensure!(
            current.key() == run,
            "global context run {} does not match instance {run}",
            current.key()
        );
        let instance_id = current.get_id();
        drop(current);
        {
            let mut rt = self.runtime.write();
            anyhow::ensure!(!rt.shutdown, "route controller is shut down");
            let instances = rt
                .instances
                .get_mut(&run)
                .ok_or_else(|| anyhow::anyhow!("instance {run} has no route inputs"))?;
            anyhow::ensure!(
                instances.registry.upgrade().is_some(),
                "instance {run} route registry is closed"
            );
            anyhow::ensure!(
                instances.global.is_none(),
                "mobile route inputs are already bound for instance {run}"
            );
            instances.instance_id = Some(instance_id);
            instances.global = Some(global);
            instances.public_address = Some(public_address);
        }
        self.dirty.mark();
        Ok(())
    }

    pub fn ensure_instance_open(&self, run: Uuid) -> anyhow::Result<()> {
        let rt = self.runtime.read();
        anyhow::ensure!(!rt.shutdown, "route controller is shut down");
        let instances = rt
            .instances
            .get(&run)
            .ok_or_else(|| anyhow::anyhow!("instance {run} has no route inputs"))?;
        anyhow::ensure!(
            instances.registry.upgrade().is_some(),
            "instance route registry is closed"
        );
        Ok(())
    }
    /// Bind the shared NIC member that currently carries this instance's TUN.
    ///
    /// Re-binding the same registration keeps the recorded interface and does
    /// not mark. A new registration replaces the member; on desktop the old
    /// interface no longer describes the new device, while on mobile only this
    /// run's old attachment record is dropped. Applied routes are not removed
    /// here: an input change still has to be reconciled against the real
    /// ledger.
    #[cfg(feature = "tun")]
    pub fn bind_member(&self, run: Uuid, member: &SharedVirtualNicMember) -> anyhow::Result<()> {
        member.ensure_open()?;
        anyhow::ensure!(
            member.member_id() == run,
            "shared NIC member does not belong to instance {run}"
        );

        let changed = {
            let mut rt = self.runtime.write();
            anyhow::ensure!(!rt.shutdown, "route controller is shut down");
            let replaced = {
                let instances = rt
                    .instances
                    .get_mut(&run)
                    .ok_or_else(|| anyhow::anyhow!("instance {run} has no route inputs"))?;
                anyhow::ensure!(
                    instances.registry.upgrade().is_some(),
                    "instance {run} route registry is closed"
                );

                let same_registration = instances
                    .member
                    .as_ref()
                    .is_some_and(|current| current.registration_id() == member.registration_id());
                if same_registration {
                    false
                } else {
                    instances.member = Some(member.clone());
                    #[cfg(not(mobile))]
                    {
                        instances.interface = None;
                    }
                    true
                }
            };

            #[cfg(mobile)]
            if replaced {
                // A new registration has no evidence from the old binding.
                rt.installed_routes
                    .retain(|(installed_run, _), _| *installed_run != run);
            }
            replaced
        };

        if changed {
            self.dirty.mark();
        }
        Ok(())
    }
    /// Withdraw the member binding of one registration.
    ///
    /// Cleanup callbacks may still arrive after shutdown or after the registry
    /// has been released, so this never reopens or recreates anything. Only a
    /// matching registration changes state: the desktop interface of this
    /// instance, or on mobile this run's attachment record. The member handle
    /// itself stays for cleanup.
    #[cfg(feature = "tun")]
    pub fn unready(&self, run: Uuid, registration: Uuid) {
        let changed = {
            let mut rt = self.runtime.write();
            #[cfg(not(mobile))]
            {
                let Some(instances) = rt.instances.get_mut(&run) else {
                    return;
                };
                let matches_registration = instances
                    .member
                    .as_ref()
                    .is_some_and(|member| member.registration_id() == registration);
                if !matches_registration {
                    return;
                }
                instances.interface.take().is_some()
            }
            #[cfg(mobile)]
            {
                // Only this exact run/registration loses its local attachment
                // evidence. A late report from an older registration must not
                // invalidate a newer binding.
                rt.installed_routes.remove(&(run, registration)).is_some()
            }
        };

        if changed {
            self.dirty.mark();
            self.changed.notify_waiters();
        }
    }
    pub fn request_shutdown(&self) {
        {
            let mut rt = self.runtime.write();
            rt.shutdown = true;
        }
        self.dirty.mark();
        self.changed.notify_waiters();
    }
    pub fn is_shutdown(&self) -> bool {
        self.runtime.read().shutdown
    }
    /// Candidate declarations of one instance for the mobile external route
    /// entry and the desktop tests.
    ///
    /// Desktop production has no route-table export: the plan and the ledger
    /// stay inside the reconciler. The policy read itself is the same one the
    /// desktop planner uses; the manual list of the current configuration
    /// decides whether AutoProxy declarations are part of the target, and
    /// Additional declarations are always included. It never depends on a
    /// bound NIC, so an instance without a TUN can still contribute its manual
    /// routes. A stopped namespace, a released registry and an unknown run all
    /// contribute nothing.
    #[cfg(test)]
    pub fn effective_routes_for_instance(&self, run: &Uuid) -> RouteSet {
        let rt = self.runtime.read();
        if rt.shutdown {
            return RouteSet::new();
        }
        rt.instances
            .get(run)
            .and_then(InstanceRoutes::declarations)
            .map_or_else(RouteSet::new, |(routes, _)| routes)
    }
    /// Mark an input change that is not visible as a slot update.
    pub fn invalidate_instance(&self, run: &Uuid) {
        let exists = self.runtime.read().instances.contains_key(run);
        if exists {
            self.dirty.mark();
        }
    }
    /// Test-only observation of the shared route input mark.
    #[cfg(test)]
    pub(crate) fn route_input_is_dirty(&self) -> bool {
        self.dirty.peek()
    }

    /// Test-only reset of the shared route input mark.
    #[cfg(test)]
    pub(crate) fn reset_route_input_dirty(&self) {
        self.dirty.reset();
    }

    /// Wait until the reconciler has removed this run's instance record.
    ///
    /// The registry having been released is not enough: the record stays while
    /// actual cleanup is still owed. The caller does not own the registry here,
    /// and an empty owner is not treated as success.
    pub async fn drain(&self, run: Uuid) -> anyhow::Result<()> {
        let wait = async {
            loop {
                let notified = self.changed.notified();
                if !self.runtime.read().instances.contains_key(&run) {
                    return;
                }
                notified.await;
            }
        };

        match tokio::time::timeout(Duration::from_secs(30), wait).await {
            Ok(()) => Ok(()),
            // The timeout stays in the error chain: a host that sees it knows
            // the background worker is still cleaning up and may keep waiting,
            // unlike a real task failure.
            Err(elapsed) => Err(self.drain_timeout_error(run, elapsed)),
        }
    }
    /// Whether every accepted record and actual effect is really finished.
    ///
    /// This is the stop diagnosis for the host: a consumed `JoinHandle` is not
    /// proof of success, only an empty record directory, ledger and, on mobile,
    /// no outstanding install request are.
    pub fn ensure_drained(&self) -> anyhow::Result<()> {
        let rt = self.runtime.read();
        #[cfg(not(mobile))]
        let drained = rt.shutdown && rt.instances.is_empty() && rt.applied.is_empty();
        #[cfg(mobile)]
        let drained = rt.shutdown && rt.instances.is_empty() && rt.installed_routes.is_empty();
        if drained {
            return Ok(());
        }
        // One complete diagnostic per platform: never hide a not-yet-shut-down
        // controller or an outstanding record behind an earlier condition.
        #[cfg(not(mobile))]
        let detail = format!(
            "route controller is not drained: shutdown {}, instance records {:?}, \
             applied routes {:?}",
            rt.shutdown,
            rt.instances.keys().collect::<Vec<_>>(),
            rt.applied
                .values()
                .map(|applied| {
                    format!(
                        "{:?} effect {:?} owners {:?}",
                        applied.route, applied.effect, applied.owners
                    )
                })
                .collect::<Vec<_>>()
        );
        #[cfg(mobile)]
        let detail = format!(
            "route controller is not drained: shutdown {}, instance records {:?}, \
             installed routes {:?}",
            rt.shutdown,
            rt.instances.keys().collect::<Vec<_>>(),
            rt.installed_routes
                .iter()
                .map(|(key, prefixes)| format!("{key:?} {prefixes:?}"))
                .collect::<Vec<_>>()
        );
        Err(anyhow::anyhow!(detail))
    }
    fn drain_timeout_error(
        &self,
        run: Uuid,
        elapsed: tokio::time::error::Elapsed,
    ) -> anyhow::Error {
        let rt = self.runtime.read();
        let record = if rt.instances.contains_key(&run) {
            "still present"
        } else {
            "removed"
        };
        #[cfg(not(mobile))]
        let detail = {
            let remaining: Vec<String> = rt
                .applied
                .values()
                .filter(|applied| applied.owners.contains(&run))
                .map(|applied| {
                    format!(
                        "{:?} effect {:?} owners {:?}",
                        applied.route, applied.effect, applied.owners
                    )
                })
                .collect();
            format!(
                "timed out waiting for route cleanup of instance {run}: \
                 instance record {record}, remaining applied routes {remaining:?}"
            )
        };
        #[cfg(mobile)]
        let detail = {
            let installed = rt
                .installed_routes
                .iter()
                .filter(|((installed_run, _), _)| *installed_run == run)
                .map(|(key, prefixes)| format!("{key:?} {prefixes:?}"))
                .collect::<Vec<_>>();
            format!(
                "timed out waiting for route cleanup of instance {run}: \
                 instance record {record}, remaining installed routes {installed:?}"
            )
        };
        anyhow::Error::new(elapsed).context(detail)
    }
}

/// Every real backend call and claims read is bounded by this.
const ROUTE_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// The first backoff after a failed operation.
const RETRY_INITIAL: Duration = Duration::from_millis(200);

/// The largest backoff a repeating failure keeps.
const RETRY_MAX: Duration = Duration::from_secs(30);

/// Backoff of the given attempt: doubling from [`RETRY_INITIAL`].
fn retry_backoff(attempt: u32) -> Duration {
    RETRY_INITIAL
        .saturating_mul(1u32 << attempt.saturating_sub(1).min(8))
        .min(RETRY_MAX)
}
