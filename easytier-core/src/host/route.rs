//! Instance-owned route declarations and route slot coordination.
//!
//! Business components publish `RouteSpec<RouteDevice>` values through a
//! [`RouteSlot`]; the instance-side [`Registry`] only registers weak references
//! to those slots. No backend, task, TUN resource or derived registry lives
//! here.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Weak},
};

#[cfg(not(mobile))]
use std::net::IpAddr;

use cidr::IpCidr;
use parking_lot::Mutex;
use tokio::sync::Notify;

use crate::foundation::dirty::DirtyFlag;

/// The declaration set published by one slot.
pub type RouteSet = BTreeSet<RouteSpec<RouteDevice>>;

/// Device selection inside a declaration.
///
/// Only [`RouteAction::Unicast`] uses it; platform actions without a device do
/// not invent one. Desktop callers resolve an interface name to
/// [`RouteDevice::Index`] before declaring it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RouteDevice {
    Tun,
    #[cfg(not(mobile))]
    Index(u32),
}

/// One route declaration. The same shape describes declarations
/// (`RouteSpec<RouteDevice>`) and installable routes (`RouteSpec<u32>`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RouteSpec<D> {
    pub destination: IpCidr,
    pub action: RouteAction<D>,

    #[cfg(all(not(mobile), any(target_os = "linux", windows)))]
    pub metric: u32,
    #[cfg(all(not(mobile), target_os = "linux"))]
    pub table: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RouteAction<D> {
    Unicast {
        dev: D,
        #[cfg(not(mobile))]
        via: Option<IpAddr>,
    },
    #[cfg(all(not(mobile), target_os = "linux"))]
    Blackhole,
    #[cfg(all(not(mobile), target_os = "linux"))]
    Unreachable,
}

impl RouteSpec<RouteDevice> {
    /// A direct route through this instance's TUN device.
    pub fn for_tun(destination: IpCidr) -> Self {
        Self {
            destination,
            action: RouteAction::Unicast {
                dev: RouteDevice::Tun,
                #[cfg(not(mobile))]
                via: None,
            },
            #[cfg(all(not(mobile), any(target_os = "linux", windows)))]
            metric: 65535,
            #[cfg(all(not(mobile), target_os = "linux"))]
            table: None,
        }
    }

    /// Whether this declaration needs the instance TUN device to resolve.
    pub fn needs_default_device(&self) -> bool {
        matches!(
            self.action,
            RouteAction::Unicast {
                dev: RouteDevice::Tun,
                ..
            }
        )
    }

    /// Resolve the declaration into an installable route.
    ///
    /// Only the device selection changes: `Tun` becomes the current instance
    /// interface index (or `None` while no interface is ready), `Index(n)`
    /// stays `n`, and actions without a device pass through unchanged. Every
    /// other field is moved over as-is; normalization and platform validation
    /// belong to the execution side.
    #[cfg(not(mobile))]
    pub fn resolve(self, tun_ifindex: Option<u32>) -> Option<RouteSpec<u32>> {
        let action = match self.action {
            RouteAction::Unicast { dev, via } => RouteAction::Unicast {
                dev: match dev {
                    RouteDevice::Tun => tun_ifindex?,
                    RouteDevice::Index(index) => index,
                },
                via,
            },
            #[cfg(target_os = "linux")]
            RouteAction::Blackhole => RouteAction::Blackhole,
            #[cfg(target_os = "linux")]
            RouteAction::Unreachable => RouteAction::Unreachable,
        };
        Some(RouteSpec {
            destination: self.destination,
            action,
            #[cfg(any(target_os = "linux", windows))]
            metric: self.metric,
            #[cfg(target_os = "linux")]
            table: self.table,
        })
    }
}

/// Per-declaration execution status, kept next to the declaration in a slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteStatus {
    Pending { error: Option<Arc<str>> },
    Ready,
    Suppressed(Arc<str>),
    Rejected(Arc<str>),
    Failed(Arc<str>),
}

/// The fixed origin of a slot's declarations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteSource {
    AutoProxy,
    Additional,
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum RouteInputError {
    #[error("route input is closed")]
    Closed,
    #[error("route configuration is already bound")]
    AlreadyBound,
}

/// Instance-side strong owner of the route inputs.
///
/// The registry only keeps weak references to slots, so it does not extend a
/// slot's declaration lifetime. Dropping the last strong reference wakes the
/// controller, which re-reads the now-empty input set.
pub struct Registry {
    slots: Mutex<Vec<Weak<RouteSlotInner>>>,
    dirty: Arc<DirtyFlag>,
}

impl Registry {
    pub fn new(dirty: Arc<DirtyFlag>) -> Self {
        Self {
            slots: Mutex::new(Vec::new()),
            dirty,
        }
    }

    pub fn handle(self: &Arc<Self>) -> RouteHandle {
        RouteHandle {
            registry: Arc::downgrade(self),
        }
    }

    /// Weak references to the slots that are still alive.
    ///
    /// Dead entries are pruned and the list is copied under one short lock;
    /// callers upgrade and release the returned references without holding it.
    pub fn slots(&self) -> Vec<Weak<RouteSlotInner>> {
        let mut slots = self.slots.lock();
        slots.retain(|slot| slot.upgrade().is_some());
        slots.clone()
    }
}

impl Drop for Registry {
    fn drop(&mut self) {
        self.dirty.mark();
    }
}

/// Cloneable handle used to open route slots for one instance.
///
/// The handle observes the registry's lifetime only; it is not an input
/// directory of its own.
#[derive(Clone)]
pub struct RouteHandle {
    registry: Weak<Registry>,
}

impl RouteHandle {
    /// Open an empty slot with a fixed source.
    ///
    /// Fails with [`RouteInputError::Closed`] once the registry has been
    /// released: the creation entry is gone and no new input can be attached
    /// to that instance. The registry is marked dirty after the new slot is
    /// registered.
    pub fn open_slot(&self, source: RouteSource) -> Result<RouteSlot, RouteInputError> {
        let registry = self.registry.upgrade().ok_or(RouteInputError::Closed)?;
        let inner = Arc::new(RouteSlotInner {
            source,
            routes: Mutex::new(BTreeMap::new()),
            dirty: registry.dirty.clone(),
            changed: Notify::new(),
        });
        registry.slots.lock().push(Arc::downgrade(&inner));
        drop(registry);
        inner.dirty.mark();
        Ok(RouteSlot { inner })
    }
}

/// Business-facing handle to one shared declaration set and its statuses.
///
/// Clones share the same `RouteSlotInner`; there is no per-clone lifetime.
#[derive(Clone)]
pub struct RouteSlot {
    inner: Arc<RouteSlotInner>,
}

impl RouteSlot {
    /// Replace the whole declaration set.
    ///
    /// Runs under the same map lock that holds the statuses: declarations that
    /// remain keep their status, new declarations start as `Pending`, and
    /// withdrawn declarations are removed. An unchanged set changes nothing.
    /// An actual input change marks the shared dirty flag and notifies
    /// [`changed`](Self::changed) once, after the lock is released.
    pub fn set_routes(&self, routes: RouteSet) {
        self.inner.set_routes(routes);
    }

    /// Edit the declaration set through `f`, then apply the same replacement
    /// rules as [`set_routes`](Self::set_routes).
    ///
    /// `f` runs while the map is locked: it must only perform set operations,
    /// without I/O or re-entering this slot. The closure's result is returned.
    pub fn modify<R>(&self, f: impl FnOnce(&mut RouteSet) -> R) -> R {
        self.inner.modify(f)
    }

    /// Withdraw every declaration; same rules as [`set_routes`](Self::set_routes)
    /// with an empty set.
    pub fn clear(&self) {
        self.inner.set_routes(RouteSet::new());
    }

    /// Copy of the current per-declaration statuses.
    ///
    /// A missing entry means the declaration has been withdrawn, not that it is
    /// still being installed or uninstalled.
    pub fn statuses(&self) -> BTreeMap<RouteSpec<RouteDevice>, RouteStatus> {
        self.inner.statuses()
    }

    /// Notification that declarations or their statuses actually changed.
    ///
    /// Create `notified()` before reading statuses so a notification between
    /// the read and the await is not lost; the notification carries no route
    /// data and does not mean installation succeeded.
    pub fn changed(&self) -> &Notify {
        &self.inner.changed
    }
}

/// Shared storage behind a [`RouteSlot`].
pub struct RouteSlotInner {
    source: RouteSource,
    routes: Mutex<BTreeMap<RouteSpec<RouteDevice>, RouteStatus>>,
    dirty: Arc<DirtyFlag>,
    changed: Notify,
}

impl RouteSlotInner {
    pub fn source(&self) -> RouteSource {
        self.source
    }

    /// Copy of the current declaration keys.
    pub fn routes(&self) -> RouteSet {
        self.routes.lock().keys().cloned().collect()
    }

    /// Recompute statuses for all currently declared routes.
    ///
    /// The callback runs under the declaration lock, once per entry that still
    /// exists. Returning `None` keeps the old status; returning `Some` replaces
    /// it when it differs from the old one. Withdrawn declarations are never
    /// presented, so they cannot be resurrected. The lock is released after
    /// the batch; only an actual status change calls
    /// [`changed`](RouteSlot::changed) waiters, and the dirty flag is left
    /// alone because status feedback is not an input change.
    ///
    /// The callback must not perform I/O or re-enter the slot. The caller is
    /// responsible for computing the status from the current policy, bindings
    /// and observed effect.
    pub fn update_statuses(
        &self,
        mut f: impl FnMut(&RouteSpec<RouteDevice>) -> Option<RouteStatus>,
    ) {
        let changed = {
            let mut routes = self.routes.lock();
            let mut changed = false;
            for (route, status) in routes.iter_mut() {
                let Some(next) = f(route) else { continue };
                if *status != next {
                    *status = next;
                    changed = true;
                }
            }
            changed
        };
        if changed {
            self.changed.notify_waiters();
        }
    }

    fn set_routes(&self, routes: RouteSet) {
        let changed = {
            let mut current = self.routes.lock();
            Self::replace_locked(&mut current, routes)
        };
        if changed {
            self.dirty.mark();
            self.changed.notify_waiters();
        }
    }

    fn modify<R>(&self, f: impl FnOnce(&mut RouteSet) -> R) -> R {
        let (result, changed) = {
            let mut current = self.routes.lock();
            let mut routes: RouteSet = current.keys().cloned().collect();
            let result = f(&mut routes);
            let changed = Self::replace_locked(&mut current, routes);
            (result, changed)
        };
        if changed {
            self.dirty.mark();
            self.changed.notify_waiters();
        }
        result
    }

    fn statuses(&self) -> BTreeMap<RouteSpec<RouteDevice>, RouteStatus> {
        self.routes.lock().clone()
    }

    /// Apply a whole-set replacement under an already held lock.
    ///
    /// Returns whether the declaration set actually changed. Retained entries
    /// keep their status; new entries start pending.
    fn replace_locked(
        current: &mut BTreeMap<RouteSpec<RouteDevice>, RouteStatus>,
        routes: RouteSet,
    ) -> bool {
        if current.len() == routes.len() && routes.iter().all(|route| current.contains_key(route)) {
            return false;
        }
        let previous = std::mem::take(current);
        current.extend(routes.into_iter().map(|route| {
            let status = previous
                .get(&route)
                .cloned()
                .unwrap_or(RouteStatus::Pending { error: None });
            (route, status)
        }));
        true
    }
}

impl Drop for RouteSlotInner {
    fn drop(&mut self) {
        self.dirty.mark();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn registry() -> (Arc<Registry>, Arc<DirtyFlag>) {
        let dirty = Arc::new(DirtyFlag::new(false));
        (Arc::new(Registry::new(dirty.clone())), dirty)
    }

    fn route(destination: &str) -> RouteSpec<RouteDevice> {
        RouteSpec::for_tun(destination.parse().unwrap())
    }

    #[test]
    fn full_replacement_preserves_unchanged_statuses() {
        let (registry, dirty) = registry();
        let slot = registry.handle().open_slot(RouteSource::AutoProxy).unwrap();
        let clone = slot.clone();

        let a = route("10.0.0.0/24");
        let b = route("10.1.0.0/24");
        let c = route("10.2.0.0/24");

        slot.set_routes(RouteSet::from([a.clone(), b.clone()]));
        slot.inner
            .update_statuses(|route| (route == &a).then_some(RouteStatus::Ready));
        assert_eq!(clone.statuses().get(&a), Some(&RouteStatus::Ready));

        dirty.reset();
        // Re-publishing the same declaration set changes nothing.
        clone.set_routes(RouteSet::from([a.clone(), b.clone()]));
        assert!(!dirty.peek());
        assert_eq!(slot.statuses().get(&a), Some(&RouteStatus::Ready));

        // {a, b} -> {a, c}: a keeps its feedback, c starts pending, b is gone.
        clone.set_routes(RouteSet::from([a.clone(), c.clone()]));
        let statuses = slot.statuses();
        assert_eq!(statuses.get(&a), Some(&RouteStatus::Ready));
        assert_eq!(statuses.get(&b), None);
        assert_eq!(
            statuses.get(&c),
            Some(&RouteStatus::Pending { error: None })
        );
        assert!(dirty.peek());
    }

    #[test]
    fn last_inner_arc_release_marks_after_slot_clones_drop() {
        let (registry, dirty) = registry();
        let slot = registry
            .handle()
            .open_slot(RouteSource::Additional)
            .unwrap();
        let clone = slot.clone();
        slot.set_routes(RouteSet::from([route("10.0.0.0/24")]));
        let upgraded = registry.slots()[0].upgrade().unwrap();

        dirty.reset();
        drop(clone);
        assert!(
            !dirty.peek(),
            "dropping one clone must not withdraw the slot"
        );

        slot.inner.update_statuses(|_| Some(RouteStatus::Ready));
        assert!(!dirty.peek(), "status feedback alone must not mark dirty");

        drop(slot);
        assert!(
            !dirty.peek(),
            "a temporary inner handle still holds the input"
        );

        drop(upgraded);
        assert!(
            dirty.peek(),
            "the final inner release must wake the controller"
        );
    }

    #[test]
    fn registry_release_requires_last_strong_arc_and_keeps_slots_usable() {
        let (registry, dirty) = registry();
        let handle = registry.handle();
        let slot = handle.open_slot(RouteSource::Additional).unwrap();
        let temporary = Arc::downgrade(&registry).upgrade().unwrap();

        dirty.reset();
        drop(registry);
        assert!(
            !dirty.peek(),
            "a temporary registry handle still keeps the input alive"
        );

        drop(temporary);
        assert!(
            dirty.peek(),
            "the final registry release must wake the controller"
        );

        assert!(matches!(
            handle.open_slot(RouteSource::Additional),
            Err(RouteInputError::Closed)
        ));

        dirty.reset();
        let target = route("10.9.0.0/24");
        slot.set_routes(RouteSet::from([target.clone()]));
        assert_eq!(slot.inner.routes(), RouteSet::from([target]));
        assert!(dirty.peek(), "an orphaned slot still wakes the controller");
    }

    #[tokio::test]
    async fn status_updates_target_current_entries_and_notify_once() {
        let (registry, dirty) = registry();
        let slot = registry.handle().open_slot(RouteSource::AutoProxy).unwrap();
        let a = route("10.0.0.0/24");
        let b = route("10.1.0.0/24");
        let withdrawn = route("10.2.0.0/24");
        slot.set_routes(RouteSet::from([a.clone(), b.clone()]));
        dirty.reset();

        // A waiter created before the batch must still observe the
        // notification even though it only awaits after the status write.
        let notified = slot.changed().notified();
        tokio::pin!(notified);

        slot.inner.update_statuses(|route| {
            if route == &a {
                Some(RouteStatus::Ready)
            } else if route == &b {
                Some(RouteStatus::Suppressed("policy".into()))
            } else if route == &withdrawn {
                Some(RouteStatus::Ready)
            } else {
                None
            }
        });

        let statuses = slot.statuses();
        assert_eq!(statuses.get(&a), Some(&RouteStatus::Ready));
        assert_eq!(
            statuses.get(&b),
            Some(&RouteStatus::Suppressed("policy".into()))
        );
        assert_eq!(
            statuses.get(&withdrawn),
            None,
            "a withdrawn declaration must not be resurrected"
        );
        assert!(
            !dirty.peek(),
            "status feedback must not wake the controller"
        );
        notified.await;

        // Rewriting equal statuses neither notifies nor marks.
        let notified = slot.changed().notified();
        tokio::pin!(notified);
        slot.inner.update_statuses(|route| {
            if route == &a {
                Some(RouteStatus::Ready)
            } else {
                None
            }
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(50), notified)
                .await
                .is_err(),
            "unchanged statuses must not notify"
        );
        assert!(!dirty.peek());
    }

    #[cfg(not(mobile))]
    #[test]
    fn resolve_translates_only_the_device() {
        let tun = RouteSpec::for_tun("10.0.0.0/24".parse().unwrap());
        assert_eq!(tun.clone().resolve(None), None);

        let resolved = tun.resolve(Some(7)).unwrap();
        assert_eq!(
            resolved.destination,
            "10.0.0.0/24".parse::<IpCidr>().unwrap()
        );
        match resolved.action {
            RouteAction::Unicast { dev, via } => {
                assert_eq!(dev, 7);
                assert_eq!(via, None);
            }
            _ => panic!("expected a unicast action"),
        }

        let indexed = RouteSpec::<RouteDevice> {
            destination: "10.1.0.0/24".parse().unwrap(),
            action: RouteAction::Unicast {
                dev: RouteDevice::Index(9),
                via: Some("192.0.2.1".parse().unwrap()),
            },
            #[cfg(any(target_os = "linux", windows))]
            metric: 10,
            #[cfg(target_os = "linux")]
            table: Some(100),
        };
        let resolved = indexed.clone().resolve(None).unwrap();
        assert_eq!(
            resolved.action,
            RouteAction::Unicast {
                dev: 9,
                via: Some("192.0.2.1".parse().unwrap()),
            },
            "an explicit interface index must not need a bound tun device"
        );
        #[cfg(any(target_os = "linux", windows))]
        assert_eq!(resolved.metric, 10);
        #[cfg(target_os = "linux")]
        assert_eq!(resolved.table, Some(100));

        #[cfg(target_os = "linux")]
        {
            let blackhole = RouteSpec::<RouteDevice> {
                destination: "10.2.0.0/24".parse().unwrap(),
                action: RouteAction::Blackhole,
                metric: 5,
                table: None,
            };
            let resolved = blackhole.clone().resolve(None).unwrap();
            assert_eq!(resolved.action, RouteAction::Blackhole);

            // A single set may mix tun, indexed and device-less actions.
            let mixed = RouteSet::from([
                RouteSpec::for_tun("10.3.0.0/24".parse().unwrap()),
                indexed,
                blackhole,
            ]);
            let resolved: Vec<_> = mixed
                .into_iter()
                .map(|route| route.resolve(Some(3)).expect("every entry resolves"))
                .collect();
            assert_eq!(resolved.len(), 3);
            assert_eq!(
                resolved
                    .iter()
                    .filter(|route| matches!(
                        &route.action,
                        RouteAction::Unicast { dev, .. } if *dev == 3
                    ))
                    .count(),
                1
            );
        }
    }
}
