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


