//! Instance-owned route inputs and route slot coordination.
//! No backend, task, TUN resource or derived registry lives here.

use std::{
    collections::BTreeSet,
    net::IpAddr,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
};

use cidr::IpCidr;

use crate::config::runtime::CoreRuntimeConfigStore;

pub type RouteSet = BTreeSet<RouteSpec>;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RouteSpec {
    pub destination: IpCidr,
    pub metric: u32,
    pub table: Option<u32>,
    pub preferred_source: Option<IpAddr>,
    pub action: RouteAction,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeviceSelector {
    InstanceTun,
    Named(String),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RouteAction {
    Unicast {
        device: Option<DeviceSelector>,
        via: Option<IpAddr>,
    },
    Blackhole,
    Unreachable,
}

impl RouteSpec {
    pub fn for_tun(destination: IpCidr) -> Self {
        Self {
            destination,
            metric: 65535,
            table: None,
            preferred_source: None,
            action: RouteAction::Unicast {
                device: Some(DeviceSelector::InstanceTun),
                via: None,
            },
        }
    }

    pub fn needs_default_device(&self) -> bool {
        matches!(
            self.action,
            RouteAction::Unicast {
                device: Some(DeviceSelector::InstanceTun),
                ..
            }
        )
    }
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum RouteInputError {
    #[error("route input is closed")]
    Closed,
    #[error("route configuration is already bound")]
    AlreadyBound,
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum RouteWaitError {
    #[error("route input is closed")]
    Closed,
    #[error("automatic route is suppressed by manual policy")]
    Suppressed,
    #[error("route rejected: {0}")]
    Rejected(Arc<str>),
    #[error("route executor failed: {0}")]
    Failed(Arc<str>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteSlotStatus {
    Pending,
    Ready,
    Suppressed,
    Closed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstanceRouteStatus {
    Active,
    Draining { remaining: Option<usize> },
    Drained,
    Failed(Arc<str>),
}

pub struct RouteSlotInner {
    instance: uuid::Uuid,
    is_auto_proxy: AtomicBool,
    routes: parking_lot::Mutex<RouteSet>,
    status: AtomicU8, // 0: Pending, 1: Ready, 2: Suppressed, 3: Closed
    error: parking_lot::Mutex<Option<Arc<str>>>,
    notify: tokio::sync::Notify,
    wake: Arc<dyn Fn() + Send + Sync>,
    closed: AtomicBool,
}

impl RouteSlotInner {
    pub fn instance(&self) -> uuid::Uuid {
        self.instance
    }

    pub fn is_auto_proxy(&self) -> bool {
        self.is_auto_proxy.load(Ordering::Acquire)
    }

    pub fn routes(&self) -> RouteSet {
        self.routes.lock().clone()
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub fn set_ready(&self) {
        self.status.store(1, Ordering::Release);
        self.notify.notify_waiters();
    }

    pub fn set_suppressed(&self) {
        self.status.store(2, Ordering::Release);
        self.notify.notify_waiters();
    }

    pub fn set_failed(&self, error: Arc<str>) {
        *self.error.lock() = Some(error);
        self.status.store(3, Ordering::Release);
        self.notify.notify_waiters();
    }
}

/// A lightweight slot handle held by business components (OSPF, Public IPv6, Magic DNS).
/// Dropping it automatically marks it closed and notifies the controller.
#[derive(Clone)]
pub struct RouteSlot {
    inner: Arc<RouteSlotInner>,
}

impl RouteSlot {
    pub fn new(
        instance: uuid::Uuid,
        is_auto_proxy: bool,
        wake: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        Self {
            inner: Arc::new(RouteSlotInner {
                instance,
                is_auto_proxy: AtomicBool::new(is_auto_proxy),
                routes: parking_lot::Mutex::new(RouteSet::new()),
                status: AtomicU8::new(0),
                error: parking_lot::Mutex::new(None),
                notify: tokio::sync::Notify::new(),
                wake,
                closed: AtomicBool::new(false),
            }),
        }
    }

    pub fn instance(&self) -> uuid::Uuid {
        self.inner.instance
    }

    pub fn is_auto_proxy(&self) -> bool {
        self.inner.is_auto_proxy()
    }

    pub fn routes(&self) -> RouteSet {
        self.inner.routes()
    }

    pub fn set_routes(&self, routes: RouteSet) -> Result<(), RouteInputError> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(RouteInputError::Closed);
        }
        *self.inner.routes.lock() = routes;
        self.inner.status.store(0, Ordering::Release);
        *self.inner.error.lock() = None;
        (self.inner.wake)();
        Ok(())
    }

    pub fn replace(&self, routes: RouteSet) -> Result<(), RouteInputError> {
        self.set_routes(routes)
    }

    pub fn modify<F, R>(&self, f: F) -> Result<R, RouteInputError>
    where
        F: FnOnce(&mut RouteSet) -> R,
    {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(RouteInputError::Closed);
        }
        let ret = {
            let mut guard = self.inner.routes.lock();
            f(&mut guard)
        };
        self.inner.status.store(0, Ordering::Release);
        *self.inner.error.lock() = None;
        (self.inner.wake)();
        Ok(ret)
    }

    pub fn clear(&self) -> Result<(), RouteInputError> {
        self.set_routes(RouteSet::new())
    }

    pub fn status(&self) -> RouteSlotStatus {
        if self.inner.closed.load(Ordering::Acquire) {
            return RouteSlotStatus::Closed;
        }
        match self.inner.status.load(Ordering::Acquire) {
            1 => RouteSlotStatus::Ready,
            2 => RouteSlotStatus::Suppressed,
            3 => RouteSlotStatus::Closed,
            _ => RouteSlotStatus::Pending,
        }
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }

    pub fn set_ready(&self) {
        self.inner.set_ready();
    }

    pub fn set_suppressed(&self) {
        self.inner.set_suppressed();
    }

    pub fn set_failed(&self, error: Arc<str>) {
        self.inner.set_failed(error);
    }

    pub async fn wait_ready(&self) -> Result<(), RouteWaitError> {
        loop {
            if self.inner.closed.load(Ordering::Acquire) {
                return Err(RouteWaitError::Closed);
            }
            if let Some(err) = self.inner.error.lock().clone() {
                return Err(RouteWaitError::Failed(err));
            }
            match self.status() {
                RouteSlotStatus::Ready => return Ok(()),
                RouteSlotStatus::Suppressed => return Err(RouteWaitError::Suppressed),
                RouteSlotStatus::Closed => return Err(RouteWaitError::Closed),
                RouteSlotStatus::Pending => {}
            }
            self.inner.notify.notified().await;
        }
    }

    pub fn downgrade(&self) -> Weak<RouteSlotInner> {
        Arc::downgrade(&self.inner)
    }
}

impl Drop for RouteSlot {
    fn drop(&mut self) {
        if Arc::strong_count(&self.inner) == 1 {
            self.inner.closed.store(true, Ordering::Release);
            self.inner.notify.notify_waiters();
            (self.inner.wake)();
        }
    }
}

/// Immutable, cloneable handle passed to business components to allocate route slots.
#[derive(Clone)]
pub struct RouteHandle {
    open_fn: Arc<dyn Fn(bool) -> Result<RouteSlot, RouteInputError> + Send + Sync>,
}

impl RouteHandle {
    pub fn new<F>(f: F) -> Self
    where
        F: Fn(bool) -> Result<RouteSlot, RouteInputError> + Send + Sync + 'static,
    {
        Self {
            open_fn: Arc::new(f),
        }
    }

    /// Allocate a new empty slot from the controller.
    pub fn open_slot(&self) -> Result<RouteSlot, RouteInputError> {
        (self.open_fn)(false)
    }

    /// Allocate a new empty slot designated for automatic proxy routes.
    pub fn open_auto_proxy_slot(&self) -> Result<RouteSlot, RouteInputError> {
        (self.open_fn)(true)
    }
}

struct InstanceRoutesInner {
    run: uuid::Uuid,
    handle: RouteHandle,
    config: parking_lot::Mutex<Option<CoreRuntimeConfigStore>>,
    closed: AtomicBool,
    wake: Arc<dyn Fn() + Send + Sync>,
}

/// Unique instance route close authority.
#[derive(Clone)]
pub struct InstanceRoutes {
    inner: Arc<InstanceRoutesInner>,
}

impl InstanceRoutes {
    pub fn new(wake: Arc<dyn Fn() + Send + Sync>) -> Self {
        let run = uuid::Uuid::new_v4();
        let wake_clone = wake.clone();
        let handle = RouteHandle::new(move |is_auto_proxy| {
            Ok(RouteSlot::new(run, is_auto_proxy, wake_clone.clone()))
        });
        Self {
            inner: Arc::new(InstanceRoutesInner {
                run,
                handle,
                config: parking_lot::Mutex::new(None),
                closed: AtomicBool::new(false),
                wake,
            }),
        }
    }

    pub fn with_handle(
        run: uuid::Uuid,
        handle: RouteHandle,
        wake: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        Self {
            inner: Arc::new(InstanceRoutesInner {
                run,
                handle,
                config: parking_lot::Mutex::new(None),
                closed: AtomicBool::new(false),
                wake,
            }),
        }
    }

    pub fn run(&self) -> uuid::Uuid {
        self.inner.run
    }

    pub fn handle(&self) -> RouteHandle {
        self.inner.handle.clone()
    }

    pub fn open_slot(&self) -> Result<RouteSlot, RouteInputError> {
        self.inner.handle.open_slot()
    }

    pub fn open_auto_proxy_slot(&self) -> Result<RouteSlot, RouteInputError> {
        self.inner.handle.open_auto_proxy_slot()
    }

    pub fn bind_config(&self, config: CoreRuntimeConfigStore) -> Result<(), RouteInputError> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(RouteInputError::Closed);
        }
        let wake = self.inner.wake.clone();
        config
            .set_route_invalidator(Arc::new(move || {
                wake();
            }))
            .map_err(|_| RouteInputError::AlreadyBound)?;
        *self.inner.config.lock() = Some(config);
        (self.inner.wake)();
        Ok(())
    }

    pub fn config(&self) -> Option<CoreRuntimeConfigStore> {
        self.inner.config.lock().clone()
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }

    pub fn request_close(&self) {
        if !self.inner.closed.swap(true, Ordering::AcqRel) {
            (self.inner.wake)();
        }
    }

    pub fn status(&self) -> InstanceRouteStatus {
        if self.is_closed() {
            InstanceRouteStatus::Drained
        } else {
            InstanceRouteStatus::Active
        }
    }

    pub async fn status_changed(&mut self) -> Result<InstanceRouteStatus, RouteWaitError> {
        Ok(self.status())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{peers::PeerRuntimeSnapshot, runtime::CoreRuntimeConfig};

    fn config() -> CoreRuntimeConfigStore {
        CoreRuntimeConfigStore::new(
            CoreRuntimeConfig::default(),
            Arc::new(PeerRuntimeSnapshot::default()),
        )
    }

    #[test]
    fn slot_replace_and_close() {
        let owner = InstanceRoutes::new(Arc::new(|| {}));
        let slot = owner.handle().open_slot().unwrap();
        assert_eq!(slot.status(), RouteSlotStatus::Pending);

        let routes = RouteSet::from([RouteSpec::for_tun("10.0.0.0/24".parse().unwrap())]);
        slot.set_routes(routes.clone()).unwrap();
        assert_eq!(slot.routes(), routes);

        slot.inner.set_ready();
        assert_eq!(slot.status(), RouteSlotStatus::Ready);

        drop(slot);
        assert!(owner.handle().open_slot().is_ok());
    }

    #[tokio::test]
    async fn slot_wait_ready_notification() {
        let dirty_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let dc = dirty_count.clone();
        let slot = RouteSlot::new(
            uuid::Uuid::new_v4(),
            false,
            Arc::new(move || {
                dc.fetch_add(1, Ordering::SeqCst);
            }),
        );

        let slot_clone = slot.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            slot_clone.inner.set_ready();
        });

        let res = slot.wait_ready().await;
        assert!(res.is_ok(), "got err: {:?}", res);
        assert_eq!(slot.status(), RouteSlotStatus::Ready);
    }

    #[test]
    fn bind_config_stores_and_invalidates() {
        let dirty_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let dc = dirty_count.clone();
        let owner = InstanceRoutes::new(Arc::new(move || {
            dc.fetch_add(1, Ordering::SeqCst);
        }));

        let store = config();
        owner.bind_config(store.clone()).unwrap();
        assert!(dirty_count.load(Ordering::SeqCst) > 0);
    }
}
