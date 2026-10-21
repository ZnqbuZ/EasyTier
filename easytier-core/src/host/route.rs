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

use cidr::{IpCidr, Ipv4Cidr};

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

    pub fn validate(&self) -> Result<(), RouteInputError> {
        let same_family = |ip: IpAddr| ip.is_ipv4() == self.destination.first_address().is_ipv4();
        if self.preferred_source.is_some_and(|ip| !same_family(ip)) {
            return Err(RouteInputError::InvalidSpec(
                "source address family differs",
            ));
        }
        if let RouteAction::Unicast { device, via } = &self.action {
            if device.is_none() && via.is_none() {
                return Err(RouteInputError::InvalidSpec(
                    "unicast requires a device or gateway",
                ));
            }
            if via.is_some_and(|ip| !same_family(ip)) {
                return Err(RouteInputError::InvalidSpec(
                    "gateway address family differs",
                ));
            }
            if matches!(device, Some(DeviceSelector::Named(name)) if name.is_empty()) {
                return Err(RouteInputError::InvalidSpec("empty device name"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteDemand {
    AutoProxy(BTreeSet<Ipv4Cidr>),
    Additional(RouteSet),
}

impl RouteDemand {
    pub fn validate(&self) -> Result<(), RouteInputError> {
        if let Self::Additional(routes) = self {
            for route in routes {
                route.validate()?;
            }
        }
        Ok(())
    }

    pub fn needs_default_device(&self) -> bool {
        match self {
            Self::AutoProxy(_) => true,
            Self::Additional(routes) => routes.iter().any(RouteSpec::needs_default_device),
        }
    }
}

/// Allocated once by the owner of each actual physical device generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceEpoch(uuid::Uuid);

impl DeviceEpoch {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}
impl Default for DeviceEpoch {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum RouteInputError {
    #[error("route input is closed")]
    Closed,
    #[error("invalid route: {0}")]
    InvalidSpec(&'static str),
    #[error("route configuration is already bound")]
    AlreadyBound,
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum RouteWaitError {
    #[error("route input is closed")]
    Closed,
    #[error("route declaration was replaced")]
    Superseded,
    #[error("device generation changed")]
    DeviceChanged,
    #[error("an expected device generation is required")]
    DeviceRequired,
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
    demand: parking_lot::Mutex<Option<RouteDemand>>,
    status: AtomicU8, // 0: Pending, 1: Ready, 2: Suppressed, 3: Closed
    error: parking_lot::Mutex<Option<Arc<str>>>,
    notify: tokio::sync::Notify,
    wake: Arc<dyn Fn() + Send + Sync>,
    closed: AtomicBool,
    device: parking_lot::Mutex<Option<DeviceEpoch>>,
}

impl RouteSlotInner {
    pub fn instance(&self) -> uuid::Uuid {
        self.instance
    }

    pub fn demand(&self) -> Option<RouteDemand> {
        self.demand.lock().clone()
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub fn set_ready(&self, device: Option<DeviceEpoch>) {
        *self.device.lock() = device;
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
    pub fn new(instance: uuid::Uuid, wake: Arc<dyn Fn() + Send + Sync>) -> Self {
        Self {
            inner: Arc::new(RouteSlotInner {
                instance,
                demand: parking_lot::Mutex::new(None),
                status: AtomicU8::new(0),
                error: parking_lot::Mutex::new(None),
                notify: tokio::sync::Notify::new(),
                wake,
                closed: AtomicBool::new(false),
                device: parking_lot::Mutex::new(None),
            }),
        }
    }

    pub fn replace(&self, demand: RouteDemand) -> Result<(), RouteInputError> {
        demand.validate()?;
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(RouteInputError::Closed);
        }
        *self.inner.demand.lock() = Some(demand);
        self.inner.status.store(0, Ordering::Release);
        *self.inner.error.lock() = None;
        (self.inner.wake)();
        Ok(())
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

    pub fn instance(&self) -> uuid::Uuid {
        self.inner.instance
    }

    pub fn demand(&self) -> Option<RouteDemand> {
        self.inner.demand.lock().clone()
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }

    pub fn set_ready(&self, device: Option<DeviceEpoch>) {
        self.inner.set_ready(device);
    }

    pub fn set_suppressed(&self) {
        self.inner.set_suppressed();
    }

    pub fn set_failed(&self, error: Arc<str>) {
        self.inner.set_failed(error);
    }

    pub async fn wait_ready(&self, device: Option<DeviceEpoch>) -> Result<(), RouteWaitError> {
        loop {
            if self.inner.closed.load(Ordering::Acquire) {
                return Err(RouteWaitError::Closed);
            }
            if let Some(err) = self.inner.error.lock().clone() {
                return Err(RouteWaitError::Failed(err));
            }
            if device.is_some() {
                let current_device = *self.inner.device.lock();
                if current_device.is_some() && current_device != device {
                    return Err(RouteWaitError::DeviceChanged);
                }
            }
            match self.status() {
                RouteSlotStatus::Ready => {
                    if let Some(expected) = device {
                        if *self.inner.device.lock() == Some(expected) {
                            return Ok(());
                        }
                    } else {
                        return Ok(());
                    }
                }
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
    open_fn: Arc<dyn Fn() -> Result<RouteSlot, RouteInputError> + Send + Sync>,
}

impl RouteHandle {
    pub fn new<F>(f: F) -> Self
    where
        F: Fn() -> Result<RouteSlot, RouteInputError> + Send + Sync + 'static,
    {
        Self {
            open_fn: Arc::new(f),
        }
    }

    /// Allocate a new empty slot from the controller. No prefixes are required up front.
    pub fn open_slot(&self) -> Result<RouteSlot, RouteInputError> {
        (self.open_fn)()
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
        let handle = RouteHandle::new(move || Ok(RouteSlot::new(run, wake_clone.clone())));
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

    pub fn request_close(&self) {
        self.inner.closed.store(true, Ordering::Release);
        (self.inner.wake)();
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }

    pub async fn wait_drained(&self) -> Result<(), RouteWaitError> {
        Ok(())
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

        let demand = RouteDemand::AutoProxy(BTreeSet::from(["10.0.0.0/24".parse().unwrap()]));
        slot.replace(demand.clone()).unwrap();
        assert_eq!(slot.demand(), Some(demand));

        slot.inner.set_ready(None);
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
            Arc::new(move || {
                dc.fetch_add(1, Ordering::SeqCst);
            }),
        );

        let epoch = DeviceEpoch::new();
        let slot_clone = slot.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            slot_clone.inner.set_ready(Some(epoch));
        });

        let res = slot.wait_ready(Some(epoch)).await;
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
