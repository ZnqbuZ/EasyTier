use std::{
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    sync::{Arc, OnceLock},
};

use easytier_core::{
    config::runtime::CoreRuntimeConfigStore,
    host::route::{RouteHandle, RouteRegistry, RouteStatus},
};
use registry::{Registration, Registry};
use tokio::sync::watch;

use super::device::TunDeviceState;

static NEXT_BINDING: AtomicU64 = AtomicU64::new(0);

/// One instance's configuration authority, declarations and feedback. This is
/// an input scope; it never owns a backend, a TUN or installed OS routes.
#[derive(Clone)]
pub(crate) struct RouteScope(Arc<ScopeInner>);

struct ScopeInner {
    member: uuid::Uuid,
    routes: RouteRegistry,
    config: OnceLock<CoreRuntimeConfigStore>,
    closed: AtomicBool,
    binding: watch::Sender<Option<RouteAttachment>>,
    cleanup: parking_lot::Mutex<Option<watch::Receiver<bool>>>,
}

#[derive(Clone)]
pub(crate) struct RouteAttachment {
    pub id: u64,
    pub devices: Arc<TunDeviceState>,
    pub ready: bool,
}

impl RouteScope {
    pub fn new(member: uuid::Uuid) -> Self {
        Self::with_registry(member, RouteRegistry::default())
    }

    pub fn with_registry(member: uuid::Uuid, routes: RouteRegistry) -> Self {
        Self(Arc::new(ScopeInner {
            member,
            routes,
            config: OnceLock::new(),
            closed: AtomicBool::new(false),
            binding: watch::channel(None).0,
            cleanup: parking_lot::Mutex::new(None),
        }))
    }

    pub fn prepare(&self, config: CoreRuntimeConfigStore) -> anyhow::Result<()> {
        anyhow::ensure!(!self.is_closed(), "route scope is closed");
        self.0
            .config
            .set(config)
            .map_err(|_| anyhow::anyhow!("route scope is already prepared"))
    }

    pub fn member(&self) -> uuid::Uuid {
        self.0.member
    }

    pub fn routes(&self) -> &RouteRegistry {
        &self.0.routes
    }

    pub fn config(&self) -> &CoreRuntimeConfigStore {
        self.0
            .config
            .get()
            .expect("only prepared route scopes can attach")
    }

    pub fn handle(&self) -> RouteHandle {
        RouteHandle::new(self.0.routes.clone())
    }

    pub fn attachment(&self) -> Option<RouteAttachment> {
        self.0.binding.borrow().clone()
    }

    pub fn subscribe_attachment(&self) -> watch::Receiver<Option<RouteAttachment>> {
        self.0.binding.subscribe()
    }

    pub fn mark_ready(&self, id: u64) {
        if !self.is_closed() {
            self.0.binding.send_if_modified(|current| {
                if let Some(attachment) = current.as_mut().filter(|a| a.id == id && !a.ready) {
                    attachment.ready = true;
                    true
                } else {
                    false
                }
            });
        }
    }

    pub fn mark_unready(&self) {
        let mut changed = false;
        self.0.binding.send_if_modified(|current| {
            if let Some(attachment) = current.as_mut().filter(|a| a.ready) {
                attachment.ready = false;
                changed = true;
                true
            } else {
                false
            }
        });
        if changed {
            self.0.routes.publish_status(RouteStatus::default());
        }
    }

    pub fn is_closed(&self) -> bool {
        self.0.closed.load(Ordering::SeqCst)
    }

    fn revoke_binding(&self, id: u64) {
        let mut revoked = false;
        self.0.binding.send_if_modified(|current| {
            if current.as_ref().is_some_and(|a| a.id == id) {
                *current = None;
                revoked = true;
                true
            } else {
                false
            }
        });
        if revoked {
            self.0.routes.publish_status(RouteStatus::default());
        }
    }

    pub fn close(&self) {
        self.0.closed.store(true, Ordering::SeqCst);
        self.0.routes.close();
    }

    pub fn publish_status(&self, binding: u64, status: RouteStatus) {
        if !self.is_closed()
            && self
                .0
                .binding
                .borrow()
                .as_ref()
                .is_some_and(|current| current.id == binding)
        {
            self.0.routes.publish_status(status);
        }
    }

    pub async fn wait_withdrawn(&self) -> anyhow::Result<()> {
        let cleanup = self.0.cleanup.lock().clone();
        if let Some(mut cleanup) = cleanup {
            while !*cleanup.borrow_and_update() {
                cleanup.changed().await.map_err(|_| {
                    anyhow::anyhow!("route writer exited before scope cleanup was confirmed")
                })?;
            }
        }
        Ok(())
    }

    pub fn attach(
        &self,
        inputs: &Registry<RouteInput>,
        devices: Arc<TunDeviceState>,
        member_registration: uuid::Uuid,
    ) -> anyhow::Result<RouteScopeLease> {
        anyhow::ensure!(self.0.config.get().is_some(), "route scope is not prepared");
        anyhow::ensure!(!self.is_closed(), "route scope is closed");
        let id = NEXT_BINDING.fetch_add(1, Ordering::Relaxed) + 1;
        let attachment = RouteAttachment {
            id,
            devices,
            ready: false,
        };
        let (cleanup, completed) = watch::channel(false);
        let lease = inputs
            .register(RouteInput {
                id,
                scope: self.clone(),
                member_registration,
                cleanup,
                observed: AtomicBool::new(false),
            })
            .ok_or_else(|| anyhow::anyhow!("route outlet is closed"))?;
        let input = lease
            .get()
            .ok_or_else(|| anyhow::anyhow!("route outlet is closed"))?;
        if self.is_closed() {
            anyhow::bail!("route scope is closed");
        }
        self.0.routes.publish_status(RouteStatus::default());
        *self.0.cleanup.lock() = Some(completed);
        self.0.binding.send_replace(Some(attachment));
        drop(input);
        Ok(RouteScopeLease {
            lease: Some(lease),
            scope: self.clone(),
            id,
        })
    }
}

pub(crate) struct RouteInput {
    pub id: u64,
    pub scope: RouteScope,
    pub member_registration: uuid::Uuid,
    pub cleanup: watch::Sender<bool>,
    observed: AtomicBool,
}

impl RouteInput {
    pub fn revoke(&self) {
        self.scope.revoke_binding(self.id);
    }
    pub fn observe(&self) {
        self.observed.store(true, Ordering::Relaxed);
    }
    pub fn is_current(&self) -> bool {
        !self.scope.is_closed()
            && self
                .scope
                .0
                .binding
                .borrow()
                .as_ref()
                .is_some_and(|attachment| attachment.id == self.id)
    }

    pub fn is_ready(&self) -> bool {
        !self.scope.is_closed()
            && self
                .scope
                .0
                .binding
                .borrow()
                .as_ref()
                .is_some_and(|attachment| attachment.id == self.id && attachment.ready)
    }
}

impl Drop for RouteInput {
    fn drop(&mut self) {
        self.revoke();
        // An input withdrawn before the writer ever saw it has no OS effects.
        if !self.observed.load(Ordering::Relaxed) {
            self.cleanup.send_replace(true);
        }
    }
}

/// Non-cloneable membership of a scope in one logical outlet. Revoking this
/// binding does not close the instance's declarations or claim OS cleanup.
pub(crate) struct RouteScopeLease {
    lease: Option<Registration<RouteInput>>,
    scope: RouteScope,
    id: u64,
}

impl Drop for RouteScopeLease {
    fn drop(&mut self) {
        self.scope.revoke_binding(self.id);
        self.lease.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use easytier_core::host::route::RouteDemand;

    fn scope() -> RouteScope {
        let scope = RouteScope::new(uuid::Uuid::new_v4());
        scope
            .prepare(CoreRuntimeConfigStore::new(
                Default::default(),
                Arc::new(Default::default()),
            ))
            .unwrap();
        scope
    }

    #[tokio::test]
    async fn closing_an_unobserved_outlet_revokes_binding_without_closing_instance() {
        let scope = scope();
        let inputs = Registry::default();
        let devices = TunDeviceState::new(Arc::new(std::sync::Mutex::new(None)));
        let _lease = scope
            .attach(&inputs, devices, uuid::Uuid::new_v4())
            .unwrap();
        scope.mark_ready(scope.attachment().unwrap().id);
        inputs.close();
        assert!(scope.attachment().is_none());
        scope.wait_withdrawn().await.unwrap();
        assert!(
            scope
                .handle()
                .register(RouteDemand::additional([]))
                .is_some()
        );
    }

    #[test]
    fn failed_attachment_does_not_revoke_the_existing_binding() {
        let scope = scope();
        let devices = TunDeviceState::new(Arc::new(std::sync::Mutex::new(None)));
        let first = Registry::default();
        let _lease = scope
            .attach(&first, devices.clone(), uuid::Uuid::new_v4())
            .unwrap();
        let id = scope.attachment().unwrap().id;
        let closed = Registry::default();
        closed.close();
        assert!(
            scope
                .attach(&closed, devices, uuid::Uuid::new_v4())
                .is_err()
        );
        assert_eq!(scope.attachment().unwrap().id, id);
    }
}
