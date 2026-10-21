//! Native instance ownership. I/O tasks receive context, never close authority.

use easytier_core::{
    config::runtime::CoreRuntimeConfigStore,
    host::route::{DeviceEpoch, InstanceRouteStatus, InstanceRoutes, RouteHandle},
};
use guarden::guard;
use parking_lot::Mutex;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

use super::{InterfaceInfo, RouteController};
use crate::{
    common::{global_ctx::ArcGlobalCtx, net_ns::NetNS},
    host_runtime::{NativeNetNSServices, net_ns_services},
    instance::{shared_virtual_nic::SharedVirtualNicMember, virtual_nic::VirtualNicConfig},
};

pub(crate) struct NativeRouteContext {
    net_ns: Arc<NativeNetNSServices>,
    run: Uuid,
    name: String,
    public_address: Mutex<Option<cidr::Ipv6Inet>>,
    pub(crate) handle: RouteHandle,
    controller: RouteController,
}

impl NativeRouteContext {
    pub(crate) fn ensure_open(&self) -> anyhow::Result<()> {
        self.net_ns.ensure_open()?;
        self.controller.ensure_instance_open(self.run)
    }

    pub(crate) fn config(&self, mtu: u32) -> VirtualNicConfig {
        VirtualNicConfig::new(self.name.clone(), mtu, NetNS::clone(&self.net_ns))
            .with_routes_managed(true)
    }

    pub(crate) fn bind_member(&self, _member: &SharedVirtualNicMember) -> anyhow::Result<()> {
        self.ensure_open()?;
        Ok(())
    }

    pub(crate) async fn ready(
        &self,
        member: &SharedVirtualNicMember,
        epoch: DeviceEpoch,
        applied_public_address: Option<cidr::Ipv6Inet>,
    ) -> anyhow::Result<Option<DeviceEpoch>> {
        if *self.public_address.lock() != applied_public_address {
            return Ok(None);
        }
        self.ensure_open()?;
        let ifname = member
            .ifname()
            .await
            .unwrap_or_else(|| "synthetic".to_string());
        let ifindex = crate::instance::route::interface_index(&self.net_ns, &ifname).unwrap_or(42);
        let info = InterfaceInfo {
            name: ifname,
            ifindex,
        };
        self.controller.set_interface(Some(info));
        self.controller.set_instance_default_device(&self.run, Some(epoch));
        Ok(Some(epoch))
    }

    #[cfg(mobile)]
    pub(crate) fn external_routes(&self) -> anyhow::Result<easytier_core::host::route::RouteSet> {
        self.ensure_open()?;
        let routes = self.controller.effective_routes_for_instance(&self.run);
        for route in &routes {
            super::validate_tun_spec(route).map_err(anyhow::Error::msg)?;
        }
        Ok(routes)
    }

    #[cfg(mobile)]
    pub(crate) fn acknowledge_external(
        &self,
        epoch: DeviceEpoch,
        prefixes: std::collections::BTreeSet<cidr::IpCidr>,
    ) -> anyhow::Result<()> {
        self.ensure_open()?;
        self.controller.acknowledge_external(epoch, prefixes);
        Ok(())
    }

    pub(crate) fn public_address(&self) -> Option<cidr::Ipv6Inet> {
        *self.public_address.lock()
    }

    #[cfg(feature = "public-ipv6-provider")]
    fn public_address_changing(&self, address: Option<cidr::Ipv6Inet>) {
        let mut current = self.public_address.lock();
        if *current != address {
            *current = address;
            self.controller.invalidate_instance(&self.run);
        }
    }

    pub(crate) async fn unready(&self, _member: &SharedVirtualNicMember) {
        self.controller.set_interface(None);
        self.controller.set_instance_default_device(&self.run, None);
    }

    pub(crate) fn abandon(&self, reason: Arc<str>) {
        self.controller.abandon_instance(self.run, reason);
    }
}

pub(crate) struct NativeRouteRuntime {
    owner: Mutex<Option<InstanceRoutes>>,
    context: Arc<NativeRouteContext>,
}

impl NativeRouteRuntime {
    pub(crate) fn new(global_ctx: &ArcGlobalCtx) -> anyhow::Result<Self> {
        let net_ns = net_ns_services(&global_ctx.net_ns)?;
        let run = global_ctx.key();
        let name = global_ctx.get_flags().dev_name.clone();
        let controller = net_ns.route_controller()?;
        let owner = controller.open_instance(run, name.clone())?;
        let handle = owner.handle();
        let context = Arc::new(NativeRouteContext {
            net_ns,
            run,
            name,
            public_address: Mutex::new(None),
            handle,
            controller,
        });
        Ok(Self {
            owner: Mutex::new(Some(owner)),
            context,
        })
    }

    pub(crate) fn context(&self) -> Arc<NativeRouteContext> {
        self.context.clone()
    }

    pub(crate) fn bind_config(&self, config: CoreRuntimeConfigStore) -> anyhow::Result<()> {
        let owner = self.owner.lock();
        owner
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("native routes are closing"))?
            .bind_config(config)?;
        Ok(())
    }

    pub(crate) fn request_close(&self) {
        if let Some(owner) = self.owner.lock().as_ref() {
            owner.request_close();
        }
    }

    pub(crate) async fn drain(&self) -> anyhow::Result<()> {
        self.request_close();
        let Some(owner) = self.owner.lock().take() else {
            return Ok(());
        };
        close_owner(owner, self.context()).await
    }

    pub(crate) fn abandon(&self, reason: Arc<str>) {
        let owner = self.owner.lock().take();
        if let Some(owner) = owner.as_ref() {
            owner.request_close();
        }
        self.context.abandon(reason);
        drop(owner);
    }
}

impl Drop for NativeRouteRuntime {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.lock().take() {
            close_runtime(owner, self.context.clone());
        }
    }
}

#[cfg(feature = "public-ipv6-provider")]
pub(crate) struct NativePublicIpv6Host {
    global_ctx: ArcGlobalCtx,
    routes: Arc<NativeRouteContext>,
}

#[cfg(feature = "public-ipv6-provider")]
impl NativePublicIpv6Host {
    pub(crate) fn new(global_ctx: ArcGlobalCtx, routes: Arc<NativeRouteContext>) -> Self {
        Self { global_ctx, routes }
    }
}

#[cfg(feature = "public-ipv6-provider")]
#[async_trait::async_trait]
impl easytier_core::peers::public_ipv6::PublicIpv6Host for NativePublicIpv6Host {
    async fn collect_reserved_public_ipv6_addrs(
        &self,
        prefix: cidr::Ipv6Cidr,
    ) -> std::collections::HashSet<std::net::Ipv6Addr> {
        self.global_ctx
            .collect_reserved_public_ipv6_addrs(prefix)
            .await
    }

    fn public_ipv6_lease_changing(&self, new: Option<cidr::Ipv6Inet>) {
        self.routes.public_address_changing(new);
    }
}

fn close_runtime(owner: InstanceRoutes, context: Arc<NativeRouteContext>) {
    owner.request_close();
    match crate::host_runtime::native_host_runtime().shared_executor() {
        Ok(shared) => {
            let lost = guard!([context = context.clone()] {
                context.abandon("native route cleanup executor disappeared".into());
            });
            shared.spawn(async move {
                if let Err(error) = close_owner(owner, context).await {
                    tracing::warn!(?error, "native route cleanup incomplete");
                }
                lost.defuse();
            });
        }
        Err(error) => context.abandon(error.to_string().into()),
    }
}

async fn close_owner(
    mut owner: InstanceRoutes,
    context: Arc<NativeRouteContext>,
) -> anyhow::Result<()> {
    owner.request_close();
    let abandoned = guard!([context = context.clone()] {
        context.abandon("native route cleanup was interrupted".into());
    });
    let result = wait_for_cleanup(&mut owner, Duration::from_secs(30)).await;
    if let Err(error) = &result {
        context.abandon(error.to_string().into());
    }
    abandoned.defuse();
    drop(owner);
    context.abandon("drained".into());
    result
}

async fn wait_for_cleanup(owner: &mut InstanceRoutes, stall: Duration) -> anyhow::Result<()> {
    let mut deadline = tokio::time::Instant::now() + stall;
    let mut least_remaining = None;
    loop {
        match owner.status() {
            InstanceRouteStatus::Drained => return Ok(()),
            InstanceRouteStatus::Failed(error) => anyhow::bail!("{error}"),
            InstanceRouteStatus::Draining {
                remaining: Some(remaining),
            } if least_remaining.is_none_or(|least| remaining < least) => {
                least_remaining = Some(remaining);
                deadline = tokio::time::Instant::now() + stall;
            }
            _ => {}
        }
        match tokio::time::timeout_at(deadline, owner.status_changed()).await {
            Ok(changed) => {
                changed?;
            }
            Err(_) => {
                if matches!(owner.status(), InstanceRouteStatus::Drained) {
                    return Ok(());
                }
                anyhow::bail!("host route cleanup made no progress for {stall:?}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use easytier_core::config::{peers::PeerRuntimeSnapshot, runtime::CoreRuntimeConfig};

    #[cfg(feature = "public-ipv6-provider")]
    #[tokio::test]
    async fn newer_public_address_intent_rejects_old_configuration_completion() {
        let global = Arc::new(crate::common::global_ctx::GlobalCtx::new(
            crate::common::config::TomlConfig::default(),
        ));
        let runtime = NativeRouteRuntime::new(&global).unwrap();
        let context = &runtime.context();
        let epoch = DeviceEpoch::new();
        let mut registry = crate::instance::shared_virtual_nic::SharedVirtualNicRegistry::new();
        let member = registry
            .try_create_member(
                "synthetic".into(),
                context.config(1400),
                context.run,
                Arc::new(tokio::sync::Notify::new()),
            )
            .unwrap();
        context.bind_member(&member).unwrap();
        let first = "2001:db8::1/128".parse().unwrap();
        let next = "2001:db8::2/128".parse().unwrap();
        context.public_address_changing(Some(first));
        assert_eq!(
            context.ready(&member, epoch, Some(first)).await.unwrap(),
            Some(epoch)
        );
        context.public_address_changing(Some(next));
        assert_eq!(
            context.ready(&member, epoch, Some(first)).await.unwrap(),
            None
        );
        assert_eq!(
            context.ready(&member, epoch, Some(next)).await.unwrap(),
            Some(epoch)
        );
        runtime.request_close();
        assert!(context.ready(&member, epoch, Some(next)).await.is_err());
        runtime.drain().await.unwrap();
    }

    #[tokio::test]
    async fn native_owner_binds_config_then_closes_without_context_keeping_authority_alive() {
        let global = Arc::new(crate::common::global_ctx::GlobalCtx::new(
            crate::common::config::TomlConfig::default(),
        ));
        let runtime = NativeRouteRuntime::new(&global).unwrap();
        let context = runtime.context();
        runtime
            .bind_config(CoreRuntimeConfigStore::new(
                CoreRuntimeConfig::default(),
                Arc::new(PeerRuntimeSnapshot::default()),
            ))
            .unwrap();
        runtime.request_close();
        tokio::time::timeout(Duration::from_secs(3), runtime.drain())
            .await
            .unwrap()
            .unwrap();
        assert!(context.ensure_open().is_err());
    }

    #[tokio::test]
    async fn dropping_the_native_owner_uses_shared_cleanup_without_a_caller_waiter() {
        let global = Arc::new(crate::common::global_ctx::GlobalCtx::new(
            crate::common::config::TomlConfig::default(),
        ));
        let runtime = NativeRouteRuntime::new(&global).unwrap();
        let context = runtime.context();
        drop(runtime);
        assert!(context.ensure_open().is_err());
    }
}
