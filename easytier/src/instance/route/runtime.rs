//! Native instance ownership. I/O tasks receive context, never close authority.

use easytier_core::{
    config::runtime::CoreRuntimeConfigStore,
    host::route::{Registry, RouteHandle},
};
use parking_lot::Mutex;
use std::sync::Arc;
use uuid::Uuid;

use super::RouteController;
#[cfg(all(feature = "tun", not(mobile)))]
use super::{InterfaceInfo, interface_index};
#[cfg(all(feature = "tun", mobile))]
use crate::instance::shared_virtual_nic::SharedIfConfigClaims;
use crate::{
    common::global_ctx::ArcGlobalCtx,
    host_runtime::{NativeNetNSServices, net_ns_services},
};
#[cfg(feature = "tun")]
use crate::{
    common::net_ns::NetNS,
    instance::{shared_virtual_nic::SharedVirtualNicMember, virtual_nic::VirtualNicConfig},
};

pub(crate) struct NativeRouteContext {
    net_ns: Arc<NativeNetNSServices>,
    run: Uuid,
    name: String,
    /// The one public-address intent. On mobile the controller observes this
    /// exact mutex instead of a second address value.
    public_address: Arc<Mutex<Option<cidr::Ipv6Inet>>>,
    pub(crate) handle: RouteHandle,
    controller: RouteController,
}

impl NativeRouteContext {
    pub(crate) fn ensure_open(&self) -> anyhow::Result<()> {
        self.net_ns.ensure_open()?;
        self.controller.ensure_instance_open(self.run)
    }

    #[cfg(feature = "tun")]
    pub(crate) fn config(&self, mtu: u32) -> VirtualNicConfig {
        VirtualNicConfig::new(self.name.clone(), mtu, NetNS::clone(&self.net_ns))
            .with_routes_managed(true)
    }

    #[cfg(feature = "tun")]
    pub(crate) fn bind_member(&self, member: &SharedVirtualNicMember) -> anyhow::Result<()> {
        self.ensure_open()?;
        self.controller.bind_member(self.run, member)
    }

    #[cfg(all(feature = "tun", not(mobile)))]
    pub(crate) async fn ready(
        &self,
        member: &SharedVirtualNicMember,
        applied_public_address: Option<cidr::Ipv6Inet>,
    ) -> anyhow::Result<bool> {
        if *self.public_address.lock() != applied_public_address {
            return Ok(false);
        }
        self.ensure_open()?;
        let ifname = member
            .ifname()
            .await
            .ok_or_else(|| anyhow::anyhow!("shared NIC member has no interface name"))?;
        let ifindex = interface_index(&self.net_ns, &ifname)?;
        // The address intent may have moved while the device was queried; only
        // the intent that is still current may confirm this configuration.
        let intent = self.public_address.lock();
        if *intent != applied_public_address {
            return Ok(false);
        }
        self.controller.ready(
            self.run,
            member,
            InterfaceInfo {
                name: ifname,
                ifindex,
            },
        )
    }

    #[cfg(mobile)]
    pub(crate) fn external_routes(&self) -> anyhow::Result<easytier_core::host::route::RouteSet> {
        self.ensure_open()?;
        Ok(self.controller.effective_routes_for_instance(&self.run))
    }

    /// Record one member's real mobile attachment.
    ///
    /// The validity and registration check and the Controller write happen
    /// without an intervening await. The dispatcher marks a dead NIC invalid
    /// before its member streams end, so a stream that really failed cannot be
    /// recorded as attached afterwards. Root release and namespace shutdown do
    /// not discard a genuine fact, so this does not call `ensure_open`.
    #[cfg(all(feature = "tun", mobile))]
    pub(crate) async fn mobile_ready(
        &self,
        member: &SharedVirtualNicMember,
        attachment_id: Uuid,
    ) -> anyhow::Result<bool> {
        let shared_nic = member.shared_nic();
        let guard = tokio::time::timeout(std::time::Duration::from_secs(5), shared_nic.lock())
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "timed out locking shared NIC for member {}",
                    member.member_id()
                )
            })?;
        if member.ensure_open().is_err()
            || !guard.is_valid()
            || !guard.is_current_member_registration(member.member_id(), member.registration_id())
        {
            return Ok(false);
        }
        // No await between the check above and this synchronous Controller write.
        Ok(self
            .controller
            .mobile_ready(self.run, member, attachment_id))
    }

    #[cfg(all(feature = "tun", mobile))]
    pub(crate) fn mobile_dns_enabled(&self) -> bool {
        self.controller.mobile_dns_enabled(self.run)
    }

    #[cfg(all(feature = "tun", mobile))]
    pub(crate) fn mobile_installed_claims(&self) -> Option<SharedIfConfigClaims> {
        self.controller.mobile_installed_claims(self.run)
    }

    pub(crate) fn public_address(&self) -> Option<cidr::Ipv6Inet> {
        *self.public_address.lock()
    }

    /// Test-only observation of the shared route input mark.
    #[cfg(test)]
    pub(crate) fn input_is_dirty(&self) -> bool {
        self.controller.route_input_is_dirty()
    }

    /// Test-only reset of the shared route input mark.
    #[cfg(test)]
    pub(crate) fn reset_input_dirty(&self) {
        self.controller.reset_route_input_dirty();
    }

    /// Mark this instance's route inputs as changed after an actual fact write.
    ///
    /// A released root has already withdrawn the input; invalidating then only
    /// marks the shared input range and never reopens anything.
    pub(crate) fn invalidate_input(&self) {
        self.controller.invalidate_instance(&self.run);
    }

    /// The real current claims of the bound mobile member, when it is a valid
    /// selection hint. This is the existing NIC read, not the old snapshot.
    #[cfg(all(feature = "tun", mobile))]
    pub(crate) async fn mobile_current_claims(
        &self,
    ) -> anyhow::Result<Option<SharedIfConfigClaims>> {
        self.controller.mobile_current_claims(self.run).await
    }

    #[cfg(feature = "public-ipv6-provider")]
    fn public_address_changing(&self, address: Option<cidr::Ipv6Inet>) {
        let mut current = self.public_address.lock();
        if *current != address {
            *current = address;
            self.controller.invalidate_instance(&self.run);
        }
    }

    #[cfg(feature = "tun")]
    pub(crate) async fn unready(&self, member: &SharedVirtualNicMember) {
        self.controller.unready(self.run, member.registration_id());
    }
}

pub(crate) struct NativeRouteRuntime {
    owner: Mutex<Option<Arc<Registry>>>,
    context: Arc<NativeRouteContext>,
}

impl NativeRouteRuntime {
    pub(crate) fn new(global_ctx: &ArcGlobalCtx) -> anyhow::Result<Self> {
        let net_ns = net_ns_services(&global_ctx.net_ns)?;
        let run = global_ctx.key();
        let name = global_ctx.get_flags().dev_name.clone();
        let controller = net_ns.route_controller()?;
        let owner = controller.open_instance(run)?;
        let handle = owner.handle();
        let public_address = Arc::new(Mutex::new(None));
        #[cfg(all(mobile, feature = "tun"))]
        controller.bind_mobile_inputs(run, Arc::downgrade(global_ctx), public_address.clone())?;
        let context = Arc::new(NativeRouteContext {
            net_ns,
            run,
            name,
            public_address,
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
        anyhow::ensure!(owner.is_some(), "native routes are closing");
        // Hold the guard across the bind so a concurrent request_close cannot
        // release the root while the first configuration is being applied.
        self.context
            .controller
            .bind_config(self.context.run, config)
    }

    pub(crate) fn request_close(&self) {
        let owner = self.owner.lock().take();
        // Release the root reference outside the owner lock; its final drop
        // wakes the controller.
        drop(owner);
    }

    pub(crate) async fn drain(&self) -> anyhow::Result<()> {
        self.request_close();
        // A released root is not proof of cleanup: the existing reconciler
        // still has to finish the actual work for this run.
        self.context.controller.drain(self.context.run).await
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{common::config::TomlConfig, utils::dirty::DirtyFlag};
    use easytier_core::{
        config::{
            peers::PeerRuntimeSnapshot,
            runtime::{CoreRuntimeConfig, CoreRuntimeConfigStore},
        },
        host::route::{RouteInputError, RouteSet, RouteSource, RouteSpec, RouteStatus},
    };
    use std::time::Duration;
    use tokio::sync::Notify;

    fn global_ctx() -> ArcGlobalCtx {
        Arc::new(crate::common::global_ctx::GlobalCtx::new(
            TomlConfig::default(),
        ))
    }

    fn config_store() -> CoreRuntimeConfigStore {
        CoreRuntimeConfigStore::new(
            CoreRuntimeConfig::default(),
            Arc::new(PeerRuntimeSnapshot::default()),
        )
    }

    /// A controller without a worker: nothing removes the instance record, so
    /// cleanup stays outstanding for the whole test.
    fn runtime_without_worker(global: &ArcGlobalCtx) -> NativeRouteRuntime {
        let net_ns = net_ns_services(&global.net_ns).unwrap();
        let controller = RouteController::new(Arc::new(DirtyFlag::new(false)));
        let run = global.key();
        let owner = controller.open_instance(run).unwrap();
        let handle = owner.handle();
        let context = Arc::new(NativeRouteContext {
            net_ns,
            run,
            name: global.get_flags().dev_name.clone(),
            public_address: Arc::new(Mutex::new(None)),
            handle,
            controller,
        });
        NativeRouteRuntime {
            owner: Mutex::new(Some(owner)),
            context,
        }
    }

    #[test]
    fn releasing_the_native_root_closes_new_slots_and_keeps_old_slots_mutable() {
        let global = global_ctx();
        let runtime = runtime_without_worker(&global);
        let context = runtime.context();
        runtime.bind_config(config_store()).unwrap();
        let slot = context.handle.open_slot(RouteSource::Additional).unwrap();

        runtime.request_close();

        assert!(
            context.ensure_open().is_err(),
            "the context must not keep the released registry alive"
        );
        assert!(
            matches!(
                context.handle.open_slot(RouteSource::Additional),
                Err(RouteInputError::Closed)
            ),
            "a released root cannot open new inputs"
        );
        assert!(
            runtime.bind_config(config_store()).is_err(),
            "configuration binding requires a live root"
        );

        let declaration = RouteSpec::for_tun("10.44.0.0/24".parse().unwrap());
        slot.set_routes(RouteSet::from([declaration.clone()]));
        assert_eq!(
            slot.statuses().get(&declaration),
            Some(&RouteStatus::Pending { error: None }),
            "an existing slot stays mutable after its root is gone"
        );
    }

    #[test]
    fn invalidate_input_marks_the_shared_range() {
        let global = global_ctx();
        let runtime = runtime_without_worker(&global);
        let context = runtime.context();
        context.reset_input_dirty();
        assert!(!context.input_is_dirty());
        context.invalidate_input();
        assert!(
            context.input_is_dirty(),
            "an actual input change marks the shared route range"
        );
    }

    #[test]
    fn dropping_the_native_runtime_naturally_releases_the_registry_root() {
        let global = global_ctx();
        let context = {
            let runtime = runtime_without_worker(&global);
            runtime.context()
        };

        assert!(
            context.ensure_open().is_err(),
            "the owner field is the only strong root"
        );
        assert!(matches!(
            context.handle.open_slot(RouteSource::Additional),
            Err(RouteInputError::Closed)
        ));
    }

    #[tokio::test]
    async fn repeated_drain_never_reports_success_while_cleanup_is_still_owed() {
        let global = global_ctx();
        let runtime = runtime_without_worker(&global);

        for attempt in 0..2 {
            assert!(
                tokio::time::timeout(Duration::from_millis(100), runtime.drain())
                    .await
                    .is_err(),
                "drain attempt {attempt} must wait for real cleanup instead of \
                 treating the released root as success"
            );
        }
    }

    #[cfg(all(feature = "tun", not(mobile)))]
    #[tokio::test]
    async fn ready_rejects_stale_public_addresses_and_missing_devices() {
        let global = global_ctx();
        let runtime = runtime_without_worker(&global);
        let context = runtime.context();
        let mut nics = crate::instance::shared_virtual_nic::SharedVirtualNicRegistry::new();
        let member = nics
            .try_create_member(
                "synthetic".into(),
                context.config(1400),
                context.run,
                Arc::new(Notify::new()),
            )
            .unwrap();
        context.bind_member(&member).unwrap();

        #[cfg(feature = "public-ipv6-provider")]
        let address: cidr::Ipv6Inet = "2001:db8::1/128".parse().unwrap();
        #[cfg(feature = "public-ipv6-provider")]
        {
            context.public_address_changing(Some(address));
            assert!(
                !context.ready(&member, None).await.unwrap(),
                "a callback from an older public address is not applied"
            );
        }
        let error = context
            .ready(&member, context.public_address())
            .await
            .expect_err("a member without a real device must not report ready");
        assert!(
            error.to_string().contains("interface name"),
            "unexpected error: {error:#}"
        );

        runtime.request_close();
        assert!(
            context
                .ready(&member, context.public_address())
                .await
                .is_err(),
            "a closed root cannot confirm a binding"
        );
    }
}
