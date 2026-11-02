#[cfg(feature = "web-client")]
use easytier_core::config::runtime::CoreInstanceRuntimeConfig;
use easytier_core::{
    gateway::dhcp::DhcpHost, host::packet::HostPacketReceiver, instance::CorePacketPlane,
};
use guarden::guard;
use guarden::guard::boxed::BoxSyncGuard;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::{Mutex, watch};
use tokio_util::sync::CancellationToken;

use crate::common::global_ctx::ArcGlobalCtx;

mod dhcp;
mod event_journal;
mod implementation;
cfg_select! {
    not(feature = "tun") => {
        #[path = "runtime_host/tun_disabled.rs"]
        mod tun_runtime;
    },
    _ => {
        mod magic_dns;
        mod tun_common;
        cfg_select! {
            mobile => {
                #[path = "runtime_host/tun_mobile.rs"]
                mod tun_runtime;
            },
            _ => {
                #[path = "runtime_host/tun_desktop.rs"]
                mod tun_runtime;
            },
        }
    },
}

use super::runtime_executor::NativeInstanceExecutor;
use event_journal::EventJournal;
#[cfg(feature = "tun")]
use magic_dns::MagicDnsRuntime;
use tun_runtime::NativeTunRuntime;

#[derive(derive_more::Deref)]
pub(crate) struct NativeInstanceRuntimeHost {
    guard: BoxSyncGuard<NativeInstanceRuntimeState>,
}

pub(crate) struct NativeInstanceRuntimeState {
    global_ctx: ArcGlobalCtx,
    operation: Arc<Mutex<()>>,
    cancel: CancellationToken,
    event_journal: Arc<EventJournal>,
    tun: Arc<NativeTunRuntime>,
    cleanup_started: AtomicBool,
    cleanup_result: watch::Sender<Option<Result<(), Arc<str>>>>,
    #[cfg(any(not(mobile), feature = "tun"))]
    routes: Option<Arc<super::route::runtime::NativeRouteRuntime>>,
    executor: Option<NativeInstanceExecutor>,
}

impl NativeInstanceRuntimeHost {
    #[cfg(test)]
    pub(crate) fn new(global_ctx: ArcGlobalCtx) -> Arc<Self> {
        Self::new_with_executor(global_ctx, None).unwrap()
    }

    pub(super) fn new_with_executor(
        global_ctx: ArcGlobalCtx,
        executor: Option<NativeInstanceExecutor>,
    ) -> anyhow::Result<Arc<Self>> {
        #[cfg(any(not(mobile), feature = "tun"))]
        let routes = {
            #[cfg(mobile)]
            {
                // A TUN-enabled mobile instance owns its route inputs even
                // before the platform provides a TUN FD, so the initial export
                // can use them; no_tun instances create none.
                (!global_ctx.no_tun())
                    .then(|| {
                        super::route::runtime::NativeRouteRuntime::new(&global_ctx).map(Arc::new)
                    })
                    .transpose()?
            }
            #[cfg(not(mobile))]
            {
                // A desktop namespace always accepts ordinary system routes,
                // whether or not its instance also creates a TUN.
                Some(Arc::new(super::route::runtime::NativeRouteRuntime::new(
                    &global_ctx,
                )?))
            }
        };
        let cancel = CancellationToken::new();
        let tun = Arc::new(NativeTunRuntime::new(
            global_ctx.clone(),
            cancel.clone(),
            #[cfg(feature = "tun")]
            crate::host_runtime::net_ns_services(&global_ctx.net_ns)
                .expect("native instance domain must be registered")
                .nics
                .clone(),
            #[cfg(feature = "tun")]
            routes.as_ref().map(|routes| routes.context()),
        ));
        let event_journal = Arc::new(EventJournal::new(&global_ctx));
        let state = NativeInstanceRuntimeState {
            global_ctx,
            event_journal,
            operation: Arc::new(Mutex::new(())),
            cancel,
            tun,
            executor,
            cleanup_started: AtomicBool::new(false),
            cleanup_result: watch::channel(None).0,
            #[cfg(any(not(mobile), feature = "tun"))]
            routes,
        };
        Ok(Arc::new(Self {
            guard: guard!([state] state.request_runtime_shutdown()).boxed(),
        }))
    }

    async fn prepare_runtime(
        &self,
        packet_plane: Arc<CorePacketPlane>,
        runtime_config: easytier_core::config::runtime::CoreRuntimeConfigStore,
    ) -> anyhow::Result<Option<Arc<dyn DhcpHost>>> {
        let _operation = self.operation.lock().await;
        anyhow::ensure!(!self.cancel.is_cancelled(), "instance runtime is closing");
        #[cfg(any(not(mobile), feature = "tun"))]
        if let Some(routes) = &self.routes {
            routes.bind_config(runtime_config)?;
        }
        #[cfg(all(mobile, not(feature = "tun")))]
        let _ = runtime_config;
        anyhow::ensure!(!self.cancel.is_cancelled(), "instance runtime is closing");
        self.event_journal.start(self.cancel.clone()).await;
        self.tun.prepare(packet_plane.clone()).await?;
        Ok(Some(
            self.tun.dhcp_host(self.operation.clone(), packet_plane),
        ))
    }

    async fn shutdown_runtime(&self) {
        self.request_runtime_shutdown();
        let mut result = self.cleanup_result.subscribe();
        while result.borrow_and_update().is_none() {
            if result.changed().await.is_err() {
                break;
            }
        }
    }

    fn runtime_shutdown_error(&self) -> Option<String> {
        self.cleanup_result
            .borrow()
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(ToString::to_string)
    }

    #[cfg(any(not(mobile), feature = "tun"))]
    pub(super) fn route_context(&self) -> Option<Arc<super::route::runtime::NativeRouteContext>> {
        self.routes.as_ref().map(|routes| routes.context())
    }

    fn management_events_snapshot(&self) -> Vec<String> {
        self.event_journal.events()
    }

    #[cfg(feature = "web-client")]
    fn synchronize_global_ctx_config(
        &self,
        patch: &crate::proto::api::config::InstanceConfigPatch,
        config: &CoreInstanceRuntimeConfig,
    ) {
        if patch.hostname.is_some() {
            self.global_ctx.set_hostname(
                config
                    .peer
                    .runtime
                    .core
                    .node
                    .hostname
                    .clone()
                    .unwrap_or_default(),
            );
        }
        if patch.ipv4.is_some() && !config.services.dhcp_ipv4 {
            dhcp::write_runtime_addresses(
                &self.global_ctx,
                || {
                    #[cfg(any(not(mobile), feature = "tun"))]
                    if let Some(routes) = self.route_context() {
                        routes.invalidate_input();
                    }
                },
                Some(crate::common::global_ctx::GlobalCtx::runtime_ipv4(
                    &config.peer,
                )),
                None,
            );
        }
        if patch.ipv6.is_some() && !config.services.dhcp_ipv6 {
            dhcp::write_runtime_addresses(
                &self.global_ctx,
                || {
                    #[cfg(any(not(mobile), feature = "tun"))]
                    if let Some(routes) = self.route_context() {
                        routes.invalidate_input();
                    }
                },
                None,
                Some(crate::common::global_ctx::GlobalCtx::runtime_ipv6(
                    &config.peer,
                )),
            );
        }
        if patch.disable_relay_data.is_some() || patch.prefer_peer_relay.is_some() {
            self.global_ctx.set_flags(config.peer.flags.clone());
        }
    }

    pub(crate) fn subscribe_event(&self) -> crate::common::global_ctx::EventBusSubscriber {
        self.global_ctx.subscribe()
    }

    #[cfg(all(feature = "tun", mobile))]
    pub(crate) fn tun_enabled(&self) -> bool {
        !self.global_ctx.get_flags().no_tun
    }

    fn attach_runtime_tun_fd(&self, fd: i32) -> anyhow::Result<()> {
        self.tun.attach_fd(fd)
    }

    #[cfg(all(feature = "tun", mobile))]
    pub(crate) async fn attach_mobile_tun_fd(
        &self,
        fd: i32,
        replace_tun_fd: bool,
        claims: Option<crate::instance::shared_virtual_nic::SharedIfConfigClaims>,
        installed_prefixes: std::collections::BTreeSet<cidr::IpCidr>,
    ) -> anyhow::Result<()> {
        self.tun
            .attach_mobile_fd(fd, replace_tun_fd, claims, installed_prefixes)
            .await
    }

    #[cfg(all(feature = "tun", mobile))]
    pub(crate) async fn mobile_tun_claims(
        &self,
        _packet_plane: &CorePacketPlane,
    ) -> anyhow::Result<(
        crate::instance::shared_virtual_nic::SharedIfConfigClaims,
        Option<crate::instance::shared_virtual_nic::SharedIfConfigClaims>,
        bool,
    )> {
        use crate::instance::shared_virtual_nic::{
            SharedIfConfigClaims, SharedIpv4Route, SharedIpv6Route,
        };
        let routes = self
            .route_context()
            .ok_or_else(|| anyhow::anyhow!("mobile route controller is unavailable"))?;
        let mut claims = SharedIfConfigClaims::default();
        claims.ipv4_addresses.extend(self.global_ctx.get_ipv4());
        claims.ipv6_addresses.extend(self.global_ctx.get_ipv6());
        claims.ipv6_addresses.extend(routes.public_address());
        for route in routes.external_routes()? {
            match route.destination {
                cidr::IpCidr::V4(prefix) => {
                    claims.ipv4_routes.insert(SharedIpv4Route::new(
                        prefix.first_address(),
                        prefix.network_length(),
                        None,
                    ));
                }
                cidr::IpCidr::V6(prefix) => {
                    claims.ipv6_routes.insert(SharedIpv6Route::new(
                        prefix.first_address(),
                        prefix.network_length(),
                        None,
                    ));
                }
            }
        }
        Ok((
            claims,
            routes.mobile_current_claims().await?,
            cfg!(feature = "magic-dns")
                && routes.mobile_dns_enabled()
                && self.global_ctx.get_ipv4().is_some(),
        ))
    }

    #[cfg(all(feature = "tun", mobile))]
    pub(crate) fn instance_run_key(&self) -> uuid::Uuid {
        self.global_ctx.key()
    }

    fn install_packet_receiver(&self, receiver: HostPacketReceiver) -> anyhow::Result<()> {
        self.tun.install_packet_receiver(receiver)
    }
}

impl NativeInstanceRuntimeState {
    /// Wait for the route domain's real local cleanup.
    ///
    /// A bounded wait expiring is only a diagnostic: the real record is still
    /// owed, so this same future keeps waiting and never publishes a terminal
    /// result.
    #[cfg(any(not(mobile), feature = "tun"))]
    async fn drain_route_input(
        routes: Option<Arc<super::route::runtime::NativeRouteRuntime>>,
    ) -> anyhow::Result<()> {
        let Some(routes) = routes else {
            return Ok(());
        };
        loop {
            match routes.drain().await {
                Ok(()) => return Ok(()),
                Err(error) if crate::host_runtime::cleanup_timed_out(&error) => {
                    tracing::warn!(%error, "native route cleanup is still in progress");
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn request_runtime_shutdown(&self) {
        // Withdraw the instance's whole route input first, then stop the
        // business producers. The cleanup below still waits for the real
        // controller cleanup before touching the TUN.
        #[cfg(any(not(mobile), feature = "tun"))]
        if let Some(routes) = &self.routes {
            routes.request_close();
        }
        self.cancel.cancel();
        if self.cleanup_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let operation = self.operation.clone();
        let journal = self.event_journal.clone();
        let tun = self.tun.clone();
        let result = self.cleanup_result.clone();
        #[cfg(any(not(mobile), feature = "tun"))]
        let routes = self.routes.clone();
        // Created before spawn so loss of an unpolled cleanup is visible too.
        let on_interrupted = {
            let result = result.clone();
            move || {
                let reason: Arc<str> = "native runtime cleanup was interrupted".into();
                result.send_replace(Some(Err(reason)));
            }
        };
        let interrupted = guard!([on_interrupted] { on_interrupted(); });
        match crate::host_runtime::native_host_runtime().shared_executor() {
            Ok(shared) => {
                shared.spawn(async move {
                    let _operation = operation.lock().await;
                    journal.stop().await;

                    // Desktop keeps OS route cleanup before NIC teardown.
                    // Mobile first stops the local install worker, DNS,
                    // forwarding and member registrations, then drains the
                    // route controller; it never waits for external VPN work.
                    #[cfg(not(mobile))]
                    let outcome = match Self::drain_route_input(routes).await {
                        Ok(()) => tun.shutdown().await,
                        Err(error) => Err(error),
                    };
                    #[cfg(all(mobile, feature = "tun"))]
                    let outcome = {
                        let tun_result = tun.shutdown().await;
                        let route_result = Self::drain_route_input(routes).await;
                        match (tun_result, route_result) {
                            (Ok(()), Ok(())) => Ok(()),
                            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
                            (Err(tun_error), Err(route_error)) => Err(tun_error
                                .context(format!("native route cleanup failed: {route_error:#}"))),
                        }
                    };
                    #[cfg(all(mobile, not(feature = "tun")))]
                    let outcome = tun.shutdown().await;

                    if let Err(error) = &outcome {
                        tracing::warn!(%error, "native runtime cleanup incomplete");
                    }
                    result.send_replace(Some(
                        outcome.map_err(|error| Arc::<str>::from(format!("{error:#}"))),
                    ));
                    let _ = interrupted.defuse();
                });
            }
            Err(error) => {
                tracing::error!(?error, "native cleanup executor unavailable");
                // Publish the concrete failure and defuse the generic guard so
                // the real cause is not overwritten by "interrupted".
                result.send_replace(Some(Err(Arc::from(format!(
                    "native cleanup executor unavailable: {error}"
                )))));
                let _ = interrupted.defuse();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{
        config::TomlConfig,
        global_ctx::{GlobalCtx, GlobalCtxEvent},
    };

    fn runtime_host(global_ctx: ArcGlobalCtx) -> Arc<NativeInstanceRuntimeHost> {
        NativeInstanceRuntimeHost::new(global_ctx)
    }

    #[tokio::test]
    async fn cleanup_survives_cancellation_of_its_first_waiter() {
        let global_ctx = Arc::new(GlobalCtx::new(TomlConfig::default()));
        let host = runtime_host(global_ctx);
        let permit = host.operation.lock().await;
        let waiter_host = host.clone();
        let waiter = tokio::spawn(async move { waiter_host.shutdown_runtime().await });
        tokio::task::yield_now().await;
        waiter.abort();
        let _ = waiter.await;
        drop(permit);
        tokio::time::timeout(std::time::Duration::from_secs(3), host.shutdown_runtime())
            .await
            .unwrap();
        assert_eq!(host.cleanup_result.borrow().as_ref(), Some(&Ok(())));
    }

    #[cfg(not(mobile))]
    #[tokio::test]
    async fn desktop_route_context_exists_without_tun() {
        let global_ctx = Arc::new(GlobalCtx::new(TomlConfig::default()));
        let mut flags = global_ctx.get_flags();
        flags.no_tun = true;
        global_ctx.set_flags(flags);
        let host = runtime_host(global_ctx);
        let context = host
            .route_context()
            .expect("desktop instances own route inputs even with no_tun");
        // Only an empty Additional slot: publishing Index declarations here
        // would ask the real Host worker to modify the system routing table.
        let slot = context
            .handle
            .open_slot(easytier_core::host::route::RouteSource::Additional)
            .unwrap();
        drop(slot);
    }

    #[cfg(feature = "web-client")]
    fn runtime_config(config: &TomlConfig) -> CoreInstanceRuntimeConfig {
        let normalized = easytier_core::instance::CoreInstanceConfig::from_toml(config).unwrap();
        CoreInstanceRuntimeConfig {
            services: normalized.connectivity.runtime,
            peer: Arc::new(normalized.peer.snapshot),
        }
    }

    #[test]
    fn runtime_host_owns_event_subscription_context() {
        let global_ctx = Arc::new(GlobalCtx::new(TomlConfig::default()));
        let runtime_host = runtime_host(global_ctx.clone());
        let mut events = runtime_host.subscribe_event();

        global_ctx.issue_event(GlobalCtxEvent::CredentialChanged);

        assert_eq!(
            events.try_recv().unwrap(),
            GlobalCtxEvent::CredentialChanged
        );
    }

    #[cfg(feature = "web-client")]
    #[test]
    fn runtime_host_synchronizes_normalized_config_without_management() {
        use easytier_core::{config::toml::ConfigLoader as _, instance::InstanceRuntimeHost as _};

        let config = TomlConfig::default();
        config.set_hostname(Some("before".to_owned()));
        config.set_ipv4(Some("10.20.0.1/24".parse().unwrap()));
        config.set_ipv6(Some("fd00::1/64".parse().unwrap()));
        let global_ctx = Arc::new(GlobalCtx::new(config.clone()));
        let runtime_host = runtime_host(global_ctx.clone());

        assert_eq!(global_ctx.get_hostname(), "before");
        assert_eq!(global_ctx.get_ipv4(), Some("10.20.0.1/24".parse().unwrap()));
        assert_eq!(global_ctx.get_ipv6(), Some("fd00::1/64".parse().unwrap()));
        assert!(!global_ctx.get_flags().disable_relay_data);
        assert!(!global_ctx.get_flags().prefer_peer_relay);

        config.set_hostname(Some("after".to_owned()));
        config.set_ipv4(Some("10.20.0.2/24".parse().unwrap()));
        config.set_ipv6(Some("fd00::2/64".parse().unwrap()));
        let mut flags = config.get_flags();
        flags.disable_relay_data = true;
        flags.prefer_peer_relay = true;
        config.set_flags(flags);
        runtime_host.synchronize_config(
            &crate::proto::api::config::InstanceConfigPatch {
                hostname: Some("ignored-raw-hostname".to_owned()),
                ipv4: Some("10.99.0.1/24".parse::<cidr::Ipv4Inet>().unwrap().into()),
                ipv6: Some("fd99::1/64".parse::<cidr::Ipv6Inet>().unwrap().into()),
                disable_relay_data: Some(false),
                prefer_peer_relay: Some(false),
                ..Default::default()
            },
            &runtime_config(&config),
        );

        assert_eq!(global_ctx.get_hostname(), "after");
        assert_eq!(global_ctx.get_ipv4(), Some("10.20.0.2/24".parse().unwrap()));
        assert_eq!(global_ctx.get_ipv6(), Some("fd00::2/64".parse().unwrap()));
        assert!(global_ctx.get_flags().disable_relay_data);
        assert!(global_ctx.get_flags().prefer_peer_relay);
    }

    #[cfg(feature = "web-client")]
    #[test]
    fn static_sync_applies_actual_address_values() {
        use easytier_core::{config::toml::ConfigLoader as _, instance::InstanceRuntimeHost as _};

        let config = TomlConfig::default();
        config.set_ipv4(Some("10.30.0.1/24".parse().unwrap()));
        let global_ctx = Arc::new(GlobalCtx::new(config.clone()));
        let runtime_host = runtime_host(global_ctx.clone());

        runtime_host.synchronize_config(
            &crate::proto::api::config::InstanceConfigPatch {
                hostname: Some("renamed".to_owned()),
                ..Default::default()
            },
            &runtime_config(&config),
        );
        assert_eq!(
            global_ctx.get_ipv4(),
            Some("10.30.0.1/24".parse().unwrap()),
            "a hostname-only patch leaves the address unchanged"
        );

        runtime_host.synchronize_config(
            &crate::proto::api::config::InstanceConfigPatch {
                ipv4: Some("10.30.0.1/24".parse::<cidr::Ipv4Inet>().unwrap().into()),
                ..Default::default()
            },
            &runtime_config(&config),
        );
        assert_eq!(global_ctx.get_ipv4(), Some("10.30.0.1/24".parse().unwrap()));

        config.set_ipv4(None);
        runtime_host.synchronize_config(
            &crate::proto::api::config::InstanceConfigPatch {
                ipv4: Some("10.99.0.1/24".parse::<cidr::Ipv4Inet>().unwrap().into()),
                ..Default::default()
            },
            &runtime_config(&config),
        );
        assert_eq!(global_ctx.get_ipv4(), None);
    }

    #[cfg(feature = "web-client")]
    #[test]
    fn runtime_host_preserves_dhcp_ipv4_during_config_synchronization() {
        use easytier_core::{config::toml::ConfigLoader as _, instance::InstanceRuntimeHost as _};

        let config = TomlConfig::default();
        config.set_dhcp(true);
        let global_ctx = Arc::new(GlobalCtx::new(config.clone()));
        let runtime_host = runtime_host(global_ctx.clone());
        let lease = "10.20.0.7/24".parse().unwrap();
        global_ctx.set_ipv4(Some(lease));

        config.set_ipv4(None);
        runtime_host.synchronize_config(
            &crate::proto::api::config::InstanceConfigPatch {
                ipv4: Some("10.99.0.1/24".parse::<cidr::Ipv4Inet>().unwrap().into()),
                ..Default::default()
            },
            &runtime_config(&config),
        );

        assert_eq!(global_ctx.get_ipv4(), Some(lease));
    }
}
