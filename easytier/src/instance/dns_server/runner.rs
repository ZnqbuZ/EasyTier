use cidr::Ipv4Inet;
use tokio_util::sync::CancellationToken;

use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use easytier_core::host::route::{
    RouteHandle, RouteSet, RouteSlot, RouteSource, RouteSpec, RouteStatus,
};
use easytier_core::instance::CorePacketPlane;

use crate::{common::global_ctx::ArcGlobalCtx, instance::virtual_nic::NicBackend};

use super::{client_instance::MagicDnsClientInstance, server_instance::MagicDnsServerInstance};

pub struct DnsRunner {
    client: Option<MagicDnsClientInstance>,
    server: Option<MagicDnsServerInstance>,
    packet_plane: Arc<CorePacketPlane>,
    global_ctx: ArcGlobalCtx,
    tun_dev: Option<String>,
    tun_inet: Ipv4Inet,
    fake_ip: Ipv4Addr,
    shared_route_backend: Option<NicBackend>,
    managed_routes: Option<RouteHandle>,
    active_fake_ip_route: Option<MagicDnsFakeIpRouteClaim>,
}

enum MagicDnsFakeIpRouteClaim {
    Legacy {
        fake_ip: Ipv4Addr,
        route_backend: NicBackend,
    },
    Managed {
        slot: RouteSlot,
    },
}

impl MagicDnsFakeIpRouteClaim {
    async fn remove(self) {
        match self {
            // Dropping the slot only withdraws this declaration. It does not
            // guarantee the physical route is uninstalled: another owner may
            // still need the same prefix.
            Self::Managed { slot } => drop(slot),
            Self::Legacy {
                fake_ip,
                route_backend,
            } => {
                if let Err(err) = route_backend.remove_route(fake_ip, 32).await {
                    tracing::warn!(?err, ?fake_ip, "remove magic dns route failed");
                }
            }
        }
    }
}

impl DnsRunner {
    pub(crate) fn new(
        packet_plane: Arc<CorePacketPlane>,
        global_ctx: ArcGlobalCtx,
        tun_dev: Option<String>,
        tun_inet: Ipv4Inet,
        fake_ip: Ipv4Addr,
    ) -> Self {
        Self {
            client: None,
            server: None,
            packet_plane,
            global_ctx,
            tun_dev,
            tun_inet,
            fake_ip,
            shared_route_backend: None,
            managed_routes: None,
            active_fake_ip_route: None,
        }
    }

    pub(crate) fn with_shared_route_backend(mut self, route_backend: Option<NicBackend>) -> Self {
        self.shared_route_backend = route_backend;
        self
    }

    pub(crate) fn with_managed_routes(mut self, routes: RouteHandle) -> Self {
        self.managed_routes = Some(routes);
        self.shared_route_backend = None;
        self
    }

    async fn clean_env(&mut self) {
        if let Some(mut server) = self.server.take() {
            server.clean_env().await;
        }
        if let Some(claim) = self.active_fake_ip_route.take() {
            claim.remove().await;
        }
        self.client.take();
    }

    fn should_manage_fake_ip_route_externally(&self) -> bool {
        (self.shared_route_backend.is_some() || self.managed_routes.is_some())
            && !self.tun_inet.contains(&self.fake_ip)
    }

    async fn run_once(&mut self, cancel_token: &CancellationToken) -> anyhow::Result<()> {
        // Try to become the server first. The prepared server owns the resolver
        // but does not touch system DNS until its fake-ip route is ready.
        let server_result = if self.should_manage_fake_ip_route_externally() {
            MagicDnsServerInstance::new_with_external_fake_ip_route(
                self.packet_plane.clone(),
                self.global_ctx.clone(),
                self.tun_dev.clone(),
                self.tun_inet,
                self.fake_ip,
            )
            .await
        } else {
            MagicDnsServerInstance::new(
                self.packet_plane.clone(),
                self.global_ctx.clone(),
                self.tun_dev.clone(),
                self.tun_inet,
                self.fake_ip,
            )
            .await
        };

        match server_result {
            Ok(server) => {
                // Own the prepared server before publishing any route so every
                // later failure reaches async cleanup through `clean_env`.
                self.server = Some(server);

                if let Some(routes) = self.managed_routes.clone()
                    && !self.tun_inet.contains(&self.fake_ip)
                {
                    let slot = routes.open_slot(RouteSource::Additional)?;
                    let spec =
                        RouteSpec::for_tun(cidr::Ipv4Cidr::new(self.fake_ip, 32).unwrap().into());
                    slot.set_routes(RouteSet::from([spec.clone()]));
                    self.active_fake_ip_route =
                        Some(MagicDnsFakeIpRouteClaim::Managed { slot: slot.clone() });

                    loop {
                        let notified = slot.changed().notified();
                        match slot.statuses().get(&spec) {
                            Some(RouteStatus::Ready) => break,
                            Some(RouteStatus::Pending { .. }) => {
                                tokio::select! {
                                    _ = cancel_token.cancelled() => {
                                        anyhow::bail!("DNS fake-ip route readiness cancelled")
                                    }
                                    _ = notified => {}
                                }
                            }
                            Some(RouteStatus::Suppressed(err)) => {
                                anyhow::bail!("magic dns fake-ip route suppressed: {err}")
                            }
                            Some(RouteStatus::Rejected(err)) => {
                                anyhow::bail!("magic dns fake-ip route rejected: {err}")
                            }
                            Some(RouteStatus::Failed(err)) => {
                                anyhow::bail!("magic dns fake-ip route failed: {err}")
                            }
                            None => anyhow::bail!(
                                "magic dns fake-ip route declaration disappeared while waiting"
                            ),
                        }
                    }
                } else if self.should_manage_fake_ip_route_externally()
                    && let Some(route_backend) = self.shared_route_backend.clone()
                {
                    self.active_fake_ip_route = Some(MagicDnsFakeIpRouteClaim::Legacy {
                        fake_ip: self.fake_ip,
                        route_backend: route_backend.clone(),
                    });
                    let cost = if cfg!(target_os = "windows") {
                        Some(4)
                    } else {
                        None
                    };
                    route_backend
                        .add_route_with_cost(self.fake_ip, 32, cost)
                        .await
                        .map_err(|err| {
                            anyhow::anyhow!("failed to add magic dns fake-ip route: {err}")
                        })?;
                }

                if cancel_token.is_cancelled() {
                    anyhow::bail!("DNS server cancelled after route preparation");
                }

                self.server
                    .as_ref()
                    .unwrap()
                    .apply_system_config(self.global_ctx.get_flags().tld_dns_zone.clone())
                    .await?;
                tracing::info!("DnsRunner::run_once: server started");
            }
            Err(e) => {
                tracing::error!("DnsRunner::run_once: {:?}", e);
            }
        }

        // Every runner must run a client. This phase and the pending route wait
        // above both observe cancellation; server initialization and the system
        // DNS write are awaited to completion before async cleanup starts.
        tokio::select! {
            _ = cancel_token.cancelled() => Ok(()),
            ret = async {
                let client = MagicDnsClientInstance::new(self.packet_plane.clone(), self.global_ctx.net_ns.clone()).await?;
                self.client = Some(client);
                self.client.as_mut().unwrap().run_and_wait().await;
                Err(anyhow::anyhow!("Client instance exit"))
            } => ret,
        }
    }

    pub async fn run(&mut self, cancel_token: CancellationToken) {
        while !cancel_token.is_cancelled() {
            tracing::info!("DnsRunner::run: start");
            let ret = self.run_once(&cancel_token).await;
            self.clean_env().await;
            if cancel_token.is_cancelled() {
                break;
            }
            if let Err(e) = ret {
                tracing::error!("DnsRunner::run: {:?}", e);
            } else {
                tracing::info!("DnsRunner::run: unexpected exit, server may be down");
            }
            tokio::select! {
                _ = cancel_token.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_millis(500)) => {}
            }
        }
        tracing::info!("DnsRunner::run: cancelled");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use easytier_core::foundation::dirty::DirtyFlag;
    use easytier_core::host::route::Registry;

    #[tokio::test]
    async fn managed_claim_final_drop_withdraws_only_the_declaration() {
        let dirty = Arc::new(DirtyFlag::new(false));
        let root = Arc::new(Registry::new(dirty.clone()));
        let slot = root.handle().open_slot(RouteSource::Additional).unwrap();
        let spec = RouteSpec::for_tun("100.100.100.100/32".parse().unwrap());
        slot.set_routes(RouteSet::from([spec]));

        let inner = root.slots()[0].upgrade().unwrap();
        assert_eq!(inner.source(), RouteSource::Additional);
        let slot_weak = Arc::downgrade(&inner);
        drop(inner);

        dirty.reset();
        let claim = MagicDnsFakeIpRouteClaim::Managed { slot };
        claim.remove().await;

        assert!(
            slot_weak.upgrade().is_none(),
            "the final claim drop must withdraw the declaration"
        );
        assert!(dirty.peek(), "the final slot drop must wake the controller");
        assert!(root.slots().is_empty());
    }

    #[cfg(target_os = "linux")]
    mod readiness_tests {
        use std::sync::Weak;

        use super::super::*;
        use crate::common::global_ctx::tests::get_mock_global_ctx;
        use crate::instance::composition::{NativeCoreInstance, runtime_core_host_adapters};
        use crate::instance::config::test_core_instance_config;
        use crate::instance::dns_server::{
            DEFAULT_ET_DNS_ZONE, MAGIC_DNS_FAKE_IP, MAGIC_DNS_INSTANCE_ADDR,
            MAGIC_DNS_INSTANCE_SOCKET_ADDR,
        };
        use crate::proto::common::Void;
        use crate::proto::magic_dns::{
            HandshakeRequest, MagicDnsServerRpc as _, MagicDnsServerRpcClientFactory,
        };
        use crate::proto::rpc::standalone::{net_ns_rpc_client, net_ns_rpc_listener};
        use crate::proto::rpc_types::controller::BaseController;
        use easytier_core::foundation::dirty::DirtyFlag;
        use easytier_core::host::packet::{HostPacket, HostPacketChannelSink};
        use easytier_core::host::route::{Registry, RouteDevice, RouteSlotInner};
        use easytier_core::process_runtime::CoreProcessRuntime;
        use easytier_core::socket::SocketListener as _;

        const TUN_INET: &str = "10.50.0.1/24";
        const WAIT_TIMEOUT: Duration = Duration::from_secs(10);

        struct RunnerFixture {
            ctx: ArcGlobalCtx,
            registry: Arc<Registry>,
            dirty: Arc<DirtyFlag>,
            core: Arc<NativeCoreInstance>,
            _packet_rx: tokio::sync::mpsc::Receiver<HostPacket>,
        }

        impl RunnerFixture {
            fn new(hostname: &str) -> Self {
                let ctx = get_mock_global_ctx();
                ctx.set_hostname(hostname.to_owned());
                ctx.set_ipv4(Some(TUN_INET.parse().unwrap()));

                let (packet_sink, packet_rx) = tokio::sync::mpsc::channel(8);
                let adapters = runtime_core_host_adapters(
                    ctx.clone(),
                    CoreProcessRuntime::new(),
                    Arc::new(HostPacketChannelSink::new(packet_sink)),
                );
                let core = NativeCoreInstance::new(test_core_instance_config(&ctx), adapters)
                    .expect("test core configuration must build");

                let dirty = Arc::new(DirtyFlag::new(false));
                let registry = Arc::new(Registry::new(dirty.clone()));
                Self {
                    ctx,
                    registry,
                    dirty,
                    core,
                    _packet_rx: packet_rx,
                }
            }

            fn runner(&self) -> DnsRunner {
                DnsRunner::new(
                    self.core.packet_plane(),
                    self.ctx.clone(),
                    None,
                    TUN_INET.parse().unwrap(),
                    MAGIC_DNS_FAKE_IP.parse().unwrap(),
                )
                .with_managed_routes(self.registry.handle())
            }
        }

        fn fake_ip_spec() -> RouteSpec<RouteDevice> {
            RouteSpec::for_tun(format!("{MAGIC_DNS_FAKE_IP}/32").parse().unwrap())
        }

        async fn wait_for_fake_ip_declaration(
            registry: &Arc<Registry>,
            spec: &RouteSpec<RouteDevice>,
        ) -> Weak<RouteSlotInner> {
            tokio::time::timeout(WAIT_TIMEOUT, async {
                loop {
                    for slot in registry.slots() {
                        let Some(inner) = slot.upgrade() else {
                            continue;
                        };
                        let declared = inner.source() == RouteSource::Additional
                            && inner.routes().contains(spec);
                        drop(inner);
                        if declared {
                            return slot;
                        }
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("the fake-ip route declaration was not published before the wait timed out")
        }

        fn update_status(
            slot: &Weak<RouteSlotInner>,
            spec: &RouteSpec<RouteDevice>,
            status: RouteStatus,
        ) {
            let inner = slot
                .upgrade()
                .expect("the fake-ip route slot must stay alive");
            inner.update_statuses(|route| (route == spec).then(|| status.clone()));
        }

        async fn assert_cleanup_releases_role(
            runner: &mut DnsRunner,
            env: &RunnerFixture,
            slot_weak: &Weak<RouteSlotInner>,
        ) {
            tokio::time::timeout(WAIT_TIMEOUT, runner.clean_env())
                .await
                .expect("cleanup must release the DNS role before the wait times out");
            assert!(runner.server.is_none(), "cleanup must drop the server");
            assert!(runner.client.is_none(), "cleanup must drop the client");
            assert!(
                runner.active_fake_ip_route.is_none(),
                "cleanup must withdraw the route claim"
            );
            assert!(
                slot_weak.upgrade().is_none(),
                "cleanup must drop the last slot reference"
            );
            assert!(
                env.dirty.peek(),
                "the final slot drop must wake the controller"
            );
            assert!(env.registry.slots().is_empty());

            let mut available = net_ns_rpc_listener(
                env.ctx.net_ns.clone(),
                MAGIC_DNS_INSTANCE_SOCKET_ADDR.parse().unwrap(),
            )
            .unwrap();
            tokio::time::timeout(WAIT_TIMEOUT, available.listen())
                .await
                .expect("reacquiring the DNS server RPC role must finish before the wait times out")
                .expect("cleanup must release the DNS server RPC role");
        }

        fn response_contains_local_record(
            response: &crate::proto::magic_dns::GetDnsRecordResponse,
            hostname: &str,
            ip: Ipv4Addr,
        ) -> bool {
            let Some(records) = response.records.get(DEFAULT_ET_DNS_ZONE) else {
                return false;
            };
            let expected_name = format!("{hostname}.{DEFAULT_ET_DNS_ZONE}");
            records.records.iter().any(|record| {
                let Some(crate::proto::magic_dns::dns_record::Record::A(a)) =
                    record.record.as_ref()
                else {
                    return false;
                };
                a.name == expected_name && a.value.map(Ipv4Addr::from) == Some(ip)
            })
        }

        async fn wait_for_local_dns_record(ctx: &ArcGlobalCtx, hostname: &str, ip: Ipv4Addr) {
            let mut client =
                net_ns_rpc_client(ctx.net_ns.clone(), MAGIC_DNS_INSTANCE_ADDR.parse().unwrap())
                    .unwrap();
            let stub = client
                .scoped_client::<MagicDnsServerRpcClientFactory<BaseController>>(String::new())
                .await
                .expect("the started DNS server must accept an independent reader");
            loop {
                if let Ok(response) = stub
                    .get_dns_record(BaseController::default(), Void::default())
                    .await
                    && response_contains_local_record(&response, hostname, ip)
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }

        #[tokio::test]
        #[ignore = "run inside an isolated user+network namespace"]
        async fn occupied_rpc_role_keeps_the_runner_from_publishing_a_slot() {
            let env = RunnerFixture::new("runner-occupied");
            let address = MAGIC_DNS_INSTANCE_SOCKET_ADDR.parse().unwrap();
            let mut occupied = net_ns_rpc_listener(env.ctx.net_ns.clone(), address).unwrap();
            tokio::time::timeout(WAIT_TIMEOUT, occupied.listen())
                .await
                .expect(
                    "the occupying DNS server RPC listener must start before the wait times out",
                )
                .unwrap();

            let mut runner = env.runner();
            let cancel = CancellationToken::new();
            cancel.cancel();
            let result = tokio::time::timeout(WAIT_TIMEOUT, runner.run_once(&cancel))
                .await
                .expect("a pre-cancelled runner must leave the client phase immediately");
            assert!(result.is_ok(), "{result:?}");

            assert!(
                runner.server.is_none(),
                "a failed role attempt must not leave a server"
            );
            assert!(
                runner.active_fake_ip_route.is_none(),
                "a failed role attempt must not leave a route claim"
            );
            assert!(env.registry.slots().is_empty());
            tokio::time::timeout(WAIT_TIMEOUT, runner.clean_env())
                .await
                .expect("cleanup must finish before the wait times out");

            drop(occupied);
            let mut available = net_ns_rpc_listener(env.ctx.net_ns.clone(), address).unwrap();
            tokio::time::timeout(WAIT_TIMEOUT, available.listen())
                .await
                .expect("reacquiring the RPC role must finish before the wait times out")
                .expect("the RPC role must be acquirable after the occupied listener is released");
        }

        #[tokio::test]
        #[ignore = "run inside an isolated user+network namespace"]
        async fn rejected_pending_route_reports_error_and_cleanup_releases_the_server_role() {
            let env = RunnerFixture::new("runner-rejected");
            let mut runner = env.runner();
            let cancel = CancellationToken::new();
            let spec = fake_ip_spec();
            let mut run = Box::pin(runner.run_once(&cancel));

            let slot_weak = tokio::select! {
                biased;
                result = &mut run => {
                    panic!("run_once exited before publishing the fake-ip route: {result:?}")
                }
                slot = wait_for_fake_ip_declaration(&env.registry, &spec) => slot,
            };

            // The prepared resolver answers RPC while the fake-ip route is still
            // pending.
            tokio::time::timeout(WAIT_TIMEOUT, async {
                let mut client = net_ns_rpc_client(
                    env.ctx.net_ns.clone(),
                    MAGIC_DNS_INSTANCE_ADDR.parse().unwrap(),
                )
                .unwrap();
                let stub = client
                    .scoped_client::<MagicDnsServerRpcClientFactory<BaseController>>(String::new())
                    .await
                    .expect("the prepared resolver must accept RPC clients");
                stub.handshake(BaseController::default(), HandshakeRequest::default())
                    .await
                    .expect("the prepared resolver must answer handshakes");
            })
            .await
            .expect(
                "the prepared resolver must complete its RPC handshake while the route is pending",
            );

            env.dirty.reset();
            update_status(
                &slot_weak,
                &spec,
                RouteStatus::Pending {
                    error: Some("route still installing".into()),
                },
            );
            let pending = tokio::time::timeout(Duration::from_millis(200), &mut run).await;
            assert!(
                pending.is_err(),
                "a pending feedback change must not complete run_once: {pending:?}"
            );

            update_status(
                &slot_weak,
                &spec,
                RouteStatus::Rejected("route denied by policy".into()),
            );
            let error = tokio::time::timeout(WAIT_TIMEOUT, &mut run)
                .await
                .expect("run_once must observe the rejected status")
                .expect_err("a rejected fake-ip route must fail the run");
            drop(run);

            assert!(
                error
                    .to_string()
                    .contains("magic dns fake-ip route rejected: route denied by policy"),
                "unexpected error: {error}"
            );
            assert!(
                runner.client.is_none(),
                "the client must not start before the route is ready"
            );
            assert!(
                runner.server.is_some(),
                "the prepared server must stay reachable for cleanup"
            );
            assert!(
                runner.active_fake_ip_route.is_some(),
                "the failed readiness must keep its claim until cleanup"
            );

            assert_cleanup_releases_role(&mut runner, &env, &slot_weak).await;
        }

        #[tokio::test]
        #[ignore = "run inside an isolated user+network namespace"]
        async fn cancelling_a_pending_route_releases_the_server_role() {
            let env = RunnerFixture::new("runner-cancelled");
            let mut runner = env.runner();
            let cancel = CancellationToken::new();
            let spec = fake_ip_spec();
            let mut run = Box::pin(runner.run_once(&cancel));

            let slot_weak = tokio::select! {
                biased;
                result = &mut run => {
                    panic!("run_once exited before publishing the fake-ip route: {result:?}")
                }
                slot = wait_for_fake_ip_declaration(&env.registry, &spec) => slot,
            };

            env.dirty.reset();
            // Cancel while the fake-ip route is still pending: the runner has
            // not reached `apply_system_config`, so no system DNS write is
            // abandoned by stopping this future.
            cancel.cancel();
            let error = tokio::time::timeout(WAIT_TIMEOUT, &mut run)
                .await
                .expect("cancellation must reach the pending route wait")
                .expect_err("cancelling a pending route must fail the run");
            drop(run);

            assert!(
                error
                    .to_string()
                    .contains("DNS fake-ip route readiness cancelled"),
                "unexpected error: {error}"
            );
            assert!(runner.client.is_none());
            assert!(runner.server.is_some());
            assert!(runner.active_fake_ip_route.is_some());

            assert_cleanup_releases_role(&mut runner, &env, &slot_weak).await;
        }

        #[tokio::test]
        #[ignore = "run inside an isolated user+network namespace"]
        async fn ready_route_starts_the_publishing_client_before_cancel() {
            let hostname = "runner-ready";
            let env = RunnerFixture::new(hostname);
            let mut runner = env.runner();
            let cancel = CancellationToken::new();
            let spec = fake_ip_spec();
            let mut run = Box::pin(runner.run_once(&cancel));

            let slot_weak = tokio::select! {
                biased;
                result = &mut run => {
                    panic!("run_once exited before publishing the fake-ip route: {result:?}")
                }
                slot = wait_for_fake_ip_declaration(&env.registry, &spec) => slot,
            };

            env.dirty.reset();
            update_status(&slot_weak, &spec, RouteStatus::Ready);

            let expected_ip: Ipv4Addr = "10.50.0.1".parse().unwrap();
            // The independent reader only calls `get_dns_record`; seeing the
            // fixture identity here proves the runner passed system DNS
            // configuration and started its client publisher.
            tokio::select! {
                biased;
                result = &mut run => {
                    panic!("run_once exited before the client published the local DNS record: {result:?}")
                }
                observed = tokio::time::timeout(
                    WAIT_TIMEOUT,
                    wait_for_local_dns_record(&env.ctx, hostname, expected_ip),
                ) => {
                    observed.expect("the started client never published the fixture local DNS record");
                }
            };

            cancel.cancel();
            let result = tokio::time::timeout(WAIT_TIMEOUT, &mut run)
                .await
                .expect("the client phase must stop on cancellation");
            drop(run);
            result.expect("cancelling the running client must return Ok");

            assert!(
                runner.client.is_some(),
                "the runner must own the started client until cleanup"
            );
            assert!(runner.server.is_some());
            assert!(runner.active_fake_ip_route.is_some());

            assert_cleanup_releases_role(&mut runner, &env, &slot_weak).await;
        }
    }
}
