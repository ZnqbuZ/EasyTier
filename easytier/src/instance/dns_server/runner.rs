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


