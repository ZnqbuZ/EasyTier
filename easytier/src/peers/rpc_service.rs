use std::{
    time::Duration,
};

use crate::{
    proto::{
        api::instance::{
            AclManageRpc, CredentialManageRpc, DumpRouteRequest, DumpRouteResponse,
            GenerateCredentialRequest, GenerateCredentialResponse, GetAclStatsRequest,
            GetAclStatsResponse, GetForeignNetworkSummaryRequest, GetForeignNetworkSummaryResponse,
            GetWhitelistRequest, GetWhitelistResponse, ListCredentialsRequest,
            ListCredentialsResponse, ListForeignNetworkRequest, ListForeignNetworkResponse,
            ListGlobalForeignNetworkRequest, ListGlobalForeignNetworkResponse, ListPeerRequest,
            ListPeerResponse, ListPublicIpv6InfoRequest, ListPublicIpv6InfoResponse,
            ListRouteRequest, ListRouteResponse, PeerInfo, PeerManageRpc, RevokeCredentialRequest,
            RevokeCredentialResponse, ShowNodeInfoRequest, ShowNodeInfoResponse,
        },
        rpc_types::{self, controller::BaseController},
    },
    utils::ptr::WeakPtr,
};

use super::peer_manager::PeerManager;

#[derive(Clone)]
pub struct PeerManagerRpcService {
    peer_manager: WeakPtr<PeerManager>,
}

impl PeerManagerRpcService {
    pub fn new(peer_manager: WeakPtr<PeerManager>) -> Self {
        PeerManagerRpcService {
            peer_manager,
        }
    }

    pub async fn list_peers(peer_manager: &PeerManager) -> Vec<PeerInfo> {
        let mut peers = peer_manager.get_peer_map().list_peers();
        peers.extend(
            peer_manager
                .get_foreign_network_client()
                .get_peer_map()
                .list_peers()
                .iter(),
        );
        let peer_map = peer_manager.get_peer_map();
        let mut peer_infos = Vec::new();
        for peer in peers {
            let mut peer_info = PeerInfo {
                peer_id: peer,
                default_conn_id: peer_map
                    .get_peer_default_conn_id(peer)
                    .await
                    .map(Into::into),
                directly_connected_conns: peer_map
                    .get_directly_connections_by_peer_id(peer)
                    .into_iter()
                    .map(Into::into)
                    .collect(),
                ..Default::default()
            };

            if let Some(conns) = peer_map.list_peer_conns(peer).await {
                peer_info.conns = conns;
            } else if let Some(conns) = peer_manager
                .get_foreign_network_client()
                .get_peer_map()
                .list_peer_conns(peer)
                .await
            {
                peer_info.conns = conns;
            }

            peer_infos.push(peer_info);
        }

        peer_infos
    }
}

#[async_trait::async_trait]
impl PeerManageRpc for PeerManagerRpcService {
    type Controller = BaseController;
    async fn list_peer(
        &self,
        _: BaseController,
        _request: ListPeerRequest,
    ) -> Result<ListPeerResponse, rpc_types::error::Error> {
        self.peer_manager
            .with_async(async move |pm, _| {
                let mut reply = ListPeerResponse::default();
                let peers = PeerManagerRpcService::list_peers(&*pm).await;
                for peer in peers {
                    reply.peer_infos.push(peer);
                }
                Ok(reply)
            })
            .await
            .ok_or_else(|| {
                rpc_types::error::Error::ExecutionError(anyhow::anyhow!(
                    "PeerManager not available"
                ))
            })?
    }

    async fn list_public_ipv6_info(
        &self,
        _: BaseController,
        _request: ListPublicIpv6InfoRequest,
    ) -> Result<ListPublicIpv6InfoResponse, rpc_types::error::Error> {
        self.peer_manager
            .with_async(async move |pm, _| {
                Ok(pm.get_local_public_ipv6_info().await)
            })
            .await
            .ok_or_else(|| {
                rpc_types::error::Error::ExecutionError(anyhow::anyhow!(
                    "PeerManager not available"
                ))
            })?
    }

    async fn list_route(
        &self,
        _: BaseController,
        _request: ListRouteRequest,
    ) -> Result<ListRouteResponse, rpc_types::error::Error> {
        let routes = self
            .peer_manager
            .with_async(async move |pm, _| { pm.list_routes().await })
            .await
            .ok_or_else(|| {
                rpc_types::error::Error::ExecutionError(anyhow::anyhow!(
                    "PeerManager not available"
                ))
            })?;
        let reply = ListRouteResponse { routes };
        Ok(reply)
    }

    async fn dump_route(
        &self,
        _: BaseController,
        _request: DumpRouteRequest,
    ) -> Result<DumpRouteResponse, rpc_types::error::Error> {
        let result = self
            .peer_manager
            .with_async(async move |pm, _| { pm.dump_route().await })
            .await
            .ok_or_else(|| {
                rpc_types::error::Error::ExecutionError(anyhow::anyhow!(
                    "PeerManager not available"
                ))
            })?;
        let reply = DumpRouteResponse { result };
        Ok(reply)
    }

    async fn list_foreign_network(
        &self,
        _: BaseController,
        request: ListForeignNetworkRequest,
    ) -> Result<ListForeignNetworkResponse, rpc_types::error::Error> {
        let reply = self
            .peer_manager
            .with_async(async move |pm, _| {
                pm.get_foreign_network_manager()
                    .list_foreign_networks_with_options(request.include_trusted_keys)
                    .await
            })
            .await
            .ok_or_else(|| {
                rpc_types::error::Error::ExecutionError(anyhow::anyhow!(
                    "PeerManager not available"
                ))
            })?;
        Ok(reply)
    }

    async fn list_global_foreign_network(
        &self,
        _: BaseController,
        _request: ListGlobalForeignNetworkRequest,
    ) -> Result<ListGlobalForeignNetworkResponse, rpc_types::error::Error> {
        self.peer_manager
            .with_async(async move |pm, _| {
                Ok(pm.list_global_foreign_network().await)
            })
            .await
            .ok_or_else(|| {
                rpc_types::error::Error::ExecutionError(anyhow::anyhow!(
                    "PeerManager not available"
                ))
            })?
    }

    async fn get_foreign_network_summary(
        &self,
        _: BaseController,
        _request: GetForeignNetworkSummaryRequest,
    ) -> Result<GetForeignNetworkSummaryResponse, rpc_types::error::Error> {
        self.peer_manager
            .with_async(async move |pm, _| {
                Ok(GetForeignNetworkSummaryResponse {
                    summary: Some(pm.get_foreign_network_summary().await),
                })
            })
            .await
            .ok_or_else(|| {
                rpc_types::error::Error::ExecutionError(anyhow::anyhow!(
                    "PeerManager not available"
                ))
            })?
    }

    async fn show_node_info(
        &self,
        _: BaseController,
        _request: ShowNodeInfoRequest,
    ) -> Result<ShowNodeInfoResponse, rpc_types::error::Error> {
        self.peer_manager
            .with_async(async move |pm, _| {
                Ok(ShowNodeInfoResponse {
                    node_info: Some(pm.get_my_info().await),
                })
            })
            .await
            .ok_or_else(|| {
                rpc_types::error::Error::ExecutionError(anyhow::anyhow!(
                    "PeerManager not available"
                ))
            })?
    }
}

#[async_trait::async_trait]
impl AclManageRpc for PeerManagerRpcService {
    type Controller = BaseController;

    async fn get_acl_stats(
        &self,
        _: BaseController,
        _request: GetAclStatsRequest,
    ) -> Result<GetAclStatsResponse, rpc_types::error::Error> {
        self.peer_manager
            .with_async(async move |pm, _| {
                let acl_stats = pm
                    .get_global_ctx()
                    .get_acl_filter()
                    .get_stats();
                Ok(GetAclStatsResponse {
                    acl_stats: Some(acl_stats),
                })
            })
            .await
            .ok_or_else(|| {
                rpc_types::error::Error::ExecutionError(anyhow::anyhow!(
                    "PeerManager not available"
                ))
            })?
    }

    async fn get_whitelist(
        &self,
        _: BaseController,
        _request: GetWhitelistRequest,
    ) -> Result<GetWhitelistResponse, rpc_types::error::Error> {
        self.peer_manager
            .with_async(async move |pm, _| {
                let global_ctx = pm.get_global_ctx();
                let tcp_ports = global_ctx.config.get_tcp_whitelist();
                let udp_ports = global_ctx.config.get_udp_whitelist();
                tracing::info!(
                    "Getting whitelist - TCP: {:?}, UDP: {:?}",
                    tcp_ports,
                    udp_ports
                );
                Ok(GetWhitelistResponse {
                    tcp_ports,
                    udp_ports,
                })
            })
            .await
            .ok_or_else(|| {
                rpc_types::error::Error::ExecutionError(anyhow::anyhow!(
                    "PeerManager not available"
                ))
            })?
    }
}

#[async_trait::async_trait]
impl CredentialManageRpc for PeerManagerRpcService {
    type Controller = BaseController;

    async fn generate_credential(
        &self,
        _: BaseController,
        request: GenerateCredentialRequest,
    ) -> Result<GenerateCredentialResponse, rpc_types::error::Error> {
        self.peer_manager
            .with_async(async move |pm, _| {
                let global_ctx = pm.get_global_ctx();

                if global_ctx.get_network_identity().network_secret.is_none() {
                    return Err(rpc_types::error::Error::ExecutionError(anyhow::anyhow!(
                        "only admin nodes (with network_secret) can generate credentials"
                    )));
                }

                let ttl = if request.ttl_seconds > 0 {
                    Duration::from_secs(request.ttl_seconds as u64)
                } else {
                    return Err(rpc_types::error::Error::ExecutionError(anyhow::anyhow!(
                        "ttl_seconds must be positive"
                    )));
                };

                let (id, secret) = global_ctx
                    .get_credential_manager()
                    .generate_credential_with_options(
                        request.groups,
                        request.allow_relay,
                        request.allowed_proxy_cidrs,
                        ttl,
                        request.credential_id,
                        request.reusable.unwrap_or(true),
                    );

                global_ctx
                    .issue_event(crate::common::global_ctx::GlobalCtxEvent::CredentialChanged);

                Ok(GenerateCredentialResponse {
                    credential_id: id,
                    credential_secret: secret,
                })
            })
            .await
            .ok_or_else(|| {
                rpc_types::error::Error::ExecutionError(anyhow::anyhow!(
                    "PeerManager not available"
                ))
            })?
    }

    async fn revoke_credential(
        &self,
        _: BaseController,
        request: RevokeCredentialRequest,
    ) -> Result<RevokeCredentialResponse, rpc_types::error::Error> {
        self.peer_manager
            .with_async(async move |pm, _| {
                let global_ctx = pm.get_global_ctx();
                if global_ctx.get_network_identity().network_secret.is_none() {
                    return Err(rpc_types::error::Error::ExecutionError(anyhow::anyhow!(
                        "only admin nodes (with network_secret) can revoke credentials"
                    )));
                }

                let success = global_ctx
                    .get_credential_manager()
                    .revoke_credential(&request.credential_id);

                if success {
                    global_ctx.issue_event(
                        crate::common::global_ctx::GlobalCtxEvent::CredentialChanged,
                    );
                }

                Ok(RevokeCredentialResponse { success })
            })
            .await
            .ok_or_else(|| {
                rpc_types::error::Error::ExecutionError(anyhow::anyhow!(
                    "PeerManager not available"
                ))
            })?
    }

    async fn list_credentials(
        &self,
        _: BaseController,
        _request: ListCredentialsRequest,
    ) -> Result<ListCredentialsResponse, rpc_types::error::Error> {
        self.peer_manager
            .with_async(async move |pm, _| {
                let global_ctx = pm.get_global_ctx();

                Ok(ListCredentialsResponse {
                    credentials: global_ctx.get_credential_manager().list_credentials(),
                })
            })
            .await
            .ok_or_else(|| {
                rpc_types::error::Error::ExecutionError(anyhow::anyhow!(
                    "PeerManager not available"
                ))
            })?
    }
}
