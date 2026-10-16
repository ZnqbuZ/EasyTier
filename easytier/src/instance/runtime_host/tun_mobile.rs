use std::sync::Arc;

use anyhow::Context as _;
use easytier_core::{
    gateway::dhcp::DhcpHost, host::packet::HostPacketReceiver, instance::CorePacketPlane,
};
use tokio::sync::{Mutex, Notify, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use super::tun_common::{NativeDhcpHost, TunNicState};
use crate::{
    common::global_ctx::ArcGlobalCtx,
    instance::{shared_virtual_nic::ArcSharedVirtualNicRegistry, virtual_nic::NicCtx},
};

struct MobileTunAttachment {
    fd: i32,
    replace_tun_fd: bool,
    completion: Option<oneshot::Sender<anyhow::Result<()>>>,
    claims: Option<crate::instance::shared_virtual_nic::SharedIfConfigClaims>,
    installed_prefixes: std::collections::BTreeSet<cidr::IpCidr>,
}

pub(super) struct NativeTunRuntime {
    global_ctx: ArcGlobalCtx,
    routes: Option<Arc<crate::instance::route::runtime::NativeRouteContext>>,
    cancel: CancellationToken,
    nic: TunNicState,
    tun_fd: mpsc::Sender<MobileTunAttachment>,
    tun_fd_receiver: Mutex<Option<mpsc::Receiver<MobileTunAttachment>>>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    shared_virtual_nic_registry: ArcSharedVirtualNicRegistry,
}

impl NativeTunRuntime {
    pub(super) fn new(
        global_ctx: ArcGlobalCtx,
        cancel: CancellationToken,
        shared_virtual_nic_registry: ArcSharedVirtualNicRegistry,
        routes: Option<Arc<crate::instance::route::runtime::NativeRouteContext>>,
    ) -> Self {
        let (tun_fd, tun_fd_receiver) = mpsc::channel(16);
        Self {
            global_ctx,
            routes,
            cancel,
            nic: TunNicState::empty(),
            tun_fd,
            tun_fd_receiver: Mutex::new(Some(tun_fd_receiver)),
            task: Mutex::new(None),
            shared_virtual_nic_registry,
        }
    }

    pub(super) fn install_packet_receiver(
        &self,
        receiver: HostPacketReceiver,
    ) -> anyhow::Result<()> {
        self.nic.install_receiver(receiver)
    }

    async fn install_mobile_tun(
        nic_state: TunNicState,
        global_ctx: ArcGlobalCtx,
        packet_plane: Arc<CorePacketPlane>,
        fd: i32,
        replace_tun_fd: bool,
        shared_virtual_nic_registry: ArcSharedVirtualNicRegistry,
        claims: Option<crate::instance::shared_virtual_nic::SharedIfConfigClaims>,
        routes: Option<Arc<crate::instance::route::runtime::NativeRouteContext>>,
        installed_prefixes: std::collections::BTreeSet<cidr::IpCidr>,
    ) -> anyhow::Result<()> {
        nic_state.drain().await?;
        if fd <= 0 {
            return Ok(());
        }
        let closed = Arc::new(Notify::new());
        let nic = NicCtx::new(
            global_ctx.clone(),
            packet_plane.clone(),
            nic_state.receiver(),
            closed,
            shared_virtual_nic_registry,
            routes,
        )
        .await?;
        let claims = match claims {
            Some(claims) => claims,
            None => {
                anyhow::bail!("mobile TUN attachment requires its installed configuration snapshot")
            }
        };
        nic_state
            .configure_for_mobile(
                nic,
                global_ctx,
                packet_plane,
                fd,
                replace_tun_fd,
                claims,
                installed_prefixes,
            )
            .await
            .context("attach mobile TUN failed")?;
        Ok(())
    }

    pub(super) async fn prepare(&self, packet_plane: Arc<CorePacketPlane>) -> anyhow::Result<()> {
        self.nic.drain().await?;
        let Some(mut tun_fds) = self.tun_fd_receiver.lock().await.take() else {
            return Ok(());
        };
        let nic_state = self.nic.clone();
        let global_ctx = self.global_ctx.clone();
        let cancel = self.cancel.clone();
        let shared_virtual_nic_registry = self.shared_virtual_nic_registry.clone();
        let routes = self.routes.clone();
        self.task.lock().await.replace(tokio::spawn(async move {
            let unfinished = loop {
                let attachment = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => break "instance is closing",
                    attachment = tun_fds.recv() => match attachment {
                        Some(attachment) => attachment,
                        None => break "the mobile TUN runtime stopped",
                    },
                };
                let result = Self::install_mobile_tun(
                    nic_state.clone(),
                    global_ctx.clone(),
                    packet_plane.clone(),
                    attachment.fd,
                    attachment.replace_tun_fd,
                    shared_virtual_nic_registry.clone(),
                    attachment.claims,
                    routes.clone(),
                    attachment.installed_prefixes,
                )
                .await;
                let result = match result {
                    Ok(()) => Ok(()),
                    Err(error) => {
                        tracing::error!(?error, "failed to attach mobile TUN fd");
                        // Finish the existing NIC error cleanup before reporting
                        // the real failure to the caller.
                        match nic_state.stop().await {
                            Ok(()) => Err(error),
                            Err(cleanup) => Err(error.context(format!(
                                "mobile TUN cleanup failed after attachment error: {cleanup:#}"
                            ))),
                        }
                    }
                };
                if let Some(completion) = attachment.completion {
                    let _ = completion.send(result);
                }
            };
            // Requests already accepted by the channel but never picked up
            // still receive a real "not executed" result.
            while let Ok(attachment) = tun_fds.try_recv() {
                if let Some(completion) = attachment.completion {
                    let _ = completion.send(Err(anyhow::anyhow!(
                        "mobile TUN attachment was not executed: {unfinished}"
                    )));
                }
            }
        }));
        Ok(())
    }

    pub(super) async fn shutdown(&self) -> anyhow::Result<()> {
        self.cancel.cancel();
        let task_result = if let Some(task) = self.task.lock().await.take() {
            task.await.map_err(|error| {
                anyhow::anyhow!("mobile TUN worker stopped without completing: {error}")
            })
        } else {
            Ok(())
        };
        let nic_result = self.nic.stop().await;
        match (task_result, nic_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(worker), Err(cleanup)) => {
                Err(worker.context(format!("mobile TUN local cleanup failed: {cleanup:#}")))
            }
        }
    }

    pub(super) fn attach_fd(&self, _fd: i32) -> anyhow::Result<()> {
        anyhow::bail!("use attach_mobile_tun_fd with the installed configuration snapshot")
    }

    pub(super) async fn attach_mobile_fd(
        &self,
        fd: i32,
        replace_tun_fd: bool,
        claims: Option<crate::instance::shared_virtual_nic::SharedIfConfigClaims>,
        installed_prefixes: std::collections::BTreeSet<cidr::IpCidr>,
    ) -> anyhow::Result<()> {
        if self.task.lock().await.is_none() {
            anyhow::bail!("mobile TUN runtime is not running");
        }

        let (completion, result) = oneshot::channel();
        // Cancellation may only prevent the request from being submitted.
        tokio::select! {
            _ = self.cancel.cancelled() => anyhow::bail!("instance is closing; TUN attachment cancelled"),
            send_result = self.tun_fd.send(MobileTunAttachment {
                fd,
                replace_tun_fd,
                completion: Some(completion),
                claims,
                installed_prefixes,
            }) => send_result.map_err(|error| {
                anyhow::anyhow!("mobile TUN attachment was not executed: {error}")
            })?,
        }

        // Once submitted, the real completion decides the outcome; closing the
        // instance does not make an accepted installation end.
        result.await.map_err(|_| {
            anyhow::anyhow!("mobile TUN runtime stopped before attachment completed")
        })?
    }

    pub(super) fn dhcp_host(
        &self,
        operation: Arc<Mutex<()>>,
        _packet_plane: Arc<CorePacketPlane>,
    ) -> Arc<dyn DhcpHost> {
        Arc::new(NativeDhcpHost {
            global_ctx: self.global_ctx.clone(),
            operation,
            cancel: self.cancel.clone(),
            nic: self.nic.clone(),
            routes: self.routes.clone(),
        })
    }
}


