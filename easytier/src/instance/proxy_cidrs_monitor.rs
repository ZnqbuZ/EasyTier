use std::collections::BTreeSet;
use std::time::Instant;

use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtxEvent};
use crate::peers::peer_manager::PeerManager;
use crate::utils::ptr::{SharedPtr, WeakPtr};
use tokio_util::task::AbortOnDropHandle;

/// ProxyCidrsMonitor monitors changes in proxy CIDRs from peer routes
/// and emits GlobalCtxEvent::ProxyCidrsUpdated with added/removed diffs.
pub struct ProxyCidrsMonitor {
    peer_mgr: WeakPtr<PeerManager>,
    global_ctx: ArcGlobalCtx,
}

impl ProxyCidrsMonitor {
    pub fn new(peer_mgr: WeakPtr<PeerManager>, global_ctx: ArcGlobalCtx) -> Self {
        Self {
            peer_mgr,
            global_ctx,
        }
    }

    /// Collects current proxy_cidrs from peer routes, VPN portal config, and manual routes.
    /// This is a static function that can be used for initial sync or recovery after Lagged errors.
    pub async fn diff_proxy_cidrs(
        peer_mgr: &PeerManager,
        global_ctx: &ArcGlobalCtx,
        cur_proxy_cidrs: &BTreeSet<cidr::Ipv4Cidr>,
    ) -> (
        BTreeSet<cidr::Ipv4Cidr>,
        Vec<cidr::Ipv4Cidr>,
        Vec<cidr::Ipv4Cidr>,
    ) {
        let proxy_cidrs = if let Some(routes) = global_ctx.config.get_routes() {
            // If manual routes exist, override entire proxy_cidrs
            routes.into_iter().collect()
        } else {
            // Collect proxy_cidrs from routes
            let mut proxy_cidrs = peer_mgr.list_proxy_cidrs().await;

            // Add VPN portal cidr to proxy_cidrs
            if let Some(vpn_cfg) = global_ctx.config.get_vpn_portal_config() {
                proxy_cidrs.insert(vpn_cfg.client_cidr);
            }

            proxy_cidrs
        };

        // Calculate diff
        if cur_proxy_cidrs == &proxy_cidrs {
            return (proxy_cidrs, Vec::new(), Vec::new());
        }
        let added = proxy_cidrs.difference(cur_proxy_cidrs).cloned().collect();
        let removed = cur_proxy_cidrs.difference(&proxy_cidrs).cloned().collect();

        (proxy_cidrs, added, removed)
    }

    /// Starts monitoring proxy_cidrs changes and emits events with diffs
    pub fn start(self) -> AbortOnDropHandle<()> {
        AbortOnDropHandle::new(tokio::spawn(async move {
            let mut cur_proxy_cidrs = BTreeSet::new();
            let mut last_update = None::<Instant>;

            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;

                let global_ctx = self.global_ctx.clone();
                let cur_cidrs = cur_proxy_cidrs.clone();
                let Some(result) = self.peer_mgr.with_async(async move |pm: &SharedPtr<PeerManager>, _| {
                    let last_update_time = pm.get_route_peer_info_last_update_time().await;
                    let (new_cidrs, added, removed) =
                        Self::diff_proxy_cidrs(&*pm, &global_ctx, &cur_cidrs).await;
                    (last_update_time, new_cidrs, added, removed)
                }).await else {
                    tracing::warn!("peer manager dropped, stopping ProxyCidrsMonitor");
                    break;
                };

                let (last_update_time, new_proxy_cidrs, added, removed) = result;

                if last_update == Some(last_update_time) {
                    continue;
                }
                last_update = Some(last_update_time);

                cur_proxy_cidrs = new_proxy_cidrs;

                if added.is_empty() && removed.is_empty() {
                    continue;
                }
                self.global_ctx
                    .issue_event(GlobalCtxEvent::ProxyCidrsUpdated(added, removed));
            }
        }))
    }
}
