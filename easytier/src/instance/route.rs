use crate::common::error::Error;
use crate::common::ifcfg;
use crate::common::ifcfg::IfConfiger;
use crate::instance::instance::ArcNicCtx;
use crate::instance::virtual_nic::NicCtx;
use cidr::IpCidr;
use std::collections::{BTreeMap, HashSet};
use tokio::sync::mpsc::{channel, Receiver, Sender};

#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum RouteSource {
    Proxy,
}

/// Default channel size for route control messages.
pub const ROUTE_CHANNEL_CAPACITY: usize = 64;

/// Desired route entry from a source snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RouteSpec {
    pub destination: IpCidr,
    pub metric: Option<i32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteSourceState {
    generation: u64,
    routes: Option<HashSet<RouteSpec>>,
}

/// Route manager command.
///
/// `SyncState` replaces the full route set for one source when generation is newer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteCommand {
    SyncSource {
        source: RouteSource,
        state: RouteSourceState,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct RouteReconcilePlan {
    pub to_add: Vec<RouteSpec>,
    pub to_remove: Vec<RouteSpec>,
}

#[derive(Debug)]
pub struct RouteManager {
    nic_ctx: ArcNicCtx,
    ifcfg: IfConfiger,
    sources: BTreeMap<RouteSource, RouteSourceState>,
    tx: Sender<RouteCommand>,
    rx: Receiver<RouteCommand>,
}

impl RouteManager {
    pub fn new(nic_ctx: ArcNicCtx) -> Self {
        let (tx, rx) = channel(ROUTE_CHANNEL_CAPACITY);
        Self {
            nic_ctx,
            ifcfg: ifcfg::get(),
            sources: BTreeMap::new(),
            tx,
            rx,
        }
    }

    pub fn tx(&self) -> Sender<RouteCommand> {
        self.tx.clone()
    }

    async fn add_route(&self, route: &RouteSpec) -> Result<(), Error> {
        let Some(nic_ctx) = self
            .nic_ctx
            .lock()
            .await
            .and_then(|nic_ctx| nic_ctx.nic_ctx.as_ref())
            .and_then(|nic_ctx| nic_ctx.downcast_ref::<NicCtx>())
        else {
            return Err(Error::NotFound);
        };
        let Some(ifname) = nic_ctx.ifname().await else {
            return Err(Error::NotFound);
        };

        match route.destination {
            IpCidr::V4(cidr) => {
                self.ifcfg
                    .add_ipv4_route(
                        ifname.as_str(),
                        cidr.first_address(),
                        cidr.network_length(),
                        route.metric,
                    )
                    .await
            }
            IpCidr::V6(cidr) => {
                self.ifcfg
                    .add_ipv6_route(
                        ifname.as_str(),
                        cidr.first_address(),
                        cidr.network_length(),
                        route.metric,
                    )
                    .await
            }
        }
    }

    async fn remove_route(&self, route: &RouteSpec) -> Result<(), Error> {
        match route.destination {
            IpCidr::V4(cidr) => {
                self.ifcfg
                    .remove_ipv4_route(&route.ifname, cidr.first_address(), cidr.network_length())
                    .await
            }
            IpCidr::V6(cidr) => {
                self.ifcfg
                    .remove_ipv6_route(&route.ifname, cidr.first_address(), cidr.network_length())
                    .await
            }
        }
    }

    async fn sync(&self) {}

    pub async fn run(&mut self) {
        while let Some(cmd) = self.rx.recv().await {
            match cmd {
                RouteCommand::SyncSource { source, state } => {
                    if self
                        .sources
                        .get(&source)
                        .is_some_and(|s| state.generation <= s.generation)
                    {
                        continue;
                    }
                    if state.routes.is_none() {
                        self.sources.remove(&source);
                    } else {
                        self.sources.insert(source, state);
                    }
                    self.sync().await;
                }
            }
        }
    }
}
