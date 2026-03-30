use crate::common::error::Error;
use crate::instance::instance::ArcNicCtx;
use crate::nic::controller::{NicController, PlatformController};
use crate::nic::Nic;
use cidr::IpCidr;
use derivative::Derivative;
use std::collections::{BTreeMap, HashSet};
use tokio::sync::mpsc::{channel, Receiver, Sender};

#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum RouteSource {
    Nic,
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

#[derive(Derivative)]
#[derivative(Debug)]
pub struct RouteManager {
    #[derivative(Debug = "ignore")]
    nic: ArcNicCtx,
    sources: BTreeMap<RouteSource, RouteSourceState>,
    tx: Sender<RouteCommand>,
    rx: Receiver<RouteCommand>,
}

impl RouteManager {
    pub fn new(nic: ArcNicCtx) -> Self {
        let (tx, rx) = channel(ROUTE_CHANNEL_CAPACITY);
        Self {
            nic,
            sources: BTreeMap::new(),
            tx,
            rx,
        }
    }

    pub fn tx(&self) -> Sender<RouteCommand> {
        self.tx.clone()
    }

    async fn ctrl(&self)-> Result<NicController, Error>  {
        let nic = self.nic.lock().await;
        nic.as_ref()
            .and_then(|nic| nic.nic_ctx.as_ref())
            .and_then(|nic| nic.downcast_ref::<Nic>())
            .map(Nic::ctrl)
            .ok_or(Error::NotFound)
    }

    async fn add_route(&self, route: &RouteSpec) -> Result<(), Error> {
        let mut ctrl = self.ctrl().await?.write().await;

        match route.destination {
            IpCidr::V4(cidr) => {
                ctrl.add_ipv4_route(cidr.first_address(), cidr.network_length(), route.metric)
                    .await
            }
            IpCidr::V6(cidr) => {
                ctrl.add_ipv6_route(cidr.first_address(), cidr.network_length(), route.metric)
                    .await
            }
        }
    }

    async fn remove_route(&self, route: &RouteSpec) -> Result<(), Error> {
        let mut ctrl = self.ctrl().await?.write().await;

        match route.destination {
            IpCidr::V4(cidr) => {
                ctrl.remove_ipv4_route(cidr.first_address(), cidr.network_length())
                    .await
            }
            IpCidr::V6(cidr) => {
                ctrl.remove_ipv6_route(cidr.first_address(), cidr.network_length())
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
