use easytier_core::host::route::RouteSpec;

use super::{RouteBackend, RouteError};
use crate::common::net_ns::NetNS;
use std::collections::BTreeSet;
use tokio::runtime::Handle;

const UNSUPPORTED: &str = "native route control is not available on this target";

pub(crate) struct PlatformRouteBackend;
impl PlatformRouteBackend {
    pub(crate) fn new(_: &NetNS, _: &Handle) -> anyhow::Result<Self> {
        Ok(Self)
    }
}
impl RouteBackend for PlatformRouteBackend {
    async fn add(&mut self, _: &RouteSpec<u32>) -> Result<(), RouteError> {
        Err(unsupported())
    }
    async fn remove(&mut self, _: &RouteSpec<u32>) -> Result<(), RouteError> {
        Err(unsupported())
    }
    async fn existing(
        &mut self,
        _: &BTreeSet<RouteSpec<u32>>,
    ) -> Result<BTreeSet<RouteSpec<u32>>, RouteError> {
        Err(unsupported())
    }
}
fn unsupported() -> RouteError {
    RouteError::Failed(std::io::Error::new(std::io::ErrorKind::Unsupported, UNSUPPORTED).into())
}
