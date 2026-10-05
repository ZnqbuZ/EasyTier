use super::model::{Route, RouteError};

pub trait RouteBackend: Send + 'static {
    /// Add a route to the system.
    /// - Ok(Some(route)): Successfully created by this manager (record in `installed_routes`).
    /// - Ok(None): Equivalent entry already present in system, not created by us (record in `external_present`).
    /// - Err(RouteError::Failed(err)): Deterministic failure (track retry with backoff).
    /// - Err(RouteError::Unknown(err)): Unknown outcome (isolate in `unknown_routes`, never blind retry).
    fn add(
        &mut self,
        route: &Route,
    ) -> impl std::future::Future<Output = Result<Option<Route>, RouteError>> + Send;

    /// Remove a route from the system.
    /// - Ok(Some(())): Successfully removed by this manager (remove from `installed_routes`).
    /// - Ok(None): Exact target already absent (remove from `installed_routes`).
    /// - Err(RouteError::Failed(err)): Deterministic failure (track retry with backoff).
    /// - Err(RouteError::Unknown(err)): Unknown outcome (isolate in `unknown_routes`, report on stop).
    fn remove(
        &mut self,
        route: &Route,
    ) -> impl std::future::Future<Output = Result<Option<()>, RouteError>> + Send;
}

#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
#[derive(Default, Clone)]
pub struct PlatformRouteBackend;

#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
impl PlatformRouteBackend {
    pub fn new() -> Result<Self, anyhow::Error> {
        Ok(Self)
    }
}

#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
impl RouteBackend for PlatformRouteBackend {
    async fn add(&mut self, route: &Route) -> Result<Option<Route>, RouteError> {
        let ifindex = route.interface.ifindex;
        let metric = route.metric;
        let destination = route.destination;
        let route_clone = route.clone();
        tokio::task::spawn_blocking(move || {
            crate::common::ifcfg::netlink::NetlinkIfConfiger::add_route(
                ifindex,
                destination,
                Some(metric as i32),
            )
        })
        .await
        .map_err(|e| RouteError::Unknown(e.into()))?
        .map(|res| res.map(|_| route_clone))
        .map_err(|e| RouteError::Failed(e.into()))
    }

    async fn remove(&mut self, route: &Route) -> Result<Option<()>, RouteError> {
        let ifindex = route.interface.ifindex;
        let destination = route.destination;
        tokio::task::spawn_blocking(move || {
            crate::common::ifcfg::netlink::NetlinkIfConfiger::remove_route(ifindex, destination)
        })
        .await
        .map_err(|e| RouteError::Unknown(e.into()))?
        .map_err(|e| RouteError::Failed(e.into()))
    }
}

