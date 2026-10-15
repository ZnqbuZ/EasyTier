pub mod backend;
pub(crate) mod device;
pub mod manager;
pub mod model;
#[cfg(native_route)]
pub(crate) mod outlet;
pub(crate) use model::RouteProjection;
pub(crate) mod scope;
#[cfg(test)]
pub(crate) mod test_support;

#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
pub use backend::PlatformRouteBackend;
pub use backend::RouteBackend;

pub use easytier_core::host::route::{
    RouteDemand, RouteHandle, RouteSet, RouteSpec, resolve_proxy_cidrs, resolve_route_demands,
};
pub use manager::RouteMgr;
pub use model::{CleanupIncomplete, DeviceId, OsRoute, Route, RouteError};
