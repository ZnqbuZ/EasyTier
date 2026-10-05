pub mod backend;
pub mod manager;
pub mod model;
pub mod policy;

pub use backend::RouteBackend;
#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
pub use backend::PlatformRouteBackend;

pub use manager::{HostRouteManager, stop_manager};
pub use model::{CleanupIncomplete, DeviceId, Route, RouteError};
pub use policy::{DnsRouteProvider, ProviderEntry, RouteProvider, RouteType};
