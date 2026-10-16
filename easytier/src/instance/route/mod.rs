//! Native control of one network domain. Production backend dispatch is static.

#[cfg(not(mobile))]
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
};

#[cfg(not(mobile))]
use cidr::IpCidr;
#[cfg(not(mobile))]
use easytier_core::host::route::{RouteAction, RouteSpec};
#[cfg(not(mobile))]
use uuid::Uuid;

#[cfg(all(not(mobile), feature = "tun"))]
use crate::instance::shared_virtual_nic::SharedVirtualNicMember;

#[cfg(feature = "tun")]
pub(crate) mod mobile;
#[cfg(not(mobile))]
pub(crate) mod platform;
#[cfg(not(mobile))]
pub(crate) use platform::PlatformRouteBackend;

#[cfg(any(not(mobile), feature = "tun"))]
pub(crate) mod controller;
#[cfg(any(not(mobile), feature = "tun"))]
pub(crate) mod runtime;

#[cfg(any(not(mobile), feature = "tun"))]
pub(crate) use controller::RouteController;

/// Resolved parameters of one instance's real device binding.
#[cfg(not(mobile))]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct InterfaceInfo {
    pub name: String,
    pub ifindex: u32,
}

/// The native exclusive key, rather than a Linux key imposed on every OS.
/// Linux: table/prefix/metric. Windows: destination/interface and the
/// normalized next hop. BSD and other non-mobile targets: destination, since
/// these routes are unscoped. The key is only an identity: fields that are
/// not in it still take part in the complete `RouteSpec<u32>` comparison.
#[cfg(not(mobile))]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RouteKey {
    #[cfg(target_os = "linux")]
    table: u32,
    destination: IpCidr,
    #[cfg(target_os = "linux")]
    metric: u32,
    #[cfg(windows)]
    ifindex: u32,
    #[cfg(windows)]
    via: Option<std::net::IpAddr>,
}

#[cfg(not(mobile))]
impl RouteKey {
    /// Key of one route.
    ///
    /// The Linux defaults arrive through normalization, so equal meanings map
    /// to the same key even when a caller still holds the un-normalized form.
    pub(crate) fn of(route: &RouteSpec<u32>) -> Self {
        cfg_select! {
            target_os = "linux" => {
                Self {
                    table: route.table.unwrap_or(254),
                    destination: route.destination,
                    // A zero IPv6 metric installs as the kernel default.
                    metric: match route.metric {
                        0 if route.destination.first_address().is_ipv6() => 1024,
                        metric => metric,
                    },
                }
            },
            windows => {
                let RouteAction::Unicast { dev, via } = &route.action;
                Self {
                    destination: route.destination,
                    ifindex: *dev,
                    // An unspecified next hop means "on-link".
                    via: (*via).filter(|via| !via.is_unspecified()),
                }
            },
            _ => {
                Self {
                    destination: route.destination,
                }
            },
        }
    }
}

/// Check the input parameters that stay meaningful after device resolution.
///
/// This only rejects real input errors; it does not re-check the platform
/// capability set, because unsupported fields do not exist in the type.
#[cfg(not(mobile))]
pub(crate) fn normalize_route(mut route: RouteSpec<u32>) -> Result<RouteSpec<u32>, RouteError> {
    match &mut route.action {
        RouteAction::Unicast { dev, via } => {
            if *dev == 0 {
                return Err(invalid_route("route requires a non-zero interface index"));
            }
            if let Some(address) = *via {
                if address.is_ipv4() != route.destination.first_address().is_ipv4() {
                    return Err(invalid_route(
                        "route gateway address family differs from the destination",
                    ));
                }
                if address.is_unspecified() {
                    *via = None;
                }
            }
        }
        #[cfg(target_os = "linux")]
        RouteAction::Blackhole | RouteAction::Unreachable => {}
    }
    #[cfg(target_os = "linux")]
    {
        match route.table {
            Some(0) => return Err(invalid_route("route table 0 is not a destination table")),
            None => route.table = Some(254),
            Some(_) => {}
        }
        // Linux replaces a zero IPv6 metric with IP6_RT_PRIO_USER (1024) in
        // inet6_rtm_newroute(), so normalize to the value the kernel installs.
        if route.metric == 0 && route.destination.first_address().is_ipv6() {
            route.metric = 1024;
        }
    }
    Ok(route)
}

#[cfg(not(mobile))]
fn invalid_route(message: &'static str) -> RouteError {
    RouteError::Failed(anyhow::anyhow!(message))
}

#[cfg(not(mobile))]
#[derive(Debug, thiserror::Error)]
pub(crate) enum RouteError {
    #[error("route operation failed: {0}")]
    Failed(anyhow::Error),
    #[error("route operation outcome is unknown: {0}")]
    Unknown(anyhow::Error),
}

#[cfg(not(mobile))]
impl RouteError {
    #[cfg(all(test, target_os = "linux", not(mobile)))]
    pub(crate) fn is_errno(&self, errno: i32) -> bool {
        matches!(self, Self::Failed(error) if error.downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.raw_os_error() == Some(errno)))
    }
}

/// One physical route observed or installed by this controller.
#[cfg(not(mobile))]
#[derive(Clone)]
pub(crate) struct AppliedRoute {
    pub route: RouteSpec<u32>,
    pub owners: BTreeSet<Uuid>,
    pub effect: RouteEffect,
    #[cfg(feature = "tun")]
    pub members: BTreeMap<Uuid, SharedVirtualNicMember>,
}

/// The evidence behind one applied record.
#[cfg(not(mobile))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RouteEffect {
    Owned,
    External,
    Adding,
    Removing,
}

#[cfg(not(mobile))]
pub(crate) type AppliedRoutes = BTreeMap<RouteKey, AppliedRoute>;

// Private test seam. Production uses the single concrete platform backend;
// there is no vtable or boxed future in its request path.
#[cfg(not(mobile))]
pub(crate) trait RouteBackend: Send + 'static {
    fn add(
        &mut self,
        route: &RouteSpec<u32>,
    ) -> impl Future<Output = Result<(), RouteError>> + Send;
    fn remove(
        &mut self,
        route: &RouteSpec<u32>,
    ) -> impl Future<Output = Result<(), RouteError>> + Send;
    fn existing(
        &mut self,
        routes: &BTreeSet<RouteSpec<u32>>,
    ) -> impl Future<Output = Result<BTreeSet<RouteSpec<u32>>, RouteError>> + Send;
}

pub(crate) fn interface_index(
    net_ns: &crate::common::net_ns::NetNS,
    name: &str,
) -> anyhow::Result<u32> {
    cfg_select! {
        windows => {
            use ::windows::Win32::NetworkManagement::IpHelper::{ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex};
            use ::windows::core::PCWSTR;
            let alias = name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
            net_ns.run(|| unsafe {
                let mut luid = Default::default();
                let mut index = 0;
                ConvertInterfaceAliasToLuid(PCWSTR(alias.as_ptr()), &mut luid).ok()?;
                ConvertInterfaceLuidToIndex(&luid, &mut index).ok()?;
                Ok::<_, ::windows::core::Error>(index)
            })?.map_err(Into::into)
        },
        unix => { net_ns.run(|| nix::net::if_::if_nametoindex(name))?.map_err(Into::into) },
        _ => { let _ = (net_ns, name); anyhow::bail!("interface lookup is unsupported") },
    }
}
