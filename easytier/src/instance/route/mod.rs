//! Native control of one network domain. Production backend dispatch is static.

use std::{collections::BTreeSet, future::Future, net::IpAddr, num::NonZeroU32};

use cidr::IpCidr;

pub(crate) mod platform;
pub(crate) use platform::PlatformRouteBackend;

cfg_select! {
    mobile => {
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub(crate) struct AppliedSnapshot {
            pub prefixes: BTreeSet<IpCidr>,
        }
        pub(crate) type AppliedRoutes = Option<AppliedSnapshot>;
    },
    _ => {
        #[derive(Clone, Debug)]
        pub(crate) struct AppliedRoute {
            pub route: OsRoute,
            #[allow(dead_code)]
            pub owners: BTreeSet<uuid::Uuid>,
            #[allow(dead_code)]
            pub retry: Option<(u32, tokio::time::Instant)>,
        }

        #[allow(dead_code)]
        impl AppliedRoute {
            pub(crate) fn new(route: OsRoute, owners: BTreeSet<uuid::Uuid>) -> Self {
                Self {
                    route,
                    owners,
                    retry: None,
                }
            }

            pub(crate) fn record_retry(&mut self) {
                let attempts = self.retry.map_or(1, |(n, _)| n.saturating_add(1));
                let millis = (100_u64 << attempts.saturating_sub(1).min(6)).min(5000);
                self.retry = Some((
                    attempts,
                    tokio::time::Instant::now() + std::time::Duration::from_millis(millis),
                ));
            }

            pub(crate) fn is_due(&self, now: tokio::time::Instant) -> bool {
                self.retry.is_none_or(|(_, deadline)| deadline <= now)
            }
        }

        pub(crate) type AppliedRoutes = std::collections::BTreeMap<OsRouteSlotKey, AppliedRoute>;
    },
}

#[cfg(feature = "tun")]
#[path = "controller.rs"]
pub(crate) mod controller;
#[cfg(feature = "tun")]
pub(crate) mod runtime;

#[cfg(feature = "tun")]
pub(crate) use controller::RouteController;

#[allow(dead_code)]
#[cfg(test)]
pub(crate) const METRIC_DIRECT: NonZeroU32 = NonZeroU32::new(65535).unwrap();
#[allow(dead_code)]
#[cfg(test)]
pub(crate) const METRIC_PUBLIC_IPV6_DEFAULT: NonZeroU32 = NonZeroU32::new(5).unwrap();

pub(crate) fn validate_tun_spec(
    spec: &easytier_core::host::route::RouteSpec,
) -> Result<NonZeroU32, &'static str> {
    use easytier_core::host::route::{DeviceSelector, RouteAction};
    if !matches!(
        &spec.action,
        RouteAction::Unicast {
            device: Some(DeviceSelector::InstanceTun),
            via: None
        }
    ) {
        return Err("only directly attached instance TUN routes are supported");
    }
    if spec.table.is_some_and(|table| table != 254) {
        return Err("non-main route tables are not supported yet");
    }
    #[cfg(any(windows, mobile))]
    if spec.preferred_source.is_some() {
        return Err("this platform cannot set a route-specific preferred source");
    }
    NonZeroU32::new(spec.metric).ok_or("route metric must be nonzero")
}

/// Resolved parameters for the initially supported, static, directly attached
/// unicast route. Device generations and application ownership stay outside.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct InterfaceInfo {
    pub name: String,
    pub ifindex: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct OsRoute {
    pub table: u32,
    pub destination: IpCidr,
    pub metric: NonZeroU32,
    pub ifindex: u32,
    pub preferred_source: Option<IpAddr>,
}

/// The native exclusive key, rather than a Linux key imposed on every OS.
/// Linux: table/prefix/metric. Windows: interface/prefix (on-link next hop).
/// BSD: table/prefix, since these routes are unscoped. External VPN: attachment/prefix.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct OsRouteSlotKey {
    table: u32,
    destination: IpCidr,
    #[cfg(all(target_os = "linux", not(mobile)))]
    metric: NonZeroU32,
    #[cfg(any(windows, mobile))]
    ifindex: u32,
}

impl OsRoute {
    pub(crate) fn slot(&self) -> OsRouteSlotKey {
        OsRouteSlotKey {
            table: self.table,
            destination: self.destination,
            #[cfg(all(target_os = "linux", not(mobile)))]
            metric: self.metric,
            #[cfg(any(windows, mobile))]
            ifindex: self.ifindex,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RouteError {
    #[error("route operation failed: {0}")]
    Failed(anyhow::Error),
    #[error("route operation outcome is unknown: {0}")]
    Unknown(anyhow::Error),
}

#[allow(dead_code)]
impl RouteError {
    fn is_kind(&self, kind: std::io::ErrorKind) -> bool {
        matches!(self, Self::Failed(error) if error.downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == kind))
    }
    fn is_absent(&self) -> bool {
        if self.is_kind(std::io::ErrorKind::NotFound) {
            return true;
        }
        cfg_select! {
            unix => { matches!(self, Self::Failed(error) if error.downcast_ref::<std::io::Error>().is_some_and(|error| error.raw_os_error() == Some(nix::libc::ESRCH))) },
            _ => { false },
        }
    }
    #[cfg(all(test, target_os = "linux", not(mobile)))]
    pub(crate) fn is_errno(&self, errno: i32) -> bool {
        matches!(self, Self::Failed(error) if error.downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.raw_os_error() == Some(errno)))
    }
}

// Private test seam. Production uses the single concrete platform backend;
// there is no vtable or boxed future in its request path.
pub(crate) trait RouteBackend: Send + 'static {
    fn add(&mut self, route: &OsRoute) -> impl Future<Output = Result<(), RouteError>> + Send;
    fn remove(&mut self, route: &OsRoute) -> impl Future<Output = Result<(), RouteError>> + Send;
    fn existing(
        &mut self,
        routes: &BTreeSet<OsRoute>,
    ) -> impl Future<Output = Result<BTreeSet<OsRoute>, RouteError>> + Send;
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
