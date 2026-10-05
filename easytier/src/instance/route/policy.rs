use std::collections::BTreeSet;
use std::sync::Arc;

use cidr::IpCidr;
use easytier_core::config::runtime::CoreRuntimeConfigStore;
use easytier_core::instance::CorePacketPlane;

use super::model::{DeviceId, Route};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum RouteType {
    Manual,
    PeerAuto,
    ServiceExtra,
}

pub trait RouteProvider: Send + Sync {
    fn get_cidrs(&self) -> BTreeSet<IpCidr>;
    fn is_active(&self) -> bool {
        true
    }
}

impl<F> RouteProvider for F
where
    F: Fn() -> BTreeSet<IpCidr> + Send + Sync,
{
    fn get_cidrs(&self) -> BTreeSet<IpCidr> {
        self()
    }
}

pub struct ProviderEntry {
    pub role: RouteType,
    pub provider: Box<dyn RouteProvider>,
}

impl ProviderEntry {
    pub fn new(role: RouteType, provider: Box<dyn RouteProvider>) -> Self {
        Self { role, provider }
    }
}

impl<T: RouteProvider + ?Sized> RouteProvider for Arc<T> {
    fn get_cidrs(&self) -> BTreeSet<IpCidr> {
        (**self).get_cidrs()
    }

    fn is_active(&self) -> bool {
        (**self).is_active()
    }
}

impl RouteProvider for CorePacketPlane {
    fn get_cidrs(&self) -> BTreeSet<IpCidr> {
        self.list_proxy_cidrs_snapshot()
            .iter()
            .map(|c| IpCidr::V4(*c))
            .collect()
    }
}

impl RouteProvider for CoreRuntimeConfigStore {
    fn is_active(&self) -> bool {
        self.snapshot().services.manual_routes.is_some()
    }

    fn get_cidrs(&self) -> BTreeSet<IpCidr> {
        self.snapshot()
            .services
            .manual_routes
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(IpCidr::V4)
            .collect()
    }
}

impl RouteProvider for parking_lot::RwLock<BTreeSet<IpCidr>> {
    fn get_cidrs(&self) -> BTreeSet<IpCidr> {
        self.read().clone()
    }
}

pub struct DnsRouteProvider {
    global_ctx: crate::common::global_ctx::ArcGlobalCtx,
}

impl DnsRouteProvider {
    pub fn new(global_ctx: crate::common::global_ctx::ArcGlobalCtx) -> Self {
        Self { global_ctx }
    }
}

impl RouteProvider for DnsRouteProvider {
    fn get_cidrs(&self) -> BTreeSet<IpCidr> {
        let mut set = BTreeSet::new();
        if self.global_ctx.get_flags().accept_dns {
            if let Some(tun_ip) = self.global_ctx.get_ipv4() {
                if let Ok(fake_ip) =
                    crate::instance::dns_server::MAGIC_DNS_FAKE_IP.parse::<std::net::Ipv4Addr>()
                {
                    if !tun_ip.contains(&fake_ip) {
                        if let Ok(cidr) = cidr::Ipv4Cidr::new(fake_ip, 32) {
                            set.insert(IpCidr::V4(cidr));
                        }
                    }
                }
            }
        }
        set
    }
}

/// Calculate the desired routes based on registered providers and rules.
///
/// Rules:
/// 1. Proxy CIDRs:
///    - If an active Manual provider exists, use its routes (overrides peer auto routes).
///    - If active Manual routes are empty, no proxy routes are installed.
///    - If no active Manual provider exists, use PeerAuto providers.
/// 2. ServiceExtra CIDRs:
///    - Any CIDRs from ServiceExtra providers are added to desired routes on default_device.
/// 3. Merging:
///    - Duplicate CIDRs merge naturally in BTreeSet.
pub fn calculate_desired_routes(
    default_device: Option<&DeviceId>,
    entries: &[ProviderEntry],
    default_metric: u32,
) -> BTreeSet<Route> {
    let mut desired = BTreeSet::new();

    let Some(dev) = default_device else {
        return desired;
    };

    let active_manual = entries
        .iter()
        .find(|e| e.role == RouteType::Manual && e.provider.is_active());

    if let Some(manual) = active_manual {
        for cidr in manual.provider.get_cidrs() {
            desired.insert(Route {
                destination: cidr,
                interface: dev.clone(),
                metric: default_metric,
            });
        }
    } else {
        for entry in entries
            .iter()
            .filter(|e| e.role == RouteType::PeerAuto && e.provider.is_active())
        {
            for cidr in entry.provider.get_cidrs() {
                desired.insert(Route {
                    destination: cidr,
                    interface: dev.clone(),
                    metric: default_metric,
                });
            }
        }
    }

    for entry in entries
        .iter()
        .filter(|e| e.role == RouteType::ServiceExtra && e.provider.is_active())
    {
        for cidr in entry.provider.get_cidrs() {
            desired.insert(Route {
                destination: cidr,
                interface: dev.clone(),
                metric: default_metric,
            });
        }
    }

    desired
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    struct TestProvider {
        active: bool,
        cidrs: BTreeSet<IpCidr>,
    }

    impl RouteProvider for TestProvider {
        fn is_active(&self) -> bool {
            self.active
        }
        fn get_cidrs(&self) -> BTreeSet<IpCidr> {
            self.cidrs.clone()
        }
    }

    #[test]
    fn test_proxy_routes_auto_vs_manual() {
        let dev = DeviceId::new(10, Some(1));
        let peer_cidrs = BTreeSet::from([IpCidr::from_str("10.1.0.0/16").unwrap()]);

        // Case 1: Manual provider inactive -> use peer auto
        let entries = vec![
            ProviderEntry::new(
                RouteType::PeerAuto,
                Box::new(TestProvider {
                    active: true,
                    cidrs: peer_cidrs.clone(),
                }),
            ),
            ProviderEntry::new(
                RouteType::Manual,
                Box::new(TestProvider {
                    active: false,
                    cidrs: BTreeSet::new(),
                }),
            ),
        ];
        let desired = calculate_desired_routes(Some(&dev), &entries, 65535);
        assert_eq!(desired.len(), 1);
        assert_eq!(
            desired.iter().next().unwrap().destination,
            IpCidr::from_str("10.1.0.0/16").unwrap()
        );

        // Case 2: Manual provider active with empty set -> overrides peer auto to empty
        let entries = vec![
            ProviderEntry::new(
                RouteType::PeerAuto,
                Box::new(TestProvider {
                    active: true,
                    cidrs: peer_cidrs.clone(),
                }),
            ),
            ProviderEntry::new(
                RouteType::Manual,
                Box::new(TestProvider {
                    active: true,
                    cidrs: BTreeSet::new(),
                }),
            ),
        ];
        let desired = calculate_desired_routes(Some(&dev), &entries, 65535);
        assert!(desired.is_empty());

        // Case 3: Manual provider active with custom routes -> overrides peer auto
        let manual_cidrs = BTreeSet::from([IpCidr::from_str("192.168.1.0/24").unwrap()]);
        let entries = vec![
            ProviderEntry::new(
                RouteType::PeerAuto,
                Box::new(TestProvider {
                    active: true,
                    cidrs: peer_cidrs,
                }),
            ),
            ProviderEntry::new(
                RouteType::Manual,
                Box::new(TestProvider {
                    active: true,
                    cidrs: manual_cidrs,
                }),
            ),
        ];
        let desired = calculate_desired_routes(Some(&dev), &entries, 65535);
        assert_eq!(desired.len(), 1);
        assert_eq!(
            desired.iter().next().unwrap().destination,
            IpCidr::from_str("192.168.1.0/24").unwrap()
        );
    }

    #[test]
    fn test_extra_routes_and_ipv6_support() {
        let dev = DeviceId::new(10, Some(1));
        let v4_extra = IpCidr::from_str("7.7.7.7/32").unwrap();
        let v6_extra = IpCidr::from_str("2001:db8::/32").unwrap();

        let entries = vec![ProviderEntry::new(
            RouteType::ServiceExtra,
            Box::new(TestProvider {
                active: true,
                cidrs: BTreeSet::from([v4_extra, v6_extra]),
            }),
        )];

        let desired = calculate_desired_routes(Some(&dev), &entries, 65535);
        assert_eq!(desired.len(), 2);
        assert!(desired.iter().any(|r| r.destination == v4_extra));
        assert!(desired.iter().any(|r| r.destination == v6_extra));
    }
}
