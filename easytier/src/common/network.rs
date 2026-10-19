#[cfg(not(mobile))]
use std::collections::HashMap;
use std::net::IpAddr;

use network_interface::{NetworkInterface, NetworkInterfaceConfig};
#[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
use tokio::sync::Mutex;

use crate::proto::peer_rpc::GetIpListResponse;

use super::net_ns::NetNS;

#[cfg(not(mobile))]
#[derive(Clone, Copy, Debug, Default)]
struct InterfaceState {
    is_point_to_point: bool,
    is_loopback: bool,
    is_up: bool,
    #[cfg(target_os = "linux")]
    index: u32,
    #[cfg(target_os = "linux")]
    is_physical: bool,
}

#[cfg(any(target_os = "freebsd", target_os = "windows"))]
fn has_nonzero_mac(iface: &NetworkInterface) -> bool {
    iface.mac_addr.as_deref().is_some_and(|mac| {
        let mut octets = mac.split([':', '-']);
        let mut nonzero = false;
        for _ in 0..6 {
            let Some(value) = octets
                .next()
                .and_then(|octet| u8::from_str_radix(octet, 16).ok())
            else {
                return false;
            };
            nonzero |= value != 0;
        }
        octets.next().is_none() && nonzero
    })
}

#[allow(dead_code)]
pub(crate) fn ip_mask_to_prefix(mask: IpAddr) -> Result<u8, ()> {
    match mask {
        IpAddr::V4(mask) => {
            let raw = u32::from(mask);
            let prefix = raw.leading_ones() as u8;
            let expected = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (raw == expected).then_some(prefix).ok_or(())
        }
        IpAddr::V6(mask) => {
            let raw = u128::from(mask);
            let prefix = raw.leading_ones() as u8;
            let expected = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (raw == expected).then_some(prefix).ok_or(())
        }
    }
}

#[cfg(not(mobile))]
struct InterfaceFilter {
    iface: NetworkInterface,
    state: InterfaceState,
}

#[cfg(not(mobile))]
fn interface_state(
    iface: &NetworkInterface,
    states: &HashMap<String, InterfaceState>,
) -> InterfaceState {
    states.get(&iface.name).copied().unwrap_or_else(|| {
        cfg_select! {
            target_os = "linux" => {
                // Missing netlink metadata cannot establish eligibility.
                InterfaceState::default()
            },
            _ => InterfaceState {
                is_loopback: iface.internal,
                is_up: true,
                ..Default::default()
            },
        }
    })
}

// Cache for networksetup command output
#[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
static NETWORKSETUP_CACHE: std::sync::OnceLock<Mutex<(String, std::time::Instant)>> =
    std::sync::OnceLock::new();

cfg_select! {
    all(not(mobile), target_os = "linux") => {
        impl InterfaceFilter {
            async fn filter_iface(&self) -> bool {
                self.state.index == self.iface.index
                    && self.state.is_physical
                    && !self.state.is_point_to_point
                    && !self.state.is_loopback
                    && self.state.is_up
                    && self.iface.addr.iter().any(|ip| {
                        !ip.ip().is_loopback() && !ip.ip().is_unspecified() && !ip.ip().is_multicast()
                    })
            }
        }
    },
    any(all(target_os = "macos", not(feature = "macos-ne")), target_os = "freebsd") => {
        impl InterfaceFilter {
            cfg_select! {
                all(target_os = "macos", not(feature = "macos-ne")) => {
                    async fn get_networksetup_output() -> String {
                        use anyhow::Context;
                        use std::time::{Duration, Instant};
                        let cache = NETWORKSETUP_CACHE.get_or_init(|| Mutex::new((String::new(), Instant::now())));
                        let mut cache_guard = cache.lock().await;

                        // Check if cache is still valid (less than 1 minute old)
                        if cache_guard.1.elapsed() < Duration::from_secs(60) && !cache_guard.0.is_empty() {
                            return cache_guard.0.clone();
                        }

                        // Cache is expired or empty, fetch new data
                        let stdout = tokio::process::Command::new("networksetup")
                            .args(["-listallhardwareports"])
                            .output()
                            .await
                            .with_context(|| "Failed to execute networksetup command")
                            .and_then(|output| {
                                std::str::from_utf8(&output.stdout)
                                    .map(|s| s.to_string())
                                    .with_context(|| "Failed to convert networksetup output to string")
                            })
                            .unwrap_or_else(|e| {
                                tracing::error!("Failed to execute networksetup command: {:?}", e);
                                String::new()
                            });

                        // Update cache
                        cache_guard.0 = stdout.clone();
                        cache_guard.1 = Instant::now();

                        stdout
                    }

                    async fn is_interface_physical(&self) -> bool {
                        let interface_name = &self.iface.name;
                        let stdout = Self::get_networksetup_output().await;

                        let lines: Vec<&str> = stdout.lines().collect();

                        for i in 0..lines.len() {
                            let line = lines[i];

                            if line.contains("Device:") && line.contains(interface_name) {
                                let next_line = lines[i + 1];
                                return !next_line.contains("Virtual Interface");
                            }
                        }

                        false
                    }
                },
                _ => {
                    async fn is_interface_physical(&self) -> bool {
                        // if mac addr is not zero, then it's physical interface
                        has_nonzero_mac(&self.iface)
                    }
                },
            }

            async fn filter_iface(&self) -> bool {
                !self.state.is_point_to_point
                    && !self.state.is_loopback
                    && self.state.is_up
                    && self.is_interface_physical().await
            }
        }
    },
    target_os = "windows" => {
        impl InterfaceFilter {
            async fn filter_iface(&self) -> bool {
                tracing::debug!(
                    "iface_name: {:?}, p2p: {:?}, is_up: {:?}, iface: {:?}",
                    self.iface.name,
                    self.state.is_point_to_point,
                    self.state.is_up,
                    self.iface
                );
                !self.state.is_point_to_point
                    && !self.state.is_loopback
                    && self
                        .iface
                        .addr
                        .iter()
                        .map(|ip| ip.ip())
                        .any(|ip| !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast())
                    && has_nonzero_mac(&self.iface)
            }
        }
    },
    _ => {},
}

pub async fn local_ipv4() -> std::io::Result<std::net::Ipv4Addr> {
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect("8.8.8.8:80").await?;
    let addr = socket.local_addr()?;
    match addr.ip() {
        std::net::IpAddr::V4(ip) => Ok(ip),
        std::net::IpAddr::V6(_) => Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "no ipv4 address",
        )),
    }
}

pub async fn local_ipv6() -> std::io::Result<std::net::Ipv6Addr> {
    let socket = tokio::net::UdpSocket::bind("[::]:0").await?;
    socket
        .connect("[2001:4860:4860:0000:0000:0000:0000:8888]:80")
        .await?;
    let addr = socket.local_addr()?;
    match addr.ip() {
        std::net::IpAddr::V6(ip) => Ok(ip),
        std::net::IpAddr::V4(_) => Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "no ipv4 address",
        )),
    }
}

/// Capture namespace-sensitive data synchronously; asynchronous filtering runs
/// after the calling thread has returned to its original namespace.
pub(crate) async fn collect_interfaces(net_ns: NetNS, filter: bool) -> Vec<NetworkInterface> {
    match tokio::task::spawn_blocking(move || net_ns.run(|| InterfaceSnapshot::capture(filter)))
        .await
    {
        Ok(Ok(snapshot)) => snapshot.select(filter).await,
        result => {
            tracing::warn!(?result, "failed to collect interfaces in bound namespace");
            Vec::new()
        }
    }
}

#[cfg(feature = "faketcp")]
fn convert_pnet_interface(iface: pnet_datalink::NetworkInterface) -> NetworkInterface {
    let internal = iface.is_loopback();
    let addr = iface
        .ips
        .into_iter()
        .filter_map(|network| match (network.ip(), network.mask()) {
            (IpAddr::V4(ip), IpAddr::V4(netmask)) => {
                Some(network_interface::Addr::V4(network_interface::V4IfAddr {
                    ip,
                    broadcast: None,
                    netmask: Some(netmask),
                }))
            }
            (IpAddr::V6(ip), IpAddr::V6(netmask)) => {
                Some(network_interface::Addr::V6(network_interface::V6IfAddr {
                    ip,
                    broadcast: None,
                    netmask: Some(netmask),
                }))
            }
            _ => None,
        })
        .collect();
    NetworkInterface {
        name: iface.name,
        addr,
        mac_addr: iface.mac.map(|mac| mac.to_string()),
        index: iface.index,
        internal,
    }
}

fn enumerate_interfaces() -> Vec<NetworkInterface> {
    NetworkInterface::show().unwrap_or_else(|error| {
        tracing::warn!(?error, "failed to enumerate network interfaces");

        cfg_select! {
            feature = "faketcp" => {
                std::panic::catch_unwind(pnet_datalink::interfaces)
                    .map(|ifaces| ifaces.into_iter().map(convert_pnet_interface).collect())
                    .inspect_err(|_| tracing::error!("failed to enumerate network interfaces via network-interface and pnet"))
                    .unwrap_or_default()
            },
            _ => {
                Vec::new();
            },
        }
    })
}

#[derive(Debug)]
struct InterfaceSnapshot {
    interfaces: Vec<NetworkInterface>,
    #[cfg(not(mobile))]
    states: HashMap<String, InterfaceState>,
}

impl InterfaceSnapshot {
    fn capture(filter: bool) -> Self {
        #[cfg(mobile)]
        let _ = filter;
        Self {
            interfaces: enumerate_interfaces(),
            #[cfg(not(mobile))]
            states: if filter {
                collect_interface_states()
            } else {
                HashMap::new()
            },
        }
    }

    async fn select(self, filter: bool) -> Vec<NetworkInterface> {
        cfg_select! {
            mobile => {
                let _ = filter;
                self.interfaces
            },
            _ => {
                if !filter {
                    return self.interfaces;
                }
                let mut selected = Vec::with_capacity(self.interfaces.len());
                for iface in self.interfaces {
                    let state = interface_state(&iface, &self.states);
                    let candidate = InterfaceFilter { iface, state };
                    if candidate.filter_iface().await {
                        selected.push(candidate.iface);
                    }
                }
                selected
            },
        }
    }
}

#[cfg(not(mobile))]
fn collect_interface_states() -> HashMap<String, InterfaceState> {
    cfg_select! {
        target_os = "linux" => {
            use nix::net::if_::InterfaceFlags;
            match read_link_interfaces() {
                Ok(links) => links
                    .into_values()
                    .map(|link| {
                        let flags = InterfaceFlags::from_bits_retain(link.flags as _);
                        let state = InterfaceState {
                            index: link.index,
                            is_physical: link.kind.as_deref() != Some("tun"),
                            is_point_to_point: flags.contains(InterfaceFlags::IFF_POINTOPOINT),
                            is_loopback: flags.contains(InterfaceFlags::IFF_LOOPBACK),
                            is_up: flags.contains(InterfaceFlags::IFF_UP | InterfaceFlags::IFF_LOWER_UP),
                        };
                        (link.name, state)
                    })
                    .collect(),
                Err(error) => {
                    tracing::warn!(%error, "cannot classify interfaces in current namespace");
                    HashMap::new()
                }
            }
        },
        any(all(target_os = "macos", not(feature = "macos-ne")), target_os = "freebsd") => {
            let mut states = HashMap::new();
            if let Ok(interfaces) = nix::ifaddrs::getifaddrs() {
                use nix::net::if_::InterfaceFlags;

                for interface in interfaces {
                    let flags = interface.flags;
                    states.insert(
                        interface.interface_name,
                        InterfaceState {
                            is_point_to_point: flags.contains(InterfaceFlags::IFF_POINTOPOINT),
                            is_loopback: flags.contains(InterfaceFlags::IFF_LOOPBACK),
                            is_up: flags.contains(InterfaceFlags::IFF_UP),
                        },
                    );
                }
            }
            states
        },
        _ => HashMap::new(),
    }
}

#[cfg(all(target_os = "linux", not(mobile)))]
fn read_link_interfaces()
-> std::io::Result<std::collections::HashMap<u32, super::ifcfg::netlink_wire::LinkMessage>> {
    use super::ifcfg::netlink_wire::{
        LinkMessage, MessageBuilder, MessageIter, NLM_F_DUMP, NLM_F_DUMP_INTR, NLM_F_REQUEST,
        NLMSG_DONE, NLMSG_ERROR, NetlinkDecode, RTM_GETLINK, RTM_NEWLINK, netlink_error_code,
    };
    use nix::sys::{
        socket::{self, AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType},
        time::{TimeVal, TimeValLike},
    };
    use std::os::fd::AsRawFd;
    let socket = socket::socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::NetlinkRoute,
    )?;
    socket::setsockopt(
        &socket,
        socket::sockopt::ReceiveTimeout,
        &TimeVal::seconds(3),
    )?;
    socket::connect(socket.as_raw_fd(), &NetlinkAddr::new(0, 0))?;
    let mut request = MessageBuilder::new(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP);
    request.append_bytes(&[0; 16]);
    socket::send(socket.as_raw_fd(), &request.finish()?, MsgFlags::empty())?;
    let mut links = std::collections::HashMap::new();
    let mut buffer = [0_u8; 65536];
    loop {
        let length = socket::recv(socket.as_raw_fd(), &mut buffer, MsgFlags::MSG_TRUNC)?;
        if length == 0 || length > buffer.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "truncated interface dump",
            ));
        }
        for frame in MessageIter::new(&buffer[..length]) {
            let (header, payload) = frame?;
            if header.flags & NLM_F_DUMP_INTR != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "interrupted interface dump",
                ));
            }
            if header.message_type == NLMSG_ERROR {
                let errno = netlink_error_code(payload)?;
                if errno != 0 {
                    return Err(std::io::Error::from_raw_os_error(errno.abs()));
                }
            } else if header.message_type == NLMSG_DONE {
                if !payload.is_empty() {
                    let errno = netlink_error_code(payload)?;
                    if errno != 0 {
                        return Err(std::io::Error::from_raw_os_error(errno.abs()));
                    }
                }
                return Ok(links);
            } else if header.message_type == RTM_NEWLINK {
                let link = LinkMessage::from_bytes(payload)?;
                links.insert(link.index, link);
            }
        }
    }
}

#[tracing::instrument(skip(net_ns))]
pub(crate) async fn collect_local_ip_addrs(net_ns: NetNS) -> GetIpListResponse {
    let captured = tokio::task::spawn_blocking(move || {
        net_ns.run(|| {
            let snapshot = InterfaceSnapshot::capture(true);
            // UDP connect selects an egress address without sending packets. Socket
            // creation and route lookup must both happen in the bound namespace.
            let probes = [
                ("0.0.0.0:0", "8.8.8.8:80"),
                ("[::]:0", "[2001:4860:4860::8888]:80"),
            ]
            .map(|(bind, remote)| {
                let socket = std::net::UdpSocket::bind(bind).ok()?;
                socket.connect(remote).ok()?;
                Some(socket.local_addr().ok()?.ip())
            });
            (snapshot, probes)
        })
    })
    .await;
    let (snapshot, probes) = match captured {
        Ok(Ok(captured)) => captured,
        result => {
            tracing::warn!(?result, "failed to collect IP addresses in bound namespace");
            return GetIpListResponse::default();
        }
    };
    let mut ret = GetIpListResponse::default();
    // IPv6 discovery includes virtual interfaces; IPv4 uses physical filtering.
    for iface in &snapshot.interfaces {
        for ip in &iface.addr {
            if let IpAddr::V6(ip) = ip.ip()
                && !ip.is_multicast()
                && !ip.is_loopback()
                && !ip.is_unicast_link_local()
            {
                ret.interface_ipv6s.push(ip.into());
            }
        }
    }
    for iface in snapshot.select(true).await {
        for ip in iface.addr {
            if let IpAddr::V4(ip) = ip.ip()
                && !ip.is_loopback()
                && !ip.is_multicast()
            {
                ret.interface_ipv4s.push(ip.into());
            }
        }
    }
    for ip in probes.into_iter().flatten() {
        match ip {
            IpAddr::V4(ip) if !ret.interface_ipv4s.contains(&ip.into()) => {
                ret.interface_ipv4s.push(ip.into())
            }
            IpAddr::V6(ip) if !ret.interface_ipv6s.contains(&ip.into()) => {
                ret.interface_ipv6s.push(ip.into())
            }
            _ => {}
        }
    }
    ret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_contiguous_ip_masks_to_prefixes() {
        assert_eq!(
            ip_mask_to_prefix(IpAddr::V4("255.255.254.0".parse().unwrap())),
            Ok(23)
        );
        assert_eq!(
            ip_mask_to_prefix(IpAddr::V6("ffff:ffff:ffff:ffff::".parse().unwrap())),
            Ok(64)
        );
        assert_eq!(
            ip_mask_to_prefix(IpAddr::V4("255.0.255.0".parse().unwrap())),
            Err(())
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn bound_interface_query_does_not_change_the_callers_net_ns() {
        let net_ns = crate::common::net_ns::current().unwrap();
        let expected = net_ns.id();
        assert!(!collect_interfaces(net_ns, false).await.is_empty());
        assert_eq!(crate::common::net_ns::current().unwrap().id(), expected);
    }

    #[cfg(all(target_os = "linux", not(mobile)))]
    #[test]
    fn interface_classification_queries_the_current_net_ns_without_sysfs() {
        assert!(!read_link_interfaces().unwrap().is_empty());
    }
}
