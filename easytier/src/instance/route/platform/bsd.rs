//! Native routing-socket writes and sysctl readback for macOS / FreeBSD.
//! No shell output parsing; request ACKs are correlated and time bounded.

use super::{RouteBackend, RouteError};
use crate::{common::net_ns::NetNS, instance::route::normalize_route};
use cidr::IpCidr;
use easytier_core::host::route::{RouteAction, RouteSpec};
use nix::libc;
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    mem::size_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::Duration,
};
use tokio::{io::unix::AsyncFd, runtime::Handle};

// ABI of <net/route.h>: Darwin uses uint32_t metrics; FreeBSD uses u_long.
// Common header fields occupy bytes 0..32, then rtm_inits and 14 metric words.
cfg_select! {
    target_os = "macos" => { type MetricWord = u32; const ALIGN: usize = 4; },
    _ => { type MetricWord = libc::c_ulong; const ALIGN: usize = size_of::<libc::c_long>(); },
}
const WORD: usize = size_of::<MetricWord>();
const HEADER: usize = 32 + 15 * WORD;
#[cfg(target_os = "macos")]
const _: () = assert!(HEADER == size_of::<libc::rt_msghdr>());
const MAX_DUMP: usize = 16 * 1024 * 1024;

pub(crate) struct PlatformRouteBackend {
    net_ns: NetNS,
    executor: Handle,
    sequence: i32,
}
impl PlatformRouteBackend {
    pub(crate) fn new(net_ns: &NetNS, executor: &Handle) -> anyhow::Result<Self> {
        net_ns.ensure_open()?;
        Ok(Self {
            net_ns: net_ns.clone(),
            executor: executor.clone(),
            sequence: 0,
        })
    }

    async fn mutate(&mut self, route: &RouteSpec<u32>, operation: u8) -> Result<(), RouteError> {
        self.sequence = self.sequence.checked_add(1).unwrap_or(1);
        let request = encode(route, operation, self.sequence)
            .map_err(|error| RouteError::Failed(error.into()))?;
        // Each operation owns its socket. A timed-out reply can never be
        // consumed by the next operation, even after sequence wraparound.
        let socket = self
            .net_ns
            .run(|| -> io::Result<_> {
                let fd = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, 0) };
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                let fd = unsafe { OwnedFd::from_raw_fd(fd) };
                if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0
                    || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } < 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(fd)
            })
            .map_err(|error| RouteError::Failed(error.into()))?
            .map_err(|error| RouteError::Failed(error.into()))?;
        let socket = {
            let _entered = self.executor.enter();
            AsyncFd::new(socket).map_err(|error| RouteError::Failed(error.into()))?
        };
        let mut sent = false;
        let result = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let mut writable = socket.writable().await?;
                match writable.try_io(|fd| {
                    let length = unsafe {
                        libc::write(
                            fd.get_ref().as_raw_fd(),
                            request.as_ptr().cast(),
                            request.len(),
                        )
                    };
                    if length < 0 {
                        let error = io::Error::last_os_error();
                        // A failed write can follow an attempted kernel mutation.
                        // WouldBlock and explicit duplicate/missing rejections are
                        // the exceptions; transport/resource failures prove nothing.
                        sent = error.kind() != io::ErrorKind::WouldBlock
                            && !matches!(
                                error.raw_os_error(),
                                Some(libc::EEXIST | libc::ESRCH | libc::ENOENT)
                            );
                        return Err(error);
                    }
                    sent = true;
                    if length as usize != request.len() {
                        return Err(io::Error::other("short routing-socket write"));
                    }
                    Ok(())
                }) {
                    Ok(result) => {
                        result?;
                        break;
                    }
                    Err(_) => continue,
                }
            }
            loop {
                let mut readable = socket.readable().await?;
                let mut bytes = [0u8; 65536];
                let length = match readable.try_io(|fd| {
                    let count = unsafe {
                        libc::recv(
                            fd.get_ref().as_raw_fd(),
                            bytes.as_mut_ptr().cast(),
                            bytes.len(),
                            libc::MSG_TRUNC,
                        )
                    };
                    if count < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(count as usize)
                    }
                }) {
                    Ok(result) => result?,
                    Err(_) => continue,
                };
                if length == 0 || length >= bytes.len() {
                    return Err(io::Error::other("truncated routing-socket reply"));
                }
                for message in frames(&bytes[..length])? {
                    // Other processes' messages are not acknowledgements.
                    if message.len() < HEADER {
                        continue;
                    }
                    if i32_at(message, 16)? != unsafe { libc::getpid() }
                        || i32_at(message, 20)? != self.sequence
                    {
                        continue;
                    }
                    if message[2] != libc::RTM_VERSION as u8 || message[3] != operation {
                        return Err(io::Error::other("invalid routing-socket ACK"));
                    }
                    return Ok(i32_at(message, 24)?);
                }
            }
        })
        .await;
        match result {
            Ok(Ok(0)) => Ok(()),
            Ok(Ok(errno)) => Err(RouteError::Failed(
                io::Error::from_raw_os_error(errno).into(),
            )),
            failed => {
                let error = match failed {
                    Ok(Err(error)) => error,
                    Err(_) => {
                        io::Error::new(io::ErrorKind::TimedOut, "routing-socket ACK timed out")
                    }
                    _ => unreachable!(),
                };
                if sent {
                    Err(RouteError::Unknown(error.into()))
                } else {
                    Err(RouteError::Failed(error.into()))
                }
            }
        }
    }
}

fn aligned(length: usize) -> usize {
    length.max(1).div_ceil(ALIGN) * ALIGN
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid native route message")
}
fn i32_at(bytes: &[u8], at: usize) -> io::Result<i32> {
    Ok(i32::from_ne_bytes(
        bytes
            .get(at..at + 4)
            .ok_or_else(invalid)?
            .try_into()
            .unwrap(),
    ))
}

fn frames(mut bytes: &[u8]) -> io::Result<Vec<&[u8]>> {
    let mut messages = Vec::new();
    while !bytes.is_empty() {
        let length =
            u16::from_ne_bytes(bytes.get(..2).ok_or_else(invalid)?.try_into().unwrap()) as usize;
        if length < 4 || length > bytes.len() {
            return Err(invalid());
        }
        messages.push(&bytes[..length]);
        bytes = &bytes[length..];
    }
    Ok(messages)
}
fn append(bytes: &mut Vec<u8>, address: &[u8]) {
    bytes.extend_from_slice(address);
    bytes.resize(bytes.len() + aligned(address.len()) - address.len(), 0);
}
fn ip_sockaddr(ip: IpAddr) -> Vec<u8> {
    let mut bytes = vec![0; if ip.is_ipv4() { 16 } else { 28 }];
    bytes[0] = bytes.len() as u8;
    match ip {
        IpAddr::V4(ip) => {
            bytes[1] = libc::AF_INET as u8;
            bytes[4..8].copy_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            bytes[1] = libc::AF_INET6 as u8;
            bytes[8..24].copy_from_slice(&ip.octets());
        }
    }
    bytes
}
fn link_sockaddr(dev: u32) -> [u8; 8] {
    let mut link = [0u8; 8];
    link[0] = 8;
    link[1] = libc::AF_LINK as u8;
    link[2..4].copy_from_slice(&(dev as u16).to_ne_bytes());
    link
}
fn is_link_local(octets: &[u8; 16]) -> bool {
    octets[0] == 0xfe && octets[1] & 0xc0 == 0x80
}

/// A gateway sockaddr. A link-local IPv6 gateway derives its zone from the
/// output interface, carried in `sin6_scope_id` rather than in the address.
fn gateway_sockaddr(via: IpAddr, dev: u32) -> Vec<u8> {
    let mut bytes = ip_sockaddr(via);
    if let IpAddr::V6(ip) = via {
        let octets = ip.octets();
        if is_link_local(&octets) {
            bytes[24..28].copy_from_slice(&dev.to_ne_bytes());
        }
    }
    bytes
}

/// Normalize one installable route and apply the routing-socket ABI bound.
fn checked(route: &RouteSpec<u32>) -> io::Result<RouteSpec<u32>> {
    let route = normalize_route(route.clone())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let RouteAction::Unicast { dev, .. } = &route.action;
    if !(1..=u16::MAX as u32).contains(dev) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported BSD route parameters",
        ));
    }
    Ok(route)
}

fn encode(route: &RouteSpec<u32>, operation: u8, sequence: i32) -> io::Result<Vec<u8>> {
    let route = checked(route)?;
    let RouteAction::Unicast { dev, via } = &route.action;
    let (dev, via) = (*dev, *via);
    let mut bytes = vec![0; HEADER];
    bytes[2] = libc::RTM_VERSION as u8;
    bytes[3] = operation;
    bytes[4..6].copy_from_slice(&(dev as u16).to_ne_bytes());
    let prefix = route.destination.network_length();
    let host = prefix == if route.destination.is_ipv4() { 32 } else { 128 };
    let flags = libc::RTF_UP
        | libc::RTF_STATIC
        | if host { libc::RTF_HOST } else { 0 }
        | if via.is_some() { libc::RTF_GATEWAY } else { 0 };
    bytes[8..12].copy_from_slice(&flags.to_ne_bytes());
    let addrs = libc::RTA_DST | libc::RTA_GATEWAY | libc::RTA_NETMASK | libc::RTA_IFP;
    bytes[12..16].copy_from_slice(&addrs.to_ne_bytes());
    bytes[16..20].copy_from_slice(&unsafe { libc::getpid() }.to_ne_bytes());
    bytes[20..24].copy_from_slice(&sequence.to_ne_bytes());
    // BSD hopcount is a TTL hint, not a route-selection priority. The route
    // type has no metric field, so the header's metric words stay at their
    // defaults.
    append(&mut bytes, &ip_sockaddr(route.destination.first_address()));
    let gateway = match via {
        Some(via) => gateway_sockaddr(via, dev),
        None => link_sockaddr(dev).to_vec(),
    };
    append(&mut bytes, &gateway);
    let mask = match route.destination.first_address() {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::from(if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        })),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::from(if prefix == 0 {
            0
        } else {
            u128::MAX << (128 - prefix)
        })),
    };
    append(&mut bytes, &ip_sockaddr(mask));
    append(&mut bytes, &link_sockaddr(dev));
    let length = u16::try_from(bytes.len()).map_err(|_| invalid())?;
    bytes[..2].copy_from_slice(&length.to_ne_bytes());
    Ok(bytes)
}

fn dump() -> io::Result<Vec<u8>> {
    let mut mib = [libc::CTL_NET, libc::PF_ROUTE, 0, 0, libc::NET_RT_DUMP, 0];
    for _ in 0..4 {
        let mut length = 0;
        if unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as _,
                std::ptr::null_mut(),
                &mut length,
                std::ptr::null_mut(),
                0,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        if length > MAX_DUMP {
            return Err(io::Error::other("native route dump exceeds size bound"));
        }
        let mut bytes = vec![0; length];
        if unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as _,
                bytes.as_mut_ptr().cast(),
                &mut length,
                std::ptr::null_mut(),
                0,
            )
        } < 0
        {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENOMEM) {
                continue;
            }
            return Err(error);
        }
        if length > bytes.len() {
            return Err(invalid());
        }
        bytes.truncate(length);
        return Ok(bytes);
    }
    Err(io::Error::other("native route table changed during dump"))
}

fn ip_address(address: &[u8], family: u8) -> io::Result<IpAddr> {
    let (offset, length) = if family == libc::AF_INET as u8 {
        (4, 4)
    } else {
        (8, 16)
    };
    let mut octets = [0; 16];
    if address.len() > offset {
        let count = (address.len() - offset).min(length);
        octets[..count].copy_from_slice(&address[offset..offset + count]);
    }
    Ok(if length == 4 {
        Ipv4Addr::from(<[u8; 4]>::try_from(&octets[..4]).unwrap()).into()
    } else {
        Ipv6Addr::from(octets).into()
    })
}

/// A gateway IP sockaddr of the destination's family.
///
/// An IPv6 gateway may carry its zone either in `sin6_scope_id` or embedded in
/// the link-local address (BSD `sa6_embedscope`). Both forms must name this
/// row's interface; the embedded form is removed before the address is
/// compared. Global address bytes are never rewritten, and a scoped row for
/// another interface is reported as unsupported rather than as this route.
fn gateway_address(address: &[u8], family: u8, dev: u32) -> io::Result<Option<IpAddr>> {
    if family == libc::AF_INET as u8 {
        if address.len() < 8 {
            return Err(invalid());
        }
        return Ok(Some(ip_address(address, family)?));
    }
    // An IPv6 gateway must also carry the complete `sin6_scope_id` field: a
    // sockaddr truncated inside it cannot tell a scoped next hop from a
    // global one.
    if address.len() < 28 {
        return Err(invalid());
    }
    let scope = u32::from_ne_bytes(address[24..28].try_into().unwrap());
    if scope != 0 && scope != dev {
        return Ok(None);
    }
    let mut octets: [u8; 16] = address[8..24].try_into().unwrap();
    if is_link_local(&octets) {
        let zone = u16::from_be_bytes([octets[2], octets[3]]);
        if zone != 0 {
            if u32::from(zone) != dev {
                return Ok(None);
            }
            octets[2] = 0;
            octets[3] = 0;
        }
    }
    Ok(Some(Ipv6Addr::from(octets).into()))
}

/// The complete installable route a kernel row represents.
///
/// Only a static unscoped unicast row is this route type. Reject and
/// blackhole rows have no device or gateway to express, and a scoped macOS
/// row is not an unscoped prefix. A direct row must name its carrier with an
/// AF_LINK gateway; a gateway row must carry a complete IP gateway of the
/// destination's family. Truncated addresses, illegal netmasks and address
/// lists that run past the message are errors, so an incomplete dump is never
/// mistaken for an absent route.
fn decode(message: &[u8]) -> io::Result<Option<RouteSpec<u32>>> {
    if message.len() < HEADER || message[2] != libc::RTM_VERSION as u8 {
        return Err(invalid());
    }
    let flags = i32_at(message, 8)?;
    if flags & (libc::RTF_REJECT | libc::RTF_BLACKHOLE) != 0 || flags & libc::RTF_STATIC == 0 {
        return Ok(None);
    }
    #[cfg(target_os = "macos")]
    if flags & libc::RTF_IFSCOPE != 0 {
        return Ok(None);
    }
    let dev = u16::from_ne_bytes(message[4..6].try_into().unwrap()) as u32;
    // Route indices are 16-bit on this ABI; zero cannot describe a device.
    if dev == 0 {
        return Ok(None);
    }
    let addrs = i32_at(message, 12)? as u32;
    let mut remaining = &message[HEADER..];
    let mut addresses = [None; 32];
    for (bit, address) in addresses.iter_mut().enumerate() {
        if addrs & (1 << bit) == 0 {
            continue;
        }
        let length = *remaining.first().ok_or_else(invalid)? as usize;
        let padded = aligned(length);
        if padded > remaining.len() {
            return Err(invalid());
        }
        *address = Some(&remaining[..length]);
        remaining = &remaining[padded..];
    }
    let Some(destination) = addresses[0] else {
        return Err(invalid());
    };
    let family = *destination.get(1).ok_or_else(invalid)?;
    if family != libc::AF_INET as u8 && family != libc::AF_INET6 as u8 {
        return Ok(None);
    }
    if destination.len() < if family == libc::AF_INET as u8 { 8 } else { 24 } {
        return Err(invalid());
    }
    let destination = ip_address(destination, family)?;
    let via = if flags & libc::RTF_GATEWAY != 0 {
        // A gateway row must carry a complete gateway sockaddr of the same
        // family. A sockaddr that stops before its family byte is truncated;
        // an unknown or other family is a row this route type cannot express.
        let Some(gateway) = addresses[1] else {
            return Ok(None);
        };
        let family_byte = *gateway.get(1).ok_or_else(invalid)?;
        if family_byte != family {
            return Ok(None);
        }
        let Some(via) = gateway_address(gateway, family, dev)? else {
            return Ok(None);
        };
        Some(via)
    } else {
        // A direct row names the carrier interface with an AF_LINK sockaddr.
        // The 8-byte `sockaddr_dl` header is the shortest complete form; a
        // shorter block is truncated, and any other family is not a carrier.
        let Some(gateway) = addresses[1] else {
            return Ok(None);
        };
        let family_byte = *gateway.get(1).ok_or_else(invalid)?;
        if family_byte != libc::AF_LINK as u8 {
            return Ok(None);
        }
        if gateway.len() < 8 {
            return Err(invalid());
        }
        None
    };
    let prefix = if flags & libc::RTF_HOST != 0 {
        if family == libc::AF_INET as u8 {
            32
        } else {
            128
        }
    } else {
        let Some(mask) = addresses[2] else {
            return Err(invalid());
        };
        // `RTA_NETMASK` is a radix-compressed mask, not a sockaddr to
        // validate: trailing zero bytes are omitted and the header's
        // `sa_family` does not describe the destination. Read the mask at the
        // destination family's address offset; omitted bytes are zero.
        let mask = ip_address(mask, family)?;
        let (mask, width) = match mask {
            IpAddr::V4(ip) => (u32::from(ip) as u128, 32),
            IpAddr::V6(ip) => (u128::from(ip), 128),
        };
        let ones = mask.count_ones();
        let expected = if ones == 0 {
            0
        } else {
            (u128::MAX >> (128 - width)) << (width - ones) & (u128::MAX >> (128 - width))
        };
        if mask != expected {
            return Err(invalid());
        }
        ones as u8
    };
    // `RTA_IFA` is the current interface address, not a declared preferred
    // source; it is parsed only to keep the address list aligned.
    Ok(Some(RouteSpec {
        destination: IpCidr::new(destination, prefix).map_err(|_| invalid())?,
        action: RouteAction::Unicast { dev, via },
    }))
}

impl RouteBackend for PlatformRouteBackend {
    async fn add(&mut self, route: &RouteSpec<u32>) -> Result<(), RouteError> {
        self.mutate(route, libc::RTM_ADD as u8).await
    }
    async fn remove(&mut self, route: &RouteSpec<u32>) -> Result<(), RouteError> {
        if self
            .existing(&BTreeSet::from([route.clone()]))
            .await?
            .is_empty()
        {
            return Ok(());
        }
        self.mutate(route, libc::RTM_DELETE as u8).await
    }
    async fn existing(
        &mut self,
        routes: &BTreeSet<RouteSpec<u32>>,
    ) -> Result<BTreeSet<RouteSpec<u32>>, RouteError> {
        if routes.is_empty() {
            return Ok(BTreeSet::new());
        }
        // Reject invalid input once, keyed by its normalized value; the
        // caller's original value is returned for a complete match.
        let mut requested = BTreeMap::<RouteSpec<u32>, Vec<&RouteSpec<u32>>>::new();
        for route in routes {
            let normalized = checked(route).map_err(|error| RouteError::Failed(error.into()))?;
            requested.entry(normalized).or_default().push(route);
        }
        // sysctl can allocate and copy a large FIB; keep it off async workers.
        let net_ns = self.net_ns.clone();
        let bytes = self
            .executor
            .spawn_blocking(move || net_ns.run(dump))
            .await
            .map_err(|error| RouteError::Failed(error.into()))?
            .map_err(|error| RouteError::Failed(error.into()))?
            .map_err(|error| RouteError::Failed(error.into()))?;
        let messages = frames(&bytes).map_err(|error| RouteError::Failed(error.into()))?;
        let mut present = BTreeSet::new();
        for message in messages {
            let Some(route) = decode(message).map_err(|error| RouteError::Failed(error.into()))?
            else {
                continue;
            };
            if let Some(candidates) = requested.get(&route) {
                present.extend(candidates.iter().map(|route| (*route).clone()));
            }
        }
        Ok(present)
    }
}


