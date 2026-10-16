//! Native routing-socket writes and sysctl readback for macOS / FreeBSD.
//! No shell output parsing; request ACKs are correlated and time bounded.

use super::{OsRoute, RouteBackend, RouteError};
use crate::common::net_ns::NetNS;
use cidr::IpCidr;
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

    async fn mutate(&mut self, route: &OsRoute, operation: u8) -> Result<(), RouteError> {
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
fn encode(route: &OsRoute, operation: u8, sequence: i32) -> io::Result<Vec<u8>> {
    if route.table != 254 || route.ifindex == 0 || route.ifindex > u16::MAX as u32 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported BSD route parameters",
        ));
    }
    let mut bytes = vec![0; HEADER];
    bytes[2] = libc::RTM_VERSION as u8;
    bytes[3] = operation;
    bytes[4..6].copy_from_slice(&(route.ifindex as u16).to_ne_bytes());
    let prefix = route.destination.network_length();
    let host = prefix == if route.destination.is_ipv4() { 32 } else { 128 };
    let flags = libc::RTF_UP | libc::RTF_STATIC | if host { libc::RTF_HOST } else { 0 };
    bytes[8..12].copy_from_slice(&flags.to_ne_bytes());
    let addrs = libc::RTA_DST
        | libc::RTA_GATEWAY
        | libc::RTA_NETMASK
        | libc::RTA_IFP
        | if route.preferred_source.is_some() {
            libc::RTA_IFA
        } else {
            0
        };
    bytes[12..16].copy_from_slice(&addrs.to_ne_bytes());
    bytes[16..20].copy_from_slice(&unsafe { libc::getpid() }.to_ne_bytes());
    bytes[20..24].copy_from_slice(&sequence.to_ne_bytes());
    // BSD hopcount is a TTL hint, not a route-selection priority. Keep
    // native metrics at their defaults; the controller still aggregates the
    // logical preference, and this platform has one unscoped prefix slot.
    append(&mut bytes, &ip_sockaddr(route.destination.first_address()));
    let mut link = [0u8; 8];
    link[0] = 8;
    link[1] = libc::AF_LINK as u8;
    link[2..4].copy_from_slice(&(route.ifindex as u16).to_ne_bytes());
    append(&mut bytes, &link);
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
    append(&mut bytes, &link);
    if let Some(source) = route.preferred_source {
        append(&mut bytes, &ip_sockaddr(source));
    }
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

fn decode(message: &[u8]) -> io::Result<Option<(IpCidr, u32, Option<IpAddr>)>> {
    if message.len() < HEADER || message[2] != libc::RTM_VERSION as u8 {
        return Err(invalid());
    }
    let flags = i32_at(message, 8)?;
    if flags & (libc::RTF_GATEWAY | libc::RTF_REJECT | libc::RTF_BLACKHOLE) != 0
        || flags & libc::RTF_STATIC == 0
    {
        return Ok(None);
    }
    #[cfg(target_os = "macos")]
    if flags & libc::RTF_IFSCOPE != 0 {
        return Ok(None);
    }
    let ifindex = u16::from_ne_bytes(message[4..6].try_into().unwrap()) as u32;
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
    let Some(gateway) = addresses[1] else {
        return Ok(None);
    };
    if gateway.get(1) != Some(&(libc::AF_LINK as u8)) {
        return Ok(None);
    }
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
    let destination =
        IpCidr::new(ip_address(destination, family)?, prefix).map_err(|_| invalid())?;
    let preferred_source = addresses[5]
        .filter(|ifa| ifa.get(1) == Some(&family))
        .map(|ifa| ip_address(ifa, family))
        .transpose()?;
    Ok(Some((destination, ifindex, preferred_source)))
}

impl RouteBackend for PlatformRouteBackend {
    async fn add(&mut self, route: &OsRoute) -> Result<(), RouteError> {
        self.mutate(route, libc::RTM_ADD as u8).await
    }
    async fn remove(&mut self, route: &OsRoute) -> Result<(), RouteError> {
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
        routes: &BTreeSet<OsRoute>,
    ) -> Result<BTreeSet<OsRoute>, RouteError> {
        if routes.is_empty() {
            return Ok(BTreeSet::new());
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
        let mut requested = BTreeMap::<_, Vec<&OsRoute>>::new();
        for route in routes {
            requested
                .entry((route.destination, route.ifindex))
                .or_default()
                .push(route);
        }
        let mut present = BTreeSet::new();
        for message in messages {
            let Some((destination, ifindex, source)) =
                decode(message).map_err(|error| RouteError::Failed(error.into()))?
            else {
                continue;
            };
            if let Some(candidates) = requested.get(&(destination, ifindex)) {
                for &route in candidates {
                    if route.preferred_source.is_none() || route.preferred_source == source {
                        present.insert(route.clone());
                    }
                }
            }
        }
        Ok(present)
    }
}
