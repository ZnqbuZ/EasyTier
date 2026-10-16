//! Windows IP Helper adapter. The shared controller owns policy and effects;
//! this backend only creates, reads and removes exact static forwarding rows.

use super::{RouteBackend, RouteError};
use crate::{common::net_ns::NetNS, instance::route::normalize_route};
use ::windows::Win32::{
    Foundation::{
        ERROR_ALREADY_EXISTS, ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR, WIN32_ERROR,
    },
    NetworkManagement::IpHelper::{
        CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable, GetIpForwardEntry2,
        GetIpForwardTable2, InitializeIpForwardEntry, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
    },
    Networking::WinSock::{
        ADDRESS_FAMILY, AF_INET, AF_INET6, AF_UNSPEC, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0,
        MIB_IPPROTO_NETMGMT, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET,
    },
};
use cidr::IpCidr;
use easytier_core::host::route::{RouteAction, RouteSpec};
use guarden::guarded;
use std::{
    collections::BTreeSet,
    ffi::c_void,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use tokio::runtime::Handle;

pub(crate) struct PlatformRouteBackend;

impl PlatformRouteBackend {
    pub(crate) fn new(net_ns: &NetNS, _: &Handle) -> anyhow::Result<Self> {
        // IP Helper has no per-namespace handle. The admission check keeps
        // construction consistent with the native backends that do.
        net_ns.ensure_open()?;
        Ok(Self)
    }
}

fn sockaddr(ip: IpAddr) -> SOCKADDR_INET {
    match ip {
        IpAddr::V4(ip) => SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(ip.octets()),
                    },
                },
                ..Default::default()
            },
        },
        IpAddr::V6(ip) => SOCKADDR_INET {
            Ipv6: SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 { Byte: ip.octets() },
                },
                ..Default::default()
            },
        },
    }
}

fn address(sockaddr: &SOCKADDR_INET) -> Option<IpAddr> {
    // SAFETY: the family selects which union member the kernel initialized.
    let family = unsafe { sockaddr.si_family.0 };
    if family == AF_INET.0 {
        // SAFETY: AF_INET selects the IPv4 member.
        Some(IpAddr::V4(Ipv4Addr::from(
            unsafe { sockaddr.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes(),
        )))
    } else if family == AF_INET6.0 {
        // SAFETY: AF_INET6 selects the IPv6 member.
        Some(IpAddr::V6(Ipv6Addr::from(unsafe {
            sockaddr.Ipv6.sin6_addr.u.Byte
        })))
    } else {
        None
    }
}

fn unspecified(destination: IpCidr) -> IpAddr {
    match destination {
        IpCidr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpCidr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }
}

/// The complete static row an accepted route describes.
///
/// Normalization rejects real input errors (a zero interface index or a
/// gateway of another address family) and folds an unspecified gateway into
/// the direct route. Every forwarding field the kernel acts on is explicit so
/// readback compares the actual row, not just its lookup key.
fn row(route: &RouteSpec<u32>) -> Result<MIB_IPFORWARD_ROW2, RouteError> {
    let RouteSpec {
        destination,
        action,
        metric,
    } = normalize_route(route.clone())?;
    let RouteAction::Unicast { dev, via } = action;
    let mut row = MIB_IPFORWARD_ROW2::default();
    // SAFETY: initializes every field of this default-initialized row.
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceIndex = dev;
    row.DestinationPrefix.Prefix = sockaddr(destination.first_address());
    row.DestinationPrefix.PrefixLength = destination.network_length();
    row.SitePrefixLength = destination.network_length();
    row.NextHop = sockaddr(via.unwrap_or_else(|| unspecified(destination)));
    row.Metric = metric;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row.ValidLifetime = u32::MAX;
    row.PreferredLifetime = u32::MAX;
    Ok(row)
}

/// A row is this effect only when it is the same static route: interface,
/// destination and prefix, next hop and metric must all match.
///
/// The expected row already carries the normalized next hop, so a direct
/// declaration requires the unspecified next hop while a gateway declaration
/// requires exactly its gateway. IP Helper lookups key on interface, prefix
/// and next hop only, so a changed metric or a gateway row must never satisfy
/// the comparison.
fn same_row(installed: &MIB_IPFORWARD_ROW2, expected: &MIB_IPFORWARD_ROW2) -> bool {
    installed.InterfaceIndex == expected.InterfaceIndex
        && installed.Metric == expected.Metric
        && installed.Protocol == MIB_IPPROTO_NETMGMT
        && installed.DestinationPrefix.PrefixLength == expected.DestinationPrefix.PrefixLength
        && address(&installed.DestinationPrefix.Prefix)
            == address(&expected.DestinationPrefix.Prefix)
        && address(&installed.NextHop) == address(&expected.NextHop)
}

fn failed(status: WIN32_ERROR) -> RouteError {
    let original = io::Error::from_raw_os_error(status.0 as i32);
    let kind = match status {
        ERROR_OBJECT_ALREADY_EXISTS | ERROR_ALREADY_EXISTS => io::ErrorKind::AlreadyExists,
        ERROR_NOT_FOUND => io::ErrorKind::NotFound,
        _ => original.kind(),
    };
    // Preserve the operating system's diagnostic while giving the shared
    // worker an ErrorKind it can classify. `io::Error::new` retains the
    // original error as its source.
    let error = if original.kind() == kind {
        original
    } else {
        io::Error::new(kind, original)
    };
    RouteError::Failed(error.into())
}

fn absent(route: &RouteSpec<u32>) -> RouteError {
    RouteError::Failed(
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("no installed route matches {} exactly", route.destination),
        )
        .into(),
    )
}

/// Enumerate every forwarding row of one family in a single kernel snapshot.
/// The table allocation is released on all paths by the scope guard.
fn visit(
    family: ADDRESS_FAMILY,
    mut inspect: impl FnMut(&MIB_IPFORWARD_ROW2),
) -> Result<(), RouteError> {
    let mut table = std::ptr::null_mut::<MIB_IPFORWARD_TABLE2>();
    // SAFETY: `table` is a valid out pointer; ownership of the allocation is
    // released below.
    let status = unsafe { GetIpForwardTable2(family, &mut table) };
    if status == ERROR_NOT_FOUND {
        // Documented result when the selected family has no route entries.
        return Ok(());
    }
    if status != NO_ERROR {
        return Err(failed(status));
    }
    guarded!(sync [raw = table] {
        // SAFETY: GetIpForwardTable2 transferred ownership of this allocation.
        unsafe { FreeMibTable(raw.cast::<c_void>()) }
    });
    if table.is_null() {
        return Err(RouteError::Failed(
            io::Error::other("IP Helper returned a null route table").into(),
        ));
    }
    // SAFETY: Table is an inline C array; the stride between entries is its
    // element size.
    let rows = unsafe { (*table).Table.as_ptr() };
    let count = unsafe { (*table).NumEntries } as usize;
    for index in 0..count {
        // SAFETY: the allocation holds at least NumEntries rows.
        inspect(unsafe { &*rows.add(index) });
    }
    Ok(())
}

/// The exact installed row for this route, if one is present. A row another
/// writer changed is reported as absent: it is not this effect and cannot
/// grant deletion authority.
fn lookup(route: &RouteSpec<u32>) -> Result<Option<MIB_IPFORWARD_ROW2>, RouteError> {
    let expected = row(route)?;
    let mut found = expected;
    // SAFETY: `found` is a fully initialized lookup key.
    let status = unsafe { GetIpForwardEntry2(&mut found) };
    if status == ERROR_NOT_FOUND {
        return Ok(None);
    }
    if status != NO_ERROR {
        return Err(failed(status));
    }
    Ok(same_row(&found, &expected).then_some(found))
}

impl RouteBackend for PlatformRouteBackend {
    async fn add(&mut self, route: &RouteSpec<u32>) -> Result<(), RouteError> {
        let row = row(route)?;
        // SAFETY: the kernel copies the row; it only needs to outlive the call.
        let status = unsafe { CreateIpForwardEntry2(&row) };
        if status == NO_ERROR {
            Ok(())
        } else {
            Err(failed(status))
        }
    }

    async fn remove(&mut self, route: &RouteSpec<u32>) -> Result<(), RouteError> {
        let Some(row) = lookup(route)? else {
            return Err(absent(route));
        };
        // SAFETY: the row was read back and outlives the call.
        let status = unsafe { DeleteIpForwardEntry2(&row) };
        match status {
            NO_ERROR => Ok(()),
            ERROR_NOT_FOUND => Err(absent(route)),
            _ => Err(failed(status)),
        }
    }

    async fn existing(
        &mut self,
        routes: &BTreeSet<RouteSpec<u32>>,
    ) -> Result<BTreeSet<RouteSpec<u32>>, RouteError> {
        if routes.is_empty() {
            return Ok(BTreeSet::new());
        }
        // Reject invalid input and normalize each expected row once, before
        // the single table scan.
        let mut expected = Vec::with_capacity(routes.len());
        for route in routes {
            expected.push((row(route)?, route));
        }
        let mut present = BTreeSet::new();
        visit(AF_UNSPEC, |installed| {
            for (wanted, route) in &expected {
                if same_row(installed, wanted) {
                    present.insert((*route).clone());
                }
            }
        })?;
        Ok(present)
    }
}


