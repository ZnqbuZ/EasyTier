use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};

use cidr::IpCidr;
use easytier_core::host::route::{RouteAction, RouteSpec};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
use nix::libc;
use tokio::{io::unix::AsyncFd, runtime::Handle};

use crate::{
    common::{
        ifcfg::netlink_wire::{
            MessageBuilder, MessageIter, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_DUMP_INTR,
            NLM_F_EXCL, NLM_F_REQUEST, NLMSG_DONE, NLMSG_ERROR, NetlinkDecode, NetlinkEncode,
            RTM_DELROUTE, RTM_GETROUTE, RTM_NEWROUTE, RouteMessage, RouteMessageBuilder, RouteType,
            netlink_error_code,
        },
        net_ns::NetNS,
    },
    instance::route::normalize_route,
};

use super::{RouteBackend, RouteError};

/// One writer's reusable socket, bound to its network namespace at creation.
/// Socket setup uses a short synchronous namespace scope. Readiness, ACKs and
/// timeout driving belong to the explicitly selected process shared runtime.
pub(crate) struct PlatformRouteBackend {
    socket: Arc<AsyncFd<Socket>>,
    net_ns: NetNS,
    executor: Handle,
    sequence: u32,
    timeout: Duration,
}

impl PlatformRouteBackend {
    pub(crate) fn new(net_ns: &NetNS, executor: &Handle) -> anyhow::Result<Self> {
        let socket = Self::socket(net_ns, executor)?;
        Ok(Self {
            socket,
            net_ns: net_ns.clone(),
            executor: executor.clone(),
            sequence: 0,
            timeout: Duration::from_secs(2),
        })
    }

    fn socket(net_ns: &NetNS, executor: &Handle) -> anyhow::Result<Arc<AsyncFd<Socket>>> {
        let socket = net_ns.run(|| -> io::Result<Socket> {
            let mut socket = Socket::new(NETLINK_ROUTE)?;
            socket.bind_auto()?;
            socket.connect(&SocketAddr::new(0, 0))?;
            socket.set_non_blocking(true)?;
            Ok(socket)
        })??;
        // Explicit registration on the host-owned Reactor, even when a first
        // caller enters from a short-lived instance runtime.
        let _entered = executor.enter();
        Ok(Arc::new(AsyncFd::new(socket)?))
    }

    async fn send(&self, request: &[u8], sent: &mut bool) -> io::Result<()> {
        loop {
            let mut ready = self.socket.writable().await?;
            match ready.try_io(|socket| {
                let result = socket.get_ref().send(request, 0);
                // WouldBlock has not queued a datagram. Any other attempted
                // send is conservatively uncertain until a matching ACK.
                *sent = !matches!(&result, Err(error) if error.kind() == io::ErrorKind::WouldBlock);
                result
            }) {
                Ok(Ok(len)) if len == request.len() => return Ok(()),
                Ok(Ok(_)) => return Err(io::Error::other("short netlink datagram send")),
                Ok(Err(error)) => return Err(error),
                Err(_) => continue,
            }
        }
    }

    async fn request(
        &mut self,
        request: MessageBuilder,
        kind: ReplyKind,
    ) -> Result<Vec<RouteMessage>, RequestFailure> {
        if self.sequence == u32::MAX {
            // Allocate/register the replacement before dropping the old socket:
            // its port cannot be reused and late ACKs stay on the old queue.
            let socket = Self::socket(&self.net_ns, &self.executor)
                .map_err(|error| RequestFailure::io(io::Error::other(error), false))?;
            self.socket = socket;
            self.sequence = 0;
        }
        self.sequence += 1;
        let request = request
            .sequence(self.sequence)
            .finish()
            .map_err(|error| RequestFailure::io(error, false))?;
        let mut reply = Reply::new(self.sequence, kind);
        let mut sent = false;
        let result = tokio::time::timeout(self.timeout, async {
            self.send(&request, &mut sent)
                .await
                .map_err(|error| RequestFailure::io(error, sent))?;
            loop {
                let bytes = receive(&self.socket)
                    .await
                    .map_err(|error| RequestFailure::io(error, sent))?;
                if reply.accept(&bytes).map_err(|error| match error {
                    ReplyFailure::Kernel(errno) => RequestFailure::Kernel(errno),
                    ReplyFailure::Io(error) => RequestFailure::io(error, sent),
                })? {
                    return Ok(reply.routes);
                }
            }
        })
        .await;
        result.unwrap_or_else(|_| {
            Err(RequestFailure::io(
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "netlink response deadline exceeded",
                ),
                sent,
            ))
        })
    }

    #[cfg(test)]
    async fn contains(&mut self, route: &RouteSpec<u32>) -> Result<bool, RouteError> {
        Ok(self
            .existing(&BTreeSet::from([route.clone()]))
            .await?
            .contains(route))
    }

    async fn dump(&mut self, family: u8) -> Result<Vec<RouteMessage>, RouteError> {
        let mut header = RouteMessage::dump_header();
        header[0] = family;
        let mut request = MessageBuilder::new(RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP);
        request.append_bytes(&header);
        self.request(request, ReplyKind::Dump)
            .await
            .map_err(|error| error.into_route_error(false))
    }
}

impl RouteBackend for PlatformRouteBackend {
    async fn add(&mut self, route: &RouteSpec<u32>) -> Result<(), RouteError> {
        let request = route_request(
            route,
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        )?;
        self.request(request, ReplyKind::Ack)
            .await
            .map(|_| ())
            .map_err(|error| error.into_route_error(true))
    }

    async fn remove(&mut self, route: &RouteSpec<u32>) -> Result<(), RouteError> {
        let normalized = normalize_route(route.clone())?;
        // Linux treats a zero delete priority as a wildcard. An IPv6 zero
        // metric has already been normalized to the kernel default, but an
        // IPv4 request can still carry a real metric-zero row. Confirm the
        // complete row exists first so a missing route cannot remove a row
        // that belongs to another metric.
        if normalized.metric == 0 {
            let present = self.existing(&BTreeSet::from([route.clone()])).await?;
            if present.is_empty() {
                return Err(RouteError::Failed(
                    io::Error::from_raw_os_error(libc::ENOENT).into(),
                ));
            }
        }
        let request = route_request(&normalized, RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK)?;
        self.request(request, ReplyKind::Ack)
            .await
            .map(|_| ())
            .map_err(|error| error.into_route_error(true))
    }

    async fn existing(
        &mut self,
        routes: &BTreeSet<RouteSpec<u32>>,
    ) -> Result<BTreeSet<RouteSpec<u32>>, RouteError> {
        let mut requested = BTreeMap::<RouteSpec<u32>, Vec<&RouteSpec<u32>>>::new();
        let mut families = BTreeSet::new();
        for route in routes {
            let normalized = normalize_route(route.clone())?;
            families.insert(family(normalized.destination));
            requested.entry(normalized).or_default().push(route);
        }
        let mut existing = BTreeSet::new();
        // Exceptional inspection batches use one dump per family, regardless
        // of how many isolated routes need checking. No steady-state dumps.
        for family in families {
            for message in self.dump(family).await? {
                if let Some(route) =
                    physical_route(&message).map_err(|error| RouteError::Failed(error.into()))?
                    && let Some(matches) = requested.get(&route)
                {
                    existing.extend(matches.iter().map(|route| (*route).clone()));
                }
            }
        }
        Ok(existing)
    }
}

fn family(destination: IpCidr) -> u8 {
    match destination {
        IpCidr::V4(_) => libc::AF_INET as u8,
        IpCidr::V6(_) => libc::AF_INET6 as u8,
    }
}

fn route_request(
    route: &RouteSpec<u32>,
    message_type: u16,
    flags: u16,
) -> Result<MessageBuilder, RouteError> {
    let route = normalize_route(route.clone())?;
    let mut message = RouteMessageBuilder::new(family(route.destination))
        .destination(
            route.destination.first_address(),
            route.destination.network_length(),
        )
        .priority(route.metric)
        .table(route.table.unwrap_or(254))
        .static_protocol()
        .universe_scope();
    match route.action {
        RouteAction::Unicast { dev, via } => {
            message = message.route_type(RouteType::Unicast).oif(dev);
            if let Some(via) = via {
                message = message.gateway(via);
            }
        }
        RouteAction::Blackhole => message = message.route_type(RouteType::Blackhole),
        RouteAction::Unreachable => message = message.route_type(RouteType::Unreachable),
    }
    let message = message.build();
    let mut request = MessageBuilder::new(message_type, flags);
    let mut bytes = Vec::new();
    message
        .write_to(&mut bytes)
        .map_err(|error| RouteError::Failed(error.into()))?;
    request.append_bytes(&bytes);
    Ok(request)
}

/// The complete installable route a kernel row represents.
///
/// Rows that use another protocol, scope, action or a forwarding capability
/// this route type cannot express are not equal to any requested route; they
/// are reported as `None` rather than silently ignored. Decode errors (bad
/// attribute lengths, address families, duplicates) are returned as errors so
/// an incomplete dump is never treated as "the route is absent".
fn physical_route(message: &RouteMessage) -> io::Result<Option<RouteSpec<u32>>> {
    if message.protocol() != libc::RTPROT_STATIC
        || message.scope() != libc::RT_SCOPE_UNIVERSE
        || !message.is_supported_route()
    {
        return Ok(None);
    }
    let unspecified = match message.family() as i32 {
        libc::AF_INET => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        libc::AF_INET6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        _ => return Ok(None),
    };
    let destination = IpCidr::new(
        message.destination().copied().unwrap_or(unspecified),
        message.dst_len(),
    )
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let action = match message.route_type() {
        RouteType::Unicast => {
            let Some(dev) = message.oif() else {
                return Ok(None);
            };
            RouteAction::Unicast {
                dev,
                via: message.gateway()?,
            }
        }
        // A device-less action carries no route device. The kernel may attach
        // a loopback output device to such a row; that is not a forwarding
        // field of the declared route. A next hop, however, is not something
        // this action can express, so such a row is not equal.
        RouteType::Blackhole | RouteType::Unreachable if message.gateway()?.is_some() => {
            return Ok(None);
        }
        RouteType::Blackhole => RouteAction::Blackhole,
        RouteType::Unreachable => RouteAction::Unreachable,
        RouteType::Other(_) => return Ok(None),
    };
    let route = RouteSpec {
        destination,
        action,
        metric: message.priority()?,
        table: Some(message.table()?),
    };
    // Apply the same input normalization as the request side (main table and
    // the IPv6 default metric), and treat a row that could not have been
    // requested as not equal.
    Ok(normalize_route(route).ok())
}

#[cfg(test)]
fn equivalent(message: &RouteMessage, route: &RouteSpec<u32>) -> io::Result<bool> {
    let Ok(route) = normalize_route(route.clone()) else {
        return Ok(false);
    };
    Ok(physical_route(message)? == Some(route))
}

#[derive(Clone, Copy)]
enum ReplyKind {
    Ack,
    Dump,
}

struct Reply {
    sequence: u32,
    kind: ReplyKind,
    routes: Vec<RouteMessage>,
}

impl Reply {
    fn new(sequence: u32, kind: ReplyKind) -> Self {
        Self {
            sequence,
            kind,
            routes: Vec::new(),
        }
    }

    fn accept(&mut self, bytes: &[u8]) -> Result<bool, ReplyFailure> {
        for frame in MessageIter::new(bytes) {
            let (header, payload) = frame.map_err(ReplyFailure::Io)?;
            if header.sequence != self.sequence {
                continue;
            }
            if header.flags & NLM_F_DUMP_INTR != 0 {
                return Err(ReplyFailure::Io(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "netlink dump interrupted",
                )));
            }
            match header.message_type {
                NLMSG_ERROR => {
                    let errno = netlink_error_code(payload).map_err(ReplyFailure::Io)?;
                    if errno > 0 {
                        return Err(ReplyFailure::Io(io::Error::other(
                            "invalid positive netlink errno",
                        )));
                    }
                    if errno != 0 {
                        return Err(ReplyFailure::Kernel(errno.checked_abs().ok_or_else(
                            || ReplyFailure::Io(io::Error::other("invalid netlink errno")),
                        )?));
                    }
                    if matches!(self.kind, ReplyKind::Ack) {
                        return Ok(true);
                    }
                }
                NLMSG_DONE if matches!(self.kind, ReplyKind::Dump) => {
                    let errno = netlink_error_code(payload).map_err(ReplyFailure::Io)?;
                    if errno > 0 {
                        return Err(ReplyFailure::Io(io::Error::other(
                            "invalid positive netlink errno",
                        )));
                    }
                    if errno != 0 {
                        return Err(ReplyFailure::Kernel(errno.checked_abs().ok_or_else(
                            || ReplyFailure::Io(io::Error::other("invalid netlink errno")),
                        )?));
                    }
                    return Ok(true);
                }
                RTM_NEWROUTE if matches!(self.kind, ReplyKind::Dump) => {
                    self.routes
                        .push(RouteMessage::from_bytes(payload).map_err(ReplyFailure::Io)?);
                }
                _ => {
                    return Err(ReplyFailure::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected netlink response",
                    )));
                }
            }
        }
        Ok(false)
    }
}

#[derive(Debug)]
enum ReplyFailure {
    Kernel(i32),
    Io(io::Error),
}
enum RequestFailure {
    Kernel(i32),
    Io { source: io::Error, sent: bool },
}

impl RequestFailure {
    fn io(source: io::Error, sent: bool) -> Self {
        Self::Io { source, sent }
    }
    fn into_route_error(self, mutation: bool) -> RouteError {
        match self {
            Self::Kernel(errno) => RouteError::Failed(io::Error::from_raw_os_error(errno).into()),
            Self::Io { source, sent: true } if mutation => RouteError::Unknown(source.into()),
            Self::Io { source, .. } => RouteError::Failed(source.into()),
        }
    }
}

async fn receive(socket: &AsyncFd<Socket>) -> io::Result<Vec<u8>> {
    loop {
        let mut ready = socket.readable().await?;
        match ready.try_io(|socket| socket.get_ref().recv_from_full()) {
            Ok(Ok((bytes, sender))) if sender.port_number() == 0 => return Ok(bytes),
            Ok(Ok(_)) => continue,
            Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
            Ok(Err(error)) => return Err(error),
            Err(_) => continue,
        }
    }
}


