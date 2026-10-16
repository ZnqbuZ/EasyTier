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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instance::route::RouteKey;

    #[tokio::test]
    #[ignore = "run inside an isolated user+network namespace"]
    async fn kernel_sequence_rollover_replaces_socket_before_reusing_a_sequence() {
        let net_ns = crate::common::net_ns::tests::isolated_net_ns_for_test().unwrap();
        let index = dummy(&net_ns, "et-rollover");
        let shared = crate::host_runtime::native_host_runtime()
            .shared_executor()
            .unwrap();
        let mut backend = PlatformRouteBackend::new(&net_ns, &shared).unwrap();
        let first = route("198.18.78.0/24", index, 65535);
        let second = route("198.18.79.0/24", index, 65535);
        let late = route_request(
            &first,
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        )
        .unwrap()
        .sequence(1)
        .finish()
        .unwrap();
        backend.send(&late, &mut false).await.unwrap();
        let old = backend.socket.clone();
        backend.sequence = u32::MAX;
        backend.add(&second).await.unwrap();
        assert!(!Arc::ptr_eq(&old, &backend.socket));
        assert_eq!(backend.sequence, 1);
        assert!(backend.contains(&first).await.unwrap());
        assert!(backend.contains(&second).await.unwrap());
        backend.remove(&first).await.unwrap();
        backend.remove(&second).await.unwrap();
    }

    fn ip(net_ns: &crate::common::net_ns::NetNS, args: &[&str]) {
        let output = net_ns
            .run(|| std::process::Command::new("ip").args(args).output())
            .unwrap()
            .unwrap();
        assert!(
            output.status.success(),
            "ip {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn dummy(net_ns: &crate::common::net_ns::NetNS, name: &str) -> u32 {
        ip(net_ns, &["link", "add", name, "type", "dummy"]);
        ip(net_ns, &["link", "set", name, "up"]);
        net_ns
            .run(|| nix::net::if_::if_nametoindex(name))
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    #[ignore = "run inside an isolated user+network namespace"]
    async fn kernel_exclusive_slots_and_exact_delete_preserve_other_routes() {
        let net_ns = crate::common::net_ns::tests::isolated_net_ns_for_test().unwrap();
        let a = dummy(&net_ns, "et-a");
        let b = dummy(&net_ns, "et-b");
        let shared = crate::host_runtime::native_host_runtime()
            .shared_executor()
            .unwrap();
        let mut backend = PlatformRouteBackend::new(&net_ns, &shared).unwrap();
        for prefix in ["198.18.71.0/24", "2001:db8:71::/64"] {
            let first = route(prefix, a, 65535);
            backend.add(&first).await.unwrap();
            assert!(
                backend
                    .add(&first)
                    .await
                    .unwrap_err()
                    .is_errno(libc::EEXIST)
            );
            let conflict = RouteSpec {
                action: RouteAction::Unicast { dev: b, via: None },
                ..first.clone()
            };
            assert_eq!(RouteKey::of(&first), RouteKey::of(&conflict));
            assert!(
                backend
                    .add(&conflict)
                    .await
                    .unwrap_err()
                    .is_errno(libc::EEXIST)
            );
            assert!(
                backend
                    .existing(&BTreeSet::from([conflict.clone()]))
                    .await
                    .unwrap()
                    .is_empty()
            );
            let alternate = RouteSpec {
                metric: 65534,
                ..conflict.clone()
            };
            let other_table = RouteSpec {
                table: Some(501),
                ..conflict.clone()
            };
            backend.add(&alternate).await.unwrap();
            backend.add(&other_table).await.unwrap();
            let wanted = BTreeSet::from([first.clone(), alternate.clone(), other_table.clone()]);
            assert_eq!(backend.existing(&wanted).await.unwrap(), wanted);
            assert!(
                backend.remove(&conflict).await.is_err(),
                "wrong interface cannot delete the owned route"
            );
            assert!(backend.contains(&first).await.unwrap());
            backend.remove(&first).await.unwrap();
            assert_eq!(
                backend.existing(&wanted).await.unwrap(),
                BTreeSet::from([alternate.clone(), other_table.clone()])
            );
            backend.remove(&alternate).await.unwrap();
            backend.remove(&other_table).await.unwrap();
        }
    }

    #[tokio::test]
    #[ignore = "run inside an isolated user+network namespace"]
    async fn kernel_missing_ack_remains_unknown_and_late_ack_is_not_reused() {
        let net_ns = crate::common::net_ns::tests::isolated_net_ns_for_test().unwrap();
        let index = dummy(&net_ns, "et-a");
        let shared = crate::host_runtime::native_host_runtime()
            .shared_executor()
            .unwrap();
        let mut backend = PlatformRouteBackend::new(&net_ns, &shared).unwrap();
        let first = route("198.18.72.0/24", index, 65535);
        let second = route("198.18.73.0/24", index, 65535);
        let request = route_request(
            &first,
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        )
        .unwrap()
        .sequence(1)
        .finish()
        .unwrap();
        backend.sequence = 1;
        backend.send(&request, &mut false).await.unwrap();
        backend.add(&second).await.unwrap();
        assert!(backend.contains(&first).await.unwrap());
        backend.timeout = Duration::from_millis(50);
        let request = route_request(&first, RTM_DELROUTE, NLM_F_REQUEST).unwrap();
        let error = backend
            .request(request, ReplyKind::Ack)
            .await
            .err()
            .expect("successful delete without ACK must time out");
        assert!(matches!(
            error.into_route_error(true),
            RouteError::Unknown(_)
        ));
        assert!(!backend.contains(&first).await.unwrap());
        backend.remove(&second).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "run inside an isolated user+network namespace"]
    async fn kernel_backend_reactor_outlives_the_first_instance_executor() {
        use crate::common::native_executor::NativeExecutor;
        let net_ns = crate::common::net_ns::tests::isolated_net_ns_for_test().unwrap();
        let index = dummy(&net_ns, "et-a");
        let first = NativeExecutor::new(false, 1).unwrap();
        let mut backend = first
            .handle()
            .spawn(async move {
                let shared = crate::host_runtime::native_host_runtime()
                    .shared_executor()
                    .unwrap();
                PlatformRouteBackend::new(&net_ns, &shared).unwrap()
            })
            .await
            .unwrap();
        let pending = first.handle().spawn(std::future::pending::<()>());
        drop(first);
        assert!(
            tokio::time::timeout(Duration::from_secs(5), pending)
                .await
                .unwrap()
                .unwrap_err()
                .is_cancelled()
        );
        let owned = route("198.18.74.0/24", index, 65535);
        backend.add(&owned).await.unwrap();
        assert!(backend.contains(&owned).await.unwrap());
        backend.remove(&owned).await.unwrap();
    }

    fn route(destination: &str, ifindex: u32, metric: u32) -> RouteSpec<u32> {
        RouteSpec {
            destination: destination.parse().unwrap(),
            action: RouteAction::Unicast {
                dev: ifindex,
                via: None,
            },
            metric,
            table: Some(254),
        }
    }

    fn frame(sequence: u32, message_type: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
        let mut builder = MessageBuilder::new(message_type, flags).sequence(sequence);
        builder.append_bytes(payload);
        builder.finish().unwrap()
    }

    #[test]
    fn late_ack_cannot_complete_a_new_request() {
        let mut reply = Reply::new(2, ReplyKind::Ack);
        assert!(
            !reply
                .accept(&frame(1, NLMSG_ERROR, 0, &0_i32.to_ne_bytes()))
                .unwrap()
        );
        assert!(
            reply
                .accept(&frame(2, NLMSG_ERROR, 0, &0_i32.to_ne_bytes()))
                .unwrap()
        );
    }

    #[test]
    fn dump_waits_for_done_and_rejects_interruptions() {
        let mut reply = Reply::new(3, ReplyKind::Dump);
        assert!(
            !reply
                .accept(&frame(3, NLMSG_ERROR, 0, &0_i32.to_ne_bytes()))
                .unwrap()
        );
        assert!(
            reply
                .accept(&frame(3, NLMSG_DONE, 0, &0_i32.to_ne_bytes()))
                .unwrap()
        );
        let mut interrupted = Reply::new(3, ReplyKind::Dump);
        assert!(
            interrupted
                .accept(&frame(3, NLMSG_DONE, NLM_F_DUMP_INTR, &0_i32.to_ne_bytes()))
                .is_err()
        );
    }

    #[test]
    fn malformed_and_error_responses_do_not_report_success() {
        for errno in [libc::EEXIST, i32::MIN] {
            let mut reply = Reply::new(1, ReplyKind::Ack);
            assert!(
                reply
                    .accept(&frame(1, NLMSG_ERROR, 0, &errno.to_ne_bytes()))
                    .is_err()
            );
        }
        let mut reply = Reply::new(1, ReplyKind::Ack);
        assert!(matches!(
            reply.accept(&frame(1, NLMSG_ERROR, 0, &(-libc::EPERM).to_ne_bytes())),
            Err(ReplyFailure::Kernel(libc::EPERM))
        ));
        assert!(reply.accept(&frame(1, NLMSG_ERROR, 0, &[])).is_err());
    }

    fn encoded(route: &RouteSpec<u32>, message_type: u16) -> RouteMessage {
        let bytes = route_request(route, message_type, NLM_F_REQUEST | NLM_F_ACK)
            .unwrap()
            .finish()
            .unwrap();
        let (_, payload) = MessageIter::new(&bytes).next().unwrap().unwrap();
        RouteMessage::from_bytes(payload).unwrap()
    }

    fn append_attribute(bytes: &mut Vec<u8>, kind: u16, value: &[u8]) {
        let len = u16::try_from(4 + value.len()).unwrap();
        bytes.extend_from_slice(&len.to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(value);
        while bytes.len() % 4 != 0 {
            bytes.push(0);
        }
    }

    #[test]
    fn add_and_delete_use_the_same_complete_route_key() {
        for destination in ["10.71.0.0/24", "2001:db8:71::/64", "0.0.0.0/0", "::/0"] {
            let route = route(destination, 7, 65535);
            for message_type in [RTM_NEWROUTE, RTM_DELROUTE] {
                let message = encoded(&route, message_type);
                assert!(equivalent(&message, &route).unwrap());
                assert!(
                    !equivalent(
                        &message,
                        &RouteSpec {
                            metric: 5,
                            ..route.clone()
                        }
                    )
                    .unwrap()
                );
                assert!(
                    !equivalent(
                        &message,
                        &RouteSpec {
                            action: RouteAction::Unicast { dev: 8, via: None },
                            ..route.clone()
                        }
                    )
                    .unwrap()
                );
            }
        }
        assert!(
            route_request(
                &route("10.71.0.0/24", 0, 65535),
                RTM_DELROUTE,
                NLM_F_REQUEST
            )
            .is_err()
        );
    }

    #[test]
    fn gateway_is_encoded_and_compared_as_part_of_the_complete_route() {
        let via: IpAddr = "192.0.2.1".parse().unwrap();
        let route = RouteSpec {
            action: RouteAction::Unicast {
                dev: 7,
                via: Some(via),
            },
            ..route("198.18.20.0/24", 7, 100)
        };
        let message = encoded(&route, RTM_NEWROUTE);
        assert_eq!(message.oif(), Some(7));
        assert_eq!(message.gateway().unwrap(), Some(via));
        assert!(equivalent(&message, &route).unwrap());

        // A different next hop is a different complete route even when the
        // route key (table/prefix/metric) is the same.
        let changed = RouteSpec {
            action: RouteAction::Unicast {
                dev: 7,
                via: Some("192.0.2.2".parse().unwrap()),
            },
            ..route.clone()
        };
        assert_eq!(RouteKey::of(&route), RouteKey::of(&changed));
        assert!(!equivalent(&message, &changed).unwrap());
        assert!(
            !equivalent(
                &message,
                &RouteSpec {
                    action: RouteAction::Unicast { dev: 7, via: None },
                    ..route.clone()
                }
            )
            .unwrap()
        );
        assert!(
            route_request(
                &RouteSpec {
                    action: RouteAction::Unicast {
                        dev: 7,
                        via: Some("2001:db8::1".parse().unwrap()),
                    },
                    ..route.clone()
                },
                RTM_NEWROUTE,
                NLM_F_REQUEST,
            )
            .is_err(),
            "a gateway of another address family is a real input error"
        );
    }

    #[test]
    fn main_table_default_normalizes_to_explicit_254() {
        let implicit = RouteSpec {
            table: None,
            ..route("198.18.24.0/24", 7, 100)
        };
        let explicit = RouteSpec {
            table: Some(254),
            ..implicit.clone()
        };
        let message = encoded(&implicit, RTM_NEWROUTE);
        assert_eq!(message.table().unwrap(), 254);
        assert!(equivalent(&message, &explicit).unwrap());
        assert_eq!(RouteKey::of(&implicit), RouteKey::of(&explicit));
        assert!(
            route_request(
                &RouteSpec {
                    table: Some(0),
                    ..implicit
                },
                RTM_NEWROUTE,
                NLM_F_REQUEST,
            )
            .is_err(),
            "table zero is not a destination table"
        );
    }

    #[test]
    fn blackhole_and_unreachable_omit_the_device_but_ignore_kernel_device_carriers() {
        for action in [RouteAction::Blackhole, RouteAction::Unreachable] {
            let route = RouteSpec {
                action: action.clone(),
                ..route("198.18.21.0/24", 7, 100)
            };
            let message = encoded(&route, RTM_NEWROUTE);
            assert_eq!(message.oif(), None);
            assert!(equivalent(&message, &route).unwrap());

            // The kernel may report an output device for these actions; it is
            // not part of the route, so the rows still compare equal.
            let mut bytes = Vec::new();
            message.write_to(&mut bytes).unwrap();
            append_attribute(&mut bytes, 4, &1_u32.to_ne_bytes());
            let carried = RouteMessage::from_bytes(&bytes).unwrap();
            assert_eq!(carried.oif(), Some(1));
            assert!(equivalent(&carried, &route).unwrap());
            assert!(
                !equivalent(
                    &carried,
                    &RouteSpec {
                        action: RouteAction::Unicast { dev: 1, via: None },
                        ..route.clone()
                    }
                )
                .unwrap()
            );
        }
    }

    #[test]
    fn ipv4_metric_zero_is_a_real_metric_and_ipv6_zero_becomes_the_kernel_default() {
        let v4 = route("198.18.22.0/24", 7, 0);
        let message = encoded(&v4, RTM_NEWROUTE);
        assert_eq!(message.priority().unwrap(), 0);
        assert!(equivalent(&message, &v4).unwrap());

        let v6 = route("2001:db8:22::/64", 7, 0);
        let message = encoded(&v6, RTM_NEWROUTE);
        assert_eq!(message.priority().unwrap(), 1024);
        assert!(equivalent(&message, &v6).unwrap());

        // A kernel row that still reports a zero IPv6 metric is that same
        // default-priority route.
        let zeroed = RouteMessageBuilder::new(libc::AF_INET6 as u8)
            .destination("2001:db8:22::".parse().unwrap(), 64)
            .oif(7)
            .priority(0)
            .table(254)
            .static_protocol()
            .universe_scope()
            .route_type(RouteType::Unicast)
            .build();
        assert!(equivalent(&zeroed, &v6).unwrap());
        assert!(
            !equivalent(&zeroed, &RouteSpec { metric: 1, ..v6 }).unwrap(),
            "the normalized default is not an arbitrary metric"
        );
    }

    #[test]
    fn unsupported_forwarding_attributes_never_match_a_complete_route() {
        let route = route("198.18.23.0/24", 7, 100);
        let message = encoded(&route, RTM_NEWROUTE);
        let mut bytes = Vec::new();
        message.write_to(&mut bytes).unwrap();
        // RTA_PREFSRC is a source-selection capability the route type cannot
        // express; an unknown attribute could also change forwarding.
        append_attribute(&mut bytes, 7, &[192, 0, 2, 9]);
        let preferred = RouteMessage::from_bytes(&bytes).unwrap();
        assert_eq!(physical_route(&preferred).unwrap(), None);
        assert!(!equivalent(&preferred, &route).unwrap());

        let mut bytes = Vec::new();
        message.write_to(&mut bytes).unwrap();
        append_attribute(&mut bytes, 8, &[0; 4]);
        let unknown = RouteMessage::from_bytes(&bytes).unwrap();
        assert_eq!(physical_route(&unknown).unwrap(), None);
        assert!(!equivalent(&unknown, &route).unwrap());
    }
}
