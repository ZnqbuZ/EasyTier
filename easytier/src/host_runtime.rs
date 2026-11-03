use easytier_core::socket::BindConfig;
use std::{
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    ops::Deref,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

use async_trait::async_trait;
use easytier_core::{
    connectivity::{composite::ConnectorRuntime, transport::ConnectedByteStream},
    host::dns::{DnsQuery, DnsRecordResolver, DnsResolver, DnsSrvRecord},
    socket::{
        SocketContext,
        tcp::{
            TcpConnectOptions, TcpListenOptions, TcpSocketPurpose, VirtualTcpListenerFactory,
            VirtualTcpSocketFactory,
        },
        udp::{PreferredIpv6Source, VirtualUdpSocketFactory},
    },
};
use hashbrown::HashSet;
#[cfg(feature = "tun")]
use tokio::sync::Mutex as AsyncMutex;
use tokio::{net::UdpSocket, runtime::Handle, sync::watch};

use crate::{
    common::{
        dns::RuntimeDnsResolver,
        net_ns::NetNS,
        network::{collect_interfaces, collect_local_ip_addrs},
    },
    proto::peer_rpc::GetIpListResponse,
    socket::{
        tcp::{RuntimeTcpListener, RuntimeTcpSocket},
        udp::{RuntimeUdpSocket, RuntimeUdpSocketFactory},
    },
};

#[cfg(feature = "tun")]
use crate::instance::shared_virtual_nic::{ArcSharedVirtualNicRegistry, SharedVirtualNicRegistry};

/// Native services attached to one shared Core namespace handle.
/// Cloning a NetNS retains its platform resource, not this service owner.
#[derive(educe::Educe)]
#[educe(PartialEq, Eq, Hash)]
pub struct NativeNetNSServices {
    net_ns: NetNS,
    #[educe(PartialEq(ignore), Hash(ignore))]
    dns: RuntimeDnsResolver,
    #[cfg(feature = "tun")]
    #[educe(PartialEq(ignore), Hash(ignore))]
    pub(crate) nics: ArcSharedVirtualNicRegistry,
}

impl fmt::Debug for NativeNetNSServices {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeNetNSServices")
            .field("net_ns", &self.net_ns)
            .finish_non_exhaustive()
    }
}

impl Deref for NativeNetNSServices {
    type Target = NetNS;
    fn deref(&self) -> &NetNS {
        &self.net_ns
    }
}

// The service directory is keyed by its namespace; look entries up by handle.
impl hashbrown::Equivalent<Arc<NativeNetNSServices>> for NetNS {
    fn equivalent(&self, services: &Arc<NativeNetNSServices>) -> bool {
        *self == services.net_ns
    }
}

impl NativeNetNSServices {
    fn new(net_ns: NetNS) -> Self {
        Self {
            dns: RuntimeDnsResolver::in_net_ns(net_ns.clone()),
            #[cfg(feature = "tun")]
            nics: Arc::new(AsyncMutex::new(SharedVirtualNicRegistry::new())),
            net_ns,
        }
    }

    async fn wait_services_stopped(&self) -> anyhow::Result<()> {
        #[cfg(feature = "tun")]
        {
            let nics = self.nics.lock().await.take_for_shutdown();
            for nic in nics {
                nic.lock().await.invalidate_and_shutdown_dispatcher().await;
            }
        }
        Ok(())
    }

    pub(crate) fn of(net_ns: &NetNS) -> io::Result<Arc<Self>> {
        NativeHostRuntime::global().net_ns_services(net_ns)
    }

    /// Services of the process default namespace, for callers not bound to an instance.
    pub(crate) fn process_default() -> io::Result<Arc<Self>> {
        Self::of(&NetNS::process()?)
    }
}

/// Process-wide directory and owner of native services.
/// Instance I/O uses a capability bound to one canonical NetNS.
#[derive(educe::Educe)]
#[educe(Debug)]
pub struct NativeHostRuntime {
    net_ns: Mutex<HashSet<Arc<NativeNetNSServices>>>,
    #[educe(Debug(ignore))]
    executor: Mutex<ServiceExecutor>,
    closing: AtomicBool,
    shutdown_result: watch::Sender<Option<Result<(), Arc<str>>>>,
}

/// Driver for Host-owned services (shared NIC dispatchers, system DNS), independent of instance runtimes.
enum ServiceExecutor {
    Unstarted,
    Running(crate::instance::runtime_executor::NativeInstanceExecutor),
    Stopped,
}

static NATIVE_HOST_RUNTIME: OnceLock<Arc<NativeHostRuntime>> = OnceLock::new();

impl NativeHostRuntime {
    pub(crate) fn global() -> Arc<Self> {
        NATIVE_HOST_RUNTIME
            .get_or_init(|| Arc::new(NativeHostRuntime::new()))
            .clone()
    }

    fn new() -> Self {
        Self {
            net_ns: Mutex::new(HashSet::new()),
            executor: Mutex::new(ServiceExecutor::Unstarted),
            closing: AtomicBool::new(false),
            shutdown_result: watch::channel(None).0,
        }
    }

    pub(crate) fn service_executor(&self) -> io::Result<Handle> {
        let mut executor = self.executor.lock().unwrap();
        match &*executor {
            ServiceExecutor::Running(running) => Ok(running.handle()),
            ServiceExecutor::Stopped => Err(io::Error::other("native host runtime is closing")),
            ServiceExecutor::Unstarted => {
                let started =
                    crate::instance::runtime_executor::NativeInstanceExecutor::with_thread_name(
                        "easytier-shared",
                        true,
                        if cfg!(mobile) { 1 } else { 2 },
                    )
                    .map_err(io::Error::other)?;
                let handle = started.handle();
                *executor = ServiceExecutor::Running(started);
                Ok(handle)
            }
        }
    }

    // Called only after domain services have completed physical cleanup.
    pub(crate) fn request_executor_shutdown(&self) {
        self.closing.store(true, Ordering::Release);
        let executor = std::mem::replace(
            &mut *self.executor.lock().unwrap(),
            ServiceExecutor::Stopped,
        );
        // Task destruction may access the Host again; release the owner lock first.
        drop(executor);
    }

    pub(crate) async fn shutdown(self: &Arc<Self>) -> anyhow::Result<()> {
        self.request_service_shutdown();
        let mut result = self.shutdown_result.subscribe();
        let outcome = loop {
            if let Some(result) = result.borrow_and_update().clone() {
                break result;
            }
            result
                .changed()
                .await
                .map_err(|_| anyhow::anyhow!("native shutdown result disappeared"))?;
        };
        outcome.map_err(|error| anyhow::anyhow!("{error}"))
    }

    fn request_service_shutdown(self: &Arc<Self>) {
        if self.closing.swap(true, Ordering::AcqRel) {
            return;
        }
        let net_ns = self
            .net_ns
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        let host = self.clone();
        let interrupted = guarden::guard!([host = host.clone()] {
            host.request_executor_shutdown();
            host.shutdown_result.send_replace(Some(Err("native service shutdown was interrupted".into())));
        });
        match self.service_executor() {
            Ok(shared) => {
                shared.spawn(async move {
                    use futures::stream::{FuturesUnordered, StreamExt};
                    let mut pending = net_ns
                        .into_iter()
                        .map(|net_ns| async move {
                            net_ns
                                .wait_services_stopped()
                                .await
                                .map_err(|error| format!("{:?}: {error:#}", net_ns.id()))
                        })
                        .collect::<FuturesUnordered<_>>();
                    let mut errors = Vec::new();
                    while let Some(result) = pending.next().await {
                        if let Err(error) = result {
                            errors.push(error);
                        }
                    }
                    let outcome = if errors.is_empty() {
                        Ok(())
                    } else {
                        Err(errors.join("; ").into())
                    };
                    host.request_executor_shutdown();
                    host.shutdown_result.send_replace(Some(outcome));
                    let _ = interrupted.defuse();
                });
            }
            Err(error) => {
                self.request_executor_shutdown();
                self.shutdown_result
                    .send_replace(Some(Err(error.to_string().into())));
                let _ = interrupted.defuse();
            }
        }
    }

    fn net_ns_services(&self, net_ns: &NetNS) -> io::Result<Arc<NativeNetNSServices>> {
        if self.closing.load(Ordering::Acquire) {
            return Err(io::Error::other("native host runtime is closing"));
        }
        let mut entries = self.net_ns.lock().unwrap();
        if self.closing.load(Ordering::Acquire) {
            return Err(io::Error::other("native host runtime is closing"));
        }
        Ok(entries
            .get_or_insert_with(net_ns, |net_ns| {
                Arc::new(NativeNetNSServices::new(net_ns.clone()))
            })
            .clone())
    }
}

#[async_trait]
impl VirtualTcpSocketFactory for NativeNetNSServices {
    type Socket = RuntimeTcpSocket;

    async fn connect_tcp(&self, options: TcpConnectOptions) -> anyhow::Result<Self::Socket> {
        if options.purpose == TcpSocketPurpose::FakeTcp {
            cfg_select! {
                feature = "faketcp" => {
                    let remote_addr = options.remote_addr;
                    let socket_mark = options.bind.context.socket_mark;
                    let net_ns = self.net_ns.clone();
                    let socket = crate::socket::fake_tcp::connect_socket(remote_addr, socket_mark, net_ns).await?;
                    return Ok(RuntimeTcpSocket::from_fake_tcp(socket));
                },
                _ => {
                    anyhow::bail!("FakeTCP socket support is disabled")
                },
            }
        }

        crate::socket::tcp::connect_tcp(&self.net_ns, options)
            .await
            .map_err(anyhow::Error::from)
    }
}

#[async_trait]
impl ConnectorRuntime for NativeNetNSServices {
    async fn connect_byte_stream(
        &self,
        url: &url::Url,
    ) -> anyhow::Result<ConnectedByteStream<RuntimeTcpSocket>> {
        #[cfg(unix)]
        if url.scheme() == "unix" {
            let socket = self.run(tokio::net::UnixSocket::new_stream)??;
            let stream = socket.connect(url.path()).await?;
            let local_url = stream
                .local_addr()
                .ok()
                .and_then(crate::socket::tcp::url_from_unix_socket_addr);
            return Ok(ConnectedByteStream::new(
                RuntimeTcpSocket::from_unix(stream),
                local_url,
                url.clone(),
                Some(url.clone()),
            ));
        }

        anyhow::bail!("unsupported runtime byte stream: {url}")
    }

    async fn local_addr_for_remote(
        &self,
        remote_addr: SocketAddr,
        context: SocketContext,
    ) -> anyhow::Result<SocketAddr> {
        let bind_addr = match remote_addr {
            SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
        };
        let options = BindConfig {
            reuse_addr: Some(false),
            context,
            local_addr: Some(bind_addr),
            ..BindConfig::default()
        };
        let socket = crate::socket::bind::<UdpSocket>(&self.net_ns, options).await?;
        socket.connect(remote_addr).await?;
        Ok(socket.local_addr()?)
    }

    async fn preferred_ipv6_source(
        &self,
        ip: Ipv6Addr,
        context: SocketContext,
    ) -> Option<PreferredIpv6Source> {
        let _ = context;
        collect_interfaces(self.net_ns.clone(), false)
            .await
            .into_iter()
            .find(|interface| {
                interface
                    .addr
                    .iter()
                    .any(|local| matches!(local.ip(), IpAddr::V6(local_ip) if local_ip == ip))
            })
            .map(|interface| PreferredIpv6Source {
                ip,
                ifindex: interface.index,
            })
    }

    async fn collect_ip_addrs(&self, context: &SocketContext) -> GetIpListResponse {
        let _ = context;
        collect_local_ip_addrs(self.net_ns.clone()).await
    }
}

impl NativeNetNSServices {
    pub(crate) fn is_local_ip(&self, ip: &IpAddr, context: &SocketContext) -> bool {
        let _ = context;
        self.run(|| std::net::UdpSocket::bind(SocketAddr::new(*ip, 0)).is_ok())
            .unwrap_or(false)
    }
}

#[async_trait]
impl VirtualTcpListenerFactory for NativeNetNSServices {
    type Listener = RuntimeTcpListener;

    async fn bind_tcp(&self, options: TcpListenOptions) -> anyhow::Result<Arc<Self::Listener>> {
        Ok(Arc::new(
            crate::socket::tcp::bind_tcp_listener(&self.net_ns, options).await?,
        ))
    }
}

#[async_trait]
impl VirtualUdpSocketFactory for NativeNetNSServices {
    type Socket = RuntimeUdpSocket;

    async fn bind_udp(&self, options: BindConfig) -> anyhow::Result<Arc<Self::Socket>> {
        let socket = RuntimeUdpSocketFactory::new(self.net_ns.clone())
            .bind_udp(options)
            .await?;
        #[cfg(target_os = "windows")]
        crate::arch::windows::disable_connection_reset(socket.socket().as_ref())?;
        Ok(socket)
    }
}

#[async_trait]
impl DnsResolver for NativeNetNSServices {
    async fn resolve(&self, query: DnsQuery) -> anyhow::Result<Vec<IpAddr>> {
        self.dns.resolve(query).await
    }
}

#[async_trait]
impl DnsRecordResolver for NativeNetNSServices {
    async fn resolve_txt(&self, query: DnsQuery) -> anyhow::Result<String> {
        self.dns.resolve_txt(query).await
    }

    async fn resolve_srv(&self, query: DnsQuery) -> anyhow::Result<Vec<DnsSrvRecord>> {
        self.dns.resolve_srv(query).await
    }
}

#[cfg(test)]
mod tests {
    use crate::instance::runtime_executor::NativeInstanceExecutor;

    use super::*;

    #[tokio::test]
    async fn terminal_shutdown_closes_domain_admission_before_stopping_the_executor() {
        use std::time::Duration;
        let host = Arc::new(NativeHostRuntime::new());
        let _net_ns = NetNS::process().unwrap();
        let shared = host.service_executor().unwrap();
        assert_eq!(
            shared.metrics().num_workers(),
            if cfg!(mobile) { 1 } else { 2 }
        );
        // Hold the asynchronous NIC directory, so the cleanup remains pending
        // while checking the synchronous close boundary.
        #[cfg(feature = "tun")]
        let services = host.net_ns_services(&_net_ns).unwrap();
        #[cfg(feature = "tun")]
        let permit = services.nics.lock().await;
        host.request_service_shutdown();
        assert!(host.net_ns_services(&NetNS::process().unwrap()).is_err());
        assert!(host.service_executor().is_ok());
        #[cfg(feature = "tun")]
        drop(permit);
        tokio::time::timeout(Duration::from_secs(5), host.shutdown())
            .await
            .unwrap()
            .unwrap();
        assert!(host.service_executor().is_err());
        assert!(host.net_ns_services(&NetNS::process().unwrap()).is_err());
        host.shutdown().await.unwrap();
    }

    #[cfg(feature = "tun")]
    #[tokio::test]
    async fn terminal_cleanup_survives_the_shutdown_waiter_being_cancelled() {
        let host = Arc::new(NativeHostRuntime::new());
        let net_ns = NetNS::process().unwrap();
        let services = host.net_ns_services(&net_ns).unwrap();
        #[cfg(feature = "tun")]
        let permit = services.nics.lock().await;
        let waiting = host.clone();
        let waiter = tokio::spawn(async move { waiting.shutdown().await });
        tokio::task::yield_now().await;
        waiter.abort();
        let _ = waiter.await;
        drop(permit);
        tokio::time::timeout(std::time::Duration::from_secs(5), host.shutdown())
            .await
            .unwrap()
            .unwrap();
        assert!(host.service_executor().is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "run inside an isolated user+network namespace"]
    fn process_default_is_not_the_first_callers_temporary_domain() {
        let original = NetNS::current().unwrap();
        let temporary = crate::common::net_ns::tests::isolated_net_ns_for_test().unwrap();
        temporary
            .run(|| {
                assert_ne!(NetNS::current().unwrap().id(), original.id());
                assert_eq!(NetNS::process().unwrap().id(), original.id());
            })
            .unwrap();
    }

    #[tokio::test]
    async fn shared_reactor_survives_the_instance_that_first_initialized_it() {
        use std::time::Duration;
        let host = Arc::new(NativeHostRuntime::new());
        let first = NativeInstanceExecutor::new(false, 1).unwrap();
        let first_handle = first.handle();
        let net_ns = NativeNetNSServices::of(&NetNS::current().unwrap()).unwrap();
        let initialize_host = host.clone();
        let socket = first_handle
            .spawn(async move {
                let shared = initialize_host.service_executor().unwrap();
                shared
                    .spawn(async move {
                        net_ns
                            .run(|| {
                                let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
                                socket.set_nonblocking(true)?;
                                tokio::net::UdpSocket::from_std(socket)
                            })
                            .unwrap()
                            .unwrap()
                    })
                    .await
                    .unwrap()
            })
            .await
            .unwrap();
        // Use a synchronous socket construction in the domain, and ensure the
        // async resource was actually registered on the shared runtime.
        let address = socket.local_addr().unwrap();
        let shared_id = host.service_executor().unwrap().id();
        assert_ne!(shared_id, first_handle.id());
        let first_task = first_handle.spawn(std::future::pending::<()>());
        drop(first);
        assert!(
            tokio::time::timeout(Duration::from_secs(5), first_task)
                .await
                .unwrap()
                .unwrap_err()
                .is_cancelled()
        );
        let second = NativeInstanceExecutor::new(false, 1).unwrap();
        let socket = Arc::new(socket);
        let receive = socket.clone();
        let receive = second.handle().spawn(async move {
            let mut packet = [0; 32];
            let length = receive.recv_from(&mut packet).await.unwrap().0;
            packet[..length].to_vec()
        });
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .send_to(b"after-first-runtime", address)
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), receive)
                .await
                .unwrap()
                .unwrap(),
            b"after-first-runtime"
        );
        assert_eq!(host.service_executor().unwrap().id(), shared_id);
        drop(socket);
        let pending = host
            .service_executor()
            .unwrap()
            .spawn(std::future::pending::<()>());
        host.request_executor_shutdown();
        assert!(host.service_executor().is_err());
        assert!(
            tokio::time::timeout(Duration::from_secs(5), pending)
                .await
                .unwrap()
                .unwrap_err()
                .is_cancelled()
        );
    }

    #[test]
    fn native_host_runtime_is_process_wide() {
        assert!(Arc::ptr_eq(
            &NativeHostRuntime::global(),
            &NativeHostRuntime::global()
        ));
    }

    #[test]
    fn native_local_ip_probe_uses_process_runtime() {
        assert!(
            NativeNetNSServices::process_default()
                .unwrap()
                .is_local_ip(&IpAddr::V4(Ipv4Addr::LOCALHOST), &SocketContext::default(),)
        );
    }

    #[tokio::test]
    async fn native_route_probe_uses_remote_address_family() {
        let local_addr = NativeNetNSServices::process_default()
            .unwrap()
            .local_addr_for_remote(
                SocketAddr::from(([127, 0, 0, 1], 9)),
                SocketContext::default(),
            )
            .await
            .unwrap();

        assert!(local_addr.is_ipv4());
    }
}
