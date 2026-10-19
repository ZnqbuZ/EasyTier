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
        native_executor::NativeExecutor,
        netns::{NetNS, PlatformNamespace},
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
pub struct NativeNamespaceServices {
    namespace: NetNS,
    #[educe(PartialEq(ignore), Hash(ignore))]
    dns: RuntimeDnsResolver,
    #[cfg(feature = "tun")]
    #[educe(PartialEq(ignore), Hash(ignore))]
    pub(crate) nics: ArcSharedVirtualNicRegistry,
}

impl fmt::Debug for NativeNamespaceServices {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeNamespaceServices")
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl Deref for NativeNamespaceServices {
    type Target = NetNS;
    fn deref(&self) -> &NetNS {
        &self.namespace
    }
}

impl NativeNamespaceServices {
    fn new(namespace: NetNS) -> Self {
        Self {
            dns: RuntimeDnsResolver::in_namespace(namespace.clone()),
            #[cfg(feature = "tun")]
            nics: Arc::new(AsyncMutex::new(SharedVirtualNicRegistry::in_domain(
                namespace.clone(),
            ))),
            namespace,
        }
    }

    fn request_service_shutdown(&self) {
        self.namespace.close();
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
}

pub(crate) fn namespace_services(namespace: &NetNS) -> io::Result<Arc<NativeNamespaceServices>> {
    native_host_runtime().services(namespace)
}

/// Process-wide directory and owner of native services.
/// Instance I/O uses a capability bound to one canonical NetNS.
#[derive(Debug)]
pub struct NativeHostRuntime {
    namespaces: Mutex<HashSet<Arc<NativeNamespaceServices>>>,
    default_platform: io::Result<PlatformNamespace>,
    default_namespace: OnceLock<NetNS>,
    shared: OnceLock<Result<NativeExecutor, String>>,
    shared_initialization: Mutex<()>,
    closing: AtomicBool,
    executor_stopping: AtomicBool,
    shutdown_result: watch::Sender<Option<Result<(), Arc<str>>>>,
}

static NATIVE_HOST_RUNTIME: OnceLock<Arc<NativeHostRuntime>> = OnceLock::new();

pub(crate) fn native_host_runtime() -> Arc<NativeHostRuntime> {
    NATIVE_HOST_RUNTIME
        .get_or_init(|| Arc::new(NativeHostRuntime::new()))
        .clone()
}

impl NativeHostRuntime {
    fn new() -> Self {
        Self {
            namespaces: Mutex::new(HashSet::new()),
            default_platform: PlatformNamespace::process_default(),
            default_namespace: OnceLock::new(),
            shared: OnceLock::new(),
            shared_initialization: Mutex::new(()),
            closing: AtomicBool::new(false),
            executor_stopping: AtomicBool::new(false),
            shutdown_result: watch::channel(None).0,
        }
    }

    pub(crate) fn shared_executor(&self) -> io::Result<Handle> {
        if self.executor_stopping.load(Ordering::Acquire) {
            return Err(io::Error::other("native host runtime is closing"));
        }
        let result = if let Some(shared) = self.shared.get() {
            shared
        } else {
            let _initialization = self.shared_initialization.lock().unwrap();
            if self.executor_stopping.load(Ordering::Acquire) {
                return Err(io::Error::other("native host runtime is closing"));
            }
            self.shared
                .get_or_init(|| NativeExecutor::shared().map_err(|error| error.to_string()))
        };
        result
            .as_ref()
            .map(NativeExecutor::handle)
            .map_err(|error| io::Error::other(error.clone()))
    }

    // Called only after domain services have completed physical cleanup.
    pub(crate) fn request_executor_shutdown(&self) {
        self.closing.store(true, Ordering::Release);
        self.executor_stopping.store(true, Ordering::Release);
        let _initialization = self.shared_initialization.lock().unwrap();
        if let Some(Ok(shared)) = self.shared.get() {
            shared.request_shutdown();
        }
    }

    pub(crate) async fn wait_executor_stopped(&self) {
        if let Some(Ok(shared)) = self.shared.get() {
            shared.wait_stopped().await;
        }
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
        self.wait_executor_stopped().await;
        outcome.map_err(|error| anyhow::anyhow!("{error}"))
    }

    fn request_service_shutdown(self: &Arc<Self>) {
        if self.closing.swap(true, Ordering::AcqRel) {
            return;
        }
        let namespaces = self
            .namespaces
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        for namespace in &namespaces {
            namespace.request_service_shutdown();
        }
        let host = self.clone();
        let interrupted = guarden::guard!([host = host.clone()] {
            host.shutdown_result.send_replace(Some(Err("native service shutdown was interrupted".into())));
            host.request_executor_shutdown();
        });
        match self.shared_executor() {
            Ok(shared) => {
                shared.spawn(async move {
                    use futures::stream::{FuturesUnordered, StreamExt};
                    let mut pending = namespaces
                        .into_iter()
                        .map(|namespace| async move {
                            namespace
                                .wait_services_stopped()
                                .await
                                .map_err(|error| format!("{:?}: {error:#}", namespace.id()))
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
                    host.shutdown_result.send_replace(Some(outcome));
                    let _ = interrupted.defuse();
                    host.request_executor_shutdown();
                });
            }
            Err(error) => {
                self.shutdown_result
                    .send_replace(Some(Err(error.to_string().into())));
                let _ = interrupted.defuse();
                self.request_executor_shutdown();
            }
        }
    }

    pub(crate) fn intern_namespace(&self, platform: PlatformNamespace) -> io::Result<NetNS> {
        if self.closing.load(Ordering::Acquire) {
            return Err(io::Error::other("native host runtime is closing"));
        }
        let candidate = NetNS::new(platform.id(), platform);
        let mut entries = self.namespaces.lock().unwrap();
        if self.closing.load(Ordering::Acquire) {
            return Err(io::Error::other("native host runtime is closing"));
        }
        let services = entries.get_or_insert_with(&candidate, |namespace| {
            Arc::new(NativeNamespaceServices::new(namespace.clone()))
        });
        Ok(services.namespace.clone())
    }

    fn services(&self, namespace: &NetNS) -> io::Result<Arc<NativeNamespaceServices>> {
        self.namespaces
            .lock()
            .unwrap()
            .get(namespace)
            .cloned()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "network namespace is not registered with this native Host",
                )
            })
    }

    pub(crate) fn capture_default_namespace(&self) -> io::Result<NetNS> {
        if self.closing.load(Ordering::Acquire) {
            return Err(io::Error::other("native host runtime is closing"));
        }
        if let Some(namespace) = self.default_namespace.get() {
            return Ok(namespace.clone());
        }
        let platform = self
            .default_platform
            .as_ref()
            .map_err(|error| io::Error::new(error.kind(), error.to_string()))?;
        let candidate = self.intern_namespace(platform.clone())?;
        let _ = self.default_namespace.set(candidate);
        Ok(self.default_namespace.get().unwrap().clone())
    }

    pub(crate) fn is_process_default(&self, namespace: &NetNS) -> io::Result<bool> {
        self.default_platform
            .as_ref()
            .map(|default| Some(default.id()) == namespace.id())
            .map_err(|error| io::Error::new(error.kind(), error.to_string()))
    }

    /// Resolve an existing shared handle; names and wire references never select
    /// or reopen a native namespace here.
    pub(crate) fn namespace(
        &self,
        context: &SocketContext,
    ) -> io::Result<Arc<NativeNamespaceServices>> {
        if self.closing.load(Ordering::Acquire) {
            return Err(io::Error::other("native host runtime is closing"));
        }
        match &context.netns {
            Some(namespace) => self.services(namespace),
            None => self.services(&self.capture_default_namespace()?),
        }
    }
}

#[async_trait]
impl VirtualTcpSocketFactory for NativeNamespaceServices {
    type Socket = RuntimeTcpSocket;

    async fn connect_tcp(&self, mut options: TcpConnectOptions) -> anyhow::Result<Self::Socket> {
        self.prepare_bind(&mut options.bind)?;
        if options.purpose == TcpSocketPurpose::FakeTcp {
            cfg_select! {
                feature = "faketcp" => {
                    let remote_addr = options.remote_addr;
                    let socket_mark = options.bind.context.socket_mark;
                    let net_ns = self.namespace.clone();
                    let socket = crate::socket::fake_tcp::connect_socket(remote_addr, socket_mark, net_ns).await?;
                    return Ok(RuntimeTcpSocket::from_fake_tcp(socket));
                },
                _ => {
                    anyhow::bail!("FakeTCP socket support is disabled")
                },
            }
        }

        crate::socket::tcp::connect_tcp(options)
            .await
            .map_err(anyhow::Error::from)
    }
}

#[async_trait]
impl ConnectorRuntime for NativeNamespaceServices {
    async fn connect_byte_stream(
        &self,
        url: &url::Url,
    ) -> anyhow::Result<ConnectedByteStream<RuntimeTcpSocket>> {
        self.ensure_open()?;
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
        self.validate_context(&context)?;
        let bind_addr = match remote_addr {
            SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
        };
        let options = BindConfig {
            reuse_addr: Some(false),
            namespace: Some(self.namespace.clone()),
            context,
            local_addr: Some(bind_addr),
            ..BindConfig::default()
        };
        let socket = crate::socket::bind::<UdpSocket>(options).await?;
        socket.connect(remote_addr).await?;
        Ok(socket.local_addr()?)
    }

    async fn preferred_ipv6_source(
        &self,
        ip: Ipv6Addr,
        context: SocketContext,
    ) -> Option<PreferredIpv6Source> {
        self.validate_context(&context).ok()?;
        collect_interfaces(self.namespace.clone(), false)
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
        if self.validate_context(context).is_err() {
            return GetIpListResponse::default();
        }
        collect_local_ip_addrs(self.namespace.clone()).await
    }
}

impl NativeNamespaceServices {
    fn prepare_bind(&self, config: &mut BindConfig) -> io::Result<()> {
        self.validate_context(&config.effective_context())?;
        // This capability supplies the default only after validating the
        // effective request; an explicit override may replace a stale context.
        config.namespace = Some(self.namespace.clone());
        Ok(())
    }

    pub(crate) fn is_local_ip(&self, ip: &IpAddr, context: &SocketContext) -> bool {
        self.validate_context(context).is_ok()
            && self
                .run(|| std::net::UdpSocket::bind(SocketAddr::new(*ip, 0)).is_ok())
                .unwrap_or(false)
    }
}

#[async_trait]
impl VirtualTcpListenerFactory for NativeNamespaceServices {
    type Listener = RuntimeTcpListener;

    async fn bind_tcp(&self, mut options: TcpListenOptions) -> anyhow::Result<Arc<Self::Listener>> {
        self.prepare_bind(&mut options.bind)?;
        Ok(Arc::new(
            crate::socket::tcp::bind_tcp_listener(options).await?,
        ))
    }
}

#[async_trait]
impl VirtualUdpSocketFactory for NativeNamespaceServices {
    type Socket = RuntimeUdpSocket;

    async fn bind_udp(&self, mut options: BindConfig) -> anyhow::Result<Arc<Self::Socket>> {
        self.prepare_bind(&mut options)?;
        let socket = RuntimeUdpSocketFactory::new().bind_udp(options).await?;
        #[cfg(target_os = "windows")]
        crate::arch::windows::disable_connection_reset(socket.socket().as_ref())?;
        Ok(socket)
    }
}

#[async_trait]
impl DnsResolver for NativeNamespaceServices {
    async fn resolve(&self, query: DnsQuery) -> anyhow::Result<Vec<IpAddr>> {
        self.ensure_open()?;
        self.dns.resolve(query).await
    }
}

#[async_trait]
impl DnsRecordResolver for NativeNamespaceServices {
    async fn resolve_txt(&self, query: DnsQuery) -> anyhow::Result<String> {
        self.ensure_open()?;
        self.dns.resolve_txt(query).await
    }

    async fn resolve_srv(&self, query: DnsQuery) -> anyhow::Result<Vec<DnsSrvRecord>> {
        self.ensure_open()?;
        self.dns.resolve_srv(query).await
    }
}

// Standalone process-level convenience APIs route to existing pinned capabilities.
#[async_trait]
impl VirtualTcpSocketFactory for NativeHostRuntime {
    type Socket = RuntimeTcpSocket;
    async fn connect_tcp(&self, options: TcpConnectOptions) -> anyhow::Result<Self::Socket> {
        self.namespace(&options.bind.effective_context())?
            .connect_tcp(options)
            .await
    }
}
#[async_trait]
impl VirtualTcpListenerFactory for NativeHostRuntime {
    type Listener = RuntimeTcpListener;
    async fn bind_tcp(&self, options: TcpListenOptions) -> anyhow::Result<Arc<Self::Listener>> {
        self.namespace(&options.bind.effective_context())?
            .bind_tcp(options)
            .await
    }
}
#[async_trait]
impl VirtualUdpSocketFactory for NativeHostRuntime {
    type Socket = RuntimeUdpSocket;
    async fn bind_udp(&self, options: BindConfig) -> anyhow::Result<Arc<Self::Socket>> {
        self.namespace(&options.effective_context())?
            .bind_udp(options)
            .await
    }
}
#[async_trait]
impl ConnectorRuntime for NativeHostRuntime {
    async fn connect_byte_stream(
        &self,
        url: &url::Url,
    ) -> anyhow::Result<ConnectedByteStream<RuntimeTcpSocket>> {
        self.services(&self.capture_default_namespace()?)?
            .connect_byte_stream(url)
            .await
    }
    async fn local_addr_for_remote(
        &self,
        remote: SocketAddr,
        context: SocketContext,
    ) -> anyhow::Result<SocketAddr> {
        self.namespace(&context)?
            .local_addr_for_remote(remote, context)
            .await
    }
    async fn preferred_ipv6_source(
        &self,
        ip: Ipv6Addr,
        context: SocketContext,
    ) -> Option<PreferredIpv6Source> {
        self.namespace(&context)
            .ok()?
            .preferred_ipv6_source(ip, context)
            .await
    }
    async fn collect_ip_addrs(&self, context: &SocketContext) -> GetIpListResponse {
        match self.namespace(context) {
            Ok(namespace) => namespace.collect_ip_addrs(context).await,
            Err(error) => {
                tracing::warn!(%error, "invalid namespace for interface collection");
                GetIpListResponse::default()
            }
        }
    }
}
#[async_trait]
impl DnsResolver for NativeHostRuntime {
    async fn resolve(&self, query: DnsQuery) -> anyhow::Result<Vec<IpAddr>> {
        self.namespace(&query.context)?.resolve(query).await
    }
}
#[async_trait]
impl DnsRecordResolver for NativeHostRuntime {
    async fn resolve_txt(&self, query: DnsQuery) -> anyhow::Result<String> {
        self.namespace(&query.context)?.resolve_txt(query).await
    }
    async fn resolve_srv(&self, query: DnsQuery) -> anyhow::Result<Vec<DnsSrvRecord>> {
        self.namespace(&query.context)?.resolve_srv(query).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl NativeHostRuntime {
        pub(crate) fn is_local_ip(&self, ip: &IpAddr, context: &SocketContext) -> bool {
            self.namespace(context)
                .is_ok_and(|namespace| namespace.is_local_ip(ip, context))
        }
    }

    #[tokio::test]
    async fn terminal_shutdown_closes_domain_admission_before_stopping_the_executor() {
        use std::time::Duration;
        let host = Arc::new(NativeHostRuntime::new());
        let namespace = host.capture_default_namespace().unwrap();
        let _driver = host.shared_executor().unwrap();
        // Hold the asynchronous NIC directory, so the cleanup remains pending
        // while checking the synchronous close boundary.
        #[cfg(feature = "tun")]
        let services = host.services(&namespace).unwrap();
        #[cfg(feature = "tun")]
        let permit = services.nics.lock().await;
        host.request_service_shutdown();
        assert!(namespace.ensure_open().is_err());
        assert!(host.capture_default_namespace().is_err());
        assert!(host.shared_executor().is_ok());
        #[cfg(feature = "tun")]
        drop(permit);
        tokio::time::timeout(Duration::from_secs(5), host.shutdown())
            .await
            .unwrap()
            .unwrap();
        assert!(host.shared_executor().is_err());
        assert!(host.namespace(&SocketContext::default()).is_err());
        host.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn closed_domains_reject_new_native_io_through_every_bound_factory() {
        let platform = PlatformNamespace::current().unwrap();
        let namespace = NativeNamespaceServices::new(NetNS::new(platform.id(), platform));
        namespace.request_service_shutdown();
        let closing =
            |error: anyhow::Error| assert!(error.to_string().contains("closing"), "{error:#}");
        closing(
            namespace
                .bind_tcp(TcpListenOptions::direct_connect(
                    "127.0.0.1:0".parse().unwrap(),
                ))
                .await
                .err()
                .unwrap(),
        );
        closing(
            namespace
                .bind_udp(BindConfig {
                    reuse_addr: Some(false),
                    ..BindConfig::default()
                })
                .await
                .err()
                .unwrap(),
        );
        closing(
            namespace
                .local_addr_for_remote("127.0.0.1:9".parse().unwrap(), SocketContext::default())
                .await
                .err()
                .unwrap(),
        );
        closing(
            namespace
                .resolve(DnsQuery::new("127.0.0.1", SocketContext::default()))
                .await
                .err()
                .unwrap(),
        );
        #[cfg(unix)]
        closing(
            namespace
                .connect_byte_stream(
                    &url::Url::parse("unix:///tmp/easytier-closed-domain.sock").unwrap(),
                )
                .await
                .err()
                .unwrap(),
        );
    }

    #[cfg(feature = "tun")]
    #[tokio::test]
    async fn terminal_cleanup_survives_the_shutdown_waiter_being_cancelled() {
        let host = Arc::new(NativeHostRuntime::new());
        let namespace = host.capture_default_namespace().unwrap();
        let services = host.services(&namespace).unwrap();
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
        assert!(host.shared_executor().is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "run inside an isolated user+network namespace"]
    fn process_default_is_not_the_first_callers_temporary_domain() {
        let original = crate::common::netns::current().unwrap();
        let temporary = crate::common::netns::tests::isolated_namespace_for_test().unwrap();
        temporary
            .run(|| {
                let host = NativeHostRuntime::new();
                assert_ne!(crate::common::netns::current().unwrap().id(), original.id());
                assert_eq!(
                    host.capture_default_namespace().unwrap().id(),
                    original.id()
                );
            })
            .unwrap();
    }

    #[tokio::test]
    async fn shared_reactor_survives_the_instance_that_first_initialized_it() {
        use std::time::Duration;
        let host = Arc::new(NativeHostRuntime::new());
        let first = NativeExecutor::new(false, 1).unwrap();
        let first_handle = first.handle();
        let namespace = namespace_services(&crate::common::netns::current().unwrap()).unwrap();
        let initialize_host = host.clone();
        let socket = first_handle
            .spawn(async move {
                let shared = initialize_host.shared_executor().unwrap();
                shared
                    .spawn(async move {
                        namespace
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
        let shared_id = host.shared_executor().unwrap().id();
        assert_ne!(shared_id, first_handle.id());
        first.request_shutdown();
        tokio::time::timeout(Duration::from_secs(5), first.wait_stopped())
            .await
            .unwrap();
        let second = NativeExecutor::new(false, 1).unwrap();
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
        assert_eq!(host.shared_executor().unwrap().id(), shared_id);
        drop(socket);
        host.request_executor_shutdown();
        tokio::time::timeout(Duration::from_secs(5), host.wait_executor_stopped())
            .await
            .unwrap();
        assert!(host.shared_executor().is_err());
    }

    #[test]
    fn native_host_runtime_is_process_wide() {
        assert!(Arc::ptr_eq(&native_host_runtime(), &native_host_runtime()));
    }

    #[test]
    fn native_local_ip_probe_uses_process_runtime() {
        assert!(
            native_host_runtime()
                .is_local_ip(&IpAddr::V4(Ipv4Addr::LOCALHOST), &SocketContext::default(),)
        );
    }

    #[tokio::test]
    async fn native_route_probe_uses_remote_address_family() {
        let local_addr = native_host_runtime()
            .local_addr_for_remote(
                SocketAddr::from(([127, 0, 0, 1], 9)),
                SocketContext::default(),
            )
            .await
            .unwrap();

        assert!(local_addr.is_ipv4());
    }
}
