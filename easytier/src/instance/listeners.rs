use std::fmt::{self, Debug};

use async_trait::async_trait;
use easytier_core::listener::{
    ExternalListenerFactory, ExternalListenerRequest, transport::AcceptedTransport,
};
#[cfg(feature = "faketcp")]
use easytier_core::socket::SocketContext;
use easytier_core::socket::SocketListener;

use crate::common::net_ns::NetNS;
#[cfg(feature = "faketcp")]
use crate::socket::fake_tcp::FakeTcpSocketListener;
use crate::socket::tcp::RuntimeTcpSocket;

pub(crate) struct RuntimeExternalListenerFactory {
    net_ns: NetNS,
}

impl RuntimeExternalListenerFactory {
    pub(crate) fn new(net_ns: NetNS) -> Self {
        Self { net_ns }
    }
}

impl ExternalListenerFactory<AcceptedTransport<RuntimeTcpSocket>>
    for RuntimeExternalListenerFactory
{
    #[allow(clippy::match_like_matches_macro)]
    fn supports_scheme(&self, scheme: &str) -> bool {
        match scheme {
            "faketcp" => cfg!(feature = "faketcp"),
            "unix" => cfg!(unix),
            _ => false,
        }
    }

    fn create(
        &self,
        request: ExternalListenerRequest,
    ) -> Box<dyn SocketListener<Accepted = AcceptedTransport<RuntimeTcpSocket>>> {
        match request.url.scheme() {
            #[cfg(feature = "faketcp")]
            "faketcp" => Box::new(RuntimeFakeTcpSocketListener::new(
                request.url,
                self.net_ns.clone(),
                request.socket_context,
            )),
            #[cfg(unix)]
            "unix" => Box::new(RuntimeUnixStreamListener::new_in_net_ns(
                request.url,
                self.net_ns.clone(),
            )),
            scheme => unreachable!("core requested unsupported external listener: {scheme}"),
        }
    }
}

#[cfg(unix)]
struct RuntimeUnixStreamListener {
    url: url::Url,
    inner: Option<tokio::net::UnixListener>,
    net_ns: NetNS,
}

#[cfg(unix)]
impl RuntimeUnixStreamListener {
    #[cfg(test)]
    fn new(url: url::Url) -> Self {
        Self::new_in_net_ns(url, NetNS::current().unwrap())
    }
    fn new_in_net_ns(url: url::Url, net_ns: NetNS) -> Self {
        Self {
            url,
            inner: None,
            net_ns,
        }
    }
}

#[cfg(unix)]
fn unix_stream_remote_url(remote_addr: tokio::net::unix::SocketAddr) -> url::Url {
    crate::socket::tcp::url_from_unix_socket_addr(remote_addr).unwrap_or_else(|| {
        format!("unix://anonymous/{}", uuid::Uuid::new_v4())
            .parse()
            .expect("synthetic Unix stream URL should be valid")
    })
}

#[cfg(unix)]
impl Debug for RuntimeUnixStreamListener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeUnixStreamListener")
            .field("url", &self.url)
            .field("listening", &self.inner.is_some())
            .finish()
    }
}

#[cfg(unix)]
#[async_trait]
impl SocketListener for RuntimeUnixStreamListener {
    type Accepted = AcceptedTransport<RuntimeTcpSocket>;

    async fn listen(&mut self) -> anyhow::Result<()> {
        if self.inner.is_none() {
            self.inner = Some(
                self.net_ns
                    .run(|| tokio::net::UnixListener::bind(self.url.path()))??,
            );
        }
        Ok(())
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        let (stream, remote_addr) = self
            .inner
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Unix stream listener is not started"))?
            .accept()
            .await?;
        Ok(AcceptedTransport::ByteStream {
            socket: RuntimeTcpSocket::from_unix(stream),
            local_url: self.url.clone(),
            remote_url: Some(unix_stream_remote_url(remote_addr)),
        })
    }

    fn local_url(&self) -> url::Url {
        self.url.clone()
    }
}

#[cfg(unix)]
impl Drop for RuntimeUnixStreamListener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.url.path());
    }
}

#[cfg(feature = "faketcp")]
struct RuntimeFakeTcpSocketListener {
    inner: FakeTcpSocketListener,
}

#[cfg(feature = "faketcp")]
impl RuntimeFakeTcpSocketListener {
    fn new(url: url::Url, net_ns: NetNS, context: SocketContext) -> Self {
        Self {
            inner: FakeTcpSocketListener::new(url, net_ns, context),
        }
    }
}

#[cfg(feature = "faketcp")]
impl Debug for RuntimeFakeTcpSocketListener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeFakeTcpSocketListener")
            .field("url", &SocketListener::local_url(&self.inner))
            .finish()
    }
}

#[cfg(feature = "faketcp")]
#[async_trait]
impl SocketListener for RuntimeFakeTcpSocketListener {
    type Accepted = AcceptedTransport<RuntimeTcpSocket>;

    async fn listen(&mut self) -> anyhow::Result<()> {
        SocketListener::listen(&mut self.inner).await?;
        Ok(())
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        let local_url = SocketListener::local_url(&self.inner);
        let socket = self.inner.accept_socket().await?;
        Ok(AcceptedTransport::Tcp {
            socket: RuntimeTcpSocket::from_fake_tcp(socket),
            local_url,
            upgrade_permit: None,
        })
    }

    fn local_url(&self) -> url::Url {
        SocketListener::local_url(&self.inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_runtime::NativeNetNSServices;

    #[test]
    fn external_listener_capabilities_follow_native_build() {
        let factory = RuntimeExternalListenerFactory::new(NetNS::current().unwrap());

        assert_eq!(
            factory.supports_scheme("faketcp"),
            cfg!(feature = "faketcp")
        );
        assert_eq!(factory.supports_scheme("unix"), cfg!(unix));
        assert!(!factory.supports_scheme("tcp"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_adapters_exchange_bytes_and_unlink_listener() {
        use easytier_core::connectivity::composite::ConnectorRuntime;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("easytier.sock");
        let url: url::Url = format!("unix://{}", path.display()).parse().unwrap();
        let mut listener = RuntimeUnixStreamListener::new(url.clone());
        SocketListener::listen(&mut listener).await.unwrap();

        let runtime = NativeNetNSServices::process_default().unwrap();
        let (accepted, connected) = tokio::join!(
            SocketListener::accept(&mut listener),
            runtime.connect_byte_stream(&url),
        );
        let AcceptedTransport::ByteStream {
            socket: mut server,
            local_url,
            ..
        } = accepted.unwrap()
        else {
            panic!("Unix listener returned a non-byte-stream transport");
        };
        let (mut client, _, _, _) = connected.unwrap().into_parts();
        assert_eq!(local_url, url);

        client.write_all(b"ping").await.unwrap();
        let mut request = [0; 4];
        server.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");

        server.write_all(b"pong").await.unwrap();
        let mut response = [0; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");

        drop(listener);
        assert!(!path.exists());
    }
}
