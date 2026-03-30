use std::sync::Arc;
use crate::common::error::Error;
use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtxEvent};
use crate::common::ifcfg;
use crate::common::netns::NetNSGuard;
use crate::nic::tun::{TunAsyncWrite, TunStream, TunZCPacketToBytes};
use crate::tunnel::common::{FramedWriter, TunnelWrapper};
use crate::utils::BoxExt;
use cfg_if::cfg_if;
use cidr::{Ipv4Inet, Ipv6Inet};
use derive_new::new;
use futures_util::lock::BiLock;
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinSet;
use tun::platform::Device;
use tun::{AbstractDevice, AsyncDevice, Configuration, Layer};
use crate::common::ifcfg::RegistryManager;
use crate::nic::configurator::{Configurator, PlatformConfigurator};
use crate::nic::{NicPeersForwarder, PeersNicForwarder};
use crate::peers::PacketRecvChanReceiver;
use crate::peers::peer_manager::PeerManager;
use crate::tunnel::Tunnel;

// #[cfg(target_os = "freebsd")]
mod freebsd;
// #[cfg(target_os = "linux")]
mod linux;
// #[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
mod macos;
// #[cfg(target_os = "windows")]
mod mobile;
mod windows;

pub trait PlatformNicCreator {
    async fn configure(&self, config: &mut Configuration) -> Result<(), Error>;
    async fn initialize(&mut self) {}
    async fn finalize(&mut self) {}
}

#[derive(new)]
struct NicCreator {
    global_ctx: ArcGlobalCtx,
    #[cfg(mobile)]
    fd: std::os::fd::RawFd,

    #[new(default)]
    name: Option<String>,
}

impl NicCreator {
    fn guard(&self) -> Option<Box<NetNSGuard>> {
        cfg_if! {
            if #[cfg(mobile)] {
                None
            } else {
                Some(self.global_ctx.net_ns.guard())
            }
        }
    }
    async fn create(mut self) -> Result<Nic, Error> {
        let mut config = Configuration::default();
        config.layer(Layer::L3);
        self.configure(&mut config).await?;
        config.up();

        #[cfg(mobile)]
        {
            config.raw_fd(self.context());
            config.close_fd_on_drop(false);
        }

        let device = {
            let _g = self.guard();
            tun::create(&config)?
        };

        let name = device.tun_name()?;
        self.name.replace(name.clone());

        let ifcfg = ifcfg::get();

        ifcfg.wait_interface_show(&name).await?;

        self.initialize().await;

        let device = AsyncDevice::new(device)?;

        #[cfg(not(mobile))]
        {
            let flags = self.global_ctx.config.get_flags();
            let mut mtu_in_config = flags.mtu;
            if flags.enable_encryption {
                mtu_in_config -= 20;
            }
            // set mtu by ourselves, rust-tun does not handle it correctly on windows
            let _g = self.guard();
            ifcfg.set_mtu(self.name.as_ref().unwrap(), mtu_in_config).await?;
        }

        let has_packet_info = cfg!(any(
            target_os = "ios",
            all(target_os = "macos", mobile, feature = "macos-ne"),
            all(target_os = "macos", not(mobile), not(feature = "macos-ne"))
        ));
        let (a, b) = BiLock::new(device);
        let ft = TunnelWrapper::new(
            TunStream::new(a, has_packet_info),
            FramedWriter::new_with_converter(
                TunAsyncWrite::new(b),
                TunZCPacketToBytes::new(has_packet_info),
            ),
            None,
        );

        self.finalize().await;
        
        let name = self.name.unwrap();

        Ok(Nic {
            global_ctx: self.global_ctx,
            tunnel: ft.boxed(),
            name: name.clone(),
            configurator: Configurator::new(name),
            tasks: JoinSet::new(),
        })
    }
}

struct Nic {
    global_ctx: ArcGlobalCtx,
    tunnel: Box<dyn Tunnel>,
    name: String,
    configurator: Configurator,
    tasks: JoinSet<()>,
}

impl Nic {
    pub async fn run(
        &mut self,
        peer_mgr: &Arc<PeerManager>,
        peer_packet_receiver: Arc<Mutex<PacketRecvChanReceiver>>,
        close_notifier: Arc<Notify>,
        ipv4_addr: Option<Ipv4Inet>,
        ipv6_addr: Option<Ipv6Inet>,
    ) -> Result<(), Error> {
        let (stream, sink) = self.tunnel.split();

        self.tasks.spawn(
            NicPeersForwarder {
                peer_mgr: peer_mgr.clone(),
                close_notifier: close_notifier.clone(),
                stream,
            }
                .run(),
        );

        self.tasks.spawn(
            PeersNicForwarder {
                packet_recv_chan_receiver: peer_packet_receiver,
                close_notifier: close_notifier.clone(),
                sink,
            }
                .run(),
        );
        
        let cfg = &self.configurator;

        cfg.wait_interface_show().await?;
        
        // TODO: run route manager

        {
            let _g = self.global_ctx.net_ns.guard();

            // Assign IPv4 address if provided
            if let Some(ipv4_addr) = ipv4_addr {
                cfg.remove_ipv4_ip(None).await?;
                cfg.add_ipv4_ip(ipv4_addr.address(), ipv4_addr.network_length()).await?;
            }

            // Assign IPv6 address if provided
            if let Some(ipv6_addr) = ipv6_addr {
                cfg.remove_ipv6_ip(None).await?;
                cfg.add_ipv6_ip(ipv6_addr.address(), ipv6_addr.network_length()).await?;
            }
            
            // TODO: publish route here
        }

        self.run_proxy_cidrs_route_updater().await?;

        Ok(())
    }
}

