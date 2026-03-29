use crate::common::error::Error;
use crate::common::ifcfg;
use crate::common::netns::NetNSGuard;
use crate::nic::tun::{TunAsyncWrite, TunStream, TunZCPacketToBytes};
use crate::tunnel::common::{FramedWriter, TunnelWrapper};
use crate::utils::BoxExt;
use cfg_if::cfg_if;
use cidr::IpInet;
use futures_util::lock::BiLock;
use tun::platform::Device;
use tun::{AbstractDevice, AsyncDevice, Configuration, Layer};

// #[cfg(target_os = "freebsd")]
mod freebsd;
// #[cfg(target_os = "linux")]
mod linux;
// #[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
mod macos;
// #[cfg(target_os = "windows")]
mod mobile;
mod windows;

pub type PlatformContext = cfg_if! {
    if #[cfg(mobile)] {
        std::os::fd::RawFd
    } else {
        ArcGlobalCtx
    }
};

pub trait PlatformIf {
    async fn configure(&self, config: &mut Configuration) -> Result<(), Error>;
    async fn initialize(&mut self) {}
    async fn finalize(&mut self) {}
}

struct If {
    name: Option<String>,
    ctx: PlatformContext,
}

impl If {
    fn new(ctx: PlatformContext) -> Self {
        Self { name: None, ctx }
    }
    fn guard(&self) -> Option<Box<NetNSGuard>> {
        cfg_if! {
            if #[cfg(mobile)] {
                None
            } else {
                Some(self.ctx.net_ns.guard())
            }
        }
    }
    fn name(&self) -> Option<&String> {
        self.name.as_ref()
    }
    async fn create(&mut self) -> Result<Device, Error> {
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
        self.set_name(name.clone());

        let ifcfg = ifcfg::get();

        ifcfg.wait_interface_show(&name).await?;

        self.initialize().await;

        let device = AsyncDevice::new(device)?;

        #[cfg(not(mobile))]
        {
            let flags = self.ctx.config.get_flags();
            let mut mtu_in_config = flags.mtu;
            if flags.enable_encryption {
                mtu_in_config -= 20;
            }
            // set mtu by ourselves, rust-tun does not handle it correctly on windows
            let _g = self.guard();
            ifcfg.set_mtu(self.name().unwrap(), mtu_in_config).await?;
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

        Ok(ft.boxed())
    }
}
