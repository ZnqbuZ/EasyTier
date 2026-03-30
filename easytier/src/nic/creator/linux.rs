use crate::common::error::Error;
use crate::common::global_ctx::ArcGlobalCtx;
use crate::common::log;
use crate::nic::creator::{NicCreator, PlatformNicCreator};
use tun::Configuration;

impl NicCreator {
    /// Check and create TUN device node if necessary on Linux systems
    async fn ensure_tun_device_node() {
        const TUN_DEV_PATH: &str = "/dev/net/tun";
        const TUN_DIR_PATH: &str = "/dev/net";

        // Check if /dev/net/tun already exists
        if tokio::fs::metadata(TUN_DEV_PATH).await.is_ok() {
            tracing::debug!("TUN device node {} already exists", TUN_DEV_PATH);
            return;
        }

        tracing::info!(
            "TUN device node {} not found, attempting to create",
            TUN_DEV_PATH
        );

        // Check if TUN kernel module is available
        let tun_module_available = tokio::fs::metadata("/proc/net/dev").await.is_ok()
            && (tokio::fs::read_to_string("/proc/modules").await)
                .map(|content| content.contains("tun"))
                .unwrap_or(false);

        if !tun_module_available {
            log::warn!("TUN kernel module may not be available.");
            log::warn!("\tYou may need to load it with: sudo modprobe tun.");
        }

        // Try to create /dev/net directory if it doesn't exist
        if tokio::fs::metadata(TUN_DIR_PATH).await.is_err() {
            if let Err(error) = tokio::fs::create_dir_all(TUN_DIR_PATH).await {
                log::warn!(
                    ?error,
                    "Failed to create directory {}. TUN device creation may fail. Continuing anyway.",
                    TUN_DIR_PATH
                );
                log::warn!(
                    "\tYou may need to run with root privileges or manually create the TUN device."
                );
                Self::print_troubleshooting_info();
                return;
            }
            tracing::info!("Created directory {}", TUN_DIR_PATH);
        }

        // Try to create the TUN device node
        // Major number 10, minor number 200 for /dev/net/tun
        let dev_node = nix::sys::stat::makedev(10, 200);

        match nix::sys::stat::mknod(
            TUN_DEV_PATH,
            nix::sys::stat::SFlag::S_IFCHR,
            nix::sys::stat::Mode::from_bits(0o600).unwrap(),
            dev_node,
        ) {
            Ok(_) => {
                log::info!("Successfully created TUN device node {}", TUN_DEV_PATH);
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    "Failed to create TUN device node {}. Continuing anyway.",
                    TUN_DEV_PATH,
                );
                Self::print_troubleshooting_info();
            }
        }
    }

    /// Print troubleshooting information for TUN device issues
    fn print_troubleshooting_info() {
        log::info!(
            "Possible solutions:\
            \n\t1. Run with root privileges: sudo ./easytier-core [options]\
            \n\t2. Manually create TUN device: sudo mkdir -p /dev/net && sudo mknod /dev/net/tun c 10 200\
            \n\t3. Load TUN kernel module: sudo modprobe tun\
            \n\t4. Use --no-tun flag if TUN functionality is not needed\
            \n\t5. Check if your system/container supports TUN devices\
            \nNote: TUN functionality may still work if the kernel supports dynamic device creation."
        );
    }
}

impl PlatformNicCreator for NicCreator {
    async fn configure(&self, config: &mut Configuration) -> Result<(), Error> {
        Self::ensure_tun_device_node().await;

        let name = &self.global_ctx.get_flags().dev_name;
        if !name.is_empty() {
            config.tun_name(name);
        }

        Ok(())
    }
}
