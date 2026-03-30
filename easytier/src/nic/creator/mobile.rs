use tun::Configuration;
use crate::common::error::Error;
use crate::nic::platform::{NicCreator, PlatformNicCreator};

impl PlatformNicCreator for NicCreator {
    async fn configure(&self, config: &mut Configuration) -> Result<(), Error> {
        #[cfg(any(target_os = "ios", all(target_os = "macos", feature = "macos-ne")))]
        config.platform_config(|config| {
            // disable packet information so we can process the header by ourselves, see tun2 impl for more details
            config.packet_information(false);
        });
        Ok(())
    }
}