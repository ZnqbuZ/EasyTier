use crate::common::error::Error;
use crate::nic::creator::{NicCreator, PlatformNicCreator};
use tun::Configuration;

impl PlatformNicCreator for NicCreator {
    async fn configure(&self, config: &mut Configuration) -> Result<(), Error> {
        config.platform_config(|config| {
            // disable packet information so we can process the header by ourselves, see tun2 impl for more details
            config.packet_information(false);
        });
        Ok(())
    }
}
