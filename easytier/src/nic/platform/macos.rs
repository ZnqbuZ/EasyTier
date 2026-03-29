use crate::common::error::Error;
use crate::nic::platform::{If, PlatformIf};
use tun::Configuration;

impl PlatformIf for If {
    async fn configure(&self, config: &mut Configuration) -> Result<(), Error> {
        config.platform_config(|config| {
            // disable packet information so we can process the header by ourselves, see tun2 impl for more details
            config.packet_information(false);
        });
        Ok(())
    }
}
