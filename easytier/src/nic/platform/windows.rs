use crate::common::error::Error;
use crate::common::ifcfg::RegistryManager;
use crate::common::log;
use crate::nic::platform::{If, PlatformIf};
use tun::Configuration;

impl PlatformIf for If {
    async fn configure(&self, config: &mut Configuration) -> Result<(), Error> {
        let name = &self.ctx.get_flags().dev_name;

        match crate::arch::windows::add_self_to_firewall_allowlist() {
            Ok(_) => tracing::info!("add_self_to_firewall_allowlist successful!"),
            Err(error) => {
                log::warn!(%error, "Failed to add Easytier to firewall allowlist, Subnet proxy and KCP proxy may not work properly.");
                log::warn!("You can add firewall rules manually, or use --use-smoltcp to run with user-space TCP/IP stack.");
            }
        }

        match RegistryManager::reg_delete_obsoleted_items(&name) {
            Ok(_) => tracing::trace!("delete successful!"),
            Err(e) => tracing::error!("An error occurred: {}", e),
        }

        if !name.is_empty() {
            config.tun_name(&name);
        } else {
            use rand::distributions::Distribution as _;
            let c = crate::arch::windows::interface_count()?;
            let mut rng = rand::thread_rng();
            let s: String = rand::distributions::Alphanumeric
                .sample_iter(&mut rng)
                .take(4)
                .map(char::from)
                .collect::<String>()
                .to_lowercase();

            let random_dev_name = format!("et_{}_{}", c, s);
            config.tun_name(random_dev_name.clone());

            let mut flags = self.ctx.get_flags();
            flags.dev_name = random_dev_name.clone();
            self.ctx.set_flags(flags);
        }

        config.platform_config(|config| {
            config.skip_config(true);
            config.ring_cap(Some(std::cmp::min(
                config.min_ring_cap() * 32,
                config.max_ring_cap(),
            )));
        });

        Ok(())
    }

    async fn initialize(&mut self) {
        let ifname = self.name().unwrap();

        if let Ok(guid) = RegistryManager::find_interface_guid(ifname) {
            if let Err(e) = RegistryManager::disable_dynamic_updates(&guid) {
                tracing::error!(
                    "Failed to disable dhcp for interface {} {}: {}",
                    ifname,
                    guid,
                    e
                );
            }

            // Disable NetBIOS over TCP/IP
            if let Err(e) = RegistryManager::disable_netbios(&guid) {
                tracing::error!(
                    "Failed to disable netbios for interface {} {}: {}",
                    ifname,
                    guid,
                    e
                );
            }
        }
    }

    async fn finalize(&mut self) {
        let ifname = self.name().unwrap();

        // Add firewall rules for virtual NIC interface to allow all traffic
        match crate::arch::windows::add_interface_to_firewall_allowlist(ifname) {
            Ok(_) => {
                tracing::info!(
                    "Successfully configured Windows Firewall for interface: {}",
                    ifname
                );
                tracing::info!(
                    "All protocols (TCP/UDP/ICMP) are now allowed on interface: {}",
                    ifname
                );
            }
            Err(error) => {
                log::warn!(%error, "Failed to configure Windows Firewall for interface {}\
                    \n\tThis may cause connectivity issues with ping and other network functions.\
                    \n\tPlease run as Administrator or manually configure Windows Firewall.\
                    \n\tAlternatively, you can disable Windows Firewall for testing purposes.", ifname);
            }
        }
    }
}

impl Drop for If {
    fn drop(&mut self) {
        if let Some(ifname) = self.name() {
            // Try to clean up firewall rules, but don't panic in destructor
            if let Err(error) = crate::arch::windows::remove_interface_firewall_rules(ifname) {
                log::warn!(
                    %error,
                    "failed to remove firewall rules for interface {}",
                    ifname
                );
            }
        }
    }
}
