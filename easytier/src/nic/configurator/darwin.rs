use std::net::Ipv4Addr;

use super::{cidr_to_subnet_mask, run_shell_cmd, Configurator, Error, PlatformConfigurator};
use async_trait::async_trait;
use cidr::{Ipv4Inet, Ipv6Inet};

#[async_trait]
impl PlatformConfigurator for Configurator {
    async fn add_ipv4_route(
        &self,
        address: Ipv4Addr,
        cidr_prefix: u8,
        cost: Option<i32>,
    ) -> Result<(), Error> {
        run_shell_cmd(
            format!(
                "route -n add {} -netmask {} -interface {} -hopcount {}",
                address,
                cidr_to_subnet_mask(cidr_prefix),
                self.name,
                cost.unwrap_or(7)
            )
            .as_str(),
        )
        .await
    }

    async fn remove_ipv4_route(&self, address: Ipv4Addr, cidr_prefix: u8) -> Result<(), Error> {
        run_shell_cmd(
            format!(
                "route -n delete {} -netmask {} -interface {}",
                address,
                cidr_to_subnet_mask(cidr_prefix),
                self.name
            )
            .as_str(),
        )
        .await
    }

    async fn add_ipv4_ip(&self, address: Ipv4Addr, cidr_prefix: u8) -> Result<(), Error> {
        run_shell_cmd(
            format!(
                "ifconfig {} {:?}/{:?} 10.8.8.8 up",
                self.name, address, cidr_prefix,
            )
            .as_str(),
        )
        .await
    }

    async fn remove_ipv4_ip(&self, ip: Option<Ipv4Inet>) -> Result<(), Error> {
        if let Some(ip) = ip {
            run_shell_cmd(format!("ifconfig {} inet {} delete", self.name, ip.address()).as_str())
                .await
        } else {
            run_shell_cmd(format!("ifconfig {} inet delete", self.name).as_str()).await
        }
    }

    async fn add_ipv6_route(
        &self,
        address: std::net::Ipv6Addr,
        cidr_prefix: u8,
        cost: Option<i32>,
    ) -> Result<(), Error> {
        let cmd = if let Some(cost) = cost {
            format!(
                "route -n add -inet6 {}/{} -interface {} -hopcount {}",
                address, cidr_prefix, self.name, cost
            )
        } else {
            format!(
                "route -n add -inet6 {}/{} -interface {}",
                address, cidr_prefix, self.name
            )
        };
        run_shell_cmd(cmd.as_str()).await
    }

    async fn remove_ipv6_route(
        &self,
        address: std::net::Ipv6Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        run_shell_cmd(
            format!(
                "route -n delete -inet6 {}/{} -interface {}",
                address, cidr_prefix, self.name
            )
            .as_str(),
        )
        .await
    }

    async fn add_ipv6_ip(&self, address: std::net::Ipv6Addr, cidr_prefix: u8) -> Result<(), Error> {
        run_shell_cmd(
            format!(
                "ifconfig {} inet6 {}/{} add",
                self.name, address, cidr_prefix
            )
            .as_str(),
        )
        .await
    }

    async fn remove_ipv6_ip(&self, ip: Option<Ipv6Inet>) -> Result<(), Error> {
        if let Some(ip) = ip {
            run_shell_cmd(format!("ifconfig {} inet6 {} delete", self.name, ip.address()).as_str())
                .await
        } else {
            // Remove all IPv6 addresses is more complex on macOS, just succeed
            Ok(())
        }
    }

    async fn set_link_status(&self, up: bool) -> Result<(), Error> {
        run_shell_cmd(format!("ifconfig {} {}", self.name, if up { "up" } else { "down" }).as_str())
            .await
    }

    async fn set_mtu(&self, mtu: u32) -> Result<(), Error> {
        run_shell_cmd(format!("ifconfig {} mtu {}", self.name, mtu).as_str()).await
    }
}
