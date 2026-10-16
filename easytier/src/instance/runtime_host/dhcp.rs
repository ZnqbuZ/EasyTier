use easytier_core::gateway::dhcp::{DhcpAddresses, DhcpApplyOutcome, DhcpApplyPermit, DhcpHost};

#[cfg(feature = "tun")]
use super::tun_common::NativeDhcpHost;
#[cfg(not(feature = "tun"))]
use super::tun_runtime::NativeDhcpHost;
use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtxEvent};

/// Write the actual runtime addresses, then invalidate the route input if a
/// value really changed.
///
/// `Some` means that address family takes part in this update; the inner value
/// is the exact value written. The invalidation runs after the write, so a
/// configuration mark published before the native value moved cannot be the
/// only wake-up. Equal values never mark.
pub(super) fn write_runtime_addresses(
    global_ctx: &ArcGlobalCtx,
    invalidate: impl FnOnce(),
    ipv4: Option<Option<cidr::Ipv4Inet>>,
    ipv6: Option<Option<cidr::Ipv6Inet>>,
) {
    let mut changed = false;
    if let Some(next) = ipv4
        && global_ctx.get_ipv4() != next
    {
        global_ctx.set_ipv4(next);
        changed = true;
    }
    if let Some(next) = ipv6
        && global_ctx.get_ipv6() != next
    {
        global_ctx.set_ipv6(next);
        changed = true;
    }
    if changed {
        invalidate();
    }
}

impl NativeDhcpHost {
    pub(super) fn current(&self) -> DhcpAddresses {
        DhcpAddresses {
            ipv4: self
                .global_ctx
                .config
                .get_dhcp()
                .then(|| self.global_ctx.get_ipv4())
                .flatten(),
            ipv6: self
                .global_ctx
                .config
                .get_dhcpv6()
                .then(|| self.global_ctx.get_ipv6())
                .flatten(),
        }
    }

    #[cfg(all(feature = "tun", not(mobile)))]
    pub(super) fn with_static_addresses(&self, mut addresses: DhcpAddresses) -> DhcpAddresses {
        if !self.global_ctx.config.get_dhcp() {
            addresses.ipv4 = self.global_ctx.config.get_ipv4();
        }
        if !self.global_ctx.config.get_dhcpv6() {
            addresses.ipv6 = self.global_ctx.config.get_ipv6();
        }
        addresses
    }

    pub(super) fn set_addresses(&self, addresses: DhcpAddresses) {
        // A static configuration patch uses a different operation lock. Never
        // write a previously read static address back over such a patch.
        let ipv4 = self.global_ctx.config.get_dhcp().then_some(addresses.ipv4);
        let ipv6 = self
            .global_ctx
            .config
            .get_dhcpv6()
            .then_some(addresses.ipv6);
        write_runtime_addresses(
            &self.global_ctx,
            || {
                #[cfg(feature = "tun")]
                if let Some(routes) = &self.routes {
                    routes.invalidate_input();
                }
            },
            ipv4,
            ipv6,
        );
    }

    pub(super) fn ensure_open(&self) -> anyhow::Result<()> {
        if self.cancel.is_cancelled() {
            anyhow::bail!("instance is closing; DHCP update cancelled");
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl DhcpHost for NativeDhcpHost {
    fn take_interface_closed(&self) -> bool {
        self.take_closed()
    }

    async fn apply_dhcp(&self, next: DhcpAddresses) -> DhcpApplyOutcome {
        let permit = self.operation.clone().lock_owned().await;
        let result = self.apply(next).await;
        let outcome = match result {
            Ok(()) => DhcpApplyOutcome::applied(self.current()),
            Err(error) => DhcpApplyOutcome::failed(self.current(), error),
        };
        outcome.with_permit(DhcpApplyPermit::new(permit))
    }

    fn publish_dhcp(&self, previous: DhcpAddresses, actual: DhcpAddresses) {
        if self.global_ctx.config.get_dhcp() && previous.ipv4 != actual.ipv4 {
            self.global_ctx.issue_event(if actual.ipv4.is_none() {
                GlobalCtxEvent::DhcpIpv4Conflicted(previous.ipv4)
            } else {
                GlobalCtxEvent::DhcpIpv4Changed(previous.ipv4, actual.ipv4)
            });
        }
        if self.global_ctx.config.get_dhcpv6() && previous.ipv6 != actual.ipv6 {
            self.global_ctx.issue_event(if actual.ipv6.is_none() {
                GlobalCtxEvent::DhcpIpv6Conflicted(previous.ipv6)
            } else {
                GlobalCtxEvent::DhcpIpv6Changed(previous.ipv6, actual.ipv6)
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{config::TomlConfig, global_ctx::GlobalCtx};
    use std::sync::Arc;

    #[test]
    fn route_inputs_are_invalidated_only_after_an_actual_address_change() {
        let global_ctx = Arc::new(GlobalCtx::new(TomlConfig::default()));
        let invalidations = std::cell::Cell::new(0);
        let ipv4: cidr::Ipv4Inet = "10.9.0.7/24".parse().unwrap();

        write_runtime_addresses(
            &global_ctx,
            || {
                assert_eq!(
                    global_ctx.get_ipv4(),
                    Some(ipv4),
                    "the actual value is written before invalidation"
                );
                invalidations.set(invalidations.get() + 1);
            },
            Some(Some(ipv4)),
            None,
        );
        assert_eq!(global_ctx.get_ipv4(), Some(ipv4));
        assert_eq!(invalidations.get(), 1);

        write_runtime_addresses(
            &global_ctx,
            || invalidations.set(invalidations.get() + 1),
            Some(Some(ipv4)),
            None,
        );
        assert_eq!(invalidations.get(), 1, "an equal value is not a change");

        write_runtime_addresses(
            &global_ctx,
            || invalidations.set(invalidations.get() + 1),
            None,
            None,
        );
        assert_eq!(invalidations.get(), 1, "an absent family is not written");

        write_runtime_addresses(
            &global_ctx,
            || invalidations.set(invalidations.get() + 1),
            Some(None),
            None,
        );
        assert_eq!(global_ctx.get_ipv4(), None);
        assert_eq!(invalidations.get(), 2, "clearing the address is a change");
    }
}
