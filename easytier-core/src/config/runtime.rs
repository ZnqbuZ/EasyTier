//! Atomic runtime configuration owned by one core instance.

use std::{
    collections::BTreeSet,
    sync::{Arc, OnceLock},
};

use arc_swap::ArcSwap;
use cidr::{Ipv4Cidr, Ipv6Cidr};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use super::{
    gateway::{GatewayRuntimeConfig, ProxyRuntimeConfig},
    peers::{AclRuleConfig, PeerRuntimeSnapshot, PublicIpv6ProviderConfig},
};
use crate::foundation::dirty::DirtyFlag;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreRuntimeConfig {
    pub acl: AclRuleConfig,
    pub dhcp_ipv4: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dhcp_ipv4_cidr: Option<Ipv4Cidr>,
    #[serde(default)]
    pub dhcp_ipv6: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dhcp_ipv6_cidr: Option<Ipv6Cidr>,
    pub gateway: GatewayRuntimeConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manual_routes: Option<BTreeSet<Ipv4Cidr>>,
    pub proxy: ProxyRuntimeConfig,
    #[serde(default)]
    pub public_ipv6_auto: bool,
    pub public_ipv6_provider: PublicIpv6ProviderConfig,
}

impl Default for CoreRuntimeConfig {
    fn default() -> Self {
        Self {
            acl: AclRuleConfig::default(),
            dhcp_ipv4: false,
            dhcp_ipv4_cidr: None,
            dhcp_ipv6: false,
            dhcp_ipv6_cidr: None,
            gateway: GatewayRuntimeConfig::default(),
            manual_routes: None,
            proxy: ProxyRuntimeConfig::default(),
            public_ipv6_auto: false,
            public_ipv6_provider: PublicIpv6ProviderConfig {
                provider_enabled: false,
                configured_prefix: None,
                provider_supported: false,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct CoreInstanceRuntimeConfig {
    pub services: CoreRuntimeConfig,
    pub peer: Arc<PeerRuntimeSnapshot>,
}

struct CoreRuntimeConfigStoreInner {
    snapshot: ArcSwap<CoreInstanceRuntimeConfig>,
    update: Mutex<()>,
    peer_changes: tokio::sync::watch::Sender<u64>,
    service_changes: tokio::sync::watch::Sender<u64>,
    route_dirty: OnceLock<Arc<DirtyFlag>>,
}

/// Atomic configuration authority shared by one core instance and its peer
/// context. Readers always observe a complete submitted version.
#[derive(Clone)]
pub struct CoreRuntimeConfigStore {
    inner: Arc<CoreRuntimeConfigStoreInner>,
}

impl CoreRuntimeConfigStore {
    pub fn new(services: CoreRuntimeConfig, peer: Arc<PeerRuntimeSnapshot>) -> Self {
        let (peer_changes, _) = tokio::sync::watch::channel(0);
        let (service_changes, _) = tokio::sync::watch::channel(0);
        Self {
            inner: Arc::new(CoreRuntimeConfigStoreInner {
                snapshot: ArcSwap::from_pointee(CoreInstanceRuntimeConfig { services, peer }),
                update: Mutex::new(()),
                peer_changes,
                service_changes,
                route_dirty: OnceLock::new(),
            }),
        }
    }

    pub fn snapshot(&self) -> Arc<CoreInstanceRuntimeConfig> {
        self.inner.snapshot.load_full()
    }

    /// Binds the shared route dirty flag to this store. Only the first binding
    /// succeeds; a rejected binding neither replaces nor marks the passed flag.
    /// The bound flag is marked so routes read any policy configured before the
    /// binding.
    pub fn bind_route_dirty(&self, dirty: Arc<DirtyFlag>) -> Result<(), ()> {
        self.inner.route_dirty.set(dirty).map_err(|_| ())?;
        self.invalidate_routes();
        Ok(())
    }

    fn invalidate_routes(&self) {
        if let Some(dirty) = self.inner.route_dirty.get() {
            dirty.mark();
        }
    }

    pub(crate) fn with_snapshot<T>(&self, read: impl FnOnce(&CoreInstanceRuntimeConfig) -> T) -> T {
        let snapshot = self.inner.snapshot.load();
        read(&snapshot)
    }

    pub fn replace(&self, config: CoreInstanceRuntimeConfig) {
        let _update = self.inner.update.lock();
        self.inner.snapshot.store(Arc::new(config));
        self.inner.peer_changes.send_modify(|version| *version += 1);
        self.inner
            .service_changes
            .send_modify(|version| *version += 1);
        drop(_update);
        self.invalidate_routes();
    }

    pub(crate) fn replace_with_current(
        &self,
        mut config: CoreInstanceRuntimeConfig,
        merge: impl FnOnce(&CoreInstanceRuntimeConfig, &mut CoreInstanceRuntimeConfig),
    ) -> Arc<CoreInstanceRuntimeConfig> {
        let _update = self.inner.update.lock();
        let current = self.inner.snapshot.load_full();
        merge(&current, &mut config);
        let config = Arc::new(config);
        self.inner.snapshot.store(config.clone());
        self.inner.peer_changes.send_modify(|version| *version += 1);
        self.inner
            .service_changes
            .send_modify(|version| *version += 1);
        drop(_update);
        self.invalidate_routes();
        config
    }

    pub fn update_services(&self, update: impl FnOnce(&mut CoreRuntimeConfig)) {
        let _update = self.inner.update.lock();
        let mut config = self.inner.snapshot.load_full().as_ref().clone();
        update(&mut config.services);
        self.inner.snapshot.store(Arc::new(config));
        self.inner
            .service_changes
            .send_modify(|version| *version += 1);
        drop(_update);
        self.invalidate_routes();
    }

    pub fn update_peer(&self, peer: Arc<PeerRuntimeSnapshot>) {
        let _update = self.inner.update.lock();
        let mut config = self.inner.snapshot.load_full().as_ref().clone();
        let previous_peer = config.peer.clone();
        config.peer = peer;
        let route_inputs_changed = peer_route_inputs_changed(&previous_peer, &config.peer);
        self.inner.snapshot.store(Arc::new(config));
        self.inner.peer_changes.send_modify(|version| *version += 1);
        drop(_update);
        if route_inputs_changed {
            self.invalidate_routes();
        }
    }

    pub(crate) fn update_peer_with(&self, update: impl FnOnce(&mut PeerRuntimeSnapshot)) {
        let _update = self.inner.update.lock();
        let mut config = self.inner.snapshot.load_full().as_ref().clone();
        let previous_peer = config.peer.clone();
        update(Arc::make_mut(&mut config.peer));
        let route_inputs_changed = peer_route_inputs_changed(&previous_peer, &config.peer);
        self.inner.snapshot.store(Arc::new(config));
        self.inner.peer_changes.send_modify(|version| *version += 1);
        drop(_update);
        if route_inputs_changed {
            self.invalidate_routes();
        }
    }

    pub fn subscribe_peer_runtime_changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.inner.peer_changes.subscribe()
    }

    pub fn subscribe_service_runtime_changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.inner.service_changes.subscribe()
    }
    #[cfg(test)]
    pub(crate) fn peer_change_subscriber_count(&self) -> usize {
        self.inner.peer_changes.receiver_count()
    }

    #[cfg(test)]
    pub(crate) fn service_change_subscriber_count(&self) -> usize {
        self.inner.service_changes.receiver_count()
    }
}

/// Peer values the shared route inputs are derived from. Comparisons are by
/// value; holding a new `Arc` for an equal snapshot is not a change.
fn peer_route_inputs_changed(
    previous: &PeerRuntimeSnapshot,
    current: &PeerRuntimeSnapshot,
) -> bool {
    previous.flags.accept_dns != current.flags.accept_dns
        || previous.runtime.core.routes.ipv4 != current.runtime.core.routes.ipv4
        || previous.runtime.core.routes.ipv6 != current.runtime.core.routes.ipv6
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IpPrefix;

    async fn marked(dirty: &DirtyFlag, message: &str) {
        tokio::time::timeout(std::time::Duration::from_secs(1), dirty.wait())
            .await
            .unwrap_or_else(|_| panic!("{message}"));
    }

    fn prefix(address: &str, prefix_len: u8) -> IpPrefix {
        IpPrefix {
            address: address.parse().unwrap(),
            prefix_len,
        }
    }

    fn peer(
        accept_dns: bool,
        ipv4: Option<IpPrefix>,
        ipv6: Option<IpPrefix>,
    ) -> PeerRuntimeSnapshot {
        let mut peer = PeerRuntimeSnapshot::default();
        peer.flags.accept_dns = accept_dns;
        peer.runtime.core.routes.ipv4 = ipv4;
        peer.runtime.core.routes.ipv6 = ipv6;
        peer
    }

    /// A store whose route flag is bound and already cleared, so an assertion
    /// does not mistake the first binding's mark for an update notification.
    fn bound_store() -> (CoreRuntimeConfigStore, Arc<DirtyFlag>) {
        let store = CoreRuntimeConfigStore::new(
            CoreRuntimeConfig::default(),
            Arc::new(PeerRuntimeSnapshot::default()),
        );
        let dirty = Arc::new(DirtyFlag::new(false));
        store.bind_route_dirty(dirty.clone()).unwrap();
        dirty.reset();
        (store, dirty)
    }

    #[tokio::test]
    async fn route_dirty_flag_follows_service_commits() {
        let manual_routes: BTreeSet<Ipv4Cidr> = BTreeSet::from(["10.20.0.0/16".parse().unwrap()]);
        let store = CoreRuntimeConfigStore::new(
            CoreRuntimeConfig {
                manual_routes: Some(manual_routes.clone()),
                ..Default::default()
            },
            Arc::new(PeerRuntimeSnapshot::default()),
        );
        let dirty = Arc::new(DirtyFlag::new(false));
        let replacement = Arc::new(DirtyFlag::new(false));

        store.bind_route_dirty(dirty.clone()).unwrap();
        assert!(
            dirty.peek(),
            "binding must mark so policy configured before it is read"
        );
        assert_eq!(
            store.snapshot().services.manual_routes,
            Some(manual_routes),
            "policy configured before binding must be readable"
        );
        assert!(
            store.bind_route_dirty(replacement.clone()).is_err(),
            "only one binding may succeed"
        );
        assert!(
            !replacement.peek(),
            "a rejected binding must not mark the passed flag"
        );

        dirty.reset();
        store.update_services(|services| services.manual_routes = Some(BTreeSet::new()));
        marked(&dirty, "update_services must mark after publishing").await;
        assert_eq!(
            store.snapshot().services.manual_routes,
            Some(BTreeSet::new()),
            "update_services publishes before marking"
        );
        assert!(!replacement.peek());

        let mut replaced_services = store.snapshot().services.clone();
        replaced_services.manual_routes = None;
        replaced_services.dhcp_ipv4 = true;
        dirty.reset();
        store.replace(CoreInstanceRuntimeConfig {
            services: replaced_services,
            peer: Arc::new(PeerRuntimeSnapshot::default()),
        });
        marked(&dirty, "replace must mark after publishing").await;
        let replaced = store.snapshot();
        assert!(replaced.services.dhcp_ipv4);
        assert_eq!(replaced.services.manual_routes, None);
        assert!(!replacement.peek());

        dirty.reset();
        store.replace_with_current(
            CoreInstanceRuntimeConfig {
                services: CoreRuntimeConfig::default(),
                peer: Arc::new(PeerRuntimeSnapshot::default()),
            },
            |_, config| config.services.dhcp_ipv6 = true,
        );
        marked(&dirty, "replace_with_current must mark after publishing").await;
        assert!(store.snapshot().services.dhcp_ipv6);
        assert!(!replacement.peek());

        dirty.reset();
        store.update_peer(Arc::new(PeerRuntimeSnapshot::default()));
        store.update_peer_with(|peer| {
            peer.runtime.core.node.hostname = Some("peer-only".to_owned())
        });
        assert!(
            !dirty.peek(),
            "peer-only commits must not mark the route policy flag"
        );
        assert!(!replacement.peek());
    }

    #[tokio::test]
    async fn peer_dns_flag_marks_route_inputs_through_both_entries() {
        let (store, dirty) = bound_store();

        store.update_peer(Arc::new(peer(true, None, None)));
        marked(&dirty, "enabling accept_dns must mark the route flag").await;
        assert!(store.snapshot().peer.flags.accept_dns);
        dirty.reset();

        store.update_peer_with(|peer| peer.flags.accept_dns = false);
        marked(&dirty, "disabling accept_dns must mark the route flag").await;
        assert!(!store.snapshot().peer.flags.accept_dns);
        dirty.reset();
    }

    #[tokio::test]
    async fn peer_ipv4_route_changes_mark_route_inputs() {
        let (store, dirty) = bound_store();

        store.update_peer(Arc::new(peer(
            false,
            Some(prefix("10.126.126.7", 24)),
            None,
        )));
        marked(&dirty, "adding a peer IPv4 route must mark").await;
        assert_eq!(
            store.snapshot().peer.runtime.core.routes.ipv4,
            Some(prefix("10.126.126.7", 24))
        );
        dirty.reset();

        store.update_peer_with(|peer| {
            peer.runtime.core.routes.ipv4 = Some(prefix("10.126.127.7", 24))
        });
        marked(&dirty, "modifying the peer IPv4 route must mark").await;
        assert_eq!(
            store.snapshot().peer.runtime.core.routes.ipv4,
            Some(prefix("10.126.127.7", 24))
        );
        dirty.reset();

        store.update_peer(Arc::new(peer(false, None, None)));
        marked(&dirty, "withdrawing the peer IPv4 route must mark").await;
        assert_eq!(store.snapshot().peer.runtime.core.routes.ipv4, None);
        dirty.reset();
    }

    #[tokio::test]
    async fn peer_ipv6_route_changes_mark_route_inputs() {
        let (store, dirty) = bound_store();

        store.update_peer_with(|peer| peer.runtime.core.routes.ipv6 = Some(prefix("fd00::7", 64)));
        marked(&dirty, "adding a peer IPv6 route must mark").await;
        assert_eq!(
            store.snapshot().peer.runtime.core.routes.ipv6,
            Some(prefix("fd00::7", 64))
        );
        dirty.reset();

        store.update_peer(Arc::new(peer(false, None, Some(prefix("fd00:1::7", 64)))));
        marked(&dirty, "modifying the peer IPv6 route must mark").await;
        assert_eq!(
            store.snapshot().peer.runtime.core.routes.ipv6,
            Some(prefix("fd00:1::7", 64))
        );
        dirty.reset();

        store.update_peer_with(|peer| peer.runtime.core.routes.ipv6 = None);
        marked(&dirty, "withdrawing the peer IPv6 route must mark").await;
        assert_eq!(store.snapshot().peer.runtime.core.routes.ipv6, None);
        dirty.reset();
    }

    #[test]
    fn equal_peer_route_inputs_do_not_mark_route_flag() {
        let route = Some(prefix("10.126.126.7", 24));
        let store = CoreRuntimeConfigStore::new(
            CoreRuntimeConfig::default(),
            Arc::new(peer(true, route.clone(), Some(prefix("fd00::7", 64)))),
        );
        let dirty = Arc::new(DirtyFlag::new(false));
        store.bind_route_dirty(dirty.clone()).unwrap();
        dirty.reset();

        store.update_peer(Arc::new(peer(
            true,
            route.clone(),
            Some(prefix("fd00::7", 64)),
        )));
        assert!(!dirty.peek(), "a new Arc with equal values is not a change");

        store.update_peer_with(|peer| {
            peer.flags.accept_dns = true;
            peer.runtime.core.routes.ipv4 = route;
            peer.runtime.core.routes.ipv6 = Some(prefix("fd00::7", 64));
        });
        assert!(
            !dirty.peek(),
            "in-place updates with equal values are not a change"
        );
    }

    #[test]
    fn hostname_only_peer_update_does_not_mark_route_flag() {
        let (store, dirty) = bound_store();

        store.update_peer_with(|peer| peer.runtime.core.node.hostname = Some("renamed".to_owned()));
        assert!(!dirty.peek());

        let mut renamed = PeerRuntimeSnapshot::default();
        renamed.runtime.core.node.hostname = Some("renamed-again".to_owned());
        store.update_peer(Arc::new(renamed));
        assert!(!dirty.peek());
    }

    #[tokio::test]
    async fn peer_route_update_notifies_peer_watch_but_not_service_watch() {
        let (store, dirty) = bound_store();
        let mut peer_changes = store.subscribe_peer_runtime_changes();
        let service_changes = store.subscribe_service_runtime_changes();

        store.update_peer(Arc::new(peer(true, None, None)));
        tokio::time::timeout(std::time::Duration::from_secs(1), peer_changes.changed())
            .await
            .expect("peer watch must still be notified")
            .expect("peer watch sender must stay alive");
        assert!(!service_changes.has_changed().unwrap());
        marked(&dirty, "peer route inputs must mark the route flag").await;
        dirty.reset();

        store.update_peer_with(|peer| {
            peer.runtime.core.routes.ipv4 = Some(prefix("10.126.126.7", 24))
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), peer_changes.changed())
            .await
            .expect("peer watch must still be notified by in-place updates")
            .expect("peer watch sender must stay alive");
        assert!(!service_changes.has_changed().unwrap());
        marked(&dirty, "peer route inputs must mark the route flag").await;
    }

    #[tokio::test]
    async fn rejected_route_flag_binding_leaves_backup_untouched_by_peer_updates() {
        let store = CoreRuntimeConfigStore::new(
            CoreRuntimeConfig::default(),
            Arc::new(PeerRuntimeSnapshot::default()),
        );
        let primary = Arc::new(DirtyFlag::new(false));
        let backup = Arc::new(DirtyFlag::new(false));
        store.bind_route_dirty(primary.clone()).unwrap();
        assert!(store.bind_route_dirty(backup.clone()).is_err());
        primary.reset();

        store.update_peer(Arc::new(peer(
            false,
            Some(prefix("10.126.126.7", 24)),
            None,
        )));
        marked(&primary, "the bound flag must still be marked").await;
        assert!(!backup.peek());

        primary.reset();
        store.update_peer_with(|peer| peer.flags.accept_dns = true);
        marked(&primary, "the bound flag must still be marked").await;
        assert!(!backup.peek());
    }

    #[test]
    fn replaces_service_and_peer_as_one_version() {
        let mut before_peer = PeerRuntimeSnapshot::default();
        before_peer.runtime.core.node.hostname = Some("before".to_owned());
        let store =
            CoreRuntimeConfigStore::new(CoreRuntimeConfig::default(), Arc::new(before_peer));
        let before = store.snapshot();

        let after_services = CoreRuntimeConfig {
            dhcp_ipv4: true,
            ..Default::default()
        };
        let mut after_peer = PeerRuntimeSnapshot::default();
        after_peer.runtime.core.node.hostname = Some("after".to_owned());
        store.replace(CoreInstanceRuntimeConfig {
            services: after_services,
            peer: Arc::new(after_peer),
        });

        assert!(!before.services.dhcp_ipv4);
        assert_eq!(
            before.peer.runtime.core.node.hostname.as_deref(),
            Some("before")
        );
        let after = store.snapshot();
        assert!(after.services.dhcp_ipv4);
        assert_eq!(
            after.peer.runtime.core.node.hostname.as_deref(),
            Some("after")
        );
    }

    #[tokio::test]
    async fn notifies_peer_snapshot_changes() {
        let store = CoreRuntimeConfigStore::new(
            CoreRuntimeConfig::default(),
            Arc::new(PeerRuntimeSnapshot::default()),
        );
        let mut changes = store.subscribe_peer_runtime_changes();
        let mut peer = PeerRuntimeSnapshot::default();
        peer.runtime.core.node.hostname = Some("updated".to_owned());

        store.update_peer(Arc::new(peer));

        assert!(changes.changed().await.is_ok());
    }

    #[tokio::test]
    async fn notifies_service_snapshot_changes() {
        let store = CoreRuntimeConfigStore::new(
            CoreRuntimeConfig::default(),
            Arc::new(PeerRuntimeSnapshot::default()),
        );
        let mut changes = store.subscribe_service_runtime_changes();

        store.update_services(|services| services.dhcp_ipv4 = true);

        assert!(changes.changed().await.is_ok());
        assert!(store.snapshot().services.dhcp_ipv4);
    }

    #[tokio::test]
    async fn peer_update_does_not_notify_service_watchers() {
        let store = CoreRuntimeConfigStore::new(
            CoreRuntimeConfig::default(),
            Arc::new(PeerRuntimeSnapshot::default()),
        );
        let changes = store.subscribe_service_runtime_changes();
        let mut peer = PeerRuntimeSnapshot::default();
        peer.runtime.core.node.hostname = Some("updated".to_owned());

        store.update_peer(Arc::new(peer));

        assert!(!changes.has_changed().unwrap());
    }

    #[test]
    fn peer_in_place_update_preserves_the_rest_of_the_atomic_snapshot() {
        let services = CoreRuntimeConfig {
            dhcp_ipv4: true,
            ..Default::default()
        };
        let mut peer = PeerRuntimeSnapshot::default();
        peer.runtime.core.node.hostname = Some("preserved".to_owned());
        let store = CoreRuntimeConfigStore::new(services, Arc::new(peer));

        store.update_peer_with(|peer| {
            peer.runtime.core.routes.ipv4 = Some(crate::config::IpPrefix {
                address: "10.20.30.7".parse().unwrap(),
                prefix_len: 24,
            });
        });

        let snapshot = store.snapshot();
        assert!(snapshot.services.dhcp_ipv4);
        assert_eq!(
            snapshot.peer.runtime.core.node.hostname.as_deref(),
            Some("preserved")
        );
        assert_eq!(
            snapshot
                .peer
                .runtime
                .core
                .routes
                .ipv4
                .as_ref()
                .unwrap()
                .address,
            "10.20.30.7".parse::<std::net::IpAddr>().unwrap()
        );
    }

    #[test]
    fn missing_manual_routes_preserves_portable_config_compatibility() {
        let encoded = serde_json::to_value(CoreRuntimeConfig::default()).unwrap();
        assert!(encoded.get("manual_routes").is_none());

        let decoded: CoreRuntimeConfig = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded.manual_routes, None);
    }
}
