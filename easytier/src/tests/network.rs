use crate::common::netns::ROOT_NETNS_NAME;
use easytier_core::socket::BindConfig;

use super::{add_ns_to_bridge, create_netns, del_netns, run_network_command};

/// Owns one test's host links and namespaces. Keep this alive until its
/// instances and background tasks have stopped, including on setup failures.
pub(super) struct TestNetwork {
    directory: tempfile::TempDir,
    namespaces: Vec<(&'static str, String)>,
    links: Vec<(&'static str, String)>,
}

impl TestNetwork {
    pub(super) fn new() -> Self {
        Self {
            directory: tempfile::Builder::new()
                .prefix("et")
                .rand_bytes(4)
                .tempdir()
                .unwrap(),
            namespaces: Vec::new(),
            links: Vec::new(),
        }
    }

    fn prefix(&self) -> &str {
        self.directory.path().file_name().unwrap().to_str().unwrap()
    }

    pub(super) fn namespace(&self, name: &str) -> &str {
        &self
            .namespaces
            .iter()
            .find(|(key, _)| *key == name)
            .unwrap()
            .1
    }

    pub(super) fn link(&self, name: &str) -> &str {
        &self.links.iter().find(|(key, _)| *key == name).unwrap().1
    }

    fn add_namespace(&mut self, name: &'static str) {
        // veth_<namespace>_h must fit Linux's 15-byte interface name limit.
        let actual = format!("{}{:02x}", self.prefix(), self.namespaces.len());
        assert!(actual.len() <= 8);
        assert!(!self.namespaces.iter().any(|(key, _)| *key == name));
        self.namespaces.push((name, actual));
    }

    pub(super) fn create_namespace(&mut self, name: &'static str, ipv4: &str, ipv6: &str) {
        self.add_namespace(name);
        create_netns(self.namespace(name), ipv4, ipv6);
    }

    pub(super) fn create_empty_namespace(&mut self, name: &'static str) {
        self.add_namespace(name);
        let actual = self.namespace(name);
        run_network_command("ip", &["netns", "add", actual]);
        run_network_command(
            "ip",
            &["netns", "exec", actual, "ip", "link", "set", "lo", "up"],
        );
    }

    pub(super) fn add_link(&mut self, name: &'static str) {
        let actual = format!("{}l{:02x}", self.prefix(), self.links.len());
        assert!(!self.links.iter().any(|(key, _)| *key == name));
        self.links.push((name, actual));
    }

    pub(super) fn create_bridge(&mut self, name: &'static str) {
        self.add_link(name);
        run_network_command("brctl", &["addbr", self.link(name)]);
        run_network_command("ip", &["link", "set", self.link(name), "up"]);
    }

    pub(super) fn add_to_bridge(&self, bridge: &str, namespace: &str) {
        add_ns_to_bridge(self.link(bridge), self.namespace(namespace));
    }
}

impl Drop for TestNetwork {
    fn drop(&mut self) {
        crate::common::netns::tests::test_namespace(Some(ROOT_NETNS_NAME.to_owned()))
            .run(|| {
                for (_, namespace) in &self.namespaces {
                    del_netns(namespace);
                }
                for (_, link) in self.links.iter().rev() {
                    let _ = std::process::Command::new("ip")
                        .args(["link", "del", link])
                        .output();
                }
            })
            .unwrap()
    }
}

#[test]
fn nested_namespace_guard_restores_current_thread() {
    let mut network = TestNetwork::new();
    network.create_empty_namespace("net_a");
    network.create_empty_namespace("net_b");
    let net_a =
        crate::common::netns::tests::test_namespace(Some(network.namespace("net_a").into()));
    let net_b =
        crate::common::netns::tests::test_namespace(Some(network.namespace("net_b").into()));
    let current = || std::fs::read_link("/proc/thread-self/ns/net").unwrap();
    let original = current();

    net_a
        .run(|| {
            let expected = current();
            assert_ne!(expected, original);
            net_b.run(|| assert_ne!(current(), expected)).unwrap();
            assert_eq!(current(), expected);
        })
        .unwrap();
    assert_eq!(current(), original);
}

#[tokio::test]
async fn bound_sockets_use_distinct_namespaces_without_switching_async_tasks() {
    use easytier_core::socket::udp::{VirtualUdpSocket, VirtualUdpSocketFactory};
    let mut network = TestNetwork::new();
    network.create_empty_namespace("net_a");
    network.create_empty_namespace("net_b");
    let a = crate::common::netns::tests::test_namespace(Some(network.namespace("net_a").into()));
    let b = crate::common::netns::tests::test_namespace(Some(network.namespace("net_b").into()));
    let original = crate::common::netns::current().unwrap();
    let socket_a = crate::host_runtime::namespace_services(&a)
        .unwrap()
        .bind_udp(BindConfig {
            reuse_addr: Some(false),
            bind_device: Some(String::new()),
            local_addr: Some("0.0.0.0:0".parse().unwrap()),
            ..BindConfig::default()
        })
        .await
        .unwrap();
    let address = socket_a.local_addr().unwrap();
    let _socket_b = crate::host_runtime::namespace_services(&b)
        .unwrap()
        .bind_udp(BindConfig {
            reuse_addr: Some(false),
            bind_device: Some(String::new()),
            local_addr: Some(address),
            ..BindConfig::default()
        })
        .await
        .unwrap();
    assert!(
        crate::host_runtime::namespace_services(&a)
            .unwrap()
            .bind_udp(BindConfig {
                reuse_addr: Some(false),
                bind_device: Some(String::new()),
                local_addr: Some(address),
                ..BindConfig::default()
            })
            .await
            .is_err()
    );
    tokio::task::yield_now().await;
    assert_eq!(original, crate::common::netns::current().unwrap());
}
