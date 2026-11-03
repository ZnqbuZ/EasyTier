use crate::common::net_ns::{NetNS, ROOT_NET_NS_NAME};
use crate::host_runtime::NativeNetNSServices;
use easytier_core::socket::BindConfig;

use super::{add_ns_to_bridge, create_net_ns, del_net_ns, run_network_command};

/// Owns one test's host links and namespaces. Keep this alive until its
/// instances and background tasks have stopped, including on setup failures.
pub(super) struct TestNetwork {
    directory: tempfile::TempDir,
    net_ns: Vec<(&'static str, String)>,
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
            net_ns: Vec::new(),
            links: Vec::new(),
        }
    }

    fn prefix(&self) -> &str {
        self.directory.path().file_name().unwrap().to_str().unwrap()
    }

    pub(super) fn net_ns(&self, name: &str) -> &str {
        &self.net_ns.iter().find(|(key, _)| *key == name).unwrap().1
    }

    pub(super) fn link(&self, name: &str) -> &str {
        &self.links.iter().find(|(key, _)| *key == name).unwrap().1
    }

    fn add_net_ns(&mut self, name: &'static str) {
        // veth_<namespace>_h must fit Linux's 15-byte interface name limit.
        let actual = format!("{}{:02x}", self.prefix(), self.net_ns.len());
        assert!(actual.len() <= 8);
        assert!(!self.net_ns.iter().any(|(key, _)| *key == name));
        self.net_ns.push((name, actual));
    }

    pub(super) fn create_net_ns(&mut self, name: &'static str, ipv4: &str, ipv6: &str) {
        self.add_net_ns(name);
        create_net_ns(self.net_ns(name), ipv4, ipv6);
    }

    pub(super) fn create_empty_net_ns(&mut self, name: &'static str) {
        self.add_net_ns(name);
        let actual = self.net_ns(name);
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

    pub(super) fn add_to_bridge(&self, bridge: &str, net_ns: &str) {
        add_ns_to_bridge(self.link(bridge), self.net_ns(net_ns));
    }
}

impl Drop for TestNetwork {
    fn drop(&mut self) {
        crate::common::net_ns::tests::test_net_ns(Some(ROOT_NET_NS_NAME.to_owned()))
            .run(|| {
                for (_, net_ns) in &self.net_ns {
                    del_net_ns(net_ns);
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
fn nested_net_ns_guard_restores_current_thread() {
    let mut network = TestNetwork::new();
    network.create_empty_net_ns("net_a");
    network.create_empty_net_ns("net_b");
    let net_a = crate::common::net_ns::tests::test_net_ns(Some(network.net_ns("net_a").into()));
    let net_b = crate::common::net_ns::tests::test_net_ns(Some(network.net_ns("net_b").into()));
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
async fn bound_sockets_use_distinct_net_ns_without_switching_async_tasks() {
    use easytier_core::socket::udp::{VirtualUdpSocket, VirtualUdpSocketFactory};
    let mut network = TestNetwork::new();
    network.create_empty_net_ns("net_a");
    network.create_empty_net_ns("net_b");
    let a = crate::common::net_ns::tests::test_net_ns(Some(network.net_ns("net_a").into()));
    let b = crate::common::net_ns::tests::test_net_ns(Some(network.net_ns("net_b").into()));
    let original = NetNS::current().unwrap();
    let socket_a = NativeNetNSServices::of(&a)
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
    let _socket_b = NativeNetNSServices::of(&b)
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
        NativeNetNSServices::of(&a)
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
    assert_eq!(original, NetNS::current().unwrap());
}
