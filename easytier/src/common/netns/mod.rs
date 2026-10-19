//! Native construction of the shared Core network-domain handle.

use crate::host_runtime::native_host_runtime;
use std::io;

pub use easytier_core::netns::NetNS;
cfg_select! {
    target_os = "linux" => {
        mod linux;
        pub(crate) use linux::PlatformNamespace;
    },
    _ => {
        use easytier_core::netns::NetNSBackend;

        #[derive(Clone, Copy, Debug)]
        pub(crate) struct DummyNamespace;

        pub(crate) type PlatformNamespace = DummyNamespace;

        impl DummyNamespace {
            pub(crate) fn process_default() -> io::Result<Self> {
                Self::current()
            }

            pub(crate) fn current() -> io::Result<Self> {
                Ok(Self)
            }

            pub(crate) fn id(&self) -> u128 {
                0
            }

            pub(crate) fn run<R>(&self, operation: impl FnOnce() -> R) -> io::Result<R> {
                Ok(operation())
            }
        }

        impl NetNSBackend for DummyNamespace {
            fn run(&self, operation: &mut dyn FnMut()) -> io::Result<()> {
                DummyNamespace::run(self, operation)
            }
        }
    },
}

/// Legacy configuration label for PID 1's network namespace (/proc/1/ns/net).
/// This is distinct from the process default and may belong to a container.
pub const ROOT_NETNS_NAME: &str = "_root_ns";

pub fn current() -> io::Result<NetNS> {
    native_host_runtime().intern_namespace(PlatformNamespace::current()?)
}

#[cfg(target_os = "linux")]
pub fn open(name: &str) -> io::Result<NetNS> {
    native_host_runtime().intern_namespace(PlatformNamespace::open(name)?)
}

pub(crate) fn resolve_config(name: Option<&str>) -> io::Result<NetNS> {
    match name {
        None => current(),
        Some(name) => {
            cfg_select! {
                target_os = "linux" => open(name),
                _ => {
                    let _ = name;
                    Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "named network namespaces are unsupported",
                    ))
                },
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use easytier_core::socket::BindConfig;
    use easytier_core::socket::SocketContext;
    use std::sync::Arc;

    pub(crate) fn test_namespace(name: Option<String>) -> NetNS {
        resolve_config(name.as_deref()).expect("open test network namespace")
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn isolated_namespace_for_test() -> io::Result<NetNS> {
        // Run the test process in `unshare --user --map-root-user --net` first, so
        // both the initial and additional domains belong to that user namespace.
        std::thread::Builder::new()
            .name("netns-test-fixture".to_owned())
            .spawn(|| {
                nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET)?;
                let status = std::process::Command::new("ip")
                    .args(["link", "set", "lo", "up"])
                    .status()?;
                if !status.success() {
                    return Err(io::Error::other("failed to bring up isolated loopback"));
                }
                crate::common::netns::current()
            })?
            .join()
            .map_err(|_| io::Error::other("namespace fixture thread panicked"))?
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "run inside an isolated user+network namespace"]
    fn distinct_domains_restore_actual_thread_context_after_errors_and_unwind() {
        let original = crate::common::netns::current().unwrap();
        let a = isolated_namespace_for_test().unwrap();
        let b = isolated_namespace_for_test().unwrap();
        assert_ne!(a.id(), b.id());
        a.run(|| {
            assert!(a == crate::common::netns::current().unwrap());
            let result = b
                .run(|| {
                    assert!(b == crate::common::netns::current().unwrap());
                    Err::<(), _>("operation failed")
                })
                .unwrap();
            assert!(result.is_err());
            assert!(a == crate::common::netns::current().unwrap());
        })
        .unwrap();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            a.run(|| panic!("namespace operation panic")).unwrap();
        }));
        assert!(panic.is_err());
        assert!(original == crate::common::netns::current().unwrap());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "run inside an isolated user+network namespace"]
    async fn asynchronous_io_keeps_its_bound_domain_on_default_runtime_threads() {
        use easytier_core::socket::udp::{VirtualUdpSocket, VirtualUdpSocketFactory};
        let original = crate::common::netns::current().unwrap();
        let a = isolated_namespace_for_test().unwrap();
        let b = isolated_namespace_for_test().unwrap();
        let first = crate::host_runtime::namespace_services(&a)
            .unwrap()
            .bind_udp(BindConfig {
                reuse_addr: Some(false),
                bind_device: Some(String::new()),
                local_addr: Some("127.0.0.1:0".parse().unwrap()),
                ..BindConfig::default()
            })
            .await
            .unwrap();
        let address = first.local_addr().unwrap();
        let second = crate::host_runtime::namespace_services(&b)
            .unwrap()
            .bind_udp(BindConfig {
                reuse_addr: Some(false),
                bind_device: Some(String::new()),
                local_addr: Some(address),
                ..BindConfig::default()
            })
            .await
            .unwrap();
        assert_eq!(first.local_addr().unwrap(), second.local_addr().unwrap());
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
        let client = crate::host_runtime::namespace_services(&a)
            .unwrap()
            .bind_udp(BindConfig {
                reuse_addr: Some(false),
                bind_device: Some(String::new()),
                ..BindConfig::default()
            })
            .await
            .unwrap();
        client.send_to(b"bound-domain", address).await.unwrap();
        let mut buffer = [0; 32];
        let (length, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            first.recv_from(&mut buffer),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&buffer[..length], b"bound-domain");
        assert!(original == crate::common::netns::current().unwrap());
    }

    #[test]
    fn independent_instances_share_the_domain_but_not_their_run_identity() {
        use crate::common::{config::TomlConfig, global_ctx::GlobalCtx};
        let first = GlobalCtx::new(TomlConfig::default());
        let second = GlobalCtx::new(TomlConfig::default());
        assert!(first.net_ns == second.net_ns);
        assert_ne!(first.run_key(), second.run_key());
        #[cfg(feature = "tun")]
        assert!(Arc::ptr_eq(
            &crate::host_runtime::namespace_services(&first.net_ns)
                .unwrap()
                .nics,
            &crate::host_runtime::namespace_services(&second.net_ns)
                .unwrap()
                .nics
        ));
    }

    #[test]
    fn concurrent_current_calls_return_the_same_service_owner() {
        let expected = crate::common::netns::current().unwrap();
        let threads = (0..8)
            .map(|_| std::thread::spawn(|| crate::common::netns::current().unwrap()))
            .collect::<Vec<_>>();
        for thread in threads {
            assert!(expected == thread.join().unwrap());
        }
    }

    #[test]
    fn contexts_are_runtime_identities_and_none_uses_the_bound_domain() {
        let namespace = crate::common::netns::current().unwrap();
        assert!(
            namespace
                .validate_context(&SocketContext::default())
                .is_ok()
        );
        assert!(
            namespace
                .validate_context(&SocketContext {
                    netns: Some(namespace.clone()),
                    ..SocketContext::default()
                })
                .is_ok()
        );
        assert!(
            namespace
                .validate_context(&SocketContext {
                    netns: Some(NetNS::from_host_reference("configured-name")),
                    ..SocketContext::default()
                })
                .is_err()
        );
    }

    #[test]
    fn current_identity_is_stable_and_clones_pin_the_same_domain() {
        let first = PlatformNamespace::current().unwrap();
        let second = PlatformNamespace::current().unwrap();
        assert_eq!(first.id(), second.id());
        assert_eq!(first.clone().id(), second.id());
        assert_eq!(first.run(|| 42).unwrap(), 42);
    }

    #[test]
    fn nested_current_domain_operations_restore_errors_and_unwind() {
        let namespace = PlatformNamespace::current().unwrap();
        assert!(
            namespace
                .run(|| namespace.run(|| Err::<(), _>("operation")))
                .unwrap()
                .unwrap()
                .is_err()
        );
        let panic = std::panic::catch_unwind(|| {
            namespace.run(|| panic!("operation panic")).unwrap();
        });
        assert!(panic.is_err());
        assert_eq!(PlatformNamespace::current().unwrap().id(), namespace.id());
    }
}
