//! Native construction of the shared Core network-domain handle.

use crate::host_runtime::native_host_runtime;
use std::io;

pub use easytier_core::net_ns::NetNS;

cfg_select! {
    target_os = "linux" => {
        mod linux;
        pub(crate) use linux::PlatformNetNS;
    },
    _ => {
        use easytier_core::net_ns::NetNSBackend;

        #[derive(Clone, Copy, Debug)]
        pub(crate) struct DummyNetNS;

        pub(crate) type PlatformNetNS = DummyNetNS;

        impl DummyNetNS {
            pub(crate) fn id(&self) -> u128 {
                0
            }

            pub(crate) fn process() -> io::Result<Self> {
                Ok(Self)
            }

            pub(crate) fn thread() -> io::Result<Self> {
                Ok(Self)
            }
        }

        impl NetNSBackend for DummyNetNS {
            fn id(&self) -> u128 {
                Self::id(self)
            }

            fn process() -> io::Result<Self> {
                Self::process()
            }

            fn thread() -> io::Result<Self> {
                Self::thread()
            }

            fn run(&self, operation: &mut dyn FnMut()) -> io::Result<()> {
                operation();
                Ok(())
            }
        }
    },
}

/// Legacy configuration label for PID 1's network namespace (/proc/1/ns/net).
/// This is distinct from the process default and may belong to a container.
pub const ROOT_NET_NS_NAME: &str = "_root_ns";

pub fn current() -> io::Result<NetNS> {
    native_host_runtime().intern_net_ns(PlatformNetNS::thread()?)
}

#[cfg(target_os = "linux")]
pub fn open(name: &str) -> io::Result<NetNS> {
    native_host_runtime().intern_net_ns(PlatformNetNS::open(name)?)
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


