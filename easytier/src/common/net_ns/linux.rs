//! Pinned OS namespace resources. This module never owns native services.

use std::{
    fs::{self, File, Metadata},
    io,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Component, Path},
    sync::Arc,
};

use easytier_core::net_ns::NetNSBackend;
use guarden::guarded;

/// Cloning pins the same kernel namespace, without retaining its service owner.
#[derive(Clone, Debug)]
pub(crate) struct PlatformNetNS {
    id: u128,
    file: Arc<File>,
}

impl PlatformNetNS {
    fn identity(metadata: &Metadata) -> u128 {
        (u128::from(metadata.dev()) << 64) | u128::from(metadata.ino())
    }

    pub(crate) fn id(&self) -> u128 {
        self.id
    }

    pub(crate) fn process() -> io::Result<Self> {
        Self::at(Path::new("/proc/self/ns/net"))
    }

    pub(crate) fn thread() -> io::Result<Self> {
        Self::at(Path::new("/proc/thread-self/ns/net"))
    }

    pub(crate) fn open(name: &str) -> io::Result<Self> {
        if name == super::ROOT_NET_NS_NAME {
            return Self::at(Path::new("/proc/1/ns/net"));
        }
        // Names are labels under /var/run/netns, not arbitrary file paths.
        let mut components = Path::new(name).components();
        if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "network namespace name must be one path component",
            ));
        }
        Self::at(&Path::new("/var/run/netns").join(name))
    }

    fn at(path: &Path) -> io::Result<Self> {
        let file = Arc::new(File::open(path)?);
        let id = Self::identity(&file.metadata()?);
        // SAFETY: the ioctl takes no argument and only queries this open fd.
        let net_ns_type = unsafe { nix::libc::ioctl(file.as_raw_fd(), nix::libc::NS_GET_NSTYPE) };
        if net_ns_type < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(nix::libc::ENOTTY) {
                return Err(error);
            }
            // NS_GET_NSTYPE was added in Linux 4.11. The current network
            // namespace is already known without requiring CAP_SYS_ADMIN.
            if id != Self::identity(&fs::metadata("/proc/thread-self/ns/net")?) {
                // On older kernels setns validates the type. Use a disposable
                // thread so validation never changes the caller's namespace.
                let probe = file.clone();
                std::thread::Builder::new()
                    .name("easytier-netns-probe".to_owned())
                    .spawn(move || {
                        nix::sched::setns(probe.as_ref(), nix::sched::CloneFlags::CLONE_NEWNET)
                    })?
                    .join()
                    .map_err(|_| io::Error::other("namespace validation thread panicked"))??;
            }
        } else if net_ns_type != nix::libc::CLONE_NEWNET {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "file is not a network namespace",
            ));
        }
        Ok(Self { id, file })
    }
}

impl NetNSBackend for PlatformNetNS {
    /// Kernel namespace identity, independent of the name/path used to open it.
    fn id(&self) -> u128 {
        self.id
    }

    fn process() -> io::Result<Self> {
        Self::at(Path::new("/proc/self/ns/net"))
    }

    fn thread() -> io::Result<Self> {
        Self::at(Path::new("/proc/thread-self/ns/net"))
    }

    /// Run only the synchronous resource-creation/query portion of an operation.
    fn run(&self, operation: &mut dyn FnMut()) -> io::Result<()> {
        let current = Self::identity(&fs::metadata("/proc/thread-self/ns/net")?);
        if current == self.id {
            // Even setns to our own namespace requires privileges. Do not do it.
            operation();
            return Ok(());
        }
        let previous = File::open("/proc/thread-self/ns/net")?;
        nix::sched::setns(self.file.as_ref(), nix::sched::CloneFlags::CLONE_NEWNET)?;
        // Keep restoration in this synchronous scope so it cannot escape the thread.
        guarded!([previous] {
            if let Err(error) = nix::sched::setns(previous, nix::sched::CloneFlags::CLONE_NEWNET) {
                // A contaminated runtime thread must never execute another task.
                tracing::error!(%error, "failed to restore network namespace; aborting");
                std::process::abort();
            }
        });
        operation();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_net_ns_type_and_path_names() {
        let error = PlatformNetNS::at(Path::new("/proc/thread-self/ns/mnt")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        for name in ["", ".", "..", "/tmp/test", "a/b"] {
            assert_eq!(
                PlatformNetNS::open(name).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }
}
