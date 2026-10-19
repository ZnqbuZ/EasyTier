//! Pinned OS namespace resources. This module never owns native services.

use std::{
    fs::{self, File, Metadata},
    io,
    marker::PhantomData,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Component, Path},
    rc::Rc,
    sync::Arc,
};

use easytier_core::netns::NetNSBackend;

/// Cloning pins the same kernel namespace, without retaining its service owner.
#[derive(Clone, Debug)]
pub(crate) struct PlatformNamespace {
    id: u128,
    file: Arc<File>,
}

impl PlatformNamespace {
    fn namespace_identity(metadata: &Metadata) -> u128 {
        (u128::from(metadata.dev()) << 64) | u128::from(metadata.ino())
    }

    pub(crate) fn process_default() -> io::Result<Self> {
        Self::at(Path::new("/proc/self/ns/net"))
    }

    pub(crate) fn current() -> io::Result<Self> {
        Self::at(Path::new("/proc/thread-self/ns/net"))
    }

    pub(crate) fn open(name: &str) -> io::Result<Self> {
        if name == super::ROOT_NETNS_NAME {
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
        let id = Self::namespace_identity(&file.metadata()?);
        // SAFETY: the ioctl takes no argument and only queries this open fd.
        let namespace_type =
            unsafe { nix::libc::ioctl(file.as_raw_fd(), nix::libc::NS_GET_NSTYPE) };
        if namespace_type < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(nix::libc::ENOTTY) {
                return Err(error);
            }
            // NS_GET_NSTYPE was added in Linux 4.11. The current network
            // namespace is already known without requiring CAP_SYS_ADMIN.
            if id != Self::namespace_identity(&fs::metadata("/proc/thread-self/ns/net")?) {
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
        } else if namespace_type != nix::libc::CLONE_NEWNET {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "file is not a network namespace",
            ));
        }
        Ok(Self { id, file })
    }

    /// Kernel namespace identity, independent of the name/path used to open it.
    pub(crate) fn id(&self) -> u128 {
        self.id
    }

    /// Run only the synchronous resource-creation/query portion of an operation.
    pub(crate) fn run<R>(&self, operation: impl FnOnce() -> R) -> io::Result<R> {
        let _guard = self.enter()?;
        Ok(operation())
    }

    fn enter(&self) -> io::Result<RestoreNamespace> {
        let current = Self::namespace_identity(&fs::metadata("/proc/thread-self/ns/net")?);
        let previous = if current == self.id {
            // Even setns to our own namespace requires privileges. Do not do it.
            None
        } else {
            let previous = File::open("/proc/thread-self/ns/net")?;
            nix::sched::setns(self.file.as_ref(), nix::sched::CloneFlags::CLONE_NEWNET)?;
            Some(previous)
        };
        Ok(RestoreNamespace {
            previous,
            _thread_bound: PhantomData,
        })
    }
}

impl NetNSBackend for PlatformNamespace {
    fn run(&self, operation: &mut dyn FnMut()) -> io::Result<()> {
        PlatformNamespace::run(self, operation)
    }
}

/// Private and !Send / !Sync: namespace membership belongs to this OS thread.
struct RestoreNamespace {
    previous: Option<File>,
    _thread_bound: PhantomData<Rc<()>>,
}

impl Drop for RestoreNamespace {
    fn drop(&mut self) {
        if let Some(previous) = &self.previous
            && let Err(error) = nix::sched::setns(previous, nix::sched::CloneFlags::CLONE_NEWNET)
        {
            // A contaminated runtime thread must never execute another task.
            tracing::error!(%error, "failed to restore network namespace; aborting");
            std::process::abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_namespace_type_and_path_names() {
        let error = PlatformNamespace::at(Path::new("/proc/thread-self/ns/mnt")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        for name in ["", ".", "..", "/tmp/test", "a/b"] {
            assert_eq!(
                PlatformNamespace::open(name).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }
}
