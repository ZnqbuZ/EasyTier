//! Shared network-domain handles. Hosts own platform resources and domain services.

use std::{
    fmt,
    hash::{Hash, Hasher},
    io,
    ops::Deref,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use crate::socket::SocketContext;
use equivalent::Equivalent;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Synchronous scope entry supplied by the Host. Invoke the operation exactly
/// once in the selected domain, restoring the calling thread before returning.
pub trait NetNSBackend: fmt::Debug + Send + Sync + 'static {
    fn run(&self, operation: &mut dyn FnMut()) -> io::Result<()>;
}

#[derive(Debug, PartialEq, Eq, Hash)]
enum Identity {
    Local(u128),
    HostReference(String),
}

struct State {
    identity: Identity,
    backend: Box<dyn NetNSBackend>,
    closing: AtomicBool,
}

/// One network domain, shared by Core and its Host. Clones retain the same
/// platform resource; DNS, NICs and other services remain owned by the Host.
#[derive(Clone)]
pub struct NetNS(Arc<State>);

impl NetNS {
    /// The Host supplies a stable identity for an actual domain and interns
    /// handles before publishing them. Identity is not an access credential.
    pub fn new(identity: u128, backend: impl NetNSBackend) -> Self {
        Self(Arc::new(State {
            identity: Identity::Local(identity),
            backend: Box::new(backend),
            closing: AtomicBool::new(false),
        }))
    }

    /// A reference interpreted by an external Host, such as the WASI ABI.
    /// It does not grant local namespace entry or resolve a configured name.
    pub fn from_host_reference(reference: impl Into<String>) -> Self {
        Self(Arc::new(State {
            identity: Identity::HostReference(reference.into()),
            backend: Box::new(ExternalHost),
            closing: AtomicBool::new(false),
        }))
    }

    pub fn host_reference(&self) -> io::Result<&str> {
        match &self.0.identity {
            Identity::HostReference(reference) => Ok(reference),
            Identity::Local(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "a local namespace handle cannot be passed to an external Host",
            )),
        }
    }

    /// Stable native domain identity, used for interning and equality checks.
    /// Linux Hosts encode (st_dev, st_ino); external Host references have no local ID.
    pub fn id(&self) -> Option<u128> {
        match self.0.identity {
            Identity::Local(identity) => Some(identity),
            Identity::HostReference(_) => None,
        }
    }

    pub fn ensure_open(&self) -> io::Result<()> {
        if self.is_closed() {
            return Err(io::Error::other("network namespace is closing"));
        }
        Ok(())
    }

    pub fn is_closed(&self) -> bool {
        self.0.closing.load(Ordering::Acquire)
    }

    /// Stop new I/O admission. The Host continues driving service cleanup.
    pub fn close(&self) {
        self.0.closing.store(true, Ordering::Release);
    }

    pub fn validate_context(&self, context: &SocketContext) -> io::Result<()> {
        self.ensure_open()?;
        if context
            .netns
            .as_ref()
            .is_some_and(|namespace| namespace != self)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "socket context belongs to a different network namespace",
            ));
        }
        Ok(())
    }

    /// Run resource creation/query synchronously. Cleanup may still enter a
    /// closing domain; factories must check admission before creating new I/O.
    pub fn run<R>(&self, operation: impl FnOnce() -> R) -> io::Result<R> {
        let mut operation = Some(operation);
        let mut result = None;
        self.0.backend.run(&mut || {
            result = Some(operation.take().expect("namespace operation invoked twice")());
        })?;
        result.ok_or_else(|| io::Error::other("namespace operation was not invoked"))
    }
}

impl fmt::Debug for NetNS {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetNS")
            .field("identity", &self.0.identity)
            .finish()
    }
}

impl PartialEq for NetNS {
    fn eq(&self, other: &Self) -> bool {
        self.0.identity == other.0.identity
    }
}

impl Eq for NetNS {}

impl Hash for NetNS {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.identity.hash(state);
    }
}

// External Host references keep their existing string representation. Local
// handles are diagnostic identities on serialization, never restorable resources.
impl Serialize for NetNS {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.0.identity {
            Identity::HostReference(reference) => serializer.serialize_str(reference),
            Identity::Local(identity) => serializer.serialize_u128(*identity),
        }
    }
}

impl<'de> Deserialize<'de> for NetNS {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::from_host_reference)
    }
}

#[derive(Debug)]
struct ExternalHost;

impl NetNSBackend for ExternalHost {
    fn run(&self, _operation: &mut dyn FnMut()) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "namespace entry is owned by the external Host",
        ))
    }
}

// Native service owners dereference to their canonical namespace and hash only
// that identity. Keep this impl beside NetNS to satisfy the orphan rules.
impl<T: Deref<Target = Self>> Equivalent<Arc<T>> for NetNS {
    fn equivalent(&self, services: &Arc<T>) -> bool {
        self == services.as_ref().deref()
    }
}
