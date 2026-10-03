//! Route demand domain models and types.
//!
//! Provides platform-independent demand models, source identifiers, lifecycle
//! versions, and pure value objects as defined in HostRouteManager Step 2.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::IpAddr,
    time::SystemTime,
};

use cidr::IpCidr;
use serde::{Deserialize, Serialize};

/// Unique identifier for a single run of an instance.
///
/// Distinct from reusable instance configuration UUIDs.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct InstanceRuntimeId(pub uuid::Uuid);

impl InstanceRuntimeId {
    pub fn random() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}

impl fmt::Debug for InstanceRuntimeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InstanceRuntimeId({})", self.0)
    }
}

impl fmt::Display for InstanceRuntimeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for a registry run.
///
/// View revisions are only comparable within the same registry instance.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RegistryId(pub uuid::Uuid);

impl RegistryId {
    pub fn random() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}

impl fmt::Debug for RegistryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RegistryId({})", self.0)
    }
}

impl fmt::Display for RegistryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Category of demand source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SourceKind {
    /// Peer subnet proxy routes and manual override routes.
    ProxyCidr,
    /// Public IPv6 default route egress (::/0).
    PublicIpv6Egress,
    /// Public IPv6 peer network routes.
    PublicIpv6Peer,
    /// Unified Public IPv6 source (combines egress ::/0 and peer routes).
    PublicIpv6,
    /// Magic DNS fake IP (/32) virtual routes.
    MagicDns,
    /// Platform explicit virtual interface subnet prefix (e.g. macOS / FreeBSD).
    InterfacePrefix,
    /// Dynamic routes from VPN portal clients.
    VpnPortalClient,
    /// Custom extension source.
    Custom(u32),
}

/// Globally unique identifier for a demand source.
///
/// The UUID identifies the source instance, distinct from the instance runtime ID.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SourceId {
    pub kind: SourceKind,
    pub uuid: uuid::Uuid,
}

impl SourceId {
    pub fn new(kind: SourceKind, uuid: uuid::Uuid) -> Self {
        Self { kind, uuid }
    }

    pub fn random(kind: SourceKind) -> Self {
        Self {
            kind,
            uuid: uuid::Uuid::new_v4(),
        }
    }
}

impl fmt::Debug for SourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SourceId({:?}, {})", self.kind, self.uuid)
    }
}

impl fmt::Display for SourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}:{}", self.kind, self.uuid)
    }
}

/// Lifecycle epoch allocated by the registry on source registration/restart.
///
/// Strictly monotonically increasing per source.
#[derive(
    Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct SourceEpoch(pub u64);

impl SourceEpoch {
    pub fn next(&self) -> Result<Self, ArithmeticOverflow> {
        self.0.checked_add(1).map(Self).ok_or(ArithmeticOverflow)
    }
}

impl fmt::Debug for SourceEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Epoch({})", self.0)
    }
}

impl fmt::Display for SourceEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Demand publication revision within a specific epoch, assigned by registry.
///
/// Strictly monotonically increasing per epoch.
#[derive(
    Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct SourceRevision(pub u64);

impl SourceRevision {
    pub fn next(&self) -> Result<Self, ArithmeticOverflow> {
        self.0.checked_add(1).map(Self).ok_or(ArithmeticOverflow)
    }
}

impl fmt::Debug for SourceRevision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Rev({})", self.0)
    }
}

impl fmt::Display for SourceRevision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Global registry view revision, incremented on every visible state change.
#[derive(
    Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct RegistryRevision(pub u64);

impl RegistryRevision {
    pub fn next(&self) -> Result<Self, ArithmeticOverflow> {
        self.0.checked_add(1).map(Self).ok_or(ArithmeticOverflow)
    }
}

impl fmt::Debug for RegistryRevision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RegistryRev({})", self.0)
    }
}

impl fmt::Display for RegistryRevision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("version counter arithmetic overflow")]
pub struct ArithmeticOverflow;

/// Purpose of the route demand.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RoutePurpose {
    /// Peer subnet proxy route advertised by remote peers.
    PeerProxy,
    /// Manual override proxy route specified in local config.
    ManualOverrideProxy,
    /// Public IPv6 default route (::/0).
    PublicIpv6Default,
    /// Public IPv6 peer routable prefix.
    PublicIpv6Peer,
    /// Magic DNS synthetic IP (/32).
    MagicDnsFakeIp,
    /// Local interface direct subnet route.
    InterfaceSubnet,
}

/// Logical packet interface associated with an instance runtime.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LogicalEgress {
    pub instance_runtime_id: InstanceRuntimeId,
}

impl LogicalEgress {
    pub fn new(instance_runtime_id: InstanceRuntimeId) -> Self {
        Self {
            instance_runtime_id,
        }
    }
}

impl fmt::Debug for LogicalEgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LogicalEgress({})", self.instance_runtime_id)
    }
}

/// Typed logical dependency reference for route demands.
///
/// Ensures route changes (e.g. lease replacement for `::/0`) produce
/// distinct demand items even if the destination CIDR remains identical.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LogicalDependency {
    None,
    AddressFactVersion(u64),
    Ipv6Lease {
        address: IpAddr,
        lease_version: u64,
    },
    Custom {
        tag: String,
        version: u64,
    },
}

impl Default for LogicalDependency {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DemandError {
    #[error("destination CIDR contains non-zero host bits or is invalid: {0}")]
    InvalidPrefix(String),
}

/// A normalized single route demand item.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RouteDemand {
    pub destination: IpCidr,
    pub purpose: RoutePurpose,
    pub logical_egress: LogicalEgress,
    pub dependency: LogicalDependency,
}

impl RouteDemand {
    /// Constructs and normalizes a new route demand, clearing any host bits.
    pub fn new(
        destination: IpCidr,
        purpose: RoutePurpose,
        logical_egress: LogicalEgress,
        dependency: LogicalDependency,
    ) -> Self {
        let normalized_dst = normalize_cidr(destination);
        Self {
            destination: normalized_dst,
            purpose,
            logical_egress,
            dependency,
        }
    }
}

/// Normalizes an `IpCidr` by zeroing any host bits beyond the prefix length.
pub fn normalize_cidr(cidr: IpCidr) -> IpCidr {
    match cidr {
        IpCidr::V4(v4) => {
            let addr = v4.first_address();
            let len = v4.network_length();
            IpCidr::V4(cidr::Ipv4Cidr::new(addr, len).unwrap_or(v4))
        }
        IpCidr::V6(v6) => {
            let addr = v6.first_address();
            let len = v6.network_length();
            IpCidr::V6(cidr::Ipv6Cidr::new(addr, len).unwrap_or(v6))
        }
    }
}

/// Parses and normalizes a CIDR string (e.g. "192.168.1.100/24" -> "192.168.1.0/24").
pub fn parse_and_normalize_cidr(s: &str) -> Result<IpCidr, DemandError> {
    if let Ok(cidr) = s.parse::<IpCidr>() {
        return Ok(normalize_cidr(cidr));
    }
    if let Ok(inet) = s.parse::<cidr::IpInet>() {
        return Ok(match inet {
            cidr::IpInet::V4(v4) => IpCidr::V4(
                cidr::Ipv4Cidr::new(v4.first_address(), v4.network_length())
                    .map_err(|e| DemandError::InvalidPrefix(e.to_string()))?,
            ),
            cidr::IpInet::V6(v6) => IpCidr::V6(
                cidr::Ipv6Cidr::new(v6.first_address(), v6.network_length())
                    .map_err(|e| DemandError::InvalidPrefix(e.to_string()))?,
            ),
        });
    }
    Err(DemandError::InvalidPrefix(s.to_string()))
}

/// Audit basis recording inputs that produced a projection.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub struct ProjectionBasis {
    pub input_revisions: BTreeMap<String, u64>,
    pub notes: Option<String>,
}

impl ProjectionBasis {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_revision(mut self, key: impl Into<String>, revision: u64) -> Self {
        self.input_revisions.insert(key.into(), revision);
        self
    }

    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.notes = Some(note.into());
        self
    }
}

/// Complete, immutable snapshot of demands submitted by one source.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSnapshot {
    pub source_id: SourceId,
    pub epoch: SourceEpoch,
    pub revision: SourceRevision,
    pub demands: BTreeSet<RouteDemand>,
    pub basis: ProjectionBasis,
    pub updated_at: SystemTime,
}

/// Lifecycle status of a demand source.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceStatus {
    /// Registered but has not yet published an initial snapshot.
    Initializing,
    /// Active with a published full snapshot.
    Active,
    /// Temporarily unavailable; retains the last valid snapshot as a stale baseline.
    Unavailable { reason: String },
    /// Explicitly revoked; demands are retired.
    Revoked { tombstone_revision: SourceRevision },
}

/// Per-source state record maintained by the registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRecord {
    pub source_id: SourceId,
    pub epoch: SourceEpoch,
    pub status: SourceStatus,
    pub latest_snapshot: Option<SourceSnapshot>,
    pub stale_baseline: Option<SourceSnapshot>,
}

/// Complete immutable snapshot of the entire registry view.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrySnapshot {
    pub registry_id: RegistryId,
    pub instance_runtime_id: InstanceRuntimeId,
    pub revision: RegistryRevision,
    pub sources: BTreeMap<SourceId, SourceRecord>,
    pub tombstones: BTreeMap<SourceId, SourceEpoch>,
    pub is_closed: bool,
}
