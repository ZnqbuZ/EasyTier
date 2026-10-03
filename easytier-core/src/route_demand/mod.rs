//! Portable route demand abstraction and versioned publication bus.
//!
//! Provides platform-independent demand models, instance-level source registration,
//! single-authority watch channel distribution, and exact token lifecycle tracking
//! as defined in HostRouteManager Step 2.

pub mod model;
pub mod projection;
pub mod registry;
pub mod subscription;
pub mod token;

#[cfg(test)]
pub(crate) mod tests;

pub use model::{
    normalize_cidr, parse_and_normalize_cidr, ArithmeticOverflow, DemandError, InstanceRuntimeId,
    LogicalDependency, LogicalEgress, ProjectionBasis, RegistryId, RegistryRevision,
    RegistrySnapshot, RouteDemand, RoutePurpose, SourceEpoch, SourceId, SourceKind, SourceRecord,
    SourceRevision, SourceSnapshot, SourceStatus,
};
pub use projection::{
    project_interface_subnet_demand, project_ipv4_proxy_demands, project_magic_dns_demand,
    project_public_ipv6_egress_demand, project_public_ipv6_peer_demands, resolve_proxy_cidrs,
};
pub use registry::{
    BatchReceipt, DemandReader, InstanceOwner, PublishError, PublishReceipt, RegistryError,
    RevocationReceipt, ScopedPublisher, SourceDemandUpdate, SourcePublisher,
};
pub use subscription::{Subscription, SubscriptionClosed};
pub use token::{
    ObsoleteOutcome, SourceSubmissionToken, SubmissionLifecycle, TokenQueryError, WaitObsoleteError,
};
