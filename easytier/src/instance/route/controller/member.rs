//! NIC synchronization and member retry helpers shared by both platforms.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

use cidr::IpCidr;
use uuid::Uuid;

use crate::instance::shared_virtual_nic::{SharedIfConfigClaims, SharedVirtualNicMember};

use super::retry_backoff;

/// Bring one member's managed routes in line with its current prefixes.
///
/// `true` means this registration's commit really completed. `false` means the
/// registration is gone or the NIC has already been stopped, so waiting for
/// it any longer is pointless. An error means nothing is confirmed yet and
/// the caller still owes a retry. Equal claims are committed again on purpose:
/// only the commit is the acknowledgement.
pub(super) async fn sync_member_routes(
    member: &SharedVirtualNicMember,
    routes: &BTreeSet<IpCidr>,
) -> anyhow::Result<bool> {
    let member_id = member.member_id();
    let registration = member.registration_id();
    let shared_nic = member.shared_nic();
    let mut nic = tokio::time::timeout(Duration::from_secs(5), shared_nic.lock())
        .await
        .map_err(|_| anyhow::anyhow!("timed out locking shared NIC for member {member_id}"))?;

    if !nic.is_valid() {
        // The dispatcher and its I/O have really stopped; there is no
        // registration left to acknowledge.
        nic.invalidate_and_shutdown_dispatcher().await;
        return Ok(false);
    }
    if !nic.is_current_member_registration(member_id, registration) {
        // A newer registration owns the NIC now; leave it untouched.
        return Ok(false);
    }
    if !routes.is_empty() {
        // An empty set may withdraw through an already closed member.
        member.ensure_open()?;
    }

    let claims = nic.prepare_managed_routes(member_id, registration, routes)?;
    tokio::time::timeout(
        Duration::from_secs(5),
        nic.commit_managed_routes(member_id, registration, claims),
    )
    .await
    .map_err(|_| anyhow::anyhow!("timed out committing routes of member {member_id}"))??;
    Ok(true)
}
/// One failed member prefix synchronization and the handle still needed for
/// its real cleanup.
///
/// The complete failed target is kept so a narrower intermediate commit never
/// shortens the deadline. The entry belongs to the platform reconciler that
/// performs the attempt; it is not shared state.
pub(super) struct MemberRetry {
    pub(super) member: SharedVirtualNicMember,
    pub(super) target: BTreeSet<IpCidr>,
    pub(super) retry_at: tokio::time::Instant,
    pub(super) attempts: u32,
    pub(super) error: Arc<str>,
}

/// Whether this member's final target still has to wait out a failure.
pub(super) fn member_retry_blocked(
    retries: &BTreeMap<(Uuid, Uuid), MemberRetry>,
    key: &(Uuid, Uuid),
    target: &BTreeSet<IpCidr>,
    now: tokio::time::Instant,
) -> bool {
    retries
        .get(key)
        .is_some_and(|retry| retry.target == *target && retry.retry_at > now)
}
/// Record (or extend) the backoff of one member's final target.
pub(super) fn record_member_failure(
    retries: &mut BTreeMap<(Uuid, Uuid), MemberRetry>,
    key: (Uuid, Uuid),
    member: &SharedVirtualNicMember,
    target: BTreeSet<IpCidr>,
    error: &anyhow::Error,
) {
    let now = tokio::time::Instant::now();
    let error: Arc<str> = Arc::from(error.to_string());
    match retries.get_mut(&key) {
        Some(retry) if retry.target == target => {
            if retry.retry_at <= now {
                retry.attempts = retry.attempts.saturating_add(1);
                retry.retry_at = now + retry_backoff(retry.attempts);
            }
            retry.error = error;
        }
        _ => {
            retries.insert(
                key,
                MemberRetry {
                    member: member.clone(),
                    target,
                    retry_at: now + retry_backoff(1),
                    attempts: 1,
                    error,
                },
            );
        }
    }
}
/// The route prefixes of one member's current claims.
pub(super) fn claim_prefixes(claims: &SharedIfConfigClaims) -> BTreeSet<IpCidr> {
    let ipv4 = claims.ipv4_routes.iter().filter_map(|route| {
        cidr::Ipv4Cidr::new(route.address, route.prefix)
            .ok()
            .map(IpCidr::V4)
    });
    let ipv6 = claims.ipv6_routes.iter().filter_map(|route| {
        cidr::Ipv6Cidr::new(route.address, route.prefix)
            .ok()
            .map(IpCidr::V6)
    });
    ipv4.chain(ipv6).collect()
}
