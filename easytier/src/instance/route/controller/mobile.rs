//! Mobile local reconciliation: whole-domain records, member prefixes and
//! per-route feedback.
//!
//! The external VPN owner performs the only actual installation. This module
//! keeps the shared NIC member claims in line with the current declarations,
//! reports per-route status from the real installation evidence, and waits for
//! real cleanup before records are removed.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use cidr::IpCidr;
use easytier_core::host::route::{RouteSource, RouteStatus};
use uuid::Uuid;

use crate::instance::{
    factory::{
        MobileTunConfig,
        mobile_tun::{MobileTunMember, member_prefixes},
    },
    route::AppliedSnapshot,
    shared_virtual_nic::{SharedIfConfigClaims, SharedIfConfigConflict, SharedVirtualNicMember},
};

use super::member::{
    MemberRetry, claim_prefixes, member_retry_blocked, record_member_failure, sync_member_routes,
};
use super::{InstanceRoutes, ROUTE_IO_TIMEOUT, RouteController, RouteControllerRuntime};

impl RouteController {
    /// Register a new whole-domain mobile install or withdraw request.
    ///
    /// Every accepted request gets a fresh identity even when the desired
    /// content is unchanged. Only a domain that is shut down with nothing left
    /// to clean up is rejected; shutdown while real cleanup is still owed must
    /// still accept requests. The write lock covers only the request mark, and
    /// the notification is sent after it is released without marking input
    /// dirty.
    pub fn request_mobile_install(&self) -> anyhow::Result<Uuid> {
        let id = Uuid::new_v4();
        {
            let mut rt = self.runtime.write();
            anyhow::ensure!(
                !(rt.shutdown
                    && rt.instances.is_empty()
                    && rt.applied.is_none()
                    && rt.pending_install.is_none()),
                "route controller is shut down and has no outstanding cleanup"
            );
            rt.pending_install = Some(id);
        }
        self.changed.notify_waiters();
        Ok(id)
    }

    /// Copy the latest accepted request identity without taking it.
    pub fn pending_mobile_install(&self) -> Option<Uuid> {
        self.runtime.read().pending_install
    }

    /// Complete the request only when it is still the latest accepted one.
    ///
    /// A late completion never clears a newer request. The actual installation
    /// record and the request mark are independent, and no input is marked
    /// dirty here.
    pub fn complete_mobile_install(&self, id: Uuid) -> bool {
        let completed = {
            let mut rt = self.runtime.write();
            if rt.pending_install != Some(id) {
                false
            } else {
                rt.pending_install = None;
                true
            }
        };
        if completed {
            self.changed.notify_waiters();
        }
        completed
    }

    /// The attachment identity of the system configuration the external owner
    /// last confirmed. A pending request is not an attachment.
    pub fn current_mobile_attachment(&self) -> Option<Uuid> {
        self.runtime
            .read()
            .applied
            .as_ref()
            .map(|snapshot| snapshot.attachment_id)
    }

    /// Record the real system installation the external owner just completed.
    ///
    /// This is an observed fact, not the acceptance of a request: a late A is
    /// recorded even after shutdown or after the latest request became D. It
    /// never clears the request mark and never reopens an instance; whether the
    /// exported content is still current is the caller's boundary check.
    pub fn record_mobile_install(
        &self,
        attachment_id: Uuid,
        config: MobileTunConfig,
        members: Vec<MobileTunMember>,
    ) {
        let members = members
            .into_iter()
            .map(|mut member| {
                // A selection hint, not part of the actual installation fact.
                member.current_claims = None;
                member
            })
            .collect();
        {
            let mut rt = self.runtime.write();
            rt.applied = Some(AppliedSnapshot {
                attachment_id,
                config,
                members,
                attached_members: BTreeMap::new(),
            });
        }
        self.dirty.mark();
        self.changed.notify_waiters();
    }

    /// Confirm one member's real attachment to the recorded installation.
    ///
    /// Only the run's current registration and the matching attachment may
    /// change the ledger. A late result from an older registration or an older
    /// attachment is rejected without touching newer records. Root release and
    /// shutdown do not erase a real I/O fact.
    pub fn mobile_ready(
        &self,
        run: Uuid,
        member: &SharedVirtualNicMember,
        attachment_id: Uuid,
    ) -> bool {
        if member.member_id() != run || member.ensure_open().is_err() {
            return false;
        }
        let changed = {
            let mut rt = self.runtime.write();
            let current_registration = rt
                .instances
                .get(&run)
                .and_then(|instances| instances.member.as_ref())
                .map(SharedVirtualNicMember::registration_id);
            if current_registration != Some(member.registration_id()) {
                return false;
            }
            let Some(snapshot) = rt.applied.as_mut() else {
                return false;
            };
            if snapshot.attachment_id != attachment_id
                || !snapshot
                    .members
                    .iter()
                    .any(|installed| installed.instance_id == run)
            {
                return false;
            }
            let previous = snapshot
                .attached_members
                .insert(run, member.registration_id());
            previous != Some(member.registration_id())
        };
        if changed {
            self.dirty.mark();
            self.changed.notify_waiters();
        }
        true
    }

    /// Cleanup handles of the recorded installation when it is still the actual
    /// one. Runs whose registry root has already been released are included:
    /// this copies the current binding for cleanup and never queries the
    /// manager's running list or closes anything here.
    pub fn mobile_attachment_members(&self, attachment_id: Uuid) -> Vec<SharedVirtualNicMember> {
        let rt = self.runtime.read();
        let Some(snapshot) = rt.applied.as_ref() else {
            return Vec::new();
        };
        if snapshot.attachment_id != attachment_id {
            return Vec::new();
        }
        snapshot
            .members
            .iter()
            .filter_map(|member| {
                rt.instances
                    .get(&member.instance_id)
                    .and_then(|instances| instances.member.clone())
            })
            .collect()
    }

    /// Clear the actual record only when it is the attachment the caller really
    /// revoked. A stale revocation never touches a newer installation, and the
    /// request mark is never cleared here.
    pub fn confirm_mobile_revoked(&self, attachment_id: Uuid) -> bool {
        let removed = {
            let mut rt = self.runtime.write();
            let matches = rt
                .applied
                .as_ref()
                .is_some_and(|snapshot| snapshot.attachment_id == attachment_id);
            if matches {
                rt.applied = None;
            }
            matches
        };
        if removed {
            self.dirty.mark();
            self.changed.notify_waiters();
        }
        removed
    }

    /// Whether the whole recorded installation is still attached: the snapshot
    /// matches, every run still owns its registry root, every current member is
    /// open, and every run's attached registration is the current one. This is
    /// not a per-route readiness verdict, and an empty target is never attached.
    pub fn mobile_snapshot_attached(&self, snapshot_id: Uuid) -> bool {
        let rt = self.runtime.read();
        if rt.shutdown {
            return false;
        }
        let Some(snapshot) = rt.applied.as_ref() else {
            return false;
        };
        if snapshot.config.snapshot_id != snapshot_id || snapshot.members.is_empty() {
            return false;
        }
        snapshot.members.iter().all(|member| {
            let run = member.instance_id;
            let Some(instances) = rt.instances.get(&run) else {
                return false;
            };
            if instances.registry.upgrade().is_none() {
                return false;
            }
            let Some(current) = instances.member.as_ref() else {
                return false;
            };
            current.ensure_open().is_ok()
                && snapshot.attached_members.get(&run) == Some(&current.registration_id())
        })
    }

    /// Whether the current configuration really asks for Magic DNS.
    ///
    /// The answer comes from the current store under a short lock: a live root,
    /// an enabled build, `accept_dns`, and a current peer IPv4. The native side
    /// still verifies the actual IPv4 source.
    pub fn mobile_dns_enabled(&self, run: Uuid) -> bool {
        #[cfg(not(feature = "magic-dns"))]
        {
            let _ = run;
            false
        }
        #[cfg(feature = "magic-dns")]
        {
            let rt = self.runtime.read();
            rt.instances
                .get(&run)
                .is_some_and(|instance| mobile_dns_configured(&rt, instance))
        }
    }

    /// Claims of the run's actual installed member.
    ///
    /// Only a registration that is both attached in the ledger and still the
    /// run's current binding may provide claims. This reads the existing ledger
    /// only: it never waits for the NIC, projects a new target or caches input.
    pub fn mobile_installed_claims(&self, run: Uuid) -> Option<SharedIfConfigClaims> {
        let rt = self.runtime.read();
        let snapshot = rt.applied.as_ref()?;
        let current = rt.instances.get(&run)?.member.as_ref()?;
        if snapshot.attached_members.get(&run) != Some(&current.registration_id()) {
            return None;
        }
        snapshot
            .members
            .iter()
            .find(|member| member.instance_id == run)
            .map(|member| member.claims.clone())
    }
}

/// Mobile background reconciler: member prefixes and per-route feedback.
///
/// It owns no system route backend and never creates the external VPN. The
/// external owner alone performs the system installation; this actor keeps the
/// shared NIC member claims in line with the current declarations, reports
/// per-route status from the real installation evidence, and waits for real
/// cleanup before records are removed.
pub(super) struct RouteReconciler {
    controller: RouteController,
    /// Only the backoff of a member synchronization that already failed; the
    /// member handle is kept until its real withdrawal finishes.
    pub(super) member_retries: BTreeMap<(Uuid, Uuid), MemberRetry>,
    /// Deadlines at or before this instant have already had their attempt.
    retry_horizon: tokio::time::Instant,
}

impl RouteReconciler {
    pub(super) fn new(controller: RouteController) -> Self {
        Self {
            controller,
            member_retries: BTreeMap::new(),
            retry_horizon: tokio::time::Instant::now(),
        }
    }

    /// Mobile worker loop.
    ///
    /// Every input mark (registry, slot, address or DNS configuration) wakes a
    /// round; every other wake only re-evaluates cleanup. Retry deadlines are
    /// local scheduling values: the next attempt is read after the previous
    /// I/O and never from the time this iteration started. The task returns
    /// `Ok` only when shutdown has no record, no actual installation, no
    /// outstanding request and no member cleanup left; shutdown alone never
    /// cancels that cleanup.
    pub(super) async fn run(mut self) -> anyhow::Result<()> {
        // The first round reads the current inputs even without any event.
        self.controller.dirty.mark();

        loop {
            // Register before reading any condition so a notification between
            // the check and the wait cannot be lost.
            let changed = self.controller.changed().clone();
            let notified = changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            let consumed_input = self.controller.dirty.reset();
            let now = tokio::time::Instant::now();
            let retry_horizon = self.retry_horizon;
            let retry_due = self
                .member_retries
                .values()
                .any(|retry| retry.retry_at > retry_horizon && retry.retry_at <= now);

            if consumed_input || retry_due {
                let batch_started = tokio::time::Instant::now();
                let (removed, recovered) = self.reconcile().await;
                self.retry_horizon = batch_started;

                if consumed_input || removed || recovered {
                    self.controller.changed().notify_waiters();
                }
                if self.drained() {
                    return Ok(());
                }
                // In-memory rounds must still hand the executor back.
                tokio::task::yield_now().await;
                continue;
            }

            // A wake without input (for example a compare that only cleared
            // the request mark) still gets its cleanup evaluated.
            let removed = self.remove_finished_instances();
            if removed {
                self.controller.changed().notify_waiters();
            }
            if self.drained() {
                return Ok(());
            }

            let next_retry = self
                .member_retries
                .values()
                .map(|retry| retry.retry_at)
                .filter(|deadline| *deadline > now)
                .min();
            match next_retry {
                Some(deadline) => tokio::select! {
                    _ = &mut notified => {}
                    _ = self.controller.dirty.wait() => {}
                    _ = tokio::time::sleep_until(deadline) => {}
                },
                None => tokio::select! {
                    _ = &mut notified => {}
                    _ = self.controller.dirty.wait() => {}
                },
            }
        }
    }

    fn drained(&self) -> bool {
        let rt = self.controller.runtime.read();
        rt.shutdown
            && rt.instances.is_empty()
            && rt.applied.is_none()
            && self.member_retries.is_empty()
            && rt.pending_install.is_none()
    }

    /// One mobile reconciliation round.
    ///
    /// Local values only: current bindings, complete member targets, this
    /// round's admissions, acknowledgements and cleared registrations. Retry
    /// entries are owned by this task: they carry the failed target, its
    /// backoff and the member handle still needed for a real withdrawal.
    /// Returns whether records were removed (visible cleanup progress) and
    /// whether a scheduled retry recovered.
    async fn reconcile(&mut self) -> (bool, bool) {
        let mut admission_failures: BTreeMap<(Uuid, Uuid), (BTreeSet<IpCidr>, RouteStatus)> =
            BTreeMap::new();
        let mut synced: BTreeMap<(Uuid, Uuid), BTreeSet<IpCidr>> = BTreeMap::new();
        let mut cleared: BTreeSet<(Uuid, Uuid)> = BTreeSet::new();
        let mut recovered = false;

        // 1. Short read of the current bindings and their complete targets.
        let mut related: BTreeMap<(Uuid, Uuid), SharedVirtualNicMember> = BTreeMap::new();
        {
            let rt = self.controller.runtime.read();
            for (run, instance) in &rt.instances {
                let Some(member) = instance.member.clone() else {
                    continue;
                };
                related.insert((*run, member.registration_id()), member);
            }
        }
        for (key, retry) in &self.member_retries {
            related.entry(*key).or_insert_with(|| retry.member.clone());
        }

        // 2. Whole-member admission against this round's complete target.
        // This result decides whether a transient failure may postpone the
        // withdrawal, and supplies the rejection feedback.
        for (key, member) in &related {
            if !Self::is_current_binding(&self.controller, *key) {
                continue;
            }
            let now = tokio::time::Instant::now();
            let target = self.mobile_current_target(*key).unwrap_or_default();
            if member_retry_blocked(&self.member_retries, key, &target, now) {
                continue;
            }
            let status = Self::admit_member(member, &target).await;
            // Recheck after the wait: a rebound registration or a changed
            // target owns the next marked round, not this result.
            if self.mobile_current_target(*key).as_ref() != Some(&target) {
                continue;
            }
            match status {
                Ok(()) => {}
                Err(status @ RouteStatus::Rejected(_)) => {
                    admission_failures.insert(*key, (target, status));
                }
                Err(RouteStatus::Pending {
                    error: Some(error), ..
                }) => {
                    admission_failures.insert(
                        *key,
                        (
                            target.clone(),
                            RouteStatus::Pending {
                                error: Some(error.clone()),
                            },
                        ),
                    );
                    record_member_failure(
                        &mut self.member_retries,
                        *key,
                        member,
                        target,
                        &anyhow::anyhow!("{error}"),
                    );
                }
                // An invalid or replaced binding is already known, not a
                // failed attempt; the stages below still record real
                // withdrawal or confirm the registration gone.
                Err(_) => {}
            }
        }

        // 3. Withdraw prefixes the member holds but its current target no
        // longer contains, before committing the complete target.
        for (key, member) in &related {
            let now = tokio::time::Instant::now();
            if self.transient_admission_unresolved(&admission_failures, *key) {
                continue;
            }
            let final_target = self.mobile_current_target(*key).unwrap_or_default();
            if member_retry_blocked(&self.member_retries, key, &final_target, now) {
                continue;
            }
            let claims = match tokio::time::timeout(ROUTE_IO_TIMEOUT, member.claims()).await {
                Ok(claims) => claims,
                Err(_) => {
                    synced.remove(key);
                    cleared.remove(key);
                    record_member_failure(
                        &mut self.member_retries,
                        *key,
                        member,
                        final_target,
                        &anyhow::anyhow!(
                            "timed out reading claims of member {}",
                            member.member_id()
                        ),
                    );
                    continue;
                }
            };
            let current = claim_prefixes(&claims);
            // The target may move while claims are read; only withdraw what
            // the still-current binding and declarations exclude.
            let target = self.mobile_current_target(*key).unwrap_or_default();
            let stage: BTreeSet<IpCidr> = current.intersection(&target).copied().collect();
            if stage == current {
                // Nothing stale. The full commit below is the acknowledgement.
                continue;
            }
            match sync_member_routes(member, &stage).await {
                Ok(true) => {
                    cleared.remove(key);
                    synced.insert(*key, stage);
                    if self.member_retries.remove(key).is_some() {
                        recovered = true;
                    }
                }
                Ok(false) => {
                    synced.remove(key);
                    cleared.insert(*key);
                    if self.member_retries.remove(key).is_some() {
                        recovered = true;
                    }
                    self.controller.unready(key.0, key.1);
                }
                Err(error) => {
                    synced.remove(key);
                    cleared.remove(key);
                    tracing::warn!(?error, ?key, "failed to withdraw member routes");
                    record_member_failure(
                        &mut self.member_retries,
                        *key,
                        member,
                        final_target,
                        &error,
                    );
                }
            }
        }

        // 3b. Admit the complete targets again after the withdrawals: a
        // conflict caused only by a stale prefix withdrawn above is no longer
        // this member's current rejection.
        for (key, member) in &related {
            if !Self::is_current_binding(&self.controller, *key) {
                continue;
            }
            // Only a rejection can have been caused by a stale prefix that
            // this round's withdrawal just removed.
            if !admission_failures
                .get(key)
                .is_some_and(|(_, status)| matches!(status, RouteStatus::Rejected(_)))
            {
                continue;
            }
            if self.transient_admission_unresolved(&admission_failures, *key) {
                continue;
            }
            let now = tokio::time::Instant::now();
            let target = self.mobile_current_target(*key).unwrap_or_default();
            if member_retry_blocked(&self.member_retries, key, &target, now) {
                continue;
            }
            let status = Self::admit_member(member, &target).await;
            if self.mobile_current_target(*key).as_ref() != Some(&target) {
                continue;
            }
            match status {
                Ok(()) => {
                    admission_failures.remove(key);
                }
                Err(status @ RouteStatus::Rejected(_)) => {
                    admission_failures.insert(*key, (target, status));
                }
                Err(RouteStatus::Pending {
                    error: Some(error), ..
                }) => {
                    admission_failures.insert(
                        *key,
                        (
                            target.clone(),
                            RouteStatus::Pending {
                                error: Some(error.clone()),
                            },
                        ),
                    );
                    record_member_failure(
                        &mut self.member_retries,
                        *key,
                        member,
                        target,
                        &anyhow::anyhow!("{error}"),
                    );
                }
                Err(_) => {}
            }
        }

        // 4. Commit every related member's complete current target. Equal
        // claims are committed again on purpose: only the commit is the
        // acknowledgement. A whole-target rejection is a real input error, so
        // it is reported but not installed and not retried as a transient
        // failure.
        for (key, member) in &related {
            let now = tokio::time::Instant::now();
            if self.transient_admission_unresolved(&admission_failures, *key) {
                continue;
            }
            let final_target = self.mobile_current_target(*key).unwrap_or_default();
            if member_retry_blocked(&self.member_retries, key, &final_target, now) {
                continue;
            }
            let target = self.mobile_current_target(*key).unwrap_or_default();
            if matches!(
                admission_failures.get(key),
                Some((failed, RouteStatus::Rejected(_))) if failed == &target
            ) {
                continue;
            }
            if !self.member_retries.contains_key(key) && synced.get(key) == Some(&target) {
                continue;
            }
            match sync_member_routes(member, &target).await {
                Ok(true) => {
                    cleared.remove(key);
                    synced.insert(*key, target);
                    if self.member_retries.remove(key).is_some() {
                        recovered = true;
                    }
                }
                Ok(false) => {
                    synced.remove(key);
                    cleared.insert(*key);
                    if self.member_retries.remove(key).is_some() {
                        recovered = true;
                    }
                    self.controller.unready(key.0, key.1);
                }
                Err(error) if error.is::<SharedIfConfigConflict>() => {
                    // Another member committed a conflicting target between
                    // admission and this commit; the whole target is rejected,
                    // not a transient failure to retry.
                    synced.remove(key);
                    cleared.remove(key);
                    tracing::warn!(?error, ?key, "rejected member route target");
                    admission_failures.insert(
                        *key,
                        (target, RouteStatus::Rejected(error.to_string().into())),
                    );
                }
                Err(error) => {
                    synced.remove(key);
                    cleared.remove(key);
                    tracing::warn!(?error, ?key, "failed to sync member routes");
                    record_member_failure(
                        &mut self.member_retries,
                        *key,
                        member,
                        final_target,
                        &error,
                    );
                }
            }
        }

        // 5. Feedback reads the current policy and available slots again.
        self.update_statuses(&admission_failures, &synced);

        // 6. A member replaced during the waits still owes withdrawal.
        self.transfer_orphan_members(&related, &synced, &cleared);

        let removed = self.remove_finished_instances();
        (removed, recovered)
    }

    /// Whole-member admission through the existing NIC rule.
    async fn admit_member(
        member: &SharedVirtualNicMember,
        target: &BTreeSet<IpCidr>,
    ) -> Result<(), RouteStatus> {
        let nic = member.shared_nic();
        let guard = match tokio::time::timeout(ROUTE_IO_TIMEOUT, nic.lock()).await {
            Ok(guard) => guard,
            Err(_) => {
                return Err(RouteStatus::Pending {
                    error: Some(
                        format!(
                            "timed out locking shared NIC for member {}",
                            member.member_id()
                        )
                        .into(),
                    ),
                });
            }
        };
        if member.ensure_open().is_err()
            || !guard.is_valid()
            || !guard.is_current_member_registration(member.member_id(), member.registration_id())
        {
            return Err(RouteStatus::Pending { error: None });
        }
        match guard.prepare_managed_routes(member.member_id(), member.registration_id(), target) {
            Ok(_) => Ok(()),
            Err(error) if error.is::<SharedIfConfigConflict>() => {
                Err(RouteStatus::Rejected(error.to_string().into()))
            }
            Err(error) => Err(RouteStatus::Pending {
                error: Some(error.to_string().into()),
            }),
        }
    }

    fn is_current_binding(controller: &RouteController, (run, registration): (Uuid, Uuid)) -> bool {
        let rt = controller.runtime.read();
        rt.instances
            .get(&run)
            .and_then(|instance| instance.member.as_ref())
            .is_some_and(|member| member.registration_id() == registration)
    }

    fn mobile_current_target(&self, (run, registration): (Uuid, Uuid)) -> Option<BTreeSet<IpCidr>> {
        let rt = self.controller.runtime.read();
        mobile_target_locked(&rt, run, registration)
    }

    /// Whether a transient admission failure for this exact registration still
    /// describes a nonempty current target. Committing anything else while it
    /// is unresolved would turn a failed prepare into an unrequested
    /// withdrawal.
    fn transient_admission_unresolved(
        &self,
        admission_failures: &BTreeMap<(Uuid, Uuid), (BTreeSet<IpCidr>, RouteStatus)>,
        key: (Uuid, Uuid),
    ) -> bool {
        matches!(
            admission_failures.get(&key),
            Some((_, RouteStatus::Pending { error: Some(_) }))
        ) && self
            .mobile_current_target(key)
            .is_some_and(|target| !target.is_empty())
    }

    /// Per-route status from this round's real evidence.
    ///
    /// Ready needs all of: a real commit for this registration containing the
    /// prefix, the attached registration of the actual installation matching
    /// the current member, and the recorded member's own projection containing
    /// the prefix. An unrelated member's change never makes this run pending.
    fn update_statuses(
        &self,
        admission_failures: &BTreeMap<(Uuid, Uuid), (BTreeSet<IpCidr>, RouteStatus)>,
        synced: &BTreeMap<(Uuid, Uuid), BTreeSet<IpCidr>>,
    ) {
        let rt = self.controller.runtime.read();
        if rt.shutdown {
            return;
        }
        for (run, instance) in &rt.instances {
            let Some(registry) = instance.registry.upgrade() else {
                continue;
            };
            let manual = instance
                .config
                .as_ref()
                .is_some_and(|store| store.snapshot().services.manual_routes.is_some());
            let current_member = instance.member.as_ref();
            let registration = current_member.map(SharedVirtualNicMember::registration_id);
            let target =
                registration.and_then(|registration| mobile_target_locked(&rt, *run, registration));
            let recorded_prefixes = rt.applied.as_ref().and_then(|snapshot| {
                snapshot
                    .members
                    .iter()
                    .find(|member| member.instance_id == *run)
                    .map(member_prefixes)
            });
            let attached = rt
                .applied
                .as_ref()
                .and_then(|snapshot| snapshot.attached_members.get(run).copied());

            for weak in registry.slots() {
                let Some(slot) = weak.upgrade() else {
                    continue;
                };
                let source = slot.source();
                slot.update_statuses(|declaration| {
                    if source == RouteSource::AutoProxy && manual {
                        return Some(RouteStatus::Suppressed(
                            "manual routes replace auto proxy declarations".into(),
                        ));
                    }
                    let prefix = declaration.destination;
                    let Some(registration) = registration else {
                        return Some(RouteStatus::Pending { error: None });
                    };
                    let Some(target) = target.as_ref() else {
                        return Some(RouteStatus::Pending { error: None });
                    };
                    // A declaration added while this round was awaiting has no
                    // evidence yet.
                    if !target.contains(&prefix) {
                        return Some(RouteStatus::Pending { error: None });
                    }
                    // Only this round's result for exactly the current
                    // complete target and registration may be reported.
                    if let Some((failed_prefixes, status)) =
                        admission_failures.get(&(*run, registration))
                        && failed_prefixes == target
                    {
                        return Some(status.clone());
                    }
                    let retry_error = self
                        .member_retries
                        .get(&(*run, registration))
                        .filter(|retry| retry.target.contains(&prefix))
                        .map(|retry| retry.error.clone());
                    let ready = current_member.is_some_and(|member| member.ensure_open().is_ok())
                        && synced
                            .get(&(*run, registration))
                            .is_some_and(|prefixes| prefixes.contains(&prefix))
                        && attached == Some(registration)
                        && recorded_prefixes
                            .as_ref()
                            .is_some_and(|prefixes| prefixes.contains(&prefix));
                    if ready {
                        Some(RouteStatus::Ready)
                    } else {
                        Some(RouteStatus::Pending { error: retry_error })
                    }
                });
            }
        }
    }

    /// Keep an orphaned member's real cleanup responsibility.
    fn transfer_orphan_members(
        &mut self,
        related: &BTreeMap<(Uuid, Uuid), SharedVirtualNicMember>,
        synced: &BTreeMap<(Uuid, Uuid), BTreeSet<IpCidr>>,
        cleared: &BTreeSet<(Uuid, Uuid)>,
    ) {
        let held: BTreeSet<(Uuid, Uuid)> = {
            let rt = self.controller.runtime.read();
            rt.instances
                .iter()
                .filter_map(|(run, instance)| {
                    instance
                        .member
                        .as_ref()
                        .map(|member| (*run, member.registration_id()))
                })
                .collect()
        };
        let now = tokio::time::Instant::now();
        for (key, member) in related {
            if held.contains(key) || cleared.contains(key) {
                continue;
            }
            if synced.get(key).is_some_and(|prefixes| prefixes.is_empty()) {
                continue;
            }
            if self
                .member_retries
                .get(key)
                .is_some_and(|retry| retry.target.is_empty())
            {
                continue;
            }
            self.member_retries.insert(
                *key,
                MemberRetry {
                    member: member.clone(),
                    target: BTreeSet::new(),
                    retry_at: now,
                    attempts: 0,
                    error: Arc::from("member binding withdrew before its prefixes were cleared"),
                },
            );
        }
    }

    /// Remove instance records whose whole real responsibility is finished.
    ///
    /// Only a released root or shutdown makes a record eligible. The actual
    /// installation must no longer contain the run (including a confirmed
    /// revocation that cleared the whole record), no member of the run may
    /// still owe prefix cleanup, and no whole-domain request may be pending.
    fn remove_finished_instances(&self) -> bool {
        let mut rt = self.controller.runtime.write();
        let shutdown = rt.shutdown;
        let pending = rt.pending_install.is_some();
        let mut finished = Vec::new();
        for (run, instance) in &rt.instances {
            if !shutdown && instance.registry.upgrade().is_some() {
                continue;
            }
            if pending {
                continue;
            }
            if self
                .member_retries
                .keys()
                .any(|(retry_run, _)| retry_run == run)
            {
                continue;
            }
            let installed = rt.applied.as_ref().is_some_and(|snapshot| {
                snapshot
                    .members
                    .iter()
                    .any(|member| member.instance_id == *run)
            });
            if installed {
                continue;
            }
            finished.push(*run);
        }
        let removed = !finished.is_empty();
        for run in finished {
            rt.instances.remove(&run);
        }
        removed
    }
}
/// The full target of one currently bound member, read under the runtime lock.
///
/// It is the distinct destinations of the run's current declarations under the
/// current policy. A released root or shutdown withdraws everything, including
/// manual routes. The recorded member's DNS bootstrap prefix is kept only while
/// the current configuration still asks for Magic DNS.
fn mobile_target_locked(
    rt: &RouteControllerRuntime,
    run: Uuid,
    registration: Uuid,
) -> Option<BTreeSet<IpCidr>> {
    if rt.shutdown {
        return None;
    }
    let instance = rt.instances.get(&run)?;
    if instance.member.as_ref()?.registration_id() != registration {
        return None;
    }
    if instance.registry.upgrade().is_none() {
        return None;
    }
    let (declarations, _slots) = instance.declarations()?;
    let mut prefixes: BTreeSet<IpCidr> = declarations
        .into_iter()
        .map(|declaration| declaration.destination)
        .collect();
    let dns_recorded = rt.applied.as_ref().is_some_and(|snapshot| {
        snapshot
            .members
            .iter()
            .any(|member| member.instance_id == run && member.dns)
    });
    if dns_recorded && mobile_dns_configured(rt, instance) {
        prefixes.insert(magic_dns_prefix());
    }
    Some(prefixes)
}
/// Whether this instance's current configuration really enables Magic DNS.
fn mobile_dns_configured(rt: &RouteControllerRuntime, instance: &InstanceRoutes) -> bool {
    #[cfg(not(feature = "magic-dns"))]
    {
        let _ = (rt, instance);
        false
    }
    #[cfg(feature = "magic-dns")]
    {
        if rt.shutdown || instance.registry.upgrade().is_none() {
            return false;
        }
        let Some(config) = instance.config.as_ref() else {
            return false;
        };
        let snapshot = config.snapshot();
        snapshot.peer.flags.accept_dns && snapshot.peer.runtime.core.routes.ipv4.is_some()
    }
}
/// The existing Magic DNS fake-IP route prefix.
fn magic_dns_prefix() -> IpCidr {
    IpCidr::V4(
        cidr::Ipv4Cidr::new(
            crate::instance::dns_server::MAGIC_DNS_FAKE_IP
                .parse()
                .expect("Magic DNS fake IP is valid"),
            32,
        )
        .expect("Magic DNS fake IP is a /32"),
    )
}
