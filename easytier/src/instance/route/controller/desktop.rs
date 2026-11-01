//! Desktop route execution: planning, OS effects, retries and audit.
//!
//! The desktop reconciler exclusively owns the platform backend. The mobile
//! implementation lives in `super::mobile`; helpers shared by both platforms
//! live in `super::member`.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Weak},
    time::Duration,
};

use cidr::IpCidr;
use easytier_core::host::route::{
    RouteAction, RouteDevice, RouteSlotInner, RouteSource, RouteSpec, RouteStatus,
};
use uuid::Uuid;

use crate::instance::route::{
    AppliedRoute, AppliedRoutes, InterfaceInfo, RouteBackend, RouteEffect, RouteError, RouteKey,
    normalize_route,
};
#[cfg(feature = "tun")]
use crate::instance::shared_virtual_nic::{SharedIfConfigConflict, SharedVirtualNicMember};

#[cfg(feature = "tun")]
use super::member::{
    claim_prefixes, member_retry_blocked, record_member_failure, sync_member_routes,
};
use super::{
    InstanceRoutes, ROUTE_IO_TIMEOUT, RouteController, RouteControllerRuntime, retry_backoff,
};

/// This round's desktop target and the operations the executor still owes.
///
/// It is a local value: targets are rebuilt from the current inputs every
/// round and never replace the applied ledger.
pub(crate) struct ReconcilePlan {
    /// Resolved target per physical route key, with the runs that need it.
    pub(crate) desired: BTreeMap<RouteKey, (RouteSpec<u32>, BTreeSet<Uuid>)>,
    /// Applied rows whose full parameters are no longer required.
    pub(crate) remove: Vec<RouteSpec<u32>>,
    /// Target rows without a confirmed Owned or External effect.
    pub(crate) add: Vec<RouteSpec<u32>>,
    /// Live slot references of this round, paired with the owning run.
    pub(crate) slots: Vec<(Uuid, Weak<RouteSlotInner>)>,
    /// Currently bound members, including instances whose inputs are gone.
    #[cfg(feature = "tun")]
    pub(crate) members: BTreeMap<Uuid, SharedVirtualNicMember>,
}

impl RouteController {
    /// Read the currently applied routes in memory (microsecond read lock, zero system calls).
    pub(super) fn applied_routes(&self) -> AppliedRoutes {
        self.runtime.read().applied.clone()
    }

    /// Record the real interface of the currently bound member.
    ///
    /// Returns `Ok(false)` for a late callback from a registration that is no
    /// longer bound, without touching the binding or any other run. This does
    /// no device query or I/O; the native context supplies the observed info.
    #[cfg(feature = "tun")]
    pub fn ready(
        &self,
        run: Uuid,
        member: &SharedVirtualNicMember,
        info: InterfaceInfo,
    ) -> anyhow::Result<bool> {
        anyhow::ensure!(info.ifindex != 0, "route interface index must be nonzero");

        let changed = {
            let mut rt = self.runtime.write();
            anyhow::ensure!(!rt.shutdown, "route controller is shut down");
            let instances = rt
                .instances
                .get_mut(&run)
                .ok_or_else(|| anyhow::anyhow!("instance {run} has no route inputs"))?;
            anyhow::ensure!(
                instances.registry.upgrade().is_some(),
                "instance {run} route registry is closed"
            );

            let current = match &instances.member {
                Some(current) => current,
                None => return Ok(false),
            };
            if current.registration_id() != member.registration_id() || member.member_id() != run {
                return Ok(false);
            }
            member.ensure_open()?;

            if instances.interface.as_ref() == Some(&info) {
                return Ok(true);
            }
            instances.interface = Some(info);
            true
        };

        if changed {
            self.dirty.mark();
        }
        Ok(true)
    }
}

/// Dedicated desktop background reconciler actor: exclusively owns the
/// RouteBackend (0 locks) and drives OS route reconciliation based on plans
/// from RouteController.
///
/// The mobile flow installs a whole domain through its own snapshot contract
/// and has no system route backend, so it has no instance of this actor.
pub(super) struct RouteReconciler<B> {
    controller: RouteController,
    backend: B,
}

impl<B: RouteBackend> RouteReconciler<B> {
    pub(super) fn new(controller: RouteController, backend: B) -> Self {
        Self {
            controller,
            backend,
        }
    }

    /// Desktop worker loop: fixed audit grid plus retry deadlines and dirty
    /// input changes.
    ///
    /// All scheduling state is local to this task; nothing here is a second
    /// ledger. The loop never cancels a shutdown: it keeps reconciling against
    /// the empty target until no record, actual effect or member cleanup is
    /// left, and only then returns `Ok`. Ordinary operation failures become
    /// retry deadlines; only a real task error is returned.
    pub(super) async fn run(mut self) -> anyhow::Result<()> {
        let mut next_audit = tokio::time::Instant::now() + AUDIT_INTERVAL;
        let mut audit_retry_at: Option<tokio::time::Instant> = None;
        let mut audit_attempt: u32 = 0;
        // Retries are only backoff for an operation that already failed. The
        // deadlines are read after every I/O wait, never from a stale `now`.
        let mut route_retries: BTreeMap<
            RouteKey,
            (RouteSpec<u32>, bool, tokio::time::Instant, u32, Arc<str>),
        > = BTreeMap::new();
        #[cfg(feature = "tun")]
        let mut member_retries: BTreeMap<
            (Uuid, Uuid),
            (
                SharedVirtualNicMember,
                BTreeSet<IpCidr>,
                tokio::time::Instant,
                u32,
                Arc<str>,
            ),
        > = BTreeMap::new();
        // Deadlines at or before this instant have already had their attempt.
        // A retry recorded by the attempt itself always lies in the future, so
        // an entry this round could not act on cannot spin the loop, while an
        // unrelated dirty mark cannot skip an operation that really is due.
        let mut retry_horizon = tokio::time::Instant::now();

        // The first round reads the current inputs even without any event.
        self.controller.dirty.mark();

        loop {
            let now = tokio::time::Instant::now();
            let mut audit_removed = false;

            // 1. The fixed audit grid wins over dirty work. Its deadline is
            // never rebuilt from an input change; its own failure backoff is
            // independent of the route and member retries. A periodic tick and
            // a due retry share one attempt; a tick that falls inside a pending
            // backoff only advances the grid, so nothing is read twice.
            let periodic_due = next_audit <= now;
            let retry_due = audit_retry_at.is_some_and(|retry_at| retry_at <= now);
            let retry_pending = audit_retry_at.is_some_and(|retry_at| retry_at > now);
            if periodic_due {
                // Advance on the original grid, not relative to this moment.
                while next_audit <= now {
                    next_audit += AUDIT_INTERVAL;
                }
            }
            if retry_due || (periodic_due && !retry_pending) {
                match self
                    .audit(
                        &mut route_retries,
                        #[cfg(feature = "tun")]
                        &mut member_retries,
                    )
                    .await
                {
                    Ok(removed) => {
                        audit_attempt = 0;
                        audit_retry_at = None;
                        audit_removed = removed;
                    }
                    Err(error) => {
                        // An incomplete read proves nothing about absence. The
                        // ledger, its effects and the slot statuses stay as
                        // they are, and only the audit itself backs off.
                        audit_attempt = audit_attempt.saturating_add(1);
                        audit_retry_at =
                            Some(tokio::time::Instant::now() + retry_backoff(audit_attempt));
                        tracing::warn!(?error, "route audit failed");
                    }
                }
            }

            // 2. Re-read the current time and every due item after that I/O.
            let now = tokio::time::Instant::now();
            let route_due = route_retries
                .values()
                .any(|(_, _, deadline, ..)| *deadline > retry_horizon && *deadline <= now);
            #[cfg(feature = "tun")]
            let member_due = member_retries
                .values()
                .any(|(_, _, deadline, ..)| *deadline > retry_horizon && *deadline <= now);
            #[cfg(not(feature = "tun"))]
            let member_due = false;

            if self.controller.dirty.peek() || audit_removed || route_due || member_due {
                // Consume the mark only right before reconcile reads the new
                // inputs. A mark that arrives during the round is the next
                // round's input, so it is never reset afterwards.
                let batch_started = tokio::time::Instant::now();
                self.controller.dirty.reset();
                self.reconcile(
                    &mut route_retries,
                    #[cfg(feature = "tun")]
                    &mut member_retries,
                )
                .await?;
                retry_horizon = batch_started;
                // A batch of purely in-memory work must still hand the
                // executor back, even while inputs keep changing.
                tokio::task::yield_now().await;
                continue;
            }

            // 3. Nothing is actionable. Shutdown is not a break: it only ends
            // the task after every accepted record and actual effect is gone,
            // and no member still owes a real prefix withdrawal. Stale route
            // retries without an actual responsibility do not block.
            {
                let rt = self.controller.runtime.read();
                #[cfg(feature = "tun")]
                let members_done = member_retries.is_empty();
                #[cfg(not(feature = "tun"))]
                let members_done = true;
                if rt.shutdown && rt.instances.is_empty() && rt.applied.is_empty() && members_done {
                    return Ok(());
                }
            }

            // 4. Wait for a real event: an input mark, the pending audit retry,
            // the next fixed audit tick, or the nearest retry deadline that has
            // not been attempted yet.
            let mut wait_until = next_audit;
            if let Some(retry_at) = audit_retry_at {
                wait_until = wait_until.min(retry_at);
            }
            for (_, _, deadline, ..) in route_retries.values() {
                if *deadline > now && *deadline < wait_until {
                    wait_until = *deadline;
                }
            }
            #[cfg(feature = "tun")]
            for (_, _, deadline, ..) in member_retries.values() {
                if *deadline > now && *deadline < wait_until {
                    wait_until = *deadline;
                }
            }
            tokio::select! {
                _ = self.controller.dirty.wait() => {}
                _ = tokio::time::sleep_until(wait_until) => {}
            }
        }
    }
}

impl<B: RouteBackend> RouteReconciler<B> {
    /// One desktop reconciliation round.
    ///
    /// The two retry maps belong to the caller's loop. They hold only the
    /// backoff of an operation that already failed and the member handles that
    /// still owe prefix cleanup; no input, target or second ledger is stored.
    /// `Ok` means this round ended, not that every route finished.
    pub(super) async fn reconcile(
        &mut self,
        route_retries: &mut BTreeMap<
            RouteKey,
            (RouteSpec<u32>, bool, tokio::time::Instant, u32, Arc<str>),
        >,
        #[cfg(feature = "tun")] member_retries: &mut BTreeMap<
            (Uuid, Uuid),
            (
                SharedVirtualNicMember,
                BTreeSet<IpCidr>,
                tokio::time::Instant,
                u32,
                Arc<str>,
            ),
        >,
    ) -> anyhow::Result<()> {
        // A. Plan from the current inputs plus the evidence of older failures.
        // The admission record belongs to one planning call: the planner clears
        // it on entry and reports only that call's failed member admissions.
        let mut admission_failures = BTreeMap::new();
        let errors = self.retry_errors(
            route_retries,
            #[cfg(feature = "tun")]
            member_retries,
        );
        #[cfg_attr(not(feature = "tun"), allow(unused_mut))]
        let mut plan = self
            .controller
            .plan_reconciliation(None, &errors, Some(&mut admission_failures))
            .await;
        #[cfg(feature = "tun")]
        self.record_admission_failures(&plan, &admission_failures, member_retries);

        #[cfg_attr(not(feature = "tun"), allow(unused_mut))]
        let mut synced: BTreeMap<(Uuid, Uuid), BTreeSet<IpCidr>> = BTreeMap::new();
        #[cfg_attr(not(feature = "tun"), allow(unused_mut))]
        let mut cleared: BTreeSet<(Uuid, Uuid)> = BTreeSet::new();
        #[cfg(feature = "tun")]
        let mut related = self.related_members(&plan, member_retries);

        // B/C. Member prefixes first: withdraw what is no longer declared so a
        // member blocked by stale claims can be admitted again, then plan once
        // more and commit every related member's complete current target.
        #[cfg(feature = "tun")]
        {
            self.withdraw_member_prefixes(
                &plan,
                &related,
                member_retries,
                &admission_failures,
                &mut synced,
                &mut cleared,
            )
            .await;
            let errors = self.retry_errors(
                route_retries,
                #[cfg(feature = "tun")]
                member_retries,
            );
            plan = self
                .controller
                .plan_reconciliation(None, &errors, Some(&mut admission_failures))
                .await;
            self.record_admission_failures(&plan, &admission_failures, member_retries);
            Self::extend_related_members(&mut related, &plan);
            self.sync_member_prefixes(
                &plan,
                &related,
                member_retries,
                &admission_failures,
                &mut synced,
                &mut cleared,
            )
            .await;
        }

        // D–H. Reconcile every actual row, its owners and the OS effects.
        let (changed, budget_exhausted) = self
            .reconcile_routes(
                &plan,
                route_retries,
                #[cfg(feature = "tun")]
                member_retries,
                &synced,
                &cleared,
            )
            .await;

        // I. Feed this round's real evidence back through the same planner.
        self.prune_route_retries(route_retries, &plan.desired);
        let errors = self.retry_errors(
            route_retries,
            #[cfg(feature = "tun")]
            member_retries,
        );
        let final_plan = self
            .controller
            .plan_reconciliation(Some(&synced), &errors, Some(&mut admission_failures))
            .await;
        #[cfg(feature = "tun")]
        {
            self.record_admission_failures(&final_plan, &admission_failures, member_retries);
            Self::extend_related_members(&mut related, &final_plan);
            self.transfer_orphan_members(&related, member_retries, &synced, &cleared);
        }
        let removed = self.remove_finished_instances(
            &synced,
            &cleared,
            #[cfg(feature = "tun")]
            member_retries,
        );
        if changed || removed {
            self.controller.changed().notify_waiters();
        }
        // A member goal that this round did not confirm and cannot start again
        // is actionable right now. A transient admission failure already has
        // its retry record and wakes at that deadline, and a matching future
        // deadline never reaches here, so neither can spin the loop.
        #[cfg(feature = "tun")]
        let member_actionable = {
            let targets = self.member_targets(&final_plan, &related);
            let now = tokio::time::Instant::now();
            related.keys().any(|key| {
                if cleared.contains(key) {
                    return false;
                }
                let final_target = targets.get(key).cloned().unwrap_or_default();
                let target = self.fresh_member_target(*key, &final_target);
                if synced.get(key) == Some(&target) {
                    // This round's own commit confirmed the whole goal.
                    return false;
                }
                if member_retry_blocked(member_retries, key, &final_target, now) {
                    // The next attempt is already scheduled.
                    return false;
                }
                !self.transient_admission_unresolved(&admission_failures, *key)
            })
        };
        #[cfg(not(feature = "tun"))]
        let member_actionable = false;
        if budget_exhausted
            || member_actionable
            || self.actionable_add(&final_plan, route_retries, &synced)
        {
            // Work this round could not start or finish is actionable right
            // now, for example a member acknowledgement that arrived after
            // this round's plan. A future retry deadline never reaches here,
            // so the loop does not spin, and an input mark produced during
            // this round's I/O is left untouched.
            self.controller.dirty.mark();
        }
        Ok(())
    }

    /// Turn this planning call's transient member admission failures into the
    /// ordinary member retries.
    ///
    /// Only a current binding whose complete declared prefix set is exactly
    /// the set that failed to prepare is a real failed attempt of the current
    /// goal. A rebound registration, a released root or any changed
    /// declaration belongs to the next marked round and must not inherit this
    /// error; an explicit conflict or a known-invalid binding never schedules
    /// a timer here.
    #[cfg(feature = "tun")]
    fn record_admission_failures(
        &self,
        plan: &ReconcilePlan,
        admission_failures: &BTreeMap<(Uuid, Uuid), (BTreeSet<IpCidr>, RouteStatus)>,
        member_retries: &mut BTreeMap<
            (Uuid, Uuid),
            (
                SharedVirtualNicMember,
                BTreeSet<IpCidr>,
                tokio::time::Instant,
                u32,
                Arc<str>,
            ),
        >,
    ) {
        for ((run, registration), (prefixes, status)) in admission_failures {
            let RouteStatus::Pending { error: Some(error) } = status else {
                continue;
            };
            let Some(member) = plan
                .members
                .get(run)
                .filter(|member| member.registration_id() == *registration)
            else {
                continue;
            };
            if self.declared_member_prefixes(*run, *registration).as_ref() != Some(prefixes) {
                continue;
            }
            record_member_failure(
                member_retries,
                (*run, *registration),
                member,
                prefixes.clone(),
                &anyhow::anyhow!("{error}"),
            );
        }
    }

    /// Whether this member's latest admission failed transiently while its
    /// declarations are still nonempty.
    ///
    /// Committing an empty set for such a member would turn a failed prepare
    /// into a withdrawal nobody requested, so both member stages leave its
    /// real claims and its retry alone until a fresh round re-admits it. A
    /// released root, a rebound registration or genuinely empty declarations
    /// need no admission and keep their real cleanup.
    #[cfg(feature = "tun")]
    fn transient_admission_unresolved(
        &self,
        admission_failures: &BTreeMap<(Uuid, Uuid), (BTreeSet<IpCidr>, RouteStatus)>,
        (run, registration): (Uuid, Uuid),
    ) -> bool {
        matches!(
            admission_failures.get(&(run, registration)),
            Some((_, RouteStatus::Pending { error: Some(_) }))
        ) && self
            .declared_member_prefixes(run, registration)
            .is_some_and(|declared| !declared.is_empty())
    }

    /// Whether a desired addition is actionable right now.
    ///
    /// This covers work that only became possible after this round's member
    /// acknowledgements, which the round's plans predate. An addition still
    /// inside its backoff, or one with no owner that can act now, is not
    /// actionable and must not wake the loop.
    fn actionable_add(
        &self,
        plan: &ReconcilePlan,
        route_retries: &BTreeMap<
            RouteKey,
            (RouteSpec<u32>, bool, tokio::time::Instant, u32, Arc<str>),
        >,
        synced: &BTreeMap<(Uuid, Uuid), BTreeSet<IpCidr>>,
    ) -> bool {
        let applied = self.controller.runtime.read().applied.clone();
        let now = tokio::time::Instant::now();
        plan.add.iter().any(|route| {
            let key = RouteKey::of(route);
            if applied.contains_key(&key)
                || route_retry_blocked(route_retries, &key, route, true, now)
            {
                return false;
            }
            let Some((_, planned_owners)) = plan.desired.get(&key) else {
                return false;
            };
            self.current_add_evidence(route, planned_owners, plan, synced)
                .is_some_and(|(owners, _, admissible)| !owners.is_empty() && admissible)
        })
    }

    /// This round's evidence of older failures, keyed by the complete route.
    ///
    /// A retry is only backoff for an operation that already failed; it never
    /// becomes a target or an effect. Member failures reach only the rows that
    /// this registration still carries.
    fn retry_errors(
        &self,
        route_retries: &BTreeMap<
            RouteKey,
            (RouteSpec<u32>, bool, tokio::time::Instant, u32, Arc<str>),
        >,
        #[cfg(feature = "tun")] member_retries: &BTreeMap<
            (Uuid, Uuid),
            (
                SharedVirtualNicMember,
                BTreeSet<IpCidr>,
                tokio::time::Instant,
                u32,
                Arc<str>,
            ),
        >,
    ) -> BTreeMap<RouteSpec<u32>, Arc<str>> {
        let mut errors = BTreeMap::new();
        for (route, _, _, _, error) in route_retries.values() {
            errors.insert(route.clone(), error.clone());
        }
        #[cfg(feature = "tun")]
        self.member_retry_errors(member_retries, &mut errors);
        errors
    }

    #[cfg(feature = "tun")]
    fn member_retry_errors(
        &self,
        member_retries: &BTreeMap<
            (Uuid, Uuid),
            (
                SharedVirtualNicMember,
                BTreeSet<IpCidr>,
                tokio::time::Instant,
                u32,
                Arc<str>,
            ),
        >,
        errors: &mut BTreeMap<RouteSpec<u32>, Arc<str>>,
    ) {
        for ((run, registration), (_, target, _, _, error)) in member_retries {
            if target.is_empty() {
                continue;
            }
            let Some(routes) = self.declared_member_routes(*run, *registration) else {
                continue;
            };
            for route in routes {
                if target.contains(&route.destination) {
                    errors.insert(route, error.clone());
                }
            }
        }
    }

    /// Every member this round may touch, deduplicated by run and registration.
    ///
    /// The set is a local cleanup reference: plan members, members recorded on
    /// actual rows and members still owing prefix withdrawals in the retry map.
    #[cfg(feature = "tun")]
    fn related_members(
        &self,
        plan: &ReconcilePlan,
        member_retries: &BTreeMap<
            (Uuid, Uuid),
            (
                SharedVirtualNicMember,
                BTreeSet<IpCidr>,
                tokio::time::Instant,
                u32,
                Arc<str>,
            ),
        >,
    ) -> BTreeMap<(Uuid, Uuid), SharedVirtualNicMember> {
        let mut related = BTreeMap::new();
        Self::extend_related_members(&mut related, plan);
        {
            let rt = self.controller.runtime.read();
            for row in rt.applied.values() {
                for (run, member) in &row.members {
                    related
                        .entry((*run, member.registration_id()))
                        .or_insert_with(|| member.clone());
                }
            }
        }
        for (key, (member, ..)) in member_retries {
            related.entry(*key).or_insert_with(|| member.clone());
        }
        related
    }

    #[cfg(feature = "tun")]
    fn extend_related_members(
        related: &mut BTreeMap<(Uuid, Uuid), SharedVirtualNicMember>,
        plan: &ReconcilePlan,
    ) {
        for (run, member) in &plan.members {
            related
                .entry((*run, member.registration_id()))
                .or_insert_with(|| member.clone());
        }
    }

    /// The final legal prefix target of every related member.
    ///
    /// The target is fixed by the selected desired rows that pass through this
    /// run's own bound device, so ordinary indexed rows and actions without a
    /// device never reach a member. A route the planner could not admit this
    /// round is not in `desired`, and its declaration is a separate concern:
    /// the retry map, not the member target, is what schedules the next
    /// attempt. A registration that is no longer bound to this run, a released
    /// registry or a shutdown leaves the target empty, which withdraws
    /// everything that registration still holds.
    #[cfg(feature = "tun")]
    fn member_targets(
        &self,
        plan: &ReconcilePlan,
        related: &BTreeMap<(Uuid, Uuid), SharedVirtualNicMember>,
    ) -> BTreeMap<(Uuid, Uuid), BTreeSet<IpCidr>> {
        let bindings = self.current_bindings();
        let mut targets = BTreeMap::new();
        for (run, registration) in related.keys() {
            let dev = match bindings.get(run) {
                Some((current, Some(dev), _)) if current == registration => Some(*dev),
                _ => None,
            };
            let mut prefixes = BTreeSet::new();
            if let Some(dev) = dev {
                for (route, owners) in plan.desired.values() {
                    if owners.contains(run) && unicast_dev(route) == Some(dev) {
                        prefixes.insert(route.destination);
                    }
                }
            }
            targets.insert((*run, *registration), prefixes);
        }
        targets
    }

    /// Withdraw every related member's stale prefixes before the full sync.
    ///
    /// A member whose claims are already a subset of the target has nothing to
    /// withdraw. The stage set is the intersection, but the backoff always
    /// belongs to the member's final target: replacing the target with this
    /// stage set would let the second stage dodge the deadline. A member whose
    /// current admission failed transiently is not read as withdrawn: its
    /// real claims and retry stay until a fresh round admits it.
    #[cfg(feature = "tun")]
    async fn withdraw_member_prefixes(
        &self,
        plan: &ReconcilePlan,
        related: &BTreeMap<(Uuid, Uuid), SharedVirtualNicMember>,
        member_retries: &mut BTreeMap<
            (Uuid, Uuid),
            (
                SharedVirtualNicMember,
                BTreeSet<IpCidr>,
                tokio::time::Instant,
                u32,
                Arc<str>,
            ),
        >,
        admission_failures: &BTreeMap<(Uuid, Uuid), (BTreeSet<IpCidr>, RouteStatus)>,
        synced: &mut BTreeMap<(Uuid, Uuid), BTreeSet<IpCidr>>,
        cleared: &mut BTreeSet<(Uuid, Uuid)>,
    ) {
        let targets = self.member_targets(plan, related);
        let now = tokio::time::Instant::now();
        for (key, member) in related {
            if self.transient_admission_unresolved(admission_failures, *key) {
                continue;
            }
            let final_target = targets.get(key).cloned().unwrap_or_default();
            if member_retry_blocked(member_retries, key, &final_target, now) {
                continue;
            }
            let claims = match tokio::time::timeout(ROUTE_IO_TIMEOUT, member.claims()).await {
                Ok(claims) => claims,
                Err(_) => {
                    let error = anyhow::anyhow!(
                        "timed out reading claims of member {}",
                        member.member_id()
                    );
                    synced.remove(key);
                    cleared.remove(key);
                    record_member_failure(member_retries, *key, member, final_target, &error);
                    continue;
                }
            };
            let current = claim_prefixes(&claims);
            let target = self.fresh_member_target(*key, &final_target);
            let stage: BTreeSet<IpCidr> = current.intersection(&target).copied().collect();
            if stage == current {
                // Nothing stale to withdraw. Committing the same claims is not
                // the confirmation of the member's goal; the full sync owns
                // that at the due final target.
                continue;
            }
            // A real withdrawal: only the commit proves it.
            match sync_member_routes(member, &stage).await {
                Ok(true) => {
                    cleared.remove(key);
                    synced.insert(*key, stage);
                    member_retries.remove(key);
                }
                Ok(false) => {
                    synced.remove(key);
                    cleared.insert(*key);
                    member_retries.remove(key);
                }
                Err(error) => {
                    synced.remove(key);
                    cleared.remove(key);
                    tracing::warn!(?error, ?key, "failed to withdraw member routes");
                    record_member_failure(member_retries, *key, member, final_target, &error);
                }
            }
        }
    }

    /// Commit every related member's complete current target.
    ///
    /// The target of a non-empty commit is rechecked against the declarations
    /// that are current now, so a requirement withdrawn during this round's
    /// waits is not re-added. An acknowledgement records its real prefix set;
    /// a dead registration records only that it is cleared.
    #[cfg(feature = "tun")]
    async fn sync_member_prefixes(
        &self,
        plan: &ReconcilePlan,
        related: &BTreeMap<(Uuid, Uuid), SharedVirtualNicMember>,
        member_retries: &mut BTreeMap<
            (Uuid, Uuid),
            (
                SharedVirtualNicMember,
                BTreeSet<IpCidr>,
                tokio::time::Instant,
                u32,
                Arc<str>,
            ),
        >,
        admission_failures: &BTreeMap<(Uuid, Uuid), (BTreeSet<IpCidr>, RouteStatus)>,
        synced: &mut BTreeMap<(Uuid, Uuid), BTreeSet<IpCidr>>,
        cleared: &mut BTreeSet<(Uuid, Uuid)>,
    ) {
        let targets = self.member_targets(plan, related);
        let now = tokio::time::Instant::now();
        for (key, member) in related {
            if self.transient_admission_unresolved(admission_failures, *key) {
                continue;
            }
            let final_target = targets.get(key).cloned().unwrap_or_default();
            if member_retry_blocked(member_retries, key, &final_target, now) {
                continue;
            }
            let target = self.fresh_member_target(*key, &final_target);
            if synced.get(key) == Some(&target) && !member_retries.contains_key(key) {
                // This round already committed exactly this target for this
                // registration; that commit is the acknowledgement.
                continue;
            }
            match sync_member_routes(member, &target).await {
                Ok(true) => {
                    cleared.remove(key);
                    synced.insert(*key, target);
                    member_retries.remove(key);
                }
                Ok(false) => {
                    synced.remove(key);
                    cleared.insert(*key);
                    member_retries.remove(key);
                }
                Err(error) => {
                    synced.remove(key);
                    cleared.remove(key);
                    tracing::warn!(?error, ?key, "failed to sync member routes");
                    record_member_failure(member_retries, *key, member, final_target, &error);
                }
            }
        }
    }

    /// One member's final target, narrowed to what is declared right now.
    ///
    /// The declared set is only a filter for this operation; the retry map
    /// keeps the final target so a narrower commit cannot reset its backoff.
    #[cfg(feature = "tun")]
    fn fresh_member_target(
        &self,
        (run, registration): (Uuid, Uuid),
        final_target: &BTreeSet<IpCidr>,
    ) -> BTreeSet<IpCidr> {
        if final_target.is_empty() {
            return BTreeSet::new();
        }
        match self.declared_member_prefixes(run, registration) {
            Some(current) => final_target.intersection(&current).copied().collect(),
            None => BTreeSet::new(),
        }
    }

    /// Keep an orphaned member's last cleanup reference.
    ///
    /// A member no longer held by the current binding of its run and by no
    /// actual row still owes a withdrawal unless this round acknowledged an
    /// empty set for it or confirmed the registration gone. It moves into the
    /// caller's retry map with an empty target, keeping an existing empty
    /// target's backoff.
    #[cfg(feature = "tun")]
    fn transfer_orphan_members(
        &self,
        related: &BTreeMap<(Uuid, Uuid), SharedVirtualNicMember>,
        member_retries: &mut BTreeMap<
            (Uuid, Uuid),
            (
                SharedVirtualNicMember,
                BTreeSet<IpCidr>,
                tokio::time::Instant,
                u32,
                Arc<str>,
            ),
        >,
        synced: &BTreeMap<(Uuid, Uuid), BTreeSet<IpCidr>>,
        cleared: &BTreeSet<(Uuid, Uuid)>,
    ) {
        let held = {
            let rt = self.controller.runtime.read();
            let mut held = BTreeSet::new();
            for (run, instance) in &rt.instances {
                if let Some(member) = &instance.member {
                    held.insert((*run, member.registration_id()));
                }
            }
            for row in rt.applied.values() {
                for (run, member) in &row.members {
                    held.insert((*run, member.registration_id()));
                }
            }
            held
        };
        let now = tokio::time::Instant::now();
        for (key, member) in related {
            if held.contains(key) || cleared.contains(key) {
                continue;
            }
            if synced.get(key).is_some_and(|prefixes| prefixes.is_empty()) {
                continue;
            }
            if member_retries
                .get(key)
                .is_some_and(|(_, target, ..)| target.is_empty())
            {
                continue;
            }
            member_retries.insert(
                *key,
                (
                    member.clone(),
                    BTreeSet::new(),
                    now,
                    0,
                    Arc::from("member binding withdrew before its prefixes were cleared"),
                ),
            );
        }
    }

    /// Remove the instance records whose real responsibility is finished.
    ///
    /// Only a released root or a shutdown makes a record eligible. It stays
    /// while any actual row still owns it, while any member withdrawal is
    /// still owed, and until its current member acknowledged an empty set or
    /// its registration is gone. A record with no bound member has no NIC
    /// condition to wait for.
    fn remove_finished_instances(
        &self,
        synced: &BTreeMap<(Uuid, Uuid), BTreeSet<IpCidr>>,
        cleared: &BTreeSet<(Uuid, Uuid)>,
        #[cfg(feature = "tun")] member_retries: &BTreeMap<
            (Uuid, Uuid),
            (
                SharedVirtualNicMember,
                BTreeSet<IpCidr>,
                tokio::time::Instant,
                u32,
                Arc<str>,
            ),
        >,
    ) -> bool {
        #[cfg(not(feature = "tun"))]
        let _ = (synced, cleared);
        let mut rt = self.controller.runtime.write();
        let shutdown = rt.shutdown;
        let mut finished = Vec::new();
        for (run, instance) in &rt.instances {
            if !shutdown && instance.registry.upgrade().is_some() {
                continue;
            }
            if rt.applied.values().any(|row| row.owners.contains(run)) {
                continue;
            }
            #[cfg(feature = "tun")]
            {
                if member_retries.keys().any(|(retry_run, _)| retry_run == run) {
                    continue;
                }
                if let Some(member) = &instance.member {
                    let registration = member.registration_id();
                    let empty_ack = synced
                        .get(&(*run, registration))
                        .is_some_and(|prefixes| prefixes.is_empty());
                    if !empty_ack && !cleared.contains(&(*run, registration)) {
                        continue;
                    }
                }
            }
            finished.push(*run);
        }
        let removed = !finished.is_empty();
        for run in finished {
            rt.instances.remove(&run);
        }
        removed
    }

    /// D–H of one round: owners, confirmed effects and the real OS operations.
    ///
    /// Returns whether the ledger really changed and whether actionable work
    /// was left only because this round's operation budget ran out.
    async fn reconcile_routes(
        &mut self,
        plan: &ReconcilePlan,
        route_retries: &mut BTreeMap<
            RouteKey,
            (RouteSpec<u32>, bool, tokio::time::Instant, u32, Arc<str>),
        >,
        #[cfg(feature = "tun")] member_retries: &mut BTreeMap<
            (Uuid, Uuid),
            (
                SharedVirtualNicMember,
                BTreeSet<IpCidr>,
                tokio::time::Instant,
                u32,
                Arc<str>,
            ),
        >,
        synced: &BTreeMap<(Uuid, Uuid), BTreeSet<IpCidr>>,
        cleared: &BTreeSet<(Uuid, Uuid)>,
    ) -> (bool, bool) {
        let now = tokio::time::Instant::now();
        let applied = self.controller.runtime.read().applied.clone();
        let live = self.live_routes();
        #[cfg(feature = "tun")]
        let bindings = self.current_bindings();
        let mut changed = false;
        let mut budget_exhausted = false;
        let mut budget = ROUTE_OPERATION_BUDGET;

        // D. A row that is still the target keeps its route and effect; only
        // its owners change. An owner whose member prefix is not yet
        // acknowledged away keeps its responsibility, and a rebind never
        // replaces the old member handle before that.
        for (key, row) in &applied {
            let Some((target, desired_owners)) = plan.desired.get(key) else {
                continue;
            };
            if *target != row.route
                || !matches!(row.effect, RouteEffect::Owned | RouteEffect::External)
            {
                continue;
            }
            let declared = live.get(&row.route);
            let mut owners: BTreeSet<Uuid> = desired_owners
                .iter()
                .copied()
                .filter(|run| declared.is_some_and(|runs| runs.contains(run)))
                .collect();
            for old_owner in &row.owners {
                if !owners.contains(old_owner)
                    && !self.row_member_released(row, *old_owner, synced, cleared)
                {
                    owners.insert(*old_owner);
                }
            }
            #[cfg(feature = "tun")]
            let members =
                self.row_members(row, &owners, desired_owners, &bindings, synced, cleared);
            #[cfg(feature = "tun")]
            let members_changed = !Self::same_members(&members, &row.members);
            #[cfg(not(feature = "tun"))]
            let members_changed = false;
            if owners.is_empty() {
                // Every declaration of this row disappeared while member
                // prefixes were synced. Keep the actual row and its owners
                // for the next round, which no longer has it as a target.
                continue;
            }
            if owners == row.owners && !members_changed {
                continue;
            }
            let mut rt = self.controller.runtime.write();
            if let Some(current) = rt.applied.get_mut(key)
                && current.route == row.route
                && matches!(current.effect, RouteEffect::Owned | RouteEffect::External)
            {
                current.owners = owners;
                #[cfg(feature = "tun")]
                {
                    current.members = members;
                }
                changed = true;
            }
        }

        // G. Rows whose earlier operation is still unconfirmed are read at
        // their deadline; only a confirmed absence may retire them.
        let mut confirm: Vec<(RouteKey, RouteSpec<u32>, bool)> = Vec::new();
        for (key, row) in &applied {
            let add = match row.effect {
                RouteEffect::Adding => true,
                RouteEffect::Removing => false,
                _ => continue,
            };
            if !route_retry_blocked(route_retries, key, &row.route, add, now) {
                confirm.push((key.clone(), row.route.clone(), add));
            }
        }

        // F. A desired row without a confirmed effect needs one complete
        // readback before any addition. Any key the actual ledger still holds
        // — Adding and Removing included — is confirmed only, never replaced
        // by a new candidate, and a future deadline is not read at all.
        let mut candidates: Vec<(RouteSpec<u32>, BTreeSet<Uuid>)> = Vec::new();
        for route in &plan.add {
            let key = RouteKey::of(route);
            let Some((target, desired_owners)) = plan.desired.get(&key) else {
                continue;
            };
            if target != route
                || applied.contains_key(&key)
                || route_retry_blocked(route_retries, &key, route, true, now)
            {
                continue;
            }
            // Only an owner that could act now justifies a readback: either an
            // ordinary owner, or one whose managed row this round acknowledged.
            let Some((owners, _, executable)) =
                self.current_add_evidence(route, desired_owners, plan, synced)
            else {
                continue;
            };
            if !executable {
                continue;
            }
            candidates.push((route.clone(), owners));
        }

        let mut read: BTreeSet<RouteSpec<u32>> =
            confirm.iter().map(|(_, route, _)| route.clone()).collect();
        read.extend(candidates.iter().map(|(route, _)| route.clone()));
        let existing = if read.is_empty() {
            Some(BTreeSet::new())
        } else {
            match tokio::time::timeout(ROUTE_IO_TIMEOUT, self.backend.existing(&read)).await {
                Ok(Ok(existing)) => Some(existing),
                Ok(Err(failure)) => {
                    // An incomplete readback proves nothing about absence.
                    let error = anyhow::anyhow!(failure.to_string());
                    record_read_failure(&confirm, &candidates, route_retries, &error);
                    None
                }
                Err(_) => {
                    let error = anyhow::anyhow!("timed out reading existing routes");
                    record_read_failure(&confirm, &candidates, route_retries, &error);
                    None
                }
            }
        };

        // G. Confirmed absence retires an uncertain record; a row that is
        // still there is never promoted, and an uncertain Adding record is
        // never deleted just because its declaration was withdrawn.
        let mut retry_removals: Vec<RouteSpec<u32>> = Vec::new();
        if let Some(existing) = &existing {
            for (key, route, add) in &confirm {
                if !existing.contains(route) {
                    let mut rt = self.controller.runtime.write();
                    let retire = rt.applied.get(key).is_some_and(|row| {
                        row.route == *route
                            && matches!(
                                (row.effect, *add),
                                (RouteEffect::Adding, true) | (RouteEffect::Removing, false)
                            )
                    });
                    if retire {
                        rt.applied.remove(key);
                    }
                    drop(rt);
                    if retire {
                        route_retries.remove(key);
                        changed = true;
                    }
                } else if *add {
                    record_route_failure(
                        route_retries,
                        key.clone(),
                        route,
                        true,
                        Arc::from("route addition is still unconfirmed"),
                    );
                } else {
                    retry_removals.push(route.clone());
                }
            }
        }

        // F. A complete external row satisfies the declaration without any
        // ownership; only a row proven absent may be added, and only with
        // owners that still declare it and admitted member evidence.
        if let Some(existing) = &existing {
            for (route, planned_owners) in candidates {
                // Fresh semantics for this operation: a declaration withdrawn
                // or an instance rebound while an earlier addition awaited must
                // not be acted on.
                let Some((owners, members, executable)) =
                    self.current_add_evidence(&route, &planned_owners, plan, synced)
                else {
                    continue;
                };
                let key = RouteKey::of(&route);
                {
                    let rt = self.controller.runtime.read();
                    if rt.applied.contains_key(&key) {
                        // An older row of this key is still in place or still
                        // unconfirmed; the new row waits for its cleanup.
                        continue;
                    }
                }
                if existing.contains(&route) {
                    let mut rt = self.controller.runtime.write();
                    if !rt.applied.contains_key(&key) {
                        rt.applied.insert(
                            key,
                            AppliedRoute {
                                route,
                                owners,
                                effect: RouteEffect::External,
                                #[cfg(feature = "tun")]
                                members,
                            },
                        );
                        changed = true;
                    }
                    continue;
                }
                #[cfg(not(feature = "tun"))]
                let _ = &members;
                if !executable {
                    // No owner can act this round: every managed owner lacks
                    // this round's acknowledgement, so creating the row now
                    // would bypass admission.
                    continue;
                }
                if route_retry_blocked(route_retries, &key, &route, true, now) {
                    continue;
                }
                if budget == 0 {
                    budget_exhausted = true;
                    break;
                }
                budget -= 1;
                #[cfg(feature = "tun")]
                let result = self
                    .add_route_effect(route.clone(), owners.clone(), members)
                    .await;
                #[cfg(not(feature = "tun"))]
                let result = self.add_route_effect(route.clone(), owners.clone()).await;
                match result {
                    Ok(()) => {
                        route_retries.remove(&key);
                        changed = true;
                    }
                    Err(error) => {
                        // An unknown outcome leaves the Adding record, which is
                        // a real ledger change; a definite failure restores the
                        // empty key and is no progress.
                        if matches!(error, RouteError::Unknown(_)) {
                            changed = true;
                        }
                        record_route_failure(
                            route_retries,
                            key,
                            &route,
                            true,
                            Arc::from(error.to_string()),
                        );
                        tracing::warn!(?error, route = %route.destination, "failed to add route");
                    }
                }
            }
        }

        // G. An external row is only released. An owned row is deleted only
        // after its member prefixes are acknowledged away, and a removing row
        // completes the deletion right it already had. The plan's selected row
        // decides whether the exact applied row is still the target. An owned
        // candidate is only queued here: its removal proof is re-admitted from
        // fresh inputs at execution time, right before the deletion, because an
        // earlier candidate's await may have changed what the row's owners
        // declare.
        let mut removals: Vec<(RouteSpec<u32>, bool)> = retry_removals
            .into_iter()
            .map(|route| (route, false))
            .collect();
        for (key, row) in &applied {
            if plan
                .desired
                .get(key)
                .is_some_and(|(target, _)| *target == row.route)
            {
                continue;
            }
            match row.effect {
                RouteEffect::External => {
                    // Release only while this exact external row is still the
                    // actual effect the snapshot described.
                    let current_external = {
                        let rt = self.controller.runtime.read();
                        rt.applied.get(key).is_some_and(|current| {
                            current.route == row.route && current.effect == RouteEffect::External
                        })
                    };
                    if !current_external
                        || !self
                            .row_may_be_removed(
                                row,
                                route_retries,
                                #[cfg(feature = "tun")]
                                member_retries,
                                synced,
                                cleared,
                            )
                            .await
                    {
                        continue;
                    }
                    let mut rt = self.controller.runtime.write();
                    let release = rt.applied.get(key).is_some_and(|current| {
                        current.route == row.route && current.effect == RouteEffect::External
                    });
                    if release {
                        rt.applied.remove(key);
                        changed = true;
                    }
                }
                RouteEffect::Owned => {
                    // Only queue: the execution loop re-checks this row's
                    // deadline and re-admits the deletion from fresh inputs
                    // immediately before it really deletes the row.
                    removals.push((row.route.clone(), true));
                }
                RouteEffect::Adding | RouteEffect::Removing => {}
            }
        }
        for (route, check_live) in removals {
            let key = RouteKey::of(&route);
            // A restored Owned row's earlier failure and every other failed
            // deletion keep their deadline until it really passes; an
            // unrelated dirty mark cannot shorten it.
            if route_retry_blocked(
                route_retries,
                &key,
                &route,
                false,
                tokio::time::Instant::now(),
            ) {
                continue;
            }
            if check_live {
                // Re-admit this row from fresh inputs now, at execution time:
                // the collection loop only queued it, and an earlier
                // candidate's awaits may have let its owners declare it again.
                let current = {
                    let rt = self.controller.runtime.read();
                    rt.applied
                        .get(&key)
                        .filter(|current| {
                            current.route == route && current.effect == RouteEffect::Owned
                        })
                        .cloned()
                };
                let Some(current) = current else {
                    continue;
                };
                if !self
                    .row_may_be_removed(
                        &current,
                        route_retries,
                        #[cfg(feature = "tun")]
                        member_retries,
                        synced,
                        cleared,
                    )
                    .await
                {
                    continue;
                }
                // No await may separate this fresh result from the deletion:
                // only the same complete row, still Owned in the actual
                // ledger, may be deleted now.
                let owned = {
                    let rt = self.controller.runtime.read();
                    rt.applied.get(&key).is_some_and(|current| {
                        current.route == route && current.effect == RouteEffect::Owned
                    })
                };
                if !owned {
                    continue;
                }
            }
            if budget == 0 {
                budget_exhausted = true;
                break;
            }
            budget -= 1;
            let prior_effect = {
                let rt = self.controller.runtime.read();
                rt.applied
                    .get(&key)
                    .filter(|row| row.route == route)
                    .map(|row| row.effect)
            };
            match self.remove_route_effect(&route).await {
                Ok(()) => {
                    route_retries.remove(&key);
                    changed = true;
                }
                Err(error) => {
                    // A definite failure restores the prior effect and an
                    // unknown one leaves Removing; only a final record that
                    // really differs from the one before the call is progress.
                    let final_effect = {
                        let rt = self.controller.runtime.read();
                        rt.applied
                            .get(&key)
                            .filter(|row| row.route == route)
                            .map(|row| row.effect)
                    };
                    if prior_effect != final_effect {
                        changed = true;
                    }
                    record_route_failure(
                        route_retries,
                        key,
                        &route,
                        false,
                        Arc::from(error.to_string()),
                    );
                    tracing::warn!(?error, route = %route.destination, "failed to remove route");
                }
            }
        }

        (changed, budget_exhausted)
    }

    /// Current member binding and real device of every run.
    #[cfg(feature = "tun")]
    fn current_bindings(&self) -> BTreeMap<Uuid, (Uuid, Option<u32>, SharedVirtualNicMember)> {
        let rt = self.controller.runtime.read();
        let mut bindings = BTreeMap::new();
        for (run, instance) in &rt.instances {
            let Some(member) = &instance.member else {
                continue;
            };
            bindings.insert(
                *run,
                (
                    member.registration_id(),
                    instance.interface.as_ref().map(|info| info.ifindex),
                    member.clone(),
                ),
            );
        }
        bindings
    }

    /// Every live declaration resolved to an installable route, by run.
    ///
    /// This is a fresh read of the current inputs, used only to check that an
    /// owner still declares the exact row before an OS operation. It applies
    /// the same managed-device rule as the planner: an explicit index that now
    /// points at a TUN this run does not own is not this run's declaration.
    fn live_routes(&self) -> BTreeMap<RouteSpec<u32>, BTreeSet<Uuid>> {
        let rt = self.controller.runtime.read();
        let mut routes: BTreeMap<RouteSpec<u32>, BTreeSet<Uuid>> = BTreeMap::new();
        if rt.shutdown {
            return routes;
        }
        #[cfg(feature = "tun")]
        let managed = Self::managed_devices(&rt);
        for (run, instance) in &rt.instances {
            #[cfg(feature = "tun")]
            let own = instance.interface.as_ref().map(|info| info.ifindex);
            for route in Self::resolved_declarations(instance) {
                #[cfg(feature = "tun")]
                if let Some(dev) = unicast_dev(&route)
                    && managed.contains(&dev)
                    && Some(dev) != own
                {
                    // Reaching another run's managed TUN needs that run's own
                    // member admission, so it is not declared here.
                    continue;
                }
                routes.entry(route).or_default().insert(*run);
            }
        }
        routes
    }

    /// Devices owned by a bound TUN or referenced by a managed row.
    #[cfg(feature = "tun")]
    fn managed_devices(rt: &RouteControllerRuntime) -> BTreeSet<u32> {
        let mut managed = BTreeSet::new();
        for instance in rt.instances.values() {
            if let Some(info) = &instance.interface {
                managed.insert(info.ifindex);
            }
        }
        for row in rt.applied.values() {
            if !row.members.is_empty()
                && let Some(dev) = unicast_dev(&row.route)
            {
                managed.insert(dev);
            }
        }
        managed
    }

    /// One instance's declarations resolved against its current device.
    fn resolved_declarations(instance: &InstanceRoutes) -> Vec<RouteSpec<u32>> {
        let Some((declarations, slots)) = instance.declarations() else {
            return Vec::new();
        };
        drop(slots);
        #[cfg(feature = "tun")]
        let interface = instance.interface.as_ref().map(|info| info.ifindex);
        #[cfg(not(feature = "tun"))]
        let interface = None::<u32>;
        declarations
            .into_iter()
            .filter_map(|declaration| declaration.resolve(interface))
            .filter_map(|resolved| normalize_route(resolved).ok())
            .collect()
    }

    /// The owners of one addition under the current semantics, with the
    /// acknowledged member evidence allowed to be recorded for them.
    ///
    /// One short read lock re-reads every fact this admission depends on:
    /// shutdown, each planned owner's complete current declarations under the
    /// current policy, the current managed devices and the current binding.
    /// No snapshot taken earlier in the round can make a withdrawn or rebound
    /// owner act on stale admission. Owners outside this round's plan stay
    /// out. The third value says whether at least one owner can act now: an
    /// ordinary owner, or a managed owner whose current registration this
    /// round acknowledged. A managed owner without that acknowledgement stays
    /// a logical owner and keeps its status pending instead of being dropped
    /// or turned into a recorded member.
    #[cfg(feature = "tun")]
    fn current_add_evidence(
        &self,
        route: &RouteSpec<u32>,
        planned_owners: &BTreeSet<Uuid>,
        plan: &ReconcilePlan,
        synced: &BTreeMap<(Uuid, Uuid), BTreeSet<IpCidr>>,
    ) -> Option<(BTreeSet<Uuid>, BTreeMap<Uuid, SharedVirtualNicMember>, bool)> {
        let rt = self.controller.runtime.read();
        if rt.shutdown {
            return None;
        }
        let managed = Self::managed_devices(&rt);
        let mut owners = BTreeSet::new();
        let mut members = BTreeMap::new();
        let mut executable = false;
        for run in planned_owners {
            let Some(instance) = rt.instances.get(run) else {
                continue;
            };
            if !Self::resolved_declarations(instance).contains(route) {
                continue;
            }
            let dev = instance.interface.as_ref().map(|info| info.ifindex);
            // An action without a device is never managed; only an explicit
            // index that currently belongs to a managed TUN needs admission.
            let managed_dev = unicast_dev(route).filter(|dev| managed.contains(dev));
            let Some(route_dev) = managed_dev else {
                owners.insert(*run);
                executable = true;
                continue;
            };
            // Another run's managed TUN, or an index this run does not
            // currently bind, cannot borrow this instance's member.
            if Some(route_dev) != dev {
                continue;
            }
            let Some(member) = &instance.member else {
                continue;
            };
            let registration = member.registration_id();
            let planned = plan
                .members
                .get(run)
                .map(SharedVirtualNicMember::registration_id);
            if planned != Some(registration) {
                // A rebind or an unplanned registration cannot inherit the
                // old admission.
                continue;
            }
            let acknowledged = synced
                .get(&(*run, registration))
                .is_some_and(|prefixes| prefixes.contains(&route.destination));
            if acknowledged && member.ensure_open().is_ok() {
                members.insert(*run, member.clone());
                executable = true;
            }
            owners.insert(*run);
        }
        if owners.is_empty() {
            return None;
        }
        Some((owners, members, executable))
    }

    #[cfg(not(feature = "tun"))]
    fn current_add_evidence(
        &self,
        route: &RouteSpec<u32>,
        planned_owners: &BTreeSet<Uuid>,
        plan: &ReconcilePlan,
        synced: &BTreeMap<(Uuid, Uuid), BTreeSet<IpCidr>>,
    ) -> Option<(BTreeSet<Uuid>, (), bool)> {
        let _ = (plan, synced);
        let rt = self.controller.runtime.read();
        if rt.shutdown {
            return None;
        }
        let owners: BTreeSet<Uuid> = planned_owners
            .iter()
            .copied()
            .filter(|run| {
                rt.instances
                    .get(run)
                    .is_some_and(|instance| Self::resolved_declarations(instance).contains(route))
            })
            .collect();
        (!owners.is_empty()).then_some((owners, (), true))
    }

    /// The member handles of a still-needed row.
    ///
    /// A recorded handle stays until its prefix is acknowledged away or its
    /// registration is cleared. A new handle is recorded only as this round's
    /// acknowledgement for the current registration, so a rebind never
    /// replaces an old cleanup reference silently.
    #[cfg(feature = "tun")]
    fn row_members(
        &self,
        row: &AppliedRoute,
        owners: &BTreeSet<Uuid>,
        desired_owners: &BTreeSet<Uuid>,
        bindings: &BTreeMap<Uuid, (Uuid, Option<u32>, SharedVirtualNicMember)>,
        synced: &BTreeMap<(Uuid, Uuid), BTreeSet<IpCidr>>,
        cleared: &BTreeSet<(Uuid, Uuid)>,
    ) -> BTreeMap<Uuid, SharedVirtualNicMember> {
        let mut members = BTreeMap::new();
        for run in owners {
            if let Some(old) = row.members.get(run) {
                let same = bindings
                    .get(run)
                    .is_some_and(|(registration, _, _)| *registration == old.registration_id());
                if same
                    || !self.member_responsibility_released(
                        &row.route.destination,
                        *run,
                        old.registration_id(),
                        synced,
                        cleared,
                    )
                {
                    members.insert(*run, old.clone());
                    continue;
                }
            }
            if desired_owners.contains(run)
                && let Some((registration, Some(dev), member)) = bindings.get(run)
                && unicast_dev(&row.route) == Some(*dev)
                && synced
                    .get(&(*run, *registration))
                    .is_some_and(|prefixes| prefixes.contains(&row.route.destination))
            {
                members.insert(*run, member.clone());
            }
        }
        members
    }

    #[cfg(feature = "tun")]
    fn same_members(
        left: &BTreeMap<Uuid, SharedVirtualNicMember>,
        right: &BTreeMap<Uuid, SharedVirtualNicMember>,
    ) -> bool {
        left.len() == right.len()
            && left.iter().all(|(run, member)| {
                right
                    .get(run)
                    .is_some_and(|other| other.registration_id() == member.registration_id())
            })
    }

    /// Whether a row's own member responsibility for this run is finished.
    fn row_member_released(
        &self,
        row: &AppliedRoute,
        run: Uuid,
        synced: &BTreeMap<(Uuid, Uuid), BTreeSet<IpCidr>>,
        cleared: &BTreeSet<(Uuid, Uuid)>,
    ) -> bool {
        #[cfg(feature = "tun")]
        {
            let Some(member) = row.members.get(&run) else {
                return true;
            };
            self.member_responsibility_released(
                &row.route.destination,
                run,
                member.registration_id(),
                synced,
                cleared,
            )
        }
        #[cfg(not(feature = "tun"))]
        {
            let _ = (row, run, synced, cleared);
            true
        }
    }

    /// Whether this actual row may really be removed or released now.
    ///
    /// A raw declaration that still exists proves nothing about ownership: a
    /// member whose whole admission was rejected keeps declaring the row, and
    /// another member may already own the same exclusive key. The same planner
    /// is asked again after the earlier waits, and only a declaration that
    /// this fresh plan still selects as an owner — or a managed one whose
    /// admission is merely pending with an error — keeps the row. Only when no
    /// such owner is left do the old member prefix proofs decide; an
    /// acknowledgement that still carries the destination is acceptable only
    /// when another full row of that same registration now carries it.
    ///
    /// This only plans: it records a transient admission failure in the
    /// caller's retry map, reads no OS state and changes no member claim.
    async fn row_may_be_removed(
        &self,
        row: &AppliedRoute,
        route_retries: &BTreeMap<
            RouteKey,
            (RouteSpec<u32>, bool, tokio::time::Instant, u32, Arc<str>),
        >,
        #[cfg(feature = "tun")] member_retries: &mut BTreeMap<
            (Uuid, Uuid),
            (
                SharedVirtualNicMember,
                BTreeSet<IpCidr>,
                tokio::time::Instant,
                u32,
                Arc<str>,
            ),
        >,
        synced: &BTreeMap<(Uuid, Uuid), BTreeSet<IpCidr>>,
        cleared: &BTreeSet<(Uuid, Uuid)>,
    ) -> bool {
        let errors = self.retry_errors(
            route_retries,
            #[cfg(feature = "tun")]
            member_retries,
        );
        let mut admission_failures = BTreeMap::new();
        let fresh = self
            .controller
            .plan_reconciliation(None, &errors, Some(&mut admission_failures))
            .await;
        #[cfg(feature = "tun")]
        self.record_admission_failures(&fresh, &admission_failures, member_retries);
        #[cfg(not(feature = "tun"))]
        let _ = (&admission_failures, synced, cleared);

        let key = RouteKey::of(&row.route);
        let mut missing = false;
        {
            // One short synchronous read of everything the fresh decision
            // depends on: shutdown, the current root, policy, complete
            // normalized declarations, managed devices and bindings. Nothing
            // is held across an await.
            let rt = self.controller.runtime.read();
            if !rt.shutdown {
                #[cfg(feature = "tun")]
                let managed = Self::managed_devices(&rt);
                for (run, instance) in &rt.instances {
                    let declarations = Self::resolved_declarations(instance);
                    if !declarations.contains(&row.route) {
                        continue;
                    }
                    #[cfg(feature = "tun")]
                    let own_dev = instance.interface.as_ref().map(|info| info.ifindex);
                    #[cfg(feature = "tun")]
                    let managed_dev = unicast_dev(&row.route).filter(|dev| managed.contains(dev));
                    #[cfg(feature = "tun")]
                    if let Some(dev) = managed_dev
                        && Some(dev) != own_dev
                    {
                        // Another run's managed TUN, or an index this run does
                        // not currently bind, is not this run's declaration.
                        continue;
                    }
                    #[cfg(feature = "tun")]
                    let registration = instance
                        .member
                        .as_ref()
                        .map(SharedVirtualNicMember::registration_id);

                    let owner = fresh.desired.get(&key).is_some_and(|(target, owners)| {
                        *target == row.route && owners.contains(run)
                    });
                    if owner {
                        #[cfg(feature = "tun")]
                        if managed_dev.is_some()
                            && fresh
                                .members
                                .get(run)
                                .map(SharedVirtualNicMember::registration_id)
                                != registration
                        {
                            // The plan selected an older binding of this run;
                            // its current declaration is not decided yet.
                            missing = true;
                            continue;
                        }
                        return false;
                    }
                    #[cfg(feature = "tun")]
                    if let Some(dev) = managed_dev {
                        let Some(registration) = registration else {
                            // Without a bound member the planner rejects every
                            // managed declaration, so it owns nothing.
                            continue;
                        };
                        let prefixes: BTreeSet<IpCidr> = declarations
                            .iter()
                            .filter(|route| unicast_dev(route) == Some(dev))
                            .map(|route| route.destination)
                            .collect();
                        match admission_failures.get(&(*run, registration)) {
                            Some((failed, RouteStatus::Pending { error: Some(_) }))
                                if *failed == prefixes =>
                            {
                                // A transient failure of this exact candidate
                                // set cannot prove the row is no longer
                                // needed; its retry is already recorded.
                                return false;
                            }
                            Some((
                                failed,
                                RouteStatus::Rejected(_) | RouteStatus::Pending { error: None },
                            )) if *failed == prefixes => {
                                // A rejected admission or a known invalid
                                // binding is no owner of this row.
                            }
                            _ => missing = true,
                        }
                        continue;
                    }
                    // The fresh plan does not describe this declaration: it
                    // arrived or was rebound while the plan waited. The next
                    // round decides, never this stale evidence.
                    missing = true;
                }
            }

            #[cfg(feature = "tun")]
            if !missing {
                // Every old member's prefix responsibility must be settled.
                for (run, member) in &row.members {
                    let old_registration = member.registration_id();
                    if cleared.contains(&(*run, old_registration)) {
                        continue;
                    }
                    let Some(acknowledged) = synced.get(&(*run, old_registration)) else {
                        // Neither an acknowledgement nor a clear: not proof.
                        return false;
                    };
                    if !acknowledged.contains(&row.route.destination) {
                        continue;
                    }
                    // The acknowledgement still carries this prefix. Only
                    // another selected full row of the same registration,
                    // under the current root, policy and binding, may justify
                    // keeping it.
                    let justified = if rt.shutdown {
                        false
                    } else if let Some(instance) = rt.instances.get(run) {
                        let bound = instance
                            .member
                            .as_ref()
                            .map(SharedVirtualNicMember::registration_id);
                        let planned = fresh
                            .members
                            .get(run)
                            .map(SharedVirtualNicMember::registration_id);
                        if bound != Some(old_registration) || planned != Some(old_registration) {
                            // A released or rebound member cannot borrow the
                            // old registration's acknowledgement.
                            false
                        } else {
                            let dev = instance.interface.as_ref().map(|info| info.ifindex);
                            let declarations = Self::resolved_declarations(instance);
                            fresh.desired.values().any(|(route, owners)| {
                                route != &row.route
                                    && route.destination == row.route.destination
                                    && owners.contains(run)
                                    && unicast_dev(route).is_some()
                                    && unicast_dev(route) == dev
                                    && declarations.contains(route)
                            })
                        }
                    } else {
                        false
                    };
                    if !justified {
                        return false;
                    }
                }
            }
        }
        if missing {
            // The next round must re-plan the declaration this plan predates.
            // This guarantees one fresh round; it is not a retry loop.
            self.controller.dirty.mark();
        }
        !missing
    }

    /// Whether this registration no longer owes the row's prefix.
    ///
    /// A cleared registration is finished. An acknowledgement that excludes
    /// the prefix is too, and so is one that still contains it when another
    /// current declaration of the same member needs that prefix anyway.
    #[cfg(feature = "tun")]
    fn member_responsibility_released(
        &self,
        prefix: &IpCidr,
        run: Uuid,
        registration: Uuid,
        synced: &BTreeMap<(Uuid, Uuid), BTreeSet<IpCidr>>,
        cleared: &BTreeSet<(Uuid, Uuid)>,
    ) -> bool {
        if cleared.contains(&(run, registration)) {
            return true;
        }
        let Some(acknowledged) = synced.get(&(run, registration)) else {
            return false;
        };
        if !acknowledged.contains(prefix) {
            return true;
        }
        self.declared_member_prefixes(run, registration)
            .is_some_and(|prefixes| prefixes.contains(prefix))
    }

    /// Routes this run currently declares through its own bound member device.
    ///
    /// `None` means the registry or the binding is gone, so the member's
    /// current target is empty. Nothing outlives the short read lock.
    #[cfg(feature = "tun")]
    fn declared_member_routes(
        &self,
        run: Uuid,
        registration: Uuid,
    ) -> Option<BTreeSet<RouteSpec<u32>>> {
        let rt = self.controller.runtime.read();
        if rt.shutdown {
            return None;
        }
        let instance = rt.instances.get(&run)?;
        if instance.member.as_ref()?.registration_id() != registration {
            return None;
        }
        let dev = instance.interface.as_ref()?.ifindex;
        Some(
            Self::resolved_declarations(instance)
                .into_iter()
                .filter(|route| unicast_dev(route) == Some(dev))
                .collect(),
        )
    }

    #[cfg(feature = "tun")]
    fn declared_member_prefixes(&self, run: Uuid, registration: Uuid) -> Option<BTreeSet<IpCidr>> {
        self.declared_member_routes(run, registration)
            .map(|routes| routes.into_iter().map(|route| route.destination).collect())
    }

    /// Drop retries that no longer guard any uncertainty or cleanup.
    fn prune_route_retries(
        &self,
        retries: &mut BTreeMap<
            RouteKey,
            (RouteSpec<u32>, bool, tokio::time::Instant, u32, Arc<str>),
        >,
        desired: &BTreeMap<RouteKey, (RouteSpec<u32>, BTreeSet<Uuid>)>,
    ) {
        let applied = self.controller.runtime.read().applied.clone();
        retries.retain(|key, (route, add, _, _, _)| {
            let confirmed = applied.get(key).is_some_and(|row| {
                row.route == *route
                    && matches!(row.effect, RouteEffect::Owned | RouteEffect::External)
            });
            let wanted = desired.get(key).is_some_and(|(target, _)| target == route);
            if *add {
                if confirmed {
                    return false;
                }
                wanted
                    || applied
                        .get(key)
                        .is_some_and(|row| row.route == *route && row.effect == RouteEffect::Adding)
            } else {
                match applied.get(key) {
                    Some(row) if row.route == *route => !(confirmed && wanted),
                    _ => false,
                }
            }
        });
    }

    /// One complete desktop audit of the actual ledger.
    ///
    /// It reads the whole ledger once and asks the backend about every recorded
    /// row in one bounded batch. An incomplete readback proves nothing about
    /// absence: the ledger, its effects and every slot status stay untouched
    /// and the error belongs to the audit's own backoff. The return value is
    /// whether a record was really confirmed missing and removed; that is
    /// actual progress the normal reconcile repairs from the current inputs.
    ///
    /// The audit never re-plans: it only invalidates the declarations this
    /// readback proved missing, so an unrelated member admission cannot turn a
    /// healthy row pending. Every other status is left for the next reconcile.
    pub(crate) async fn audit(
        &mut self,
        route_retries: &mut BTreeMap<
            RouteKey,
            (RouteSpec<u32>, bool, tokio::time::Instant, u32, Arc<str>),
        >,
        #[cfg(feature = "tun")] member_retries: &mut BTreeMap<
            (Uuid, Uuid),
            (
                SharedVirtualNicMember,
                BTreeSet<IpCidr>,
                tokio::time::Instant,
                u32,
                Arc<str>,
            ),
        >,
    ) -> anyhow::Result<bool> {
        // One short lock copies the complete actual rows: full route, effect,
        // owners and member registrations. No lock survives the readback.
        let observed = self.controller.runtime.read().applied.clone();
        if observed.is_empty() {
            return Ok(false);
        }
        let requested: BTreeSet<RouteSpec<u32>> =
            observed.values().map(|row| row.route.clone()).collect();
        let existing =
            match tokio::time::timeout(ROUTE_IO_TIMEOUT, self.backend.existing(&requested)).await {
                Ok(Ok(existing)) => existing,
                // A partial or failed readback is not a missing route.
                Ok(Err(failure)) => return Err(failure.into()),
                Err(_) => return Err(anyhow::anyhow!("timed out reading existing routes")),
            };

        // Only a record that is still exactly what was observed may adopt this
        // readback's absence. A row that appeared, changed effect, gained or
        // lost an owner or changed its member registration meanwhile belongs to
        // the newer facts. A complete, still identity-matching absence clears
        // every effect, Adding and Removing included; a present Adding row does
        // not gain ownership, and a present Removing row keeps its record.
        let mut removed: Vec<(RouteKey, RouteSpec<u32>, RouteEffect)> = Vec::new();
        {
            let mut rt = self.controller.runtime.write();
            for (key, row) in &observed {
                if existing.contains(&row.route) {
                    continue;
                }
                let unchanged = rt.applied.get(key).is_some_and(|current| {
                    let same = current.route == row.route
                        && current.effect == row.effect
                        && current.owners == row.owners;
                    #[cfg(feature = "tun")]
                    let same = same && Self::same_members(&current.members, &row.members);
                    same
                });
                if unchanged {
                    rt.applied.remove(key);
                    removed.push((key.clone(), row.route.clone(), row.effect));
                }
            }
        }
        if removed.is_empty() {
            return Ok(false);
        }

        // The observation and this local map hold the real member handles until
        // the audit ends; the ledger entry was only removed, not its cleanup
        // responsibility.
        #[cfg(feature = "tun")]
        let mut removed_members: BTreeMap<(Uuid, Uuid), SharedVirtualNicMember> = BTreeMap::new();
        let mut missing: BTreeSet<RouteSpec<u32>> = BTreeSet::new();
        for (key, route, effect) in &removed {
            // Only the retry of this exact row and operation is stale: a
            // confirmed absence is real progress for it.
            let stale = |add: bool| match effect {
                RouteEffect::Owned | RouteEffect::External => true,
                RouteEffect::Adding => add,
                RouteEffect::Removing => !add,
            };
            if route_retries
                .get(key)
                .is_some_and(|(failed, add, ..)| failed == route && stale(*add))
            {
                route_retries.remove(key);
            }
            #[cfg(feature = "tun")]
            if let Some(row) = observed.get(key) {
                for (run, member) in &row.members {
                    removed_members
                        .entry((*run, member.registration_id()))
                        .or_insert_with(|| member.clone());
                }
            }
            missing.insert(route.clone());
        }

        // A member no longer held by its run's binding and by no other actual
        // row still owes the prefix withdrawal; keep it in the existing
        // empty-goal retry. An entry that already has an empty goal keeps its
        // own deadline.
        #[cfg(feature = "tun")]
        {
            let empty_synced = BTreeMap::new();
            let empty_cleared = BTreeSet::new();
            self.transfer_orphan_members(
                &removed_members,
                member_retries,
                &empty_synced,
                &empty_cleared,
            );
        }

        // Invalidate only the current declarations this readback proved
        // missing. Everything recomputed here comes from the live runtime: a
        // released root, a rebound device or a withdrawn slot is never
        // described by an older observation, and no slot is prepared or
        // re-planned.
        let errors = self.retry_errors(
            route_retries,
            #[cfg(feature = "tun")]
            member_retries,
        );
        {
            let rt = self.controller.runtime.read();
            if !rt.shutdown {
                for instance in rt.instances.values() {
                    let Some(registry) = instance.registry.upgrade() else {
                        continue;
                    };
                    let manual = instance
                        .config
                        .as_ref()
                        .and_then(|config| config.snapshot().services.manual_routes.clone());
                    #[cfg(feature = "tun")]
                    let tun_ifindex = instance.interface.as_ref().map(|info| info.ifindex);
                    #[cfg(not(feature = "tun"))]
                    let tun_ifindex = None;
                    for weak in registry.slots() {
                        let Some(slot) = weak.upgrade() else {
                            continue;
                        };
                        let source = slot.source();
                        let manual = manual.as_ref();
                        slot.update_statuses(|declaration| {
                            // The current policy decides what this slot
                            // contributes at all.
                            if source == RouteSource::AutoProxy && manual.is_some() {
                                return None;
                            }
                            let resolved = declaration.clone().resolve(tun_ifindex)?;
                            let route = normalize_route(resolved).ok()?;
                            if !missing.contains(&route) {
                                return None;
                            }
                            let confirmed =
                                rt.applied.get(&RouteKey::of(&route)).is_some_and(|row| {
                                    row.route == route
                                        && matches!(
                                            row.effect,
                                            RouteEffect::Owned | RouteEffect::External
                                        )
                                });
                            if confirmed {
                                return None;
                            }
                            Some(RouteStatus::Pending {
                                error: errors.get(&route).cloned(),
                            })
                        });
                    }
                }
            }
        }

        // The normal reconcile repairs these rows from the current inputs.
        self.controller.dirty.mark();
        self.controller.changed().notify_waiters();
        Ok(true)
    }

    /// Perform one real desktop addition and record its actual result.
    ///
    /// The caller has already rechecked, in its last short synchronous step,
    /// the current root, policy, complete declarations and registration. The
    /// owners are nonempty, `members` holds only acknowledged members, and the
    /// caller's local related set keeps the cleanup handles. Nothing awaits
    /// before this operation's record is registered. The confirmed fact is
    /// recorded before returning; Slot feedback, owner removal, a compensating
    /// delete, dirty marking and backoff all belong to later rounds.
    async fn add_route_effect(
        &mut self,
        route: RouteSpec<u32>,
        owners: BTreeSet<Uuid>,
        #[cfg(feature = "tun")] members: BTreeMap<Uuid, SharedVirtualNicMember>,
    ) -> Result<(), RouteError> {
        let key = RouteKey::of(&route);
        // The record precedes the system call: an addition in flight is not a
        // confirmed effect and never replaces an existing actual row.
        {
            let mut rt = self.controller.runtime.write();
            if owners.is_empty() {
                return Err(RouteError::Failed(anyhow::anyhow!(
                    "route {} has no owner",
                    route.destination
                )));
            }
            if rt.applied.contains_key(&key) {
                return Err(RouteError::Failed(anyhow::anyhow!(
                    "route {} already has an applied record",
                    route.destination
                )));
            }
            rt.applied.insert(
                key.clone(),
                AppliedRoute {
                    route: route.clone(),
                    owners: owners.clone(),
                    effect: RouteEffect::Adding,
                    #[cfg(feature = "tun")]
                    members: members.clone(),
                },
            );
        }

        // The call, not the match, owns the borrow of `route`: a match
        // scrutinee keeps its temporaries until the whole match ends.
        let result = tokio::time::timeout(Duration::from_secs(5), self.backend.add(&route)).await;
        match result {
            // The addition really happened: the same key and the same full
            // route become the confirmed fact immediately.
            Ok(Ok(())) => {
                let mut rt = self.controller.runtime.write();
                if let Some(row) = rt.applied.get_mut(&key)
                    && row.route == route
                {
                    row.effect = RouteEffect::Owned;
                }
                Ok(())
            }
            // A definite failure first removes this operation's record and
            // restores the empty ledger. Only an "already exists" failure is
            // probed for a complete external row; other failures are never
            // read back into an External effect.
            Ok(Err(RouteError::Failed(error))) => {
                {
                    let mut rt = self.controller.runtime.write();
                    if rt
                        .applied
                        .get(&key)
                        .is_some_and(|row| row.effect == RouteEffect::Adding && row.route == route)
                    {
                        rt.applied.remove(&key);
                    }
                }

                let already_exists = error.chain().any(|cause| {
                    cause
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|cause| cause.kind() == std::io::ErrorKind::AlreadyExists)
                });
                if !already_exists {
                    return Err(RouteError::Failed(error));
                }

                // A complete matching row may satisfy this declaration; only a
                // complete match becomes External, and nothing is deleted.
                let requested = BTreeSet::from([route.clone()]);
                let existing =
                    tokio::time::timeout(Duration::from_secs(5), self.backend.existing(&requested))
                        .await;
                match existing {
                    Ok(Ok(existing)) if existing.contains(&route) => {
                        self.controller.runtime.write().applied.insert(
                            key,
                            AppliedRoute {
                                route,
                                owners,
                                effect: RouteEffect::External,
                                #[cfg(feature = "tun")]
                                members,
                            },
                        );
                        Ok(())
                    }
                    // A readback error or a partial match keeps the original
                    // definite failure; it is not success.
                    _ => Err(RouteError::Failed(error)),
                }
            }
            // An unknown outcome, including an add timeout, keeps the Adding
            // record: the side effect may have happened, so neither drop the
            // responsibility nor promote it to Owned.
            Ok(Err(RouteError::Unknown(error))) => Err(RouteError::Unknown(error)),
            Err(_) => Err(RouteError::Unknown(anyhow::anyhow!(
                "timed out adding route {}",
                route.destination
            ))),
        }
    }

    /// Perform one real desktop removal and record its actual result.
    ///
    /// The caller has already confirmed that this route must be withdrawn, has
    /// released the member prefixes that are no longer needed and keeps the
    /// related cleanup handles in its local set. Only a full row that matches
    /// this key and route and is already Owned or Removing has delete rights;
    /// an External or Adding row fails without any system operation. The
    /// record becomes Removing before the call. A definite delete, or a
    /// definite failure whose single readback proves the row absent, removes
    /// the record; an unknown outcome keeps Removing. Slot feedback, owner
    /// removal, marking and backoff all belong to later rounds.
    async fn remove_route_effect(&mut self, route: &RouteSpec<u32>) -> Result<(), RouteError> {
        let key = RouteKey::of(route);
        {
            let mut rt = self.controller.runtime.write();
            let Some(row) = rt.applied.get_mut(&key) else {
                return Err(RouteError::Failed(anyhow::anyhow!(
                    "route {} has no applied record",
                    route.destination
                )));
            };
            if row.route != *route {
                return Err(RouteError::Failed(anyhow::anyhow!(
                    "route {} has a different applied record",
                    route.destination
                )));
            }
            match row.effect {
                // Both already hold the delete right; the second call of an
                // earlier unknown removal simply stays in flight.
                RouteEffect::Owned | RouteEffect::Removing => row.effect = RouteEffect::Removing,
                RouteEffect::External | RouteEffect::Adding => {
                    return Err(RouteError::Failed(anyhow::anyhow!(
                        "route {} cannot be removed with effect {:?}",
                        route.destination,
                        row.effect
                    )));
                }
            }
        }

        // The call, not the match, owns the borrow of `route`.
        let result = tokio::time::timeout(Duration::from_secs(5), self.backend.remove(route)).await;
        match result {
            // The row really went away: the record of this exact route is no
            // longer an effect that still exists.
            Ok(Ok(())) => {
                let mut rt = self.controller.runtime.write();
                if rt.applied.get(&key).is_some_and(|row| row.route == *route) {
                    rt.applied.remove(&key);
                }
                Ok(())
            }
            // A definite failure does not prove the row absent. Restore the
            // prior actual record first, then allow exactly one complete
            // readback to confirm the deletion did happen anyway.
            Ok(Err(RouteError::Failed(error))) => {
                {
                    let mut rt = self.controller.runtime.write();
                    if let Some(row) = rt.applied.get_mut(&key)
                        && row.route == *route
                        && row.effect == RouteEffect::Removing
                    {
                        row.effect = RouteEffect::Owned;
                    }
                }

                let requested = BTreeSet::from([route.clone()]);
                let existing =
                    tokio::time::timeout(Duration::from_secs(5), self.backend.existing(&requested))
                        .await;
                match existing {
                    // A complete readback without the row is the only other
                    // evidence that the removal happened.
                    Ok(Ok(existing)) if !existing.contains(route) => {
                        let mut rt = self.controller.runtime.write();
                        if rt.applied.get(&key).is_some_and(|row| row.route == *route) {
                            rt.applied.remove(&key);
                        }
                        Ok(())
                    }
                    // The row is still there, or the readback itself failed:
                    // keep the restored Owned record and the original failure.
                    _ => Err(RouteError::Failed(error)),
                }
            }
            // An unknown outcome, including a removal timeout, keeps the
            // Removing record: the deletion may have happened, so neither the
            // right nor the responsibility is dropped.
            Ok(Err(RouteError::Unknown(error))) => Err(RouteError::Unknown(error)),
            Err(_) => Err(RouteError::Unknown(anyhow::anyhow!(
                "timed out removing route {}",
                route.destination
            ))),
        }
    }
}

impl RouteController {
    /// Rebuild this round's target and feed the current declarations.
    ///
    /// `synced` is this round's local `(run, registration) -> acknowledged
    /// prefixes` set: `None` plans before executing, `Some` feeds back after
    /// execution. `errors` holds this round's local installation failures.
    /// `admission_failures`, when given, is cleared on entry and then receives
    /// only this call's failed member admissions. None of them is stored
    /// anywhere. The target is rebuilt from the current inputs; the applied
    /// ledger is only read for comparison and is never replaced, cleared or
    /// written from here.
    pub(super) async fn plan_reconciliation(
        &self,
        synced: Option<&BTreeMap<(Uuid, Uuid), BTreeSet<IpCidr>>>,
        errors: &BTreeMap<RouteSpec<u32>, Arc<str>>,
        admission_failures: Option<&mut BTreeMap<(Uuid, Uuid), (BTreeSet<IpCidr>, RouteStatus)>>,
    ) -> ReconcilePlan {
        let mut admission_failures = admission_failures;
        if let Some(failures) = admission_failures.as_deref_mut() {
            // The caller's record describes this call only.
            failures.clear();
        }
        // A. Copy the current inputs, slots and, with the TUN feature, members
        // and managed interfaces under one short read lock. No registry or
        // slot strong reference survives it.
        let mut slots = Vec::new();
        #[cfg(feature = "tun")]
        let mut members = BTreeMap::new();
        let mut inputs = Vec::new();
        #[cfg(feature = "tun")]
        let mut managed = BTreeSet::new();
        let applied = {
            let rt = self.runtime.read();
            #[cfg(feature = "tun")]
            {
                for instance in rt.instances.values() {
                    if let Some(info) = &instance.interface {
                        managed.insert(info.ifindex);
                    }
                }
                for row in rt.applied.values() {
                    if !row.members.is_empty()
                        && let Some(dev) = unicast_dev(&row.route)
                    {
                        managed.insert(dev);
                    }
                }
            }
            for (run, instance) in &rt.instances {
                #[cfg(feature = "tun")]
                if let Some(member) = &instance.member {
                    members.insert(*run, member.clone());
                }
                if rt.shutdown {
                    continue;
                }
                let Some((declarations, instance_slots)) = instance.declarations() else {
                    continue;
                };
                for weak in instance_slots {
                    slots.push((*run, weak));
                }
                // Without the TUN feature an instance has no real device, so
                // its `Tun` declarations stay unresolved.
                #[cfg(feature = "tun")]
                let interface = instance.interface.clone();
                #[cfg(not(feature = "tun"))]
                let interface = None::<InterfaceInfo>;
                inputs.push((*run, declarations, interface));
            }
            rt.applied.clone()
        };

        // B/C. Resolve each declaration through this run's real device, then
        // normalize the platform fields. Everything that reaches a managed TUN
        // needs this run's matching member; other routes go straight into the
        // system candidates.
        let mut planned = BTreeMap::<(Uuid, RouteSpec<RouteDevice>), RouteSpec<u32>>::new();
        // Per-member admission outcomes, tied to the resolved contents and the
        // registration that produced them. Parameter and ownership errors are
        // recomputed during feedback; only the whole-member admission needs
        // this round's NIC result.
        #[cfg(feature = "tun")]
        let mut admission_failed =
            BTreeMap::<(Uuid, RouteSpec<RouteDevice>), (RouteSpec<u32>, Uuid, RouteStatus)>::new();
        let mut claims = BTreeMap::<RouteKey, Vec<(RouteSpec<u32>, Uuid)>>::new();
        #[cfg(feature = "tun")]
        let mut through_tun =
            BTreeMap::<Uuid, Vec<(RouteSpec<u32>, RouteSpec<RouteDevice>)>>::new();

        for (run, declarations, interface) in &inputs {
            let tun_ifindex = interface.as_ref().map(|info| info.ifindex);
            for declaration in declarations {
                let Some(resolved) = declaration.clone().resolve(tun_ifindex) else {
                    // `Tun` without a bound device stays pending until the
                    // binding changes.
                    continue;
                };
                let Ok(route) = normalize_route(resolved) else {
                    // A real input error, recomputed during feedback.
                    continue;
                };
                match unicast_dev(&route) {
                    // Only this run's own bound device goes through member
                    // admission. An index into another known managed TUN has no
                    // matching member here, so it is rejected rather than
                    // becoming an ordinary system route; feedback recomputes
                    // that from the same current interface set.
                    #[cfg(feature = "tun")]
                    Some(dev) if managed.contains(&dev) => {
                        if Some(dev) != tun_ifindex {
                            continue;
                        }
                        through_tun
                            .entry(*run)
                            .or_default()
                            .push((route, declaration.clone()));
                    }
                    // Without the TUN feature nothing is managed, and a normal
                    // interface needs no TUN membership either.
                    _ => {
                        planned.insert((*run, declaration.clone()), route.clone());
                        claims
                            .entry(RouteKey::of(&route))
                            .or_default()
                            .push((route, *run));
                    }
                }
            }
        }

        // D. Admit every TUN candidate of a member as one whole, using the
        // current registration and the existing overlap rule. This only plans:
        // nothing is committed and the returned claims are dropped here.
        #[cfg(feature = "tun")]
        for (run, candidates) in &through_tun {
            let prefixes: BTreeSet<IpCidr> = candidates
                .iter()
                .map(|(route, _)| route.destination)
                .collect();
            let member = members.get(run);
            let registration = member.map(SharedVirtualNicMember::registration_id);
            let admission: Result<_, RouteStatus> = match member {
                // Reaching a managed device without this run's own member would
                // bypass admission, so it is an input error.
                None => Err(RouteStatus::Rejected(
                    "route targets a managed tun interface this instance does not own".into(),
                )),
                Some(member) => {
                    let nic = member.shared_nic();
                    // Bounding this wait only settles this member's admission;
                    // the rest of the round still plans, and the retry policy
                    // belongs to the caller's next round.
                    match tokio::time::timeout(Duration::from_secs(5), nic.lock()).await {
                        Err(_) => Err(RouteStatus::Pending {
                            error: Some(
                                format!(
                                    "timed out locking shared NIC for member {}",
                                    member.member_id()
                                )
                                .into(),
                            ),
                        }),
                        Ok(guard) => {
                            // Recheck under the NIC lock: a member may close or
                            // its binding may go stale while this round waits
                            // for it, and neither may prepare. Those facts are
                            // already known invalidations, not failed attempts.
                            if member.ensure_open().is_err()
                                || !guard.is_valid()
                                || !guard.is_current_member_registration(
                                    member.member_id(),
                                    member.registration_id(),
                                )
                            {
                                Err(RouteStatus::Pending { error: None })
                            } else {
                                match guard.prepare_managed_routes(
                                    member.member_id(),
                                    member.registration_id(),
                                    &prefixes,
                                ) {
                                    Ok(claims) => Ok(claims),
                                    // A whole-member overlap is an input error until the
                                    // declarations or the topology change.
                                    Err(error) if error.is::<SharedIfConfigConflict>() => {
                                        Err(RouteStatus::Rejected(error.to_string().into()))
                                    }
                                    // The binding was current, valid and open, so
                                    // this is a real failed prepare the caller may
                                    // retry.
                                    Err(error) => Err(RouteStatus::Pending {
                                        error: Some(error.to_string().into()),
                                    }),
                                }
                            }
                        }
                    }
                }
            };
            match admission {
                Ok(_claims) => {
                    for (route, declaration) in candidates {
                        planned.insert((*run, declaration.clone()), route.clone());
                        claims
                            .entry(RouteKey::of(route))
                            .or_default()
                            .push((route.clone(), *run));
                    }
                }
                Err(status) => {
                    if let Some(registration) = registration {
                        if let Some(failures) = admission_failures.as_deref_mut() {
                            failures.insert((*run, registration), (prefixes, status.clone()));
                        }
                        for (route, declaration) in candidates {
                            admission_failed.insert(
                                (*run, declaration.clone()),
                                (route.clone(), registration, status.clone()),
                            );
                        }
                    }
                }
            }
        }

        // E. One complete row per physical key. The row already installed wins
        // while it is still a candidate; otherwise the first claim in stable
        // run and declaration order does. Different keys coexist, so a metric
        // never acts as a per-prefix selector.
        let mut desired: BTreeMap<RouteKey, (RouteSpec<u32>, BTreeSet<Uuid>)> = BTreeMap::new();
        for (key, mut key_claims) in claims {
            key_claims.sort_by_key(|(_, run)| *run);
            let winner = applied
                .get(&key)
                .map(|row| row.route.clone())
                .filter(|current| key_claims.iter().any(|(route, _)| route == current))
                .or_else(|| key_claims.first().map(|(route, _)| route.clone()));
            let Some(winner) = winner else {
                continue;
            };
            let owners: BTreeSet<Uuid> = key_claims
                .iter()
                .filter(|(route, _)| *route == winner)
                .map(|(_, run)| *run)
                .collect();
            desired.insert(key, (winner, owners));
        }

        // F. Diff the target against the actual ledger. Adding and Removing
        // effects stay unconfirmed, and the ledger itself stays untouched.
        let mut remove = Vec::new();
        let mut add = Vec::new();
        for (key, row) in &applied {
            if desired
                .get(key)
                .is_none_or(|(route, _)| *route != row.route)
            {
                remove.push(row.route.clone());
            }
        }
        for (key, (route, _)) in &desired {
            let confirmed = applied.get(key).is_some_and(|row| {
                row.route == *route
                    && matches!(row.effect, RouteEffect::Owned | RouteEffect::External)
            });
            if !confirmed {
                add.push(route.clone());
            }
        }

        // Feedback. One short synchronous scope re-reads the live runtime:
        // shutdown, the current instance records and their live slots, the
        // current policy and bindings, and the actual ledger. Nothing awaits
        // here, so no registry root or slot handle crosses a suspension point.
        // Each run's temporary root lives only until that run's feedback ends.
        {
            let rt = self.runtime.read();
            if !rt.shutdown {
                // The managed set is recomputed from the current bindings and
                // ledger, not from the copied planning inputs.
                #[cfg(feature = "tun")]
                let mut managed = BTreeSet::new();
                #[cfg(feature = "tun")]
                {
                    for instance in rt.instances.values() {
                        if let Some(info) = &instance.interface {
                            managed.insert(info.ifindex);
                        }
                    }
                    for row in rt.applied.values() {
                        if !row.members.is_empty()
                            && let Some(dev) = unicast_dev(&row.route)
                        {
                            managed.insert(dev);
                        }
                    }
                }

                for (run, instance) in &rt.instances {
                    let Some(registry) = instance.registry.upgrade() else {
                        // The instance withdrew its inputs; no feedback.
                        continue;
                    };
                    let run = *run;
                    // A failed admission describes the whole candidate set it
                    // prepared. If any other managed declaration of this member
                    // changed while it awaited, that failure no longer describes
                    // the current input and the next marked round decides.
                    #[cfg(feature = "tun")]
                    let admission_prefixes = admission_failed
                        .keys()
                        .any(|(failed_run, _)| *failed_run == run)
                        .then(|| {
                            let planned: BTreeSet<IpCidr> = through_tun
                                .get(&run)
                                .into_iter()
                                .flatten()
                                .map(|(route, _)| route.destination)
                                .collect();
                            let current: BTreeSet<IpCidr> = instance
                                .interface
                                .as_ref()
                                .map_or_else(BTreeSet::new, |info| {
                                    let dev = info.ifindex;
                                    let (declarations, slots) =
                                        instance.declarations().unwrap_or_default();
                                    drop(slots);
                                    declarations
                                        .into_iter()
                                        .filter_map(|declaration| declaration.resolve(Some(dev)))
                                        .filter_map(|resolved| normalize_route(resolved).ok())
                                        .filter(|route| unicast_dev(route) == Some(dev))
                                        .map(|route| route.destination)
                                        .collect()
                                });
                            planned == current
                        });
                    for weak in registry.slots() {
                        let Some(slot) = weak.upgrade() else {
                            continue;
                        };
                        let source = slot.source();
                        slot.update_statuses(|declaration| {
                            let manual = instance.config.as_ref().is_some_and(|store| {
                                store.snapshot().services.manual_routes.is_some()
                            });
                            if source == RouteSource::AutoProxy && manual {
                                return Some(RouteStatus::Suppressed(
                                    "manual routes replace auto proxy declarations".into(),
                                ));
                            }

                            // Without the TUN feature an instance has no real
                            // device, so its `Tun` declarations stay pending.
                            #[cfg(feature = "tun")]
                            let tun_ifindex = instance.interface.as_ref().map(|info| info.ifindex);
                            #[cfg(not(feature = "tun"))]
                            let tun_ifindex = None;
                            let Some(resolved) = declaration.clone().resolve(tun_ifindex) else {
                                return Some(pending_status(None, errors));
                            };
                            let route = match normalize_route(resolved) {
                                Ok(route) => route,
                                Err(error) => {
                                    return Some(RouteStatus::Rejected(error.to_string().into()));
                                }
                            };
                            #[cfg(feature = "tun")]
                            let managed_tun =
                                unicast_dev(&route).filter(|dev| managed.contains(dev));
                            #[cfg(feature = "tun")]
                            if let Some(dev) = managed_tun
                                && Some(dev) != tun_ifindex
                            {
                                return Some(RouteStatus::Rejected(
                                    "route targets a managed tun interface this instance does not own"
                                        .into(),
                                ));
                            }

                            #[cfg(feature = "tun")]
                            {
                                // A declaration admitted this round keeps this round's
                                // result. Anything else — including content that changed
                                // while planning, or a rebinding that now resolves through
                                // another device — waits for the next marked round.
                                if let Some((admitted, registration, status)) =
                                    admission_failed.get(&(run, declaration.clone()))
                                {
                                    // The whole candidate set that failed to prepare
                                    // must still be exactly the current one, or this
                                    // result describes an input that no longer exists.
                                    let unchanged_set = admission_prefixes == Some(true);
                                    if *admitted == route
                                        && unchanged_set
                                        && Some(*registration) == instance
                                            .member
                                            .as_ref()
                                            .map(SharedVirtualNicMember::registration_id)
                                    {
                                        return Some(status.clone());
                                    }
                                    return Some(pending_status(Some(&route), errors));
                                }
                                // Admission used this round's member. If the instance
                                // is now bound to another registration, that result
                                // describes an old binding and cannot stand, even
                                // when the declaration itself did not change. An
                                // unrelated change to another run leaves this
                                // registration intact.
                                if managed_tun.is_some()
                                    && members
                                        .get(&run)
                                        .map(SharedVirtualNicMember::registration_id)
                                        != instance
                                            .member
                                            .as_ref()
                                            .map(SharedVirtualNicMember::registration_id)
                                {
                                    return Some(pending_status(Some(&route), errors));
                                }
                            }
                            if planned.get(&(run, declaration.clone())) != Some(&route) {
                                return Some(pending_status(Some(&route), errors));
                            }

                            let key = RouteKey::of(&route);
                            match desired.get(&key) {
                                Some((target, owners)) if *target == route => {
                                    if !owners.contains(&run) {
                                        return Some(pending_status(Some(&route), errors));
                                    }
                                }
                                Some(_) => {
                                    return Some(RouteStatus::Suppressed(
                                        "another declaration takes this route".into(),
                                    ));
                                }
                                None => return Some(pending_status(Some(&route), errors)),
                            }

                            let Some(row) = rt.applied.get(&key) else {
                                return Some(pending_status(Some(&route), errors));
                            };
                            if row.route != route
                                || !matches!(row.effect, RouteEffect::Owned | RouteEffect::External)
                                || !row.owners.contains(&run)
                            {
                                return Some(pending_status(Some(&route), errors));
                            }

                            // A managed declaration also needs this run's member
                            // and, after execution, this round's acknowledgement.
                            #[cfg(feature = "tun")]
                            let status = {
                                let Some(member) =
                                    managed_tun.and_then(|_| instance.member.as_ref())
                                else {
                                    if managed_tun.is_some() {
                                        return Some(pending_status(Some(&route), errors));
                                    }
                                    return Some(RouteStatus::Ready);
                                };
                                if member.ensure_open().is_err()
                                    || row
                                        .members
                                        .get(&run)
                                        .map(SharedVirtualNicMember::registration_id)
                                        != Some(member.registration_id())
                                {
                                    return Some(pending_status(Some(&route), errors));
                                }

                                match synced {
                                    // Planning alone must not turn an old confirmation into
                                    // pending; the post-execution round reports the effect.
                                    None => None,
                                    Some(synced) => {
                                        let acknowledged = synced
                                            .get(&(run, member.registration_id()))
                                            .is_some_and(|prefixes| {
                                                prefixes.contains(&route.destination)
                                            });
                                        if acknowledged {
                                            Some(RouteStatus::Ready)
                                        } else {
                                            Some(pending_status(Some(&route), errors))
                                        }
                                    }
                                }
                            };
                            // Without the TUN feature no declaration reaches a
                            // managed device, so an installed row that is the
                            // desired target and owned by this run is ready.
                            #[cfg(not(feature = "tun"))]
                            let status = {
                                let _ = synced;
                                Some(RouteStatus::Ready)
                            };
                            status
                        });
                    }
                }
            }
        }

        ReconcilePlan {
            desired,
            remove,
            add,
            slots,
            #[cfg(feature = "tun")]
            members,
        }
    }
}
/// The fixed desktop audit grid. Input changes never restart it.
const AUDIT_INTERVAL: Duration = Duration::from_secs(60);

/// At most this many route additions and deletions per round.
const ROUTE_OPERATION_BUDGET: u32 = 64;

/// Whether this exact operation still has to wait out an earlier failure.
///
/// A different complete route or the other operation is a real change and is
/// allowed to proceed; an unrelated dirty mark cannot shorten the wait.
fn route_retry_blocked(
    retries: &BTreeMap<RouteKey, (RouteSpec<u32>, bool, tokio::time::Instant, u32, Arc<str>)>,
    key: &RouteKey,
    route: &RouteSpec<u32>,
    add: bool,
    now: tokio::time::Instant,
) -> bool {
    retries
        .get(key)
        .is_some_and(|(failed, failed_add, deadline, ..)| {
            failed == route && *failed_add == add && *deadline > now
        })
}
/// Record (or extend) the backoff of one failed route operation.
fn record_route_failure(
    retries: &mut BTreeMap<RouteKey, (RouteSpec<u32>, bool, tokio::time::Instant, u32, Arc<str>)>,
    key: RouteKey,
    route: &RouteSpec<u32>,
    add: bool,
    error: Arc<str>,
) {
    let now = tokio::time::Instant::now();
    match retries.get_mut(&key) {
        Some((failed, failed_add, deadline, attempt, failed_error))
            if failed == route && *failed_add == add =>
        {
            // A repeated readback failure of an operation that has not been
            // retried keeps its original deadline.
            if *deadline <= now {
                *attempt = attempt.saturating_add(1);
                *deadline = now + retry_backoff(*attempt);
            }
            *failed_error = error;
        }
        _ => {
            retries.insert(key, (route.clone(), add, now + retry_backoff(1), 1, error));
        }
    }
}
/// A failed round readback: neither absence nor a confirmed effect.
fn record_read_failure(
    confirm: &[(RouteKey, RouteSpec<u32>, bool)],
    candidates: &[(RouteSpec<u32>, BTreeSet<Uuid>)],
    retries: &mut BTreeMap<RouteKey, (RouteSpec<u32>, bool, tokio::time::Instant, u32, Arc<str>)>,
    error: &anyhow::Error,
) {
    let error: Arc<str> = Arc::from(error.to_string());
    for (key, route, add) in confirm {
        record_route_failure(retries, key.clone(), route, *add, error.clone());
    }
    for (route, _) in candidates {
        record_route_failure(retries, RouteKey::of(route), route, true, error.clone());
    }
}
/// The interface index of a unicast route, if it has one.
fn unicast_dev(route: &RouteSpec<u32>) -> Option<u32> {
    match &route.action {
        RouteAction::Unicast { dev, .. } => Some(*dev),
        _ => None,
    }
}
/// Pending feedback, carrying this round's error for the same complete row.
fn pending_status(
    route: Option<&RouteSpec<u32>>,
    errors: &BTreeMap<RouteSpec<u32>, Arc<str>>,
) -> RouteStatus {
    RouteStatus::Pending {
        error: route.and_then(|route| errors.get(route).cloned()),
    }
}
