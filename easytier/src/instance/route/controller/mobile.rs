//! Mobile local reconciliation: whole-domain records, member prefixes and
//! per-route feedback.
//!
//! The external VPN owner performs the only actual installation. This module
//! keeps the shared NIC member claims in line with the current declarations,
//! reports per-route status from the real installation evidence, and waits for
//! real cleanup before records are removed.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Weak},
};

use cidr::IpCidr;
use easytier_core::host::route::{RouteSource, RouteStatus};
use uuid::Uuid;

use crate::instance::{
    route::mobile::{
        MobilePlan, MobileTunConfig, MobileTunMember, MobileWithdraw, claims_from_facts,
        filter_scope, select_and_project,
    },
    shared_virtual_nic::{SharedIfConfigClaims, SharedIfConfigConflict, SharedVirtualNicMember},
};

use super::member::{MemberRetry, member_retry_blocked, record_member_failure, sync_member_routes};
use super::{
    InstanceRoutes, ROUTE_IO_TIMEOUT, RouteController, RouteControllerRuntime, retry_backoff,
};

/// The authority values the mobile policy reads for one live instance.
///
/// This is a per-call observation, not a cache: `instance_id` is the
/// configuration identity and `run` is the runtime key, and both addresses are
/// read from `GlobalCtx` at sampling time.
pub(super) struct MobileRouteInputs {
    pub(super) instance_id: Uuid,
    pub(super) run: Uuid,
    pub(super) ipv4: Option<cidr::Ipv4Inet>,
    pub(super) ipv6: Option<cidr::Ipv6Inet>,
    pub(super) public_address: Option<cidr::Ipv6Inet>,
}

/// One live instance sampled for a policy pass.
struct SampledMobileMember {
    instance_id: Uuid,
    run: Uuid,
    member: Option<SharedVirtualNicMember>,
    claims: SharedIfConfigClaims,
    dns: bool,
}

impl SampledMobileMember {
    fn into_member(self, current_claims: Option<SharedIfConfigClaims>) -> MobileTunMember {
        MobileTunMember::new(
            self.instance_id,
            self.run,
            self.claims,
            current_claims,
            self.dns,
        )
    }
}

/// One observation of the live domain and the host's scope.
struct MobileSample {
    scope: Option<BTreeSet<Uuid>>,
    members: Vec<SampledMobileMember>,
}

/// Local mobile attachment evidence, keyed by run and registration.
///
/// The value is the prefix set the execution path confirmed at attachment time.
/// It owns no FD, system VPN, Registry or NativeRuntime.
pub(super) type MobileInstalledRoutes = BTreeMap<(Uuid, Uuid), BTreeSet<IpCidr>>;

impl RouteController {
    /// Record one member's real local attachment evidence.
    ///
    /// Only the run's current registration and an open member may contribute.
    /// Root release and shutdown do not erase a real I/O fact, but a record
    /// that has already been removed is never recreated. A repeated report is
    /// accepted without marking or notifying again.
    pub fn record_mobile_ready(
        &self,
        run: Uuid,
        member: &SharedVirtualNicMember,
        installed_prefixes: BTreeSet<IpCidr>,
    ) -> bool {
        if member.member_id() != run || member.ensure_open().is_err() {
            return false;
        }
        let changed = {
            let mut rt = self.runtime.write();
            let Some(instance) = rt.instances.get(&run) else {
                return false;
            };
            if instance
                .member
                .as_ref()
                .map(SharedVirtualNicMember::registration_id)
                != Some(member.registration_id())
            {
                return false;
            }
            let key = (run, member.registration_id());
            if rt.installed_routes.get(&key) == Some(&installed_prefixes) {
                false
            } else {
                rt.installed_routes.insert(key, installed_prefixes);
                true
            }
        };
        if changed {
            self.dirty.mark();
            self.changed.notify_waiters();
        }
        true
    }

    /// The local attachment evidence of this exact run/registration.
    #[cfg(test)]
    pub(super) fn mobile_installed_prefixes(
        &self,
        run: Uuid,
        registration: Uuid,
    ) -> Option<BTreeSet<IpCidr>> {
        self.runtime
            .read()
            .installed_routes
            .get(&(run, registration))
            .cloned()
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

    /// The live mobile authority inputs of one instance.
    ///
    /// The addresses are read from the bound `GlobalCtx` on every call; the
    /// directory never stores a second address value. A released registry root
    /// or a shut-down controller is an input withdrawal even while the context
    /// is alive, and no temporary root survives this read.
    pub(super) fn mobile_inputs(&self, run: Uuid) -> anyhow::Result<Option<MobileRouteInputs>> {
        let (global, public_address) = {
            let rt = self.runtime.read();
            if rt.shutdown {
                return Ok(None);
            }
            let Some(instance) = rt.instances.get(&run) else {
                return Ok(None);
            };
            if instance.registry.upgrade().is_none() {
                return Ok(None);
            }
            let Some(global) = instance.global.as_ref().and_then(Weak::upgrade) else {
                return Ok(None);
            };
            let Some(public_address) = instance.public_address.as_ref() else {
                return Ok(None);
            };
            (global, public_address.clone())
        };
        let public_address = *public_address.lock();
        Ok(Some(MobileRouteInputs {
            instance_id: global.get_id(),
            run: global.key(),
            ipv4: global.get_ipv4(),
            ipv6: global.get_ipv6(),
            public_address,
        }))
    }

    /// Read the current bound member's claims as this round's selection hint.
    ///
    /// Only the runtime lock's short section copies the member handle; the
    /// claim read is the existing NIC lock wait and no controller lock is held
    /// across it. A registration that changed while waiting discards the hint
    /// instead of returning another binding's claims. A real read failure is
    /// reported, never turned into an empty input.
    pub(crate) async fn mobile_current_claims(
        &self,
        run: Uuid,
    ) -> anyhow::Result<Option<SharedIfConfigClaims>> {
        let member = {
            let rt = self.runtime.read();
            if rt.shutdown {
                return Ok(None);
            }
            let Some(instance) = rt.instances.get(&run) else {
                return Ok(None);
            };
            if instance.registry.upgrade().is_none() {
                return Ok(None);
            }
            let Some(member) = instance.member.as_ref() else {
                return Ok(None);
            };
            member.clone()
        };
        if member.ensure_open().is_err() {
            // A closed binding has no current claims to offer as a hint.
            return Ok(None);
        }
        let claims = tokio::time::timeout(ROUTE_IO_TIMEOUT, member.claims())
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "timed out reading current claims of member {}",
                    member.member_id()
                )
            })?;
        let current = {
            let rt = self.runtime.read();
            if rt.shutdown {
                return Ok(None);
            }
            let Some(instance) = rt.instances.get(&run) else {
                return Ok(None);
            };
            if instance.registry.upgrade().is_none() {
                return Ok(None);
            }
            instance
                .member
                .as_ref()
                .map(SharedVirtualNicMember::registration_id)
        };
        if current == Some(member.registration_id()) {
            Ok(Some(claims))
        } else {
            // The binding or its root changed while waiting: the old hint is
            // not evidence for the current registration.
            Ok(None)
        }
    }

    /// Accept the host's participation range as a route-domain input.
    ///
    /// The range is keyed by configured instance id. `None` means every live
    /// instance of this domain; an empty set is an explicit empty range. Only
    /// a real value change marks the shared dirty flag; reading the complete
    /// result never rewrites the range.
    pub(crate) fn set_mobile_scope(&self, scope: Option<BTreeSet<Uuid>>) -> anyhow::Result<()> {
        let changed = {
            let mut rt = self.runtime.write();
            if rt.mobile_scope == scope {
                false
            } else {
                rt.mobile_scope = scope;
                true
            }
        };
        if changed {
            self.dirty.mark();
        }
        Ok(())
    }

    /// Read the complete exported table through the one policy entry.
    ///
    /// This is a read: it neither modifies the accepted range nor any NIC.
    pub(crate) async fn mobile_config(&self) -> anyhow::Result<MobileTunConfig> {
        Ok(self.build_mobile_plan().await?.config)
    }

    /// Validate the host's snapshot and return the exact execution plan.
    ///
    /// The same private policy entry produces the complete result; a stale
    /// marker is rejected before any NIC work. Only the crate-internal
    /// execution adapter receives the accepted member data and withdrawals.
    pub(crate) async fn prepare_mobile_attach(
        &self,
        snapshot_id: Uuid,
    ) -> anyhow::Result<MobilePlan> {
        let plan = self.build_mobile_plan().await?;
        anyhow::ensure!(
            plan.config.snapshot_id == snapshot_id,
            "mobile TUN configuration changed; query and install a new snapshot before attaching"
        );
        Ok(plan)
    }

    /// The only complete mobile policy pass.
    ///
    /// Facts are sampled twice: the first pass supplies the current member
    /// handles used for bounded claims hints, and the second pass is the actual
    /// plan input. A registration that changed while waiting drops its hint;
    /// the complete target and admission never come from a hint. Config,
    /// prepare and the background local reconciler all use this one entry.
    async fn build_mobile_plan(&self) -> anyhow::Result<MobilePlan> {
        let before = self.sample_mobile_members();
        let in_scope = |member: &SampledMobileMember| {
            before
                .scope
                .as_ref()
                .is_none_or(|scope| scope.contains(&member.instance_id))
        };
        let mut hints = BTreeMap::new();
        for sampled in &before.members {
            if !in_scope(sampled) {
                continue;
            }
            let Some(member) = &sampled.member else {
                continue;
            };
            if let Some(claims) = self.mobile_current_claims(sampled.run).await? {
                hints.insert((sampled.run, member.registration_id()), claims);
            }
        }

        // Re-read root, configuration, addresses, declarations and bindings
        // after every await. Only a hint whose registration is still current
        // reaches the policy pass.
        let after = self.sample_mobile_members();
        let members = after
            .members
            .into_iter()
            .map(|sampled| {
                let current = sampled.member.as_ref().and_then(|member| {
                    hints.get(&(sampled.run, member.registration_id())).cloned()
                });
                sampled.into_member(current)
            })
            .collect();
        let (members, rejected) = filter_scope(members, after.scope.as_ref());
        let (members, config) = select_and_project(members, rejected);
        let accepted_runs = members.iter().map(|member| member.run).collect();
        let withdraw = self.mobile_withdrawals(&accepted_runs);
        Ok(MobilePlan {
            config,
            members,
            withdraw,
        })
    }

    /// One observation of every live instance's current mobile facts.
    ///
    /// The runtime lock only copies handles and values. The shared public
    /// address is read after it is released, so the NIC/address locks are
    /// never nested inside the controller lock.
    fn sample_mobile_members(&self) -> MobileSample {
        let rt = self.runtime.read();
        let scope = rt.mobile_scope.clone();
        if rt.shutdown {
            return MobileSample {
                scope,
                members: Vec::new(),
            };
        }
        let mut sampled = Vec::new();
        for (run, instance) in &rt.instances {
            if instance.registry.upgrade().is_none() {
                continue;
            }
            let Some(global) = instance.global.as_ref().and_then(Weak::upgrade) else {
                continue;
            };
            let Some(public_address) = instance.public_address.clone() else {
                continue;
            };
            let Some((declarations, _slots)) = instance.declarations() else {
                continue;
            };
            let ipv4 = global.get_ipv4();
            let ipv6 = global.get_ipv6();
            let dns = mobile_dns_configured(&rt, instance) && ipv4.is_some();
            sampled.push((
                SampledMobileMember {
                    instance_id: global.get_id(),
                    run: *run,
                    member: instance.member.clone(),
                    claims: SharedIfConfigClaims::default(),
                    dns,
                },
                ipv4,
                ipv6,
                public_address,
                declarations
                    .into_iter()
                    .map(|declaration| declaration.destination)
                    .collect::<BTreeSet<_>>(),
            ));
        }
        drop(rt);
        let members = sampled
            .into_iter()
            .map(|(mut member, ipv4, ipv6, public_address, declarations)| {
                let public_address = *public_address.lock();
                member.claims = claims_from_facts(ipv4, ipv6, public_address, declarations);
                member
            })
            .collect();
        MobileSample { scope, members }
    }

    /// Every currently bound member that the accepted result no longer uses.
    fn mobile_withdrawals(&self, accepted_runs: &BTreeSet<Uuid>) -> Vec<MobileWithdraw> {
        let rt = self.runtime.read();
        let mut withdraw = Vec::new();
        for (run, instance) in &rt.instances {
            let Some(member) = instance.member.as_ref() else {
                continue;
            };
            if accepted_runs.contains(run) {
                continue;
            }
            withdraw.push(MobileWithdraw {
                run: *run,
                registration: member.registration_id(),
                member: member.clone(),
            });
        }
        withdraw
    }
}

/// One failed whole-plan build and its local backoff.
struct PlanRetry {
    retry_at: tokio::time::Instant,
    attempts: u32,
}

/// Mobile background reconciler: local member routes, local evidence and
/// per-route feedback.
///
/// It owns no system route backend and never creates the external VPN. Every
/// round takes its complete targets from the same policy entry used by config
/// export and attach preparation; this actor only performs local NIC route
/// synchronization and reports feedback from real ACKs and local evidence.
pub(super) struct RouteReconciler {
    controller: RouteController,
    /// Only the backoff of a member synchronization that already failed; the
    /// member handle is kept until its real withdrawal finishes.
    pub(super) member_retries: BTreeMap<(Uuid, Uuid), MemberRetry>,
    /// The complete table could not be read because a claims hint timed out.
    /// This is a local retry of the policy entry, not an install request.
    plan_retry: Option<PlanRetry>,
    /// Deadlines at or before this instant have already had their attempt.
    retry_horizon: tokio::time::Instant,
}

impl RouteReconciler {
    pub(super) fn new(controller: RouteController) -> Self {
        Self {
            controller,
            member_retries: BTreeMap::new(),
            plan_retry: None,
            retry_horizon: tokio::time::Instant::now(),
        }
    }

    /// Mobile worker loop.
    ///
    /// Every input mark (registry, slot, address or DNS configuration) wakes a
    /// round; every other wake only re-evaluates local cleanup. Retry deadlines
    /// are local scheduling values: the next attempt is read after the previous
    /// I/O and never from the time this iteration started. The task returns
    /// `Ok` only when shutdown has no instance record, no local attachment
    /// evidence, no member cleanup and no local retry left. It never waits for
    /// the host's system VPN, an external request or a historical snapshot.
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
            let retry_due =
                self.member_retries
                    .values()
                    .any(|retry| retry.retry_at > retry_horizon && retry.retry_at <= now)
                    || self.plan_retry.as_ref().is_some_and(|retry| {
                        retry.retry_at > retry_horizon && retry.retry_at <= now
                    });

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

            // A wake without input still gets local cleanup evaluated. Without
            // a fresh policy pass no bound member can prove an empty target, so
            // only records with no current member can be removed here.
            let removed = self.remove_finished_instances(&BTreeMap::new(), &BTreeSet::new());
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
                .chain(self.plan_retry.as_ref().map(|retry| retry.retry_at))
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
            && rt.installed_routes.is_empty()
            && self.member_retries.is_empty()
            && self.plan_retry.is_none()
    }

    /// One mobile reconciliation round.
    ///
    /// Local values only: the complete policy plan, this round's admissions,
    /// ACKs and cleared registrations. Retry entries are owned by this task:
    /// they carry the failed target, its backoff and the member handle still
    /// needed for a real local withdrawal. Returns whether records or local
    /// evidence were removed (visible cleanup progress) and whether a
    /// scheduled retry recovered.
    pub(super) async fn reconcile(&mut self) -> (bool, bool) {
        let mut recovered = false;
        let plan = match self.controller.build_mobile_plan().await {
            Ok(plan) => {
                if self.plan_retry.take().is_some() {
                    recovered = true;
                }
                plan
            }
            Err(error) => {
                tracing::warn!(?error, "failed to read the complete mobile route plan");
                self.record_plan_failure();
                return (false, recovered);
            }
        };

        // Controller decisions: which members were accepted and why a live
        // member was not. Feedback uses these instead of deciding per instance.
        let accepted: BTreeMap<Uuid, BTreeSet<IpCidr>> = plan
            .members
            .iter()
            .map(|member| (member.run, member.installed_prefixes.clone()))
            .collect();
        let rejected_by_instance: BTreeMap<Uuid, Arc<str>> = plan
            .config
            .rejected
            .iter()
            .map(|rejected| (rejected.instance_id, Arc::from(rejected.error.as_str())))
            .collect();

        let mut removed_evidence = self.prune_installed_evidence().await;

        // Every current binding, every withdrawal decided by the complete
        // result, and every old registration that still owes cleanup.
        let mut related: BTreeMap<(Uuid, Uuid), (SharedVirtualNicMember, BTreeSet<IpCidr>)> =
            BTreeMap::new();
        {
            let rt = self.controller.runtime.read();
            for (run, instance) in &rt.instances {
                let Some(member) = instance.member.as_ref() else {
                    continue;
                };
                let target = accepted.get(run).cloned().unwrap_or_default();
                related.insert((*run, member.registration_id()), (member.clone(), target));
            }
        }
        for withdraw in plan.withdraw {
            related
                .entry((withdraw.run, withdraw.registration))
                .or_insert((withdraw.member, BTreeSet::new()));
        }
        for (key, retry) in &self.member_retries {
            related
                .entry(*key)
                .or_insert_with(|| (retry.member.clone(), BTreeSet::new()));
        }
        let mut admission_failures: BTreeMap<(Uuid, Uuid), (BTreeSet<IpCidr>, RouteStatus)> =
            BTreeMap::new();
        let mut synced: BTreeMap<(Uuid, Uuid), BTreeSet<IpCidr>> = BTreeMap::new();
        let mut cleared: BTreeSet<(Uuid, Uuid)> = BTreeSet::new();

        // 1. Clear every member that the complete result no longer accepts.
        // Empty targets are committed first, before any accepted member asks
        // for admission, so stale local routes cannot block this round.
        for (key, (member, target)) in &related {
            if !target.is_empty() {
                continue;
            }
            let now = tokio::time::Instant::now();
            if member_retry_blocked(&self.member_retries, key, target, now) {
                continue;
            }
            match sync_member_routes(member, target).await {
                Ok(true) => {
                    cleared.remove(key);
                    synced.insert(*key, target.clone());
                    if self.member_retries.remove(key).is_some() {
                        recovered = true;
                    }
                }
                Ok(false) => {
                    // The registration is gone or the NIC is invalid. This is
                    // real local cleanup evidence, not an inference from a
                    // closed flag.
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
                    tracing::warn!(?error, ?key, "failed to clear member routes");
                    record_member_failure(
                        &mut self.member_retries,
                        *key,
                        member,
                        target.clone(),
                        &error,
                    );
                }
            }
        }

        // 2. Admit and commit exactly the targets the complete result accepted.
        // Admission here is a real NIC check; a conflict with stale local
        // claims is a temporary local failure and is retried. A member the
        // Controller rejected never reaches this stage.
        for (key, (member, target)) in &related {
            if target.is_empty() {
                continue;
            }
            if !Self::is_current_binding(&self.controller, *key) {
                continue;
            }
            let now = tokio::time::Instant::now();
            if member_retry_blocked(&self.member_retries, key, target, now) {
                continue;
            }
            match Self::admit_member(member, target).await {
                Ok(()) => {}
                Err(RouteStatus::Pending { error: None }) => {
                    // Closed, invalid or replaced binding: no write target can
                    // be confirmed this round, and there is nothing to retry
                    // until a new binding or input arrives.
                    admission_failures.remove(key);
                    synced.remove(key);
                    cleared.remove(key);
                    continue;
                }
                Err(status @ RouteStatus::Pending { error: Some(_) }) => {
                    synced.remove(key);
                    cleared.remove(key);
                    let error = match &status {
                        RouteStatus::Pending {
                            error: Some(error), ..
                        } => error.clone(),
                        _ => unreachable!("matched Pending with an error"),
                    };
                    admission_failures.insert(*key, (target.clone(), status));
                    record_member_failure(
                        &mut self.member_retries,
                        *key,
                        member,
                        target.clone(),
                        &anyhow::anyhow!("{error}"),
                    );
                    continue;
                }
                Err(status) => {
                    // Admission currently only produces Pending, but keep the
                    // feedback generic if a definite status is added later.
                    synced.remove(key);
                    cleared.remove(key);
                    admission_failures.insert(*key, (target.clone(), status));
                    continue;
                }
            }
            // Recheck after the admission wait: a rebound registration belongs
            // to the next marked round.
            if !Self::is_current_binding(&self.controller, *key) {
                synced.remove(key);
                cleared.remove(key);
                continue;
            }
            match sync_member_routes(member, target).await {
                Ok(true) => {
                    cleared.remove(key);
                    synced.insert(*key, target.clone());
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
                    tracing::warn!(?error, ?key, "failed to sync member routes");
                    let status = RouteStatus::Pending {
                        error: Some(error.to_string().into()),
                    };
                    admission_failures.insert(*key, (target.clone(), status));
                    record_member_failure(
                        &mut self.member_retries,
                        *key,
                        member,
                        target.clone(),
                        &error,
                    );
                }
            }
        }

        // 3. Feedback only consumes Controller decisions, this round's real
        // ACKs and local installed evidence; it never recomputes a target.
        self.update_statuses(
            &accepted,
            &rejected_by_instance,
            &admission_failures,
            &synced,
        );

        // 4. A member replaced during the waits still owes local cleanup.
        self.transfer_orphan_members(&related, &synced, &cleared);

        if self.remove_finished_instances(&synced, &cleared) {
            removed_evidence = true;
        }
        (removed_evidence, recovered)
    }

    /// Drop evidence only after the actual NIC registration is gone or the
    /// dispatcher is invalid. A closed flag alone is intentionally enough to
    /// keep it: close is allowed to set that flag before its cleanup finishes.
    async fn prune_installed_evidence(&mut self) -> bool {
        let observed: Vec<((Uuid, Uuid), SharedVirtualNicMember)> = {
            let rt = self.controller.runtime.read();
            rt.installed_routes
                .keys()
                .filter_map(|key| {
                    let member = rt.instances.get(&key.0)?.member.as_ref()?;
                    (member.registration_id() == key.1).then(|| (*key, member.clone()))
                })
                .collect()
        };
        let mut remove = Vec::new();
        for (key, member) in &observed {
            let nic = member.shared_nic();
            match tokio::time::timeout(ROUTE_IO_TIMEOUT, nic.lock()).await {
                Ok(guard) => {
                    if !guard.is_valid() || !guard.is_current_member_registration(key.0, key.1) {
                        remove.push(*key);
                    }
                }
                Err(_) => {
                    // Keep the evidence and schedule the existing local retry
                    // path rather than guessing that cleanup happened.
                    if !self.member_retries.contains_key(key) {
                        record_member_failure(
                            &mut self.member_retries,
                            *key,
                            member,
                            BTreeSet::new(),
                            &anyhow::anyhow!(
                                "timed out verifying installed prefixes of member {}",
                                member.member_id()
                            ),
                        );
                    }
                }
            }
        }
        // A key with no matching current member has no live registration that
        // could later confirm it.
        {
            let rt = self.controller.runtime.read();
            for key in rt.installed_routes.keys() {
                if !observed.iter().any(|(observed, _)| observed == key) {
                    remove.push(*key);
                }
            }
        }
        remove.sort();
        remove.dedup();
        let mut rt = self.controller.runtime.write();
        let mut removed = false;
        for key in remove {
            removed |= rt.installed_routes.remove(&key).is_some();
        }
        removed
    }

    fn record_plan_failure(&mut self) {
        let now = tokio::time::Instant::now();
        match &mut self.plan_retry {
            Some(retry) if retry.retry_at <= now => {
                retry.attempts = retry.attempts.saturating_add(1);
                retry.retry_at = now + retry_backoff(retry.attempts);
            }
            Some(_) => {}
            None => {
                self.plan_retry = Some(PlanRetry {
                    retry_at: now + retry_backoff(1),
                    attempts: 1,
                });
            }
        }
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
        guard
            .prepare_managed_routes(member.member_id(), member.registration_id(), target)
            .map(|_| ())
            .map_err(|error| {
                let message: Arc<str> = if error.is::<SharedIfConfigConflict>() {
                    // The complete plan accepted this target; a remaining
                    // overlap is stale local state to clear, not a policy
                    // rejection.
                    format!("local route admission conflict: {error}").into()
                } else {
                    error.to_string().into()
                };
                RouteStatus::Pending {
                    error: Some(message),
                }
            })
    }

    fn is_current_binding(controller: &RouteController, (run, registration): (Uuid, Uuid)) -> bool {
        let rt = controller.runtime.read();
        rt.instances
            .get(&run)
            .and_then(|instance| instance.member.as_ref())
            .is_some_and(|member| member.registration_id() == registration)
    }

    /// Per-route status from the complete plan plus this round's real evidence.
    ///
    /// Ready requires all of: the Controller accepted this declaration in the
    /// complete result for the current registration, this round really ACKed
    /// the complete target, and this exact run/registration has installed
    /// evidence covering the prefix. Another member's evidence or an equal
    /// domain-wide union never substitutes for that.
    fn update_statuses(
        &self,
        accepted: &BTreeMap<Uuid, BTreeSet<IpCidr>>,
        rejected_by_instance: &BTreeMap<Uuid, Arc<str>>,
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
            let rejection = instance
                .global
                .as_ref()
                .and_then(Weak::upgrade)
                .and_then(|global| rejected_by_instance.get(&global.get_id()).cloned());
            let manual = instance
                .config
                .as_ref()
                .is_some_and(|store| store.snapshot().services.manual_routes.is_some());
            let current_member = instance.member.as_ref();
            let registration = current_member.map(SharedVirtualNicMember::registration_id);
            let target = accepted.get(run);
            let installed = registration
                .and_then(|registration| rt.installed_routes.get(&(*run, registration)));

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
                    if let Some(error) = &rejection {
                        return Some(RouteStatus::Rejected(error.clone()));
                    }
                    let (Some(registration), Some(target)) = (registration, target) else {
                        return Some(RouteStatus::Pending { error: None });
                    };
                    // A declaration added after the plan, or an instance outside
                    // the host's scope, has no Controller acceptance yet.
                    if !target.contains(&prefix) {
                        return Some(RouteStatus::Pending { error: None });
                    }
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
                        && synced.get(&(*run, registration)) == Some(target)
                        && installed.is_some_and(|prefixes| prefixes.contains(&prefix));
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
        related: &BTreeMap<(Uuid, Uuid), (SharedVirtualNicMember, BTreeSet<IpCidr>)>,
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
        for (key, (member, _target)) in related {
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

    /// Remove instance records whose whole local responsibility is finished.
    ///
    /// Only a released root or shutdown makes a record eligible. There must be
    /// no pending member retry, no installed evidence for the run, and every
    /// current member must have proven an empty local route target this round
    /// (or have lost its registration). A closed flag or an empty route list
    /// alone is not proof.
    fn remove_finished_instances(
        &self,
        synced: &BTreeMap<(Uuid, Uuid), BTreeSet<IpCidr>>,
        cleared: &BTreeSet<(Uuid, Uuid)>,
    ) -> bool {
        let mut rt = self.controller.runtime.write();
        let shutdown = rt.shutdown;
        let mut finished = Vec::new();
        for (run, instance) in &rt.instances {
            if !shutdown && instance.registry.upgrade().is_some() {
                continue;
            }
            if self
                .member_retries
                .keys()
                .any(|(retry_run, _)| retry_run == run)
            {
                continue;
            }
            if rt
                .installed_routes
                .keys()
                .any(|(installed_run, _)| installed_run == run)
            {
                continue;
            }
            if let Some(member) = instance.member.as_ref() {
                let key = (*run, member.registration_id());
                let locally_clean =
                    cleared.contains(&key) || synced.get(&key).is_some_and(BTreeSet::is_empty);
                if !locally_clean {
                    continue;
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
