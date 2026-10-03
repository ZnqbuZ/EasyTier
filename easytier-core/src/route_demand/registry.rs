//! Instance-level DemandRegistry and actor handles.
//!
//! Provides the serial submission synchronization, source lifecycle state machine,
//! single-authority watch channel distribution, and exact token lifecycle queries.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Weak},
    time::Duration,
};

use parking_lot::Mutex;

use super::{
    model::{
        ArithmeticOverflow, InstanceRuntimeId, ProjectionBasis, RegistryId, RegistryRevision,
        RegistrySnapshot, RouteDemand, SourceEpoch, SourceId, SourceKind, SourceRecord,
        SourceRevision, SourceSnapshot, SourceStatus,
    },
    subscription::Subscription,
    token::{
        ObsoleteOutcome, SourceSubmissionToken, SubmissionLifecycle, TokenQueryError,
        WaitObsoleteError,
    },
};

/// Error when registering or supervising a source.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RegistryError {
    #[error("registry is closed")]
    RegistryClosed,
    #[error("source with slot '{0}' is already registered")]
    SlotAlreadyExists(String),
    #[error("source '{0}' not found for restart")]
    SourceNotFound(SourceId),
    #[error("source '{0}' is not authorized for this publisher")]
    UnauthorizedSource(SourceId),
    #[error("version overflow: {0}")]
    Overflow(#[from] ArithmeticOverflow),
}

/// Error returned by publish operations.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PublishError {
    #[error("stale epoch: submitted with {submitted}, current is {current}")]
    StaleEpoch {
        submitted: SourceEpoch,
        current: SourceEpoch,
    },
    #[error("source '{0}' has been explicitly revoked")]
    Revoked(SourceId),
    #[error("registry is closed")]
    RegistryClosed,
    #[error("source '{0}' not found in registry")]
    SourceNotFound(SourceId),
    #[error("invalid demand item: {0}")]
    InvalidDemand(String),
    #[error("version counter overflow")]
    Overflow(#[from] ArithmeticOverflow),
    #[error("source '{0}' is not authorized in this scope")]
    Unauthorized(SourceId),
}

/// Receipt returned on successful demand publish.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishReceipt {
    pub token: SourceSubmissionToken,
    pub registry_revision: RegistryRevision,
}

/// Receipt returned on explicit source revocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationReceipt {
    pub source_id: SourceId,
    pub epoch: SourceEpoch,
    pub registry_revision: RegistryRevision,
}

/// Receipt returned on batch publication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchReceipt {
    pub receipts: Vec<PublishReceipt>,
    pub registry_revision: RegistryRevision,
}

/// Internal per-source state.
struct SourceState {
    source_id: SourceId,
    logical_slot: String,
    epoch: SourceEpoch,
    status: SourceStatus,
    current_revision: SourceRevision,
    latest_snapshot: Option<SourceSnapshot>,
    stale_baseline: Option<SourceSnapshot>,
    revoked_epochs: BTreeMap<SourceEpoch, SourceRevision>,
}

impl SourceState {
    fn to_record(&self) -> SourceRecord {
        SourceRecord {
            source_id: self.source_id,
            epoch: self.epoch,
            status: self.status.clone(),
            latest_snapshot: self.latest_snapshot.clone(),
            stale_baseline: self.stale_baseline.clone(),
        }
    }
}

/// Internal synchronized state of the registry.
struct RegistryState {
    revision: RegistryRevision,
    sources: BTreeMap<SourceId, SourceState>,
    slot_to_source: BTreeMap<String, SourceId>,
    tombstones: BTreeMap<SourceId, SourceEpoch>,
    history_tokens: BTreeSet<SourceSubmissionToken>,
    is_closed: bool,
}

impl RegistryState {
    fn build_snapshot(
        &self,
        registry_id: RegistryId,
        instance_runtime_id: InstanceRuntimeId,
    ) -> RegistrySnapshot {
        let sources = self
            .sources
            .iter()
            .map(|(k, v)| (*k, v.to_record()))
            .collect();
        RegistrySnapshot {
            registry_id,
            instance_runtime_id,
            revision: self.revision,
            sources,
            tombstones: self.tombstones.clone(),
            is_closed: self.is_closed,
        }
    }
}

struct RegistryInner {
    registry_id: RegistryId,
    instance_runtime_id: InstanceRuntimeId,
    state: Mutex<RegistryState>,
    watch_tx: tokio::sync::watch::Sender<Arc<RegistrySnapshot>>,
}

/// Instance-level authority owning the demand registry.
///
/// Can register sources, restart sources, close the registry, and produce readers.
#[derive(Clone)]
pub struct InstanceOwner {
    inner: Arc<RegistryInner>,
}

impl InstanceOwner {
    /// Creates a new instance-level demand registry.
    pub fn new(instance_runtime_id: InstanceRuntimeId) -> Self {
        let registry_id = RegistryId::random();
        let initial_state = RegistryState {
            revision: RegistryRevision(0),
            sources: BTreeMap::new(),
            slot_to_source: BTreeMap::new(),
            tombstones: BTreeMap::new(),
            history_tokens: BTreeSet::new(),
            is_closed: false,
        };
        let initial_snapshot = Arc::new(initial_state.build_snapshot(registry_id, instance_runtime_id));
        let (watch_tx, _) = tokio::sync::watch::channel(initial_snapshot);

        Self {
            inner: Arc::new(RegistryInner {
                registry_id,
                instance_runtime_id,
                state: Mutex::new(initial_state),
                watch_tx,
            }),
        }
    }

    pub fn registry_id(&self) -> RegistryId {
        self.inner.registry_id
    }

    pub fn instance_runtime_id(&self) -> InstanceRuntimeId {
        self.inner.instance_runtime_id
    }

    /// Registers a new source with a logical slot.
    pub fn register(
        &self,
        kind: SourceKind,
        logical_slot: impl Into<String>,
    ) -> Result<SourcePublisher, RegistryError> {
        let slot = logical_slot.into();
        let source_id = SourceId::random(kind);
        let epoch = SourceEpoch(1);

        let mut state = self.inner.state.lock();
        if state.is_closed {
            return Err(RegistryError::RegistryClosed);
        }
        if state.slot_to_source.contains_key(&slot) {
            return Err(RegistryError::SlotAlreadyExists(slot));
        }

        let source_state = SourceState {
            source_id,
            logical_slot: slot.clone(),
            epoch,
            status: SourceStatus::Initializing,
            current_revision: SourceRevision(0),
            latest_snapshot: None,
            stale_baseline: None,
            revoked_epochs: BTreeMap::new(),
        };

        state.sources.insert(source_id, source_state);
        state.slot_to_source.insert(slot.clone(), source_id);
        state.revision = state.revision.next()?;

        let snapshot = Arc::new(state.build_snapshot(self.inner.registry_id, self.inner.instance_runtime_id));
        self.inner.watch_tx.send_replace(snapshot);

        Ok(SourcePublisher {
            source_id,
            epoch,
            logical_slot: slot,
            registry: Arc::downgrade(&self.inner),
        })
    }

    /// Restarts an existing source, strictly advancing its epoch.
    ///
    /// The previous valid demands are preserved as a stale baseline until the new epoch
    /// publishes its first snapshot.
    pub fn restart(&self, source_id: SourceId) -> Result<SourcePublisher, RegistryError> {
        let mut state = self.inner.state.lock();
        if state.is_closed {
            return Err(RegistryError::RegistryClosed);
        }

        let (new_epoch, logical_slot) = {
            let source = state
                .sources
                .get_mut(&source_id)
                .ok_or(RegistryError::SourceNotFound(source_id))?;

            let new_epoch = source.epoch.next()?;
            source.epoch = new_epoch;
            source.current_revision = SourceRevision(0);
            // Retain latest valid snapshot as stale baseline
            if let Some(latest) = source.latest_snapshot.take() {
                source.stale_baseline = Some(latest);
            }
            source.status = SourceStatus::Initializing;
            (new_epoch, source.logical_slot.clone())
        };

        state.revision = state.revision.next()?;
        let snapshot = Arc::new(state.build_snapshot(self.inner.registry_id, self.inner.instance_runtime_id));
        self.inner.watch_tx.send_replace(snapshot);

        Ok(SourcePublisher {
            source_id,
            epoch: new_epoch,
            logical_slot,
            registry: Arc::downgrade(&self.inner),
        })
    }

    /// Creates a scoped batch publisher authorized for the given sources.
    pub fn scoped_publisher(
        &self,
        sources: &[SourceId],
    ) -> Result<ScopedPublisher, RegistryError> {
        let state = self.inner.state.lock();
        if state.is_closed {
            return Err(RegistryError::RegistryClosed);
        }
        for id in sources {
            if !state.sources.contains_key(id) {
                return Err(RegistryError::UnauthorizedSource(*id));
            }
        }
        Ok(ScopedPublisher {
            authorized_sources: sources.iter().copied().collect(),
            registry: Arc::downgrade(&self.inner),
        })
    }

    /// Closes the registry, revoking all sources and disallowing future publications.
    pub fn close(&self) -> Result<(), RegistryError> {
        let mut state = self.inner.state.lock();
        if state.is_closed {
            return Ok(());
        }

        state.is_closed = true;
        let mut tombstones = Vec::with_capacity(state.sources.len());
        for (source_id, source) in state.sources.iter_mut() {
            source.status = SourceStatus::Revoked {
                tombstone_revision: source.current_revision,
            };
            source.latest_snapshot = None;
            tombstones.push((*source_id, source.epoch));
        }
        for (source_id, epoch) in tombstones {
            state.tombstones.insert(source_id, epoch);
        }

        state.revision = state.revision.next()?;
        let snapshot = Arc::new(state.build_snapshot(self.inner.registry_id, self.inner.instance_runtime_id));
        self.inner.watch_tx.send_replace(snapshot);

        Ok(())
    }

    /// Returns a read-only facade for the registry.
    pub fn reader(&self) -> DemandReader {
        DemandReader {
            inner: self.inner.clone(),
        }
    }
}

/// Restricted publisher handle held by a demand source.
#[derive(Debug)]
pub struct SourcePublisher {
    pub source_id: SourceId,
    pub epoch: SourceEpoch,
    pub logical_slot: String,
    registry: Weak<RegistryInner>,
}

impl SourcePublisher {
    /// Publishes a full snapshot of demands for this source.
    ///
    /// Synchronously validates and commits the snapshot under a short mutex.
    pub fn publish(
        &self,
        demands: BTreeSet<RouteDemand>,
        basis: ProjectionBasis,
    ) -> Result<PublishReceipt, PublishError> {
        let inner = self.registry.upgrade().ok_or(PublishError::RegistryClosed)?;
        let mut state = inner.state.lock();

        if state.is_closed {
            return Err(PublishError::RegistryClosed);
        }

        // Check tombstones
        if let Some(tombstone_epoch) = state.tombstones.get(&self.source_id) {
            if self.epoch <= *tombstone_epoch {
                return Err(PublishError::Revoked(self.source_id));
            }
        }

        let source = state
            .sources
            .get_mut(&self.source_id)
            .ok_or(PublishError::SourceNotFound(self.source_id))?;

        if self.epoch != source.epoch {
            return Err(PublishError::StaleEpoch {
                submitted: self.epoch,
                current: source.epoch,
            });
        }

        // Check idempotence
        if let Some(existing) = &source.latest_snapshot {
            if existing.demands == demands {
                // If demands and dependencies are identical, don't advance demand revision.
                let token = SourceSubmissionToken::new(self.source_id, self.epoch, source.current_revision);
                if existing.basis != basis {
                    // Update diagnostic basis and registry revision only
                    source.latest_snapshot = Some(SourceSnapshot {
                        source_id: self.source_id,
                        epoch: self.epoch,
                        revision: source.current_revision,
                        demands,
                        basis,
                        updated_at: std::time::SystemTime::now(),
                    });
                    state.revision = state.revision.next()?;
                    let snapshot = Arc::new(state.build_snapshot(inner.registry_id, inner.instance_runtime_id));
                    inner.watch_tx.send_replace(snapshot);
                }
                return Ok(PublishReceipt {
                    token,
                    registry_revision: state.revision,
                });
            }
        }

        // New demands: advance revision
        let next_rev = source.current_revision.next()?;
        source.current_revision = next_rev;

        let snapshot = SourceSnapshot {
            source_id: self.source_id,
            epoch: self.epoch,
            revision: next_rev,
            demands,
            basis,
            updated_at: std::time::SystemTime::now(),
        };

        source.latest_snapshot = Some(snapshot);
        source.stale_baseline = None;
        source.status = SourceStatus::Active;

        let token = SourceSubmissionToken::new(self.source_id, self.epoch, next_rev);
        state.history_tokens.insert(token);

        state.revision = state.revision.next()?;
        let reg_snapshot = Arc::new(state.build_snapshot(inner.registry_id, inner.instance_runtime_id));
        inner.watch_tx.send_replace(reg_snapshot);

        Ok(PublishReceipt {
            token,
            registry_revision: state.revision,
        })
    }

    /// Marks the source as temporarily unavailable, preserving its last valid snapshot as a stale baseline.
    pub fn mark_unavailable(&self, reason: impl Into<String>) -> Result<(), PublishError> {
        let inner = self.registry.upgrade().ok_or(PublishError::RegistryClosed)?;
        let mut state = inner.state.lock();

        if state.is_closed {
            return Err(PublishError::RegistryClosed);
        }

        let source = state
            .sources
            .get_mut(&self.source_id)
            .ok_or(PublishError::SourceNotFound(self.source_id))?;

        if self.epoch != source.epoch {
            return Err(PublishError::StaleEpoch {
                submitted: self.epoch,
                current: source.epoch,
            });
        }

        source.status = SourceStatus::Unavailable {
            reason: reason.into(),
        };
        if let Some(latest) = source.latest_snapshot.take() {
            source.stale_baseline = Some(latest);
        }

        state.revision = state.revision.next()?;
        let snapshot = Arc::new(state.build_snapshot(inner.registry_id, inner.instance_runtime_id));
        inner.watch_tx.send_replace(snapshot);

        Ok(())
    }

    /// Explicitly revokes the source, writing a tombstone and retiring its demands.
    pub fn revoke(self) -> Result<RevocationReceipt, PublishError> {
        let inner = self.registry.upgrade().ok_or(PublishError::RegistryClosed)?;
        let mut state = inner.state.lock();

        if state.is_closed {
            return Err(PublishError::RegistryClosed);
        }

        let source = state
            .sources
            .get_mut(&self.source_id)
            .ok_or(PublishError::SourceNotFound(self.source_id))?;

        if self.epoch != source.epoch {
            return Err(PublishError::StaleEpoch {
                submitted: self.epoch,
                current: source.epoch,
            });
        }

        source.status = SourceStatus::Revoked {
            tombstone_revision: source.current_revision,
        };
        source.latest_snapshot = None;
        source.stale_baseline = None;
        source
            .revoked_epochs
            .insert(self.epoch, source.current_revision);
        state.tombstones.insert(self.source_id, self.epoch);

        state.revision = state.revision.next()?;
        let snapshot = Arc::new(state.build_snapshot(inner.registry_id, inner.instance_runtime_id));
        inner.watch_tx.send_replace(snapshot);

        Ok(RevocationReceipt {
            source_id: self.source_id,
            epoch: self.epoch,
            registry_revision: state.revision,
        })
    }
}

/// Batch update request for a single source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceDemandUpdate {
    pub source_id: SourceId,
    pub epoch: SourceEpoch,
    pub demands: BTreeSet<RouteDemand>,
    pub basis: ProjectionBasis,
}

/// Scoped publisher allowing atomic multi-source batch publication.
pub struct ScopedPublisher {
    authorized_sources: BTreeSet<SourceId>,
    registry: Weak<RegistryInner>,
}

impl ScopedPublisher {
    /// Publishes batch updates across multiple authorized sources in a single atomic transaction.
    pub fn publish_batch(
        &self,
        updates: Vec<SourceDemandUpdate>,
    ) -> Result<BatchReceipt, PublishError> {
        let inner = self.registry.upgrade().ok_or(PublishError::RegistryClosed)?;
        let mut state = inner.state.lock();

        if state.is_closed {
            return Err(PublishError::RegistryClosed);
        }

        // Validate all updates first
        for update in &updates {
            if !self.authorized_sources.contains(&update.source_id) {
                return Err(PublishError::Unauthorized(update.source_id));
            }
            if let Some(tombstone) = state.tombstones.get(&update.source_id) {
                if update.epoch <= *tombstone {
                    return Err(PublishError::Revoked(update.source_id));
                }
            }
            let source = state
                .sources
                .get(&update.source_id)
                .ok_or(PublishError::SourceNotFound(update.source_id))?;
            if update.epoch != source.epoch {
                return Err(PublishError::StaleEpoch {
                    submitted: update.epoch,
                    current: source.epoch,
                });
            }
        }

        // Apply all updates
        let mut receipts = Vec::with_capacity(updates.len());
        let mut any_demand_changed = false;

        for update in updates {
            let source = state.sources.get_mut(&update.source_id).unwrap();
            let is_identical = source
                .latest_snapshot
                .as_ref()
                .map(|s| s.demands == update.demands)
                .unwrap_or(false);

            if is_identical {
                let token = SourceSubmissionToken::new(
                    update.source_id,
                    update.epoch,
                    source.current_revision,
                );
                receipts.push(PublishReceipt {
                    token,
                    registry_revision: state.revision,
                });
            } else {
                any_demand_changed = true;
                let next_rev = source.current_revision.next()?;
                source.current_revision = next_rev;

                let snapshot = SourceSnapshot {
                    source_id: update.source_id,
                    epoch: update.epoch,
                    revision: next_rev,
                    demands: update.demands,
                    basis: update.basis,
                    updated_at: std::time::SystemTime::now(),
                };
                source.latest_snapshot = Some(snapshot);
                source.stale_baseline = None;
                source.status = SourceStatus::Active;

                let token = SourceSubmissionToken::new(update.source_id, update.epoch, next_rev);
                state.history_tokens.insert(token);
                receipts.push(PublishReceipt {
                    token,
                    registry_revision: state.revision,
                });
            }
        }

        if any_demand_changed {
            state.revision = state.revision.next()?;
            for r in &mut receipts {
                r.registry_revision = state.revision;
            }
            let snapshot = Arc::new(state.build_snapshot(inner.registry_id, inner.instance_runtime_id));
            inner.watch_tx.send_replace(snapshot);
        }

        Ok(BatchReceipt {
            receipts,
            registry_revision: state.revision,
        })
    }
}

/// Read-only facade for the demand registry.
#[derive(Clone)]
pub struct DemandReader {
    inner: Arc<RegistryInner>,
}

impl DemandReader {
    pub fn registry_id(&self) -> RegistryId {
        self.inner.registry_id
    }

    pub fn instance_runtime_id(&self) -> InstanceRuntimeId {
        self.inner.instance_runtime_id
    }

    /// Obtains the current immutable snapshot of the registry.
    pub fn current(&self) -> Arc<RegistrySnapshot> {
        let _state = self.inner.state.lock();
        self.inner.watch_tx.borrow().clone()
    }

    /// Atomically establishes a subscription and returns the initial snapshot.
    ///
    /// Executed under the synchronization boundary so no updates can be missed between
    /// subscription creation and initial snapshot retrieval.
    pub fn subscribe(&self) -> (Subscription, Arc<RegistrySnapshot>) {
        let _state = self.inner.state.lock();
        let receiver = self.inner.watch_tx.subscribe();
        let initial_snapshot = receiver.borrow().clone();
        let initial_version = initial_snapshot.revision;
        (
            Subscription::new(receiver, initial_version),
            initial_snapshot,
        )
    }

    /// Queries the lifecycle status of a previously issued submission token.
    pub fn query_token(
        &self,
        token: SourceSubmissionToken,
    ) -> Result<SubmissionLifecycle, TokenQueryError> {
        let state = self.inner.state.lock();

        if state.is_closed {
            return Err(TokenQueryError::RegistryClosed);
        }

        if !state.history_tokens.contains(&token) {
            return Err(TokenQueryError::UnknownToken);
        }

        let source = state
            .sources
            .get(&token.source_id)
            .ok_or(TokenQueryError::UnknownToken)?;

        // Rule 2: Token's epoch was explicitly revoked
        if source.revoked_epochs.contains_key(&token.epoch) {
            return Ok(SubmissionLifecycle::Revoked);
        }
        if let SourceStatus::Revoked { .. } = source.status {
            if source.epoch == token.epoch {
                return Ok(SubmissionLifecycle::Revoked);
            }
        }
        if let Some(tombstone_epoch) = state.tombstones.get(&token.source_id) {
            if token.epoch <= *tombstone_epoch {
                return Ok(SubmissionLifecycle::Revoked);
            }
        }

        // Rule 3: Higher epoch or same epoch with higher revision is Superseded
        if source.epoch > token.epoch {
            let superseded_by_token = if source.current_revision.0 > 0 {
                Some(SourceSubmissionToken::new(
                    token.source_id,
                    source.epoch,
                    source.current_revision,
                ))
            } else {
                None
            };
            return Ok(SubmissionLifecycle::Superseded {
                superseded_by_epoch: Some(source.epoch),
                superseded_by_token,
            });
        }

        if source.epoch == token.epoch && source.current_revision > token.revision {
            let superseded_by_token = Some(SourceSubmissionToken::new(
                token.source_id,
                source.epoch,
                source.current_revision,
            ));
            return Ok(SubmissionLifecycle::Superseded {
                superseded_by_epoch: Some(source.epoch),
                superseded_by_token,
            });
        }

        // Rule 4: Current (Fresh if Active, Stale if Unavailable)
        let is_fresh = matches!(source.status, SourceStatus::Active);
        Ok(SubmissionLifecycle::Current { is_fresh })
    }

    /// Awaits until the given token becomes obsolete (superseded, revoked, or registry closed).
    pub async fn wait_obsolete(
        &self,
        token: SourceSubmissionToken,
        timeout: Option<Duration>,
    ) -> Result<ObsoleteOutcome, WaitObsoleteError> {
        let (mut sub, _) = self.subscribe();

        // Initial check
        match self.query_token(token) {
            Ok(SubmissionLifecycle::Superseded {
                superseded_by_epoch,
                superseded_by_token,
            }) => {
                return Ok(ObsoleteOutcome::Superseded {
                    superseded_by_epoch,
                    superseded_by_token,
                });
            }
            Ok(SubmissionLifecycle::Revoked) => {
                return Ok(ObsoleteOutcome::Revoked);
            }
            Err(TokenQueryError::RegistryClosed) => {
                return Ok(ObsoleteOutcome::RegistryClosed);
            }
            Err(e) => {
                return Err(WaitObsoleteError::Query(e));
            }
            Ok(SubmissionLifecycle::Current { .. }) => {}
        }

        let wait_loop = async {
            loop {
                sub.wait_next()
                    .await
                    .map_err(|_| WaitObsoleteError::SubscriptionClosed)?;

                match self.query_token(token) {
                    Ok(SubmissionLifecycle::Superseded {
                        superseded_by_epoch,
                        superseded_by_token,
                    }) => {
                        return Ok(ObsoleteOutcome::Superseded {
                            superseded_by_epoch,
                            superseded_by_token,
                        });
                    }
                    Ok(SubmissionLifecycle::Revoked) => {
                        return Ok(ObsoleteOutcome::Revoked);
                    }
                    Err(TokenQueryError::RegistryClosed) => {
                        return Ok(ObsoleteOutcome::RegistryClosed);
                    }
                    Err(e) => {
                        return Err(WaitObsoleteError::Query(e));
                    }
                    Ok(SubmissionLifecycle::Current { .. }) => {
                        continue;
                    }
                }
            }
        };

        if let Some(dur) = timeout {
            tokio::time::timeout(dur, wait_loop)
                .await
                .map_err(|_| WaitObsoleteError::Timeout)?
        } else {
            wait_loop.await
        }
    }
}
