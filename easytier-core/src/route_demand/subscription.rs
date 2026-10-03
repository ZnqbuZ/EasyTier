//! Demand subscription and change notification stream.
//!
//! Provides a clean, leak-free wrapper around the authoritative watch channel,
//! ensuring subscribers never drop the latest view and never hold borrows across await points.

use std::sync::Arc;

use super::model::{RegistryRevision, RegistrySnapshot};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("demand subscription channel has been closed")]
pub struct SubscriptionClosed;

/// An active subscription to registry snapshot changes.
pub struct Subscription {
    pub(crate) receiver: tokio::sync::watch::Receiver<Arc<RegistrySnapshot>>,
    pub(crate) last_seen_version: RegistryRevision,
}

impl Subscription {
    pub(crate) fn new(
        receiver: tokio::sync::watch::Receiver<Arc<RegistrySnapshot>>,
        initial_version: RegistryRevision,
    ) -> Self {
        Self {
            receiver,
            last_seen_version: initial_version,
        }
    }

    /// Returns the last seen registry revision.
    pub fn last_seen_version(&self) -> RegistryRevision {
        self.last_seen_version
    }

    /// Awaits the next updated registry snapshot.
    ///
    /// The internal borrow is dropped immediately after cloning the Arc,
    /// guaranteeing no borrow guards cross await boundaries.
    pub async fn wait_next(&mut self) -> Result<Arc<RegistrySnapshot>, SubscriptionClosed> {
        loop {
            self.receiver
                .changed()
                .await
                .map_err(|_| SubscriptionClosed)?;
            let snapshot = self.receiver.borrow_and_update().clone();
            if snapshot.revision <= self.last_seen_version {
                continue;
            }
            self.last_seen_version = snapshot.revision;
            return Ok(snapshot);
        }
    }
}
