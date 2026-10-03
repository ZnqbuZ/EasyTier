//! Submission tokens and lifecycle query definitions.
//!
//! Enforces exact token identification and honest lifecycle query outcomes.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::model::{SourceEpoch, SourceId, SourceRevision};

/// Typed submission token binding a specific accepted demand publication.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SourceSubmissionToken {
    pub source_id: SourceId,
    pub epoch: SourceEpoch,
    pub revision: SourceRevision,
}

impl SourceSubmissionToken {
    pub fn new(source_id: SourceId, epoch: SourceEpoch, revision: SourceRevision) -> Self {
        Self {
            source_id,
            epoch,
            revision,
        }
    }
}

impl fmt::Debug for SourceSubmissionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SubmissionToken({}, {}, {})",
            self.source_id, self.epoch, self.revision
        )
    }
}

impl fmt::Display for SourceSubmissionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.source_id, self.epoch, self.revision)
    }
}

/// Lifecycle status of an accepted submission token within the registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubmissionLifecycle {
    /// The token is the current active or stale submission for its source.
    Current { is_fresh: bool },
    /// The submission has been superseded by a higher epoch or revision.
    Superseded {
        superseded_by_epoch: Option<SourceEpoch>,
        superseded_by_token: Option<SourceSubmissionToken>,
    },
    /// The source was explicitly revoked.
    Revoked,
}

/// Query error when looking up a token.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TokenQueryError {
    #[error("token was not issued by or recorded in this registry")]
    UnknownToken,
    #[error("token belongs to another registry instance")]
    ForeignRegistry,
    #[error("registry is closed")]
    RegistryClosed,
}

/// Result of waiting for a token to become obsolete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObsoleteOutcome {
    Superseded {
        superseded_by_epoch: Option<SourceEpoch>,
        superseded_by_token: Option<SourceSubmissionToken>,
    },
    Revoked,
    RegistryClosed,
}

/// Error returned by wait_obsolete.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WaitObsoleteError {
    #[error("timed out waiting for token to become obsolete")]
    Timeout,
    #[error("query error: {0}")]
    Query(#[from] TokenQueryError),
    #[error("underlying subscription channel was closed")]
    SubscriptionClosed,
}
