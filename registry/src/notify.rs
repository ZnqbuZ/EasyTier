use std::{
    collections::BTreeSet,
    sync::Arc,
};
use parking_lot::{Mutex, RwLock};
use tokio::sync::watch;

/// Trait for notifying observers when a registry's contents change.
pub trait Notify: Send + Sync + 'static {
    fn notify(&self);
}

impl Notify for watch::Sender<()> {
    fn notify(&self) {
        let _ = self.send_replace(());
    }
}

impl Notify for Arc<dyn Notify> {
    fn notify(&self) {
        (**self).notify();
    }
}

struct DirtyState<K> {
    dirty: Mutex<BTreeSet<K>>,
    wake: watch::Sender<()>,
}

/// A keyed notify signal. When notified, it inserts `key` into the shared dirty set
/// and wakes the associated [`Dirty`] receiver.
#[derive(Clone)]
pub struct Signal<K> {
    state: Arc<DirtyState<K>>,
    key: K,
}

impl<K: Ord + Clone + Send + Sync + 'static> Signal<K> {
    pub fn notify(&self) {
        self.state.dirty.lock().insert(self.key.clone());
        let _ = self.state.wake.send_replace(());
    }

    pub fn mark_dirty(&self) {
        self.notify();
    }

    pub fn key(&self) -> &K {
        &self.key
    }
}

impl<K: Ord + Clone + Send + Sync + 'static> Notify for Signal<K> {
    fn notify(&self) {
        Signal::notify(self);
    }
}

/// The sending side of a [`Dirty`] tracker, allowing creation of [`Signal`] handles.
#[derive(Clone)]
pub struct DirtySender<K> {
    state: Arc<DirtyState<K>>,
}

impl<K: Ord + Clone + Send + Sync + 'static> DirtySender<K> {
    pub fn signal(&self, key: K) -> Signal<K> {
        Signal {
            state: self.state.clone(),
            key,
        }
    }

    pub fn mark_dirty(&self, key: K) {
        self.state.dirty.lock().insert(key);
        let _ = self.state.wake.send_replace(());
    }

    pub fn subscribe(&self) -> Dirty<K> {
        Dirty {
            state: self.state.clone(),
            rx: self.state.wake.subscribe(),
        }
    }
}

impl<K> std::fmt::Debug for DirtySender<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirtySender").finish()
    }
}

/// Aggregates dirty notifications from multiple [`Signal`] sources into a unified wake signal.
pub struct Dirty<K> {
    state: Arc<DirtyState<K>>,
    rx: watch::Receiver<()>,
}

impl<K: Ord + Clone + Send + Sync + 'static> Dirty<K> {
    pub fn new() -> Self {
        Self::channel().1
    }

    pub fn channel() -> (DirtySender<K>, Self) {
        let (tx, rx) = watch::channel(());
        let state = Arc::new(DirtyState {
            dirty: Mutex::new(BTreeSet::new()),
            wake: tx,
        });
        (
            DirtySender {
                state: state.clone(),
            },
            Self { state, rx },
        )
    }

    pub fn sender(&self) -> DirtySender<K> {
        DirtySender {
            state: self.state.clone(),
        }
    }

    pub fn signal(&self, key: K) -> Signal<K> {
        Signal {
            state: self.state.clone(),
            key,
        }
    }

    pub async fn changed(&mut self) -> Result<(), watch::error::RecvError> {
        self.rx.changed().await
    }

    pub fn has_changed(&self) -> bool {
        self.rx.has_changed().unwrap_or(true)
    }

    pub fn mark_unchanged(&mut self) {
        self.rx.mark_unchanged();
    }

    /// Atomically clears the dirty set and returns all marked keys, confirming the notification baseline.
    pub fn take(&mut self) -> BTreeSet<K> {
        self.rx.mark_unchanged();
        std::mem::take(&mut *self.state.dirty.lock())
    }

    pub fn is_dirty(&self) -> bool {
        !self.state.dirty.lock().is_empty()
    }
}

impl<K: Ord + Clone + Send + Sync + 'static> Default for Dirty<K> {
    fn default() -> Self {
        Self::new()
    }
}

/// A dynamic forwarder that can redirect notifications to another [`Notify`] target,
/// or drop them if no target is currently set.
#[derive(Clone)]
pub struct ForwardNotify {
    target: Arc<RwLock<Option<Arc<dyn Notify>>>>,
    local: watch::Sender<()>,
}

impl Default for ForwardNotify {
    fn default() -> Self {
        Self::new()
    }
}

impl ForwardNotify {
    pub fn new() -> Self {
        let (tx, _) = watch::channel(());
        Self {
            target: Arc::new(RwLock::new(None)),
            local: tx,
        }
    }

    pub fn subscribe(&self) -> watch::Receiver<()> {
        self.local.subscribe()
    }

    pub fn forward_to<N: Notify>(&self, target: N) {
        *self.target.write() = Some(Arc::new(target));
    }

    pub fn clear(&self) {
        *self.target.write() = None;
    }

    pub fn notify(&self) {
        Notify::notify(self);
    }
}

impl<K: std::fmt::Debug> std::fmt::Debug for Signal<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signal").field("key", &self.key).finish()
    }
}

impl<K> std::fmt::Debug for Dirty<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dirty").finish()
    }
}

impl Notify for ForwardNotify {
    fn notify(&self) {
        let _ = self.local.send_replace(());
        if let Some(target) = self.target.read().as_ref() {
            target.notify();
        }
    }
}

impl std::fmt::Debug for ForwardNotify {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForwardNotify").finish()
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dirty_accumulates_keys_and_take_clears() {
        let mut dirty = Dirty::<u32>::new();
        let sig1 = dirty.signal(1);
        let sig2 = dirty.signal(2);

        assert!(!dirty.is_dirty());
        sig1.notify();
        sig2.notify();
        sig1.notify();

        assert!(dirty.is_dirty());
        assert!(dirty.has_changed());
        let taken = dirty.take();
        assert_eq!(taken, BTreeSet::from([1, 2]));
        assert!(!dirty.is_dirty());
    }

    #[tokio::test]
    async fn forward_notify_switches_target_dynamically() {
        let mut dirty1 = Dirty::<&'static str>::new();
        let mut dirty2 = Dirty::<&'static str>::new();
        let fwd = ForwardNotify::new();

        // No target yet
        fwd.notify();
        assert!(!dirty1.is_dirty());

        // Forward to dirty1
        fwd.forward_to(dirty1.signal("inst-a"));
        fwd.notify();
        assert_eq!(dirty1.take(), BTreeSet::from(["inst-a"]));
        assert!(!dirty2.is_dirty());

        // Forward to dirty2
        fwd.forward_to(dirty2.signal("inst-b"));
        fwd.notify();
        assert!(!dirty1.is_dirty());
        assert_eq!(dirty2.take(), BTreeSet::from(["inst-b"]));

        // Clear
        fwd.clear();
        fwd.notify();
        assert!(!dirty1.is_dirty());
        assert!(!dirty2.is_dirty());
    }
}
