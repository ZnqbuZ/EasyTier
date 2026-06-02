#[cfg(debug_assertions)]
pub mod debug {
    use crate::utils::trace::Trace;
    use std::sync::LazyLock;
    use std::{
        collections::HashMap,
        sync::{Mutex, atomic::AtomicU64},
    };

    pub(super) static ID: AtomicU64 = AtomicU64::new(0);
    pub(super) static POINTERS: LazyLock<
        Mutex<HashMap<u64, (&'static str, Option<u64>, Trace<'static>)>>,
    > = LazyLock::new(|| Mutex::new(HashMap::new()));

    pub fn print() {
        let pointers = POINTERS.lock().unwrap();
        for (id, (ty, parent, trace)) in pointers.iter() {
            println!(
                "  [Type: {} | ID: {} | Parent: {:?}] {}",
                ty, id, parent, trace,
            );
        }
    }
}

#[cfg(debug_assertions)]
use debug::{ID, POINTERS};

use std::mem::ManuallyDrop;
use derivative::Derivative;
use std::ops::Deref;
use std::sync::{Arc, Weak};
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
pub struct SharedPtr<T: ?Sized> {
    inner: Arc<T>,
    token: CancellationToken,
    #[cfg(debug_assertions)]
    id: u64,
}

impl<T: ?Sized> SharedPtr<T> {
    pub fn make(data: T) -> Self
    where
        T: Sized,
    {
        Self::new(Arc::new(data), None)
    }

    fn new(data: Arc<T>, parent: Option<u64>) -> Self {
        #[cfg(debug_assertions)]
        let id = {
            use crate::utils::trace::Trace;
            use std::any::type_name;
            use std::sync::atomic::Ordering;
            let id = ID.fetch_add(1, Ordering::Relaxed);
            POINTERS
                .lock()
                .unwrap()
                .insert(id, (type_name::<T>(), parent, Trace::capture()));
            id
        };
        Self {
            inner: data,
            token: CancellationToken::new(),
            #[cfg(debug_assertions)]
            id,
        }
    }

    pub fn share(&self) -> WeakPtr<T> {
        WeakPtr {
            inner: Arc::downgrade(&self.inner),
            token: self.token.child_token(),
            #[cfg(debug_assertions)]
            parent: self.id,
        }
    }

    pub fn cast<U: ?Sized>(self, f: impl FnOnce(Arc<T>) -> Arc<U>) -> SharedPtr<U> {
        let this = ManuallyDrop::new(self);

        SharedPtr {
            inner: f(unsafe { std::ptr::read(&this.inner) }),
            token: unsafe { std::ptr::read(&this.token) },
            #[cfg(debug_assertions)]
            id: this.id,
        }
    }
}

impl<T: ?Sized> Deref for SharedPtr<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: ?Sized> Drop for SharedPtr<T> {
    fn drop(&mut self) {
        self.token.cancel();
        #[cfg(debug_assertions)]
        if let Ok(mut pointers) = POINTERS.lock() {
            pointers.remove(&self.id);
        }
    }
}

#[derive(Derivative, Debug)]
#[derivative(Clone(bound = ""))]
pub struct WeakPtr<T: ?Sized> {
    inner: Weak<T>,
    token: CancellationToken,
    #[cfg(debug_assertions)]
    parent: u64,
}

impl<T: ?Sized> WeakPtr<T> {
    #[track_caller]
    pub fn with<R>(&self, f: impl FnOnce(&SharedPtr<T>, CancellationToken) -> R) -> Option<R> {
        let ptr = SharedPtr::new(self.inner.upgrade()?, Some(self.parent));
        Some(f(&ptr, self.token.clone()))
    }

    pub async fn with_async<R>(
        &self,
        f: impl AsyncFnOnce(&SharedPtr<T>, CancellationToken) -> R,
    ) -> Option<R> {
        let ptr = SharedPtr::new(self.inner.upgrade()?, Some(self.parent));
        Some(f(&ptr, self.token.clone()).await)
    }

    pub fn cast<U: ?Sized>(self, f: impl FnOnce(Weak<T>) -> Weak<U>) -> WeakPtr<U> {
        WeakPtr {
            inner: f(self.inner),
            token: self.token,
            #[cfg(debug_assertions)]
            parent: self.parent,
        }
    }
}
