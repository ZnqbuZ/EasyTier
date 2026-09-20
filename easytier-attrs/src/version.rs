use std::sync::atomic::{AtomicU32, Ordering};

pub type Version = u32;

#[derive(Debug, Default)]
pub struct VersionCounter(AtomicU32);

impl VersionCounter {
    pub const fn new(v: Version) -> Self {
        Self(AtomicU32::new(v))
    }

    pub fn get(&self) -> Version {
        self.0.load(Ordering::Acquire)
    }

    pub fn inc(&self) -> Version {
        self.0.fetch_add(1, Ordering::AcqRel) + 1
    }

    pub fn set_if_larger(&self, version: Version) -> bool {
        let mut current = self.0.load(Ordering::Acquire);
        loop {
            if current >= version {
                return false;
            }
            match self.0.compare_exchange_weak(
                current,
                version,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }
}
