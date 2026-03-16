// src/policy/store.rs
use std::sync::Arc;
use parking_lot::{RwLock, RwLockReadGuard};
use crate::policy::compiled::CompiledPolicy;

/// Thread-safe, shared policy store.
#[derive(Clone)]
pub struct PolicyStore {
    inner: Arc<RwLock<Option<CompiledPolicy>>>,
}

impl PolicyStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(None)),
        }
    }

    pub fn read(&self) -> RwLockReadGuard<'_, Option<CompiledPolicy>> {
        self.inner.read()
    }

    pub fn swap(&self, policy: CompiledPolicy) {
        *self.inner.write() = Some(policy);
    }

    pub fn current_version(&self) -> Option<String> {
        self.inner.read().as_ref().map(|p| p.version.clone())
    }
}

impl Default for PolicyStore {
    fn default() -> Self {
        Self::new()
    }
}
