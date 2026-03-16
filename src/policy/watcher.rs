// src/policy/watcher.rs
use crate::error::PolicyError;

pub struct PolicySet {
    pub version: String,
    pub source: String,
    pub checksum: String,
}

pub trait PolicyWatcher: Send + Sync {
    fn push(&self, policy: PolicySet) -> Result<(), PolicyError>;
}
