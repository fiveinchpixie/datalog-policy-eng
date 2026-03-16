use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};

use sha2::{Sha256, Digest};

use crate::error::PolicyError;
use crate::policy::watcher::{PolicySet, PolicyWatcher};

pub enum WatchEvent {
    Reloaded { version: String, path: PathBuf },
    CompileError { error: PolicyError, path: PathBuf },
    IoError { error: std::io::Error, path: PathBuf },
}

pub struct PolicyFileWatcher {
    stop_flag: Arc<AtomicBool>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl PolicyFileWatcher {
    pub fn start<W, F>(
        path: &Path, watcher: W, interval: Duration, on_event: F,
    ) -> Result<Self, PolicyError>
    where W: PolicyWatcher + 'static, F: Fn(WatchEvent) + Send + 'static,
    { todo!() }

    pub fn stop(&self) { todo!() }
}

impl Drop for PolicyFileWatcher {
    fn drop(&mut self) { self.stop(); }
}
