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
    {
        let path = path.to_path_buf();

        // Initial synchronous load
        let source = std::fs::read_to_string(&path)
            .map_err(|e| PolicyError::Compile(format!("cannot read {}: {e}", path.display())))?;
        let checksum = sha256_hex(&source);
        let version = "watch-v1".to_string();
        watcher.push(PolicySet {
            version: version.clone(),
            source,
            checksum: checksum.clone(),
        })?;

        let mtime = std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);

        let stop_flag = Arc::new(AtomicBool::new(false));
        let flag = stop_flag.clone();

        let handle = thread::spawn(move || {
            let mut last_mtime = mtime;
            let mut last_checksum = checksum;
            let mut version_counter: u32 = 1;

            while !flag.load(Ordering::SeqCst) {
                thread::sleep(interval);
                if flag.load(Ordering::SeqCst) { break; }

                let current_mtime = match std::fs::metadata(&path).and_then(|m| m.modified()) {
                    Ok(mt) => mt,
                    Err(e) => {
                        on_event(WatchEvent::IoError { error: e, path: path.clone() });
                        continue;
                    }
                };

                if current_mtime == last_mtime { continue; }

                let source = match std::fs::read_to_string(&path) {
                    Ok(s) => s,
                    Err(e) => {
                        on_event(WatchEvent::IoError { error: e, path: path.clone() });
                        continue;
                    }
                };

                let new_checksum = sha256_hex(&source);
                if new_checksum == last_checksum {
                    last_mtime = current_mtime;
                    continue;
                }

                version_counter += 1;
                let version = format!("watch-v{version_counter}");
                match watcher.push(PolicySet {
                    version: version.clone(),
                    source,
                    checksum: new_checksum.clone(),
                }) {
                    Ok(()) => {
                        last_mtime = current_mtime;
                        last_checksum = new_checksum;
                        on_event(WatchEvent::Reloaded { version, path: path.clone() });
                    }
                    Err(e) => {
                        last_mtime = current_mtime;
                        on_event(WatchEvent::CompileError { error: e, path: path.clone() });
                    }
                }
            }
        });

        Ok(Self {
            stop_flag,
            handle: Mutex::new(Some(handle)),
        })
    }

    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.lock().unwrap().take() {
            handle.join().ok();
        }
    }
}

impl Drop for PolicyFileWatcher {
    fn drop(&mut self) { self.stop(); }
}

fn sha256_hex(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::AtomicU32;
    use std::sync::mpsc;

    const DENY_ALL: &str = r#"policy "d" priority 100 { deny when true reason "deny-all"; }"#;
    const ALLOW_ANALYST: &str = r#"
        policy "d" priority 100 {
            allow when tool_call(call_id, agent_id, _), agent_role(agent_id, "analyst");
            deny when true reason "fallback deny";
        }
    "#;
    const INVALID_DSL: &str = "this is not valid policy!!!";

    fn tmp_policy(content: &str) -> (tempfile::NamedTempFile, PathBuf) {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        let path = f.path().to_path_buf();
        (f, path)
    }

    fn engine() -> crate::Engine {
        crate::Engine::new()
    }

    #[test]
    fn initial_load_succeeds() {
        let (_f, path) = tmp_policy(DENY_ALL);
        let engine = engine();
        let (tx, _rx) = mpsc::channel();
        let w = PolicyFileWatcher::start(
            &path, engine.clone(), Duration::from_millis(50),
            move |e| { tx.send(e).ok(); },
        ).unwrap();
        assert_eq!(engine.current_version(), Some("watch-v1".to_string()));
        w.stop();
    }

    #[test]
    fn nonexistent_file_returns_error() {
        let engine = engine();
        let result = PolicyFileWatcher::start(
            Path::new("/nonexistent/policy.dl"), engine, Duration::from_millis(50),
            |_| {},
        );
        assert!(result.is_err());
    }

    #[test]
    fn content_change_triggers_reload() {
        let (_f, path) = tmp_policy(DENY_ALL);
        let engine = engine();
        let (tx, rx) = mpsc::channel();
        let w = PolicyFileWatcher::start(
            &path, engine.clone(), Duration::from_millis(50),
            move |e| { tx.send(e).ok(); },
        ).unwrap();
        assert_eq!(engine.current_version(), Some("watch-v1".to_string()));

        thread::sleep(Duration::from_millis(20));
        fs::write(&path, ALLOW_ANALYST).unwrap();

        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(event, WatchEvent::Reloaded { ref version, .. } if version == "watch-v2"));
        assert_eq!(engine.current_version(), Some("watch-v2".to_string()));
        w.stop();
    }

    #[test]
    fn same_content_does_not_trigger_reload() {
        let (_f, path) = tmp_policy(DENY_ALL);
        let engine = engine();
        let reload_count = Arc::new(AtomicU32::new(0));
        let rc = reload_count.clone();
        let w = PolicyFileWatcher::start(
            &path, engine.clone(), Duration::from_millis(50),
            move |e| { if matches!(e, WatchEvent::Reloaded { .. }) { rc.fetch_add(1, Ordering::SeqCst); } },
        ).unwrap();

        thread::sleep(Duration::from_millis(20));
        let content = fs::read_to_string(&path).unwrap();
        fs::write(&path, &content).unwrap();

        thread::sleep(Duration::from_millis(200));
        assert_eq!(reload_count.load(Ordering::SeqCst), 0, "should not reload on same content");
        w.stop();
    }

    #[test]
    fn invalid_dsl_emits_compile_error_keeps_old_policy() {
        let (_f, path) = tmp_policy(DENY_ALL);
        let engine = engine();
        let (tx, rx) = mpsc::channel();
        let w = PolicyFileWatcher::start(
            &path, engine.clone(), Duration::from_millis(50),
            move |e| { tx.send(e).ok(); },
        ).unwrap();
        assert_eq!(engine.current_version(), Some("watch-v1".to_string()));

        thread::sleep(Duration::from_millis(20));
        fs::write(&path, INVALID_DSL).unwrap();

        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(event, WatchEvent::CompileError { .. }));
        assert_eq!(engine.current_version(), Some("watch-v1".to_string()));
        w.stop();
    }

    #[test]
    fn deleted_file_emits_io_error_keeps_old_policy() {
        let (f, path) = tmp_policy(DENY_ALL);
        let engine = engine();
        let (tx, rx) = mpsc::channel();
        let w = PolicyFileWatcher::start(
            &path, engine.clone(), Duration::from_millis(50),
            move |e| { tx.send(e).ok(); },
        ).unwrap();

        drop(f);
        thread::sleep(Duration::from_millis(20));
        let _ = fs::remove_file(&path);

        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(event, WatchEvent::IoError { .. }));
        assert_eq!(engine.current_version(), Some("watch-v1".to_string()));
        w.stop();
    }

    #[test]
    fn stop_terminates_thread() {
        let (_f, path) = tmp_policy(DENY_ALL);
        let engine = engine();
        let w = PolicyFileWatcher::start(
            &path, engine, Duration::from_millis(50),
            |_| {},
        ).unwrap();
        w.stop();
        w.stop(); // double stop is safe
    }
}
