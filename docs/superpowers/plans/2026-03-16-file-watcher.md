# File-Based Policy Watcher Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `PolicyFileWatcher` that polls a policy DSL file on a background thread, detects content changes via SHA-256 checksum, and hot-reloads the policy. Integrate into the noodle REPL via `:watch` / `:unwatch` commands.

**Architecture:** New `src/policy/file_watcher.rs` module with a `PolicyFileWatcher` struct that spawns a `std::thread` polling loop. Uses mtime + SHA-256 two-tier change detection. Reports events via a caller-provided callback. The REPL stores an `Option<PolicyFileWatcher>` and adds two commands.

**Tech Stack:** `sha2 = "0.10"` (SHA-256); existing `std::thread`, `std::sync::atomic`, `std::time`

**Spec:** `docs/superpowers/specs/2026-03-16-file-watcher-design.md`

---

## File Structure

```
Cargo.toml                      # Modify: add sha2 dependency
src/
  policy/
    mod.rs                      # Modify: add `pub mod file_watcher;`
    file_watcher.rs             # Create: PolicyFileWatcher, WatchEvent, polling logic
  cli/
    repl.rs                     # Modify: add :watch/:unwatch commands, store watcher
```

---

## Chunk 1: PolicyFileWatcher library module

### Task 1: Add sha2 dependency and module scaffold

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/policy/mod.rs`
- Create: `src/policy/file_watcher.rs`

- [ ] **Step 1: Update Cargo.toml**

Add `sha2` to `[dependencies]`:

```toml
sha2       = "0.10"
```

- [ ] **Step 2: Add module declaration**

In `src/policy/mod.rs`, add:

```rust
pub mod file_watcher;
```

- [ ] **Step 3: Create file_watcher.rs with types and stub**

```rust
// src/policy/file_watcher.rs
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};

use sha2::{Sha256, Digest};

use crate::error::PolicyError;
use crate::policy::watcher::{PolicySet, PolicyWatcher};

/// Events emitted by the file watcher to the caller's callback.
pub enum WatchEvent {
    /// Policy was successfully reloaded.
    Reloaded { version: String, path: PathBuf },
    /// Policy file had a compile error. Old policy remains active.
    CompileError { error: PolicyError, path: PathBuf },
    /// Could not read the policy file. Old policy remains active.
    IoError { error: std::io::Error, path: PathBuf },
}

/// Watches a policy DSL file and hot-reloads on content changes.
pub struct PolicyFileWatcher {
    stop_flag: Arc<AtomicBool>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl PolicyFileWatcher {
    /// Start watching a policy file. Performs an initial load synchronously.
    /// Returns an error if the file cannot be read or the initial compile fails.
    pub fn start<W, F>(
        path: &Path,
        watcher: W,
        interval: Duration,
        on_event: F,
    ) -> Result<Self, PolicyError>
    where
        W: PolicyWatcher + 'static,
        F: Fn(WatchEvent) + Send + 'static,
    {
        todo!()
    }

    /// Stop the background polling thread.
    pub fn stop(&self) {
        todo!()
    }
}

impl Drop for PolicyFileWatcher {
    fn drop(&mut self) {
        self.stop();
    }
}
```

- [ ] **Step 4: Verify it compiles**

Run: `cargo build`
Expected: Compiles (with unused warnings, that's fine).

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml src/policy/mod.rs src/policy/file_watcher.rs
git commit -m "feat(watcher): scaffold PolicyFileWatcher with types"
```

### Task 2: Implement PolicyFileWatcher

**Files:**
- Modify: `src/policy/file_watcher.rs`

- [ ] **Step 1: Add tempfile dev-dependency**

In `Cargo.toml`:

```toml
[dev-dependencies]
tempfile = "3"
```

- [ ] **Step 2: Write tests**

Add to the bottom of `src/policy/file_watcher.rs`:

```rust
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
        let (tx, rx) = mpsc::channel();
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

        // Overwrite with new content
        thread::sleep(Duration::from_millis(20)); // ensure mtime differs
        fs::write(&path, ALLOW_ANALYST).unwrap();

        // Wait for reload event
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

        // Touch the file (change mtime) without changing content
        thread::sleep(Duration::from_millis(20));
        let content = fs::read_to_string(&path).unwrap();
        fs::write(&path, &content).unwrap();

        // Wait a few poll cycles
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

        // Write invalid DSL
        thread::sleep(Duration::from_millis(20));
        fs::write(&path, INVALID_DSL).unwrap();

        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(event, WatchEvent::CompileError { .. }));
        // Old policy still active
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

        // Delete the file
        drop(f); // closes and deletes temp file
        thread::sleep(Duration::from_millis(20));
        // Force mtime check to fail by ensuring file is gone
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
        // Calling stop again should be safe (no-op)
        w.stop();
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test policy::file_watcher`
Expected: All tests fail with `not yet implemented`.

- [ ] **Step 4: Implement PolicyFileWatcher**


Replace the `todo!()` stubs in `src/policy/file_watcher.rs` with the full implementation:

```rust
// src/policy/file_watcher.rs
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};

use sha2::{Sha256, Digest};

use crate::error::PolicyError;
use crate::policy::watcher::{PolicySet, PolicyWatcher};

/// Events emitted by the file watcher to the caller's callback.
pub enum WatchEvent {
    /// Policy was successfully reloaded.
    Reloaded { version: String, path: PathBuf },
    /// Policy file had a compile error. Old policy remains active.
    CompileError { error: PolicyError, path: PathBuf },
    /// Could not read the policy file. Old policy remains active.
    IoError { error: std::io::Error, path: PathBuf },
}

/// Watches a policy DSL file and hot-reloads on content changes.
pub struct PolicyFileWatcher {
    stop_flag: Arc<AtomicBool>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl PolicyFileWatcher {
    /// Start watching a policy file. Performs an initial load synchronously.
    /// Returns an error if the file cannot be read or the initial compile fails.
    pub fn start<W, F>(
        path: &Path,
        watcher: W,
        interval: Duration,
        on_event: F,
    ) -> Result<Self, PolicyError>
    where
        W: PolicyWatcher + 'static,
        F: Fn(WatchEvent) + Send + 'static,
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
                if flag.load(Ordering::SeqCst) {
                    break;
                }

                // Step 1: check mtime
                let current_mtime = match std::fs::metadata(&path).and_then(|m| m.modified()) {
                    Ok(mt) => mt,
                    Err(e) => {
                        on_event(WatchEvent::IoError { error: e, path: path.clone() });
                        continue;
                    }
                };

                if current_mtime == last_mtime {
                    continue;
                }

                // Step 2: read and checksum
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

                // Step 3: push new policy
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
                        // Keep last_checksum unchanged so a content fix is detected
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

    /// Stop the background polling thread.
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.lock().unwrap().take() {
            handle.join().ok();
        }
    }
}

impl Drop for PolicyFileWatcher {
    fn drop(&mut self) {
        self.stop();
    }
}

fn sha256_hex(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test policy::file_watcher`
Expected: All 7 tests pass.

- [ ] **Step 6: Run full test suite**

Run: `cargo test`
Expected: All existing tests + 7 new tests pass.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml src/policy/file_watcher.rs
git commit -m "feat(watcher): implement PolicyFileWatcher with polling and SHA-256"
```

---

## Chunk 2: REPL integration

### Task 3: Add :watch and :unwatch commands to the REPL

**Files:**
- Modify: `src/cli/repl.rs`

- [ ] **Step 1: Add watcher field to ReplState**

In `src/cli/repl.rs`, add the import and field:

Add to imports:
```rust
use crate::policy::file_watcher::{PolicyFileWatcher, WatchEvent};
use std::time::Duration;
```

Add field to `ReplState`:
```rust
struct ReplState {
    engine: Engine,
    policy_path: Option<PathBuf>,
    version_counter: u32,
    watcher: Option<PolicyFileWatcher>,
}
```

Update `ReplState::new()`:
```rust
fn new() -> Self {
    Self {
        engine: Engine::new(),
        policy_path: None,
        version_counter: 0,
        watcher: None,
    }
}
```

- [ ] **Step 2: Add :watch and :unwatch to handle_command**

Add these match arms inside `handle_command`:

```rust
":watch" | ":w" => {
    if let Some(path) = parts.get(1).map(|s| s.trim()) {
        // Stop existing watcher if any
        state.watcher.take();
        let file_path = Path::new(path);
        match PolicyFileWatcher::start(
            file_path,
            state.engine.clone(),
            Duration::from_secs(2),
            |event| match event {
                WatchEvent::Reloaded { version, path } => {
                    eprintln!("[watch] reloaded {} ({})", path.display(), version);
                }
                WatchEvent::CompileError { error, path } => {
                    eprintln!("[watch] compile error in {}: {}", path.display(), error);
                }
                WatchEvent::IoError { error, path } => {
                    eprintln!("[watch] I/O error reading {}: {}", path.display(), error);
                }
            },
        ) {
            Ok(w) => {
                state.policy_path = Some(file_path.to_path_buf());
                state.watcher = Some(w);
                eprintln!("watching {} (poll every 2s)", path);
            }
            Err(e) => eprintln!("error: {e}"),
        }
    } else {
        eprintln!("usage: :watch <path>");
    }
}
":unwatch" => {
    if state.watcher.take().is_some() {
        eprintln!("stopped watching");
    } else {
        eprintln!("no active watch");
    }
}
```

- [ ] **Step 3: Update print_help**

Add these lines to `print_help()`:

```rust
println!("  :watch <path>  Watch a policy file for changes (auto-reload)");
println!("  :unwatch       Stop watching");
```

- [ ] **Step 4: Verify it compiles**

Run: `cargo build`
Expected: Compiles with no errors.

- [ ] **Step 5: Run full test suite**

Run: `cargo test`
Expected: All tests pass (existing + file_watcher tests).

- [ ] **Step 6: Manual smoke test**

Create a temp policy file and test watching:

```bash
echo 'policy "d" priority 100 { deny when true reason "deny-all"; }' > /tmp/test.dl
```

Run: `cargo run`

In the REPL:
```
noodle> :watch /tmp/test.dl
```

Expected: `watching /tmp/test.dl (poll every 2s)` and policy loads.

In another terminal, modify the file:
```bash
echo 'policy "d" priority 100 { deny when true reason "updated"; }' > /tmp/test.dl
```

Expected: REPL prints `[watch] reloaded /tmp/test.dl (v2)` within ~2 seconds.

Then:
```
noodle> :unwatch
noodle> :quit
```

Clean up: `rm /tmp/test.dl`

- [ ] **Step 7: Commit**

```bash
git add src/cli/repl.rs
git commit -m "feat(cli): add :watch and :unwatch REPL commands"
```
