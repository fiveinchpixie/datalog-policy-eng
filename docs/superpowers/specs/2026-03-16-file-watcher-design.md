# File-Based Policy Watching Design

## Overview

A `PolicyFileWatcher` that polls a policy DSL file on a background thread, detects content changes via SHA-256 checksum, and hot-reloads the policy into any `impl PolicyWatcher` (typically an `Engine`). Failed compiles keep the old policy and report the error via a caller-provided callback. The CLI gains `:watch` and `:unwatch` REPL commands.

## Library: `PolicyFileWatcher`

### Location

New file: `src/policy/file_watcher.rs`, re-exported from `src/policy/mod.rs`.

### API

```rust
use std::path::Path;
use std::time::Duration;

pub struct PolicyFileWatcher { /* ... */ }

impl PolicyFileWatcher {
    /// Start watching a policy file. Performs an initial load immediately.
    /// Returns an error if the file cannot be read or the initial compile fails.
    pub fn start<W, F>(
        path: &Path,
        watcher: W,
        interval: Duration,
        on_event: F,
    ) -> Result<Self, PolicyError>
    where
        W: PolicyWatcher + 'static,
        F: Fn(WatchEvent) + Send + 'static;

    /// Stop the background thread. Also called on Drop.
    pub fn stop(&self);
}

impl Drop for PolicyFileWatcher {
    fn drop(&mut self) { self.stop(); }
}
```

### Watch events

```rust
pub enum WatchEvent {
    Reloaded { version: String, path: PathBuf },
    CompileError { error: PolicyError, path: PathBuf },
    IoError { error: std::io::Error, path: PathBuf },
}
```

Reported to the caller via the `on_event` callback. The callback runs on the watcher's background thread.

### Polling logic

Each poll cycle:

1. `stat()` the file to get mtime
2. If mtime unchanged since last check → skip (cheap path)
3. If mtime changed → read file contents, compute SHA-256
4. If checksum matches last successful compile → skip (editor touched mtime but content unchanged)
5. If checksum differs → call `PolicyWatcher::push()` with new source
   - On success: update stored checksum and mtime, emit `WatchEvent::Reloaded`
   - On compile error: keep old checksum/mtime (will retry next poll), emit `WatchEvent::CompileError`
6. If file read fails → emit `WatchEvent::IoError`, keep old policy

### Versioning

The watcher maintains a monotonic counter starting from 1. Each successful `push()` increments the counter and uses `v{N}` as the version string. The `PolicySet.checksum` field is set to the SHA-256 hex string of the file contents.

### Threading

- Spawns one `std::thread` via `std::thread::spawn`
- Uses `Arc<AtomicBool>` as stop signal, checked each poll cycle
- `stop()` sets the flag and joins the thread
- No async, no tokio — consistent with the crate's synchronous design
- The `PolicyWatcher` (typically `Engine`) is `Clone + Send + Sync`, so the background thread holds its own clone

### Initial load

`start()` performs the first load synchronously before spawning the background thread. If the file doesn't exist or fails to compile, `start()` returns `Err(PolicyError)` and no thread is spawned. This ensures the caller has a working policy before the watcher takes over.

### Dependencies

- `sha2` crate for SHA-256 checksumming (lightweight, pure Rust)
- No other new dependencies

## CLI: `:watch` and `:unwatch` commands

### REPL changes

Add to `src/cli/repl.rs`:

| Command | Description |
|---------|-------------|
| `:watch <path>` | Start watching a policy file for changes |
| `:unwatch` | Stop watching |

### Behavior

- `:watch <path>` creates a `PolicyFileWatcher` pointed at the given file, using the REPL's `Engine`. The initial load happens immediately (same as `:load`). If a watch is already active, it stops the old one first.
- `:unwatch` stops the current watch. The loaded policy remains active.
- `:load` and `:reload` continue to work independently. They do not affect the watch (the watch tracks its own file and checksum).
- Watch events (`Reloaded`, `CompileError`, `IoError`) print to stderr so they appear inline in the REPL without corrupting output.
- One-shot mode is not affected — no watching support needed for batch evaluation.

### Event display format

```
[watch] reloaded policy.dl (v3)
[watch] compile error in policy.dl: DSL parse error: unexpected token at line 5
[watch] I/O error reading policy.dl: No such file or directory
```

### Ownership

The `PolicyFileWatcher` is stored as `Option<PolicyFileWatcher>` in `ReplState`. When the REPL exits (Ctrl-D / `:quit`), the watcher is dropped, which stops the background thread.

## Testing

### Unit tests (library)

- `file_watcher` module tests using temp files:
  - Initial load succeeds and policy is active
  - Modifying file content triggers reload with new version
  - Modifying file without changing content (touch) does not trigger reload
  - Invalid DSL in file produces `CompileError` event, old policy stays active
  - Deleting the file produces `IoError` event, old policy stays active
  - `stop()` terminates the background thread
  - Calling `start()` with nonexistent file returns error

### Integration

- No new integration test files needed — the unit tests with temp files are sufficient
- Existing tests must continue to pass unchanged
