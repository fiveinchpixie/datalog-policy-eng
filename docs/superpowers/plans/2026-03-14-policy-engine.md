# Policy Engine Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Rust library crate (`datalog-noodle`) implementing a stateless, request-scoped Datalog policy engine using CozoDB as the evaluation backend, with a custom policy DSL that compiles to CozoDB queries.

**Architecture:** The engine embeds CozoDB in-memory as the Datalog backend. Policies are authored in a custom DSL, parsed into an AST, compiled to a `CompiledPolicy` (a CozoDB instance pre-loaded with policy facts + a generated decision script), and stored in a `PolicyStore` protected by `Arc<parking_lot::RwLock<Option<CompiledPolicy>>>`. Per-request evaluation passes `FactPackage` data as CozoDB script parameters, runs the compiled decision script against the shared policy DB, applies regex builtins as a pre-pass, and returns a structured `Decision`. Any error at any point returns `Deny + Audit(Critical)` — the engine never fails open.

**Tech Stack:** Rust 2021 edition; `cozo = "0.7"` (in-memory CozoDB); `pest = "2"` + `pest_derive = "2"` (DSL parser); `regex = "1"`; `parking_lot = "0.12"`; `thiserror = "1"`

---

## File Structure

```
datalog-noodle/
├── Cargo.toml
└── src/
    ├── lib.rs               # Crate root — public API re-exports only
    ├── types.rs             # Primitive ID newtypes: CallId, AgentId, Role, ToolName, Uri, Op
    ├── error.rs             # EngineError, PolicyError
    ├── facts.rs             # All fact structs + FactPackage
    ├── decision.rs          # Decision, Verdict, Effect, AuditLevel, AuditRecord
    ├── policy/
    │   ├── mod.rs           # Re-exports
    │   ├── compiled.rs      # CompiledPolicy struct
    │   ├── store.rs         # PolicyStore: Arc<RwLock<Option<CompiledPolicy>>>
    │   └── watcher.rs       # PolicyWatcher trait + PolicySet
    ├── dsl/
    │   ├── mod.rs           # Re-exports
    │   ├── ast.rs           # DSL AST node types
    │   ├── grammar.pest     # pest PEG grammar for policy DSL
    │   ├── parser.rs        # pest output → AST
    │   └── compiler.rs      # AST → CompiledPolicy
    └── evaluator/
        ├── mod.rs           # Public evaluate() with fail-closed wrapper
        ├── engine.rs        # evaluate_inner(): the actual evaluation logic
        ├── facts_loader.rs  # FactPackage → BTreeMap<String, DataValue> for CozoDB params
        └── builtins.rs      # matches() regex pre-pass: populates matched_pattern facts
└── tests/
    ├── scenario_tests.rs    # Evaluator correctness: named test cases a security engineer can read
    ├── dsl_tests.rs         # DSL parser + compiler correctness
    ├── fail_closed_tests.rs # Every error path → Deny + Audit(Critical)
    └── concurrency_tests.rs # Concurrent requests + policy push: no torn reads
```

**Key boundary decisions:**
- `facts.rs` owns all input types; `decision.rs` owns all output types. Neither depends on the other.
- `dsl/` is self-contained: input is `String` (DSL source), output is `CompiledPolicy`. No evaluator dependency.
- `evaluator/` depends on `facts.rs`, `decision.rs`, `policy/`, and `dsl/` — but `dsl/` does not depend on `evaluator/`.
- `policy/store.rs` owns the `Arc<RwLock<>>` — callers never touch the lock directly.

---

## Chunk 1: Scaffold + Core Types

**Covers:** `Cargo.toml`, `src/lib.rs`, `src/types.rs`, `src/error.rs`, `src/facts.rs`, `src/decision.rs`

**Goal:** A compiling crate with all core data types in place. No logic yet — just the vocabulary the rest of the codebase speaks.

---

### Task 1: Project scaffold

**Files:**
- Create: `Cargo.toml`
- Create: `src/lib.rs`

- [ ] **Step 1: Create directory structure**

```bash
cargo init --lib datalog-noodle
cd datalog-noodle
mkdir -p src/policy src/dsl src/evaluator tests
```

Expected: `Cargo.toml` and `src/lib.rs` created by cargo.

- [ ] **Step 2: Replace `Cargo.toml` with project dependencies**

Replace the generated `Cargo.toml` with:

```toml
[package]
name = "datalog-noodle"
version = "0.1.0"
edition = "2021"

[dependencies]
cozo       = { version = "0.7", default-features = false, features = ["storage-mem"] }
pest       = "2"
pest_derive = "2"
regex      = "1"
parking_lot = "0.12"
thiserror  = "1"

[dev-dependencies]
# none yet — added as needed
```

> **Note for implementer:** Run `cargo check` after editing `Cargo.toml` to confirm all crates resolve. If `cozo 0.7` is unavailable on crates.io, use the latest 0.x release and verify that `DbInstance::new("mem", ...)` and `db.run_script(...)` exist. Run `cargo doc --open -p cozo` to browse the API.

- [ ] **Step 3: Replace `src/lib.rs` with module declarations**

```rust
// src/lib.rs
pub mod decision;
pub mod error;
pub mod facts;
pub mod policy;
pub mod types;

pub(crate) mod dsl;
pub(crate) mod evaluator;

// Public surface re-exports
pub use decision::{AuditLevel, AuditRecord, Decision, Effect, Verdict};
pub use error::{EngineError, PolicyError};
pub use facts::FactPackage;
pub use policy::watcher::{PolicySet, PolicyWatcher};
pub use policy::store::PolicyStore;
```

- [ ] **Step 4: Verify the project compiles (empty modules)**

Create placeholder `mod.rs` files so the module tree resolves:

```bash
touch src/policy/mod.rs src/dsl/mod.rs src/evaluator/mod.rs
```

Add stub re-exports to `src/policy/mod.rs`:

```rust
// src/policy/mod.rs
pub mod compiled;
pub mod store;
pub mod watcher;
```

Add stub `mod.rs` files:

```bash
touch src/policy/compiled.rs src/policy/store.rs src/policy/watcher.rs
touch src/dsl/ast.rs src/dsl/compiler.rs src/dsl/parser.rs src/dsl/grammar.pest
touch src/evaluator/engine.rs src/evaluator/facts_loader.rs src/evaluator/builtins.rs
```

Add stub content to each `src/dsl/mod.rs` and `src/evaluator/mod.rs`:

```rust
// src/dsl/mod.rs
pub(crate) mod ast;
pub(crate) mod compiler;
pub(crate) mod parser;
```

```rust
// src/evaluator/mod.rs
mod builtins;
mod engine;
mod facts_loader;
```

Run:

```bash
cargo check
```

Expected: compile errors only about missing items referenced in `lib.rs` (the types don't exist yet). This is expected — proceed to Task 2.

- [ ] **Step 5: Commit scaffold**

```bash
git add Cargo.toml src/
git commit -m "chore: scaffold crate with module tree"
```

---

### Task 2: Primitive ID types

**Files:**
- Create: `src/types.rs`

- [ ] **Step 1: Write the failing test**

Add to `src/types.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_id_equality() {
        let a = CallId("call-1".to_string());
        let b = CallId("call-1".to_string());
        let c = CallId("call-2".to_string());
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn op_debug() {
        assert_eq!(format!("{:?}", Op::Read), "Read");
        assert_eq!(format!("{:?}", Op::Write), "Write");
    }

    #[test]
    fn newtypes_are_hashable() {
        use std::collections::HashMap;
        let mut m: HashMap<AgentId, u32> = HashMap::new();
        m.insert(AgentId("agt-1".to_string()), 1);
        assert_eq!(m[&AgentId("agt-1".to_string())], 1);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test --lib types
```

Expected: compile error — `CallId`, `AgentId`, `Op` not defined.

- [ ] **Step 3: Implement `src/types.rs`**

```rust
// src/types.rs

/// Unique identifier for a single MCP tool call within an evaluation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CallId(pub String);

/// Unique identifier for an agent (the entity making the call).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AgentId(pub String);

/// A role name as declared in the policy DSL (e.g. "analyst", "admin").
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Role(pub String);

/// The name of an MCP tool (e.g. "db_query", "db_write").
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ToolName(pub String);

/// A resource URI (e.g. "data/finance/report.csv").
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Uri(pub String);

/// The operation being performed on a resource.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Op {
    Read,
    Write,
    Delete,
    Execute,
}

impl Op {
    pub fn as_str(&self) -> &'static str {
        match self {
            Op::Read    => "read",
            Op::Write   => "write",
            Op::Delete  => "delete",
            Op::Execute => "execute",
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test --lib types
```

Expected: all 3 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/types.rs
git commit -m "feat: add primitive ID newtypes"
```

---

### Task 3: Error types

**Files:**
- Create: `src/error.rs`

- [ ] **Step 1: Write the failing test**

Add to `src/error.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_error_display() {
        let e = EngineError::StoreUninitialized;
        assert!(e.to_string().contains("uninitialized"));
    }

    #[test]
    fn policy_error_preserves_message() {
        let e = PolicyError::Parse("unexpected token at line 3".to_string());
        assert!(e.to_string().contains("line 3"));
    }

    #[test]
    fn policy_error_undefined_pattern() {
        let e = PolicyError::UndefinedPattern("sql_injection".to_string());
        assert!(e.to_string().contains("sql_injection"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test --lib error
```

Expected: compile error — types not defined.

- [ ] **Step 3: Implement `src/error.rs`**

```rust
// src/error.rs
use thiserror::Error;

/// Errors that occur during request evaluation.
#[derive(Debug, Error)]
pub enum EngineError {
    #[error("policy store uninitialized — no policy has been pushed")]
    StoreUninitialized,

    #[error("CozoDB evaluation error: {0}")]
    Cozo(String),

    #[error("evaluation timed out")]
    Timeout,

    #[error("fact assembly error: {0}")]
    FactAssembly(String),
}

/// Errors that occur during policy load / DSL compilation.
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("DSL parse error: {0}")]
    Parse(String),

    #[error("DSL compile error: {0}")]
    Compile(String),

    #[error("undefined pattern reference: {0}")]
    UndefinedPattern(String),

    #[error("CozoDB store error: {0}")]
    Cozo(String),
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test --lib error
```

Expected: all 3 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/error.rs
git commit -m "feat: add EngineError and PolicyError types"
```

---

### Task 4: Fact types and FactPackage

**Files:**
- Create: `src/facts.rs`

- [ ] **Step 1: Write the failing test**

Add to `src/facts.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AgentId, CallId, Op, Role, ToolName, Uri};

    fn minimal_package() -> FactPackage {
        FactPackage {
            agents: vec![AgentFact {
                id: AgentId("agt-1".to_string()),
                display_name: "Analyst Bot".to_string(),
            }],
            agent_roles: vec![AgentRoleFact {
                agent_id: AgentId("agt-1".to_string()),
                role: Role("analyst".to_string()),
            }],
            agent_clearances: vec![],
            delegations: vec![],
            users: vec![],
            tool_calls: vec![ToolCallFact {
                call_id: CallId("call-1".to_string()),
                agent_id: AgentId("agt-1".to_string()),
                tool_name: ToolName("db_query".to_string()),
            }],
            call_args: vec![],
            tool_results: vec![],
            resource_accesses: vec![],
            resource_mimes: vec![],
            content_tags: vec![],
            timestamps: vec![TimestampFact {
                call_id: CallId("call-1".to_string()),
                unix_ts: 1_700_000_000,
            }],
            call_counts: vec![],
            environment: vec![],
        }
    }

    #[test]
    fn package_construction() {
        let pkg = minimal_package();
        assert_eq!(pkg.agents.len(), 1);
        assert_eq!(pkg.tool_calls[0].tool_name.0, "db_query");
    }

    #[test]
    fn package_primary_call_id() {
        let pkg = minimal_package();
        assert_eq!(pkg.primary_call_id(), Some(&CallId("call-1".to_string())));
    }

    #[test]
    fn package_primary_call_id_empty() {
        let pkg = FactPackage::default();
        assert_eq!(pkg.primary_call_id(), None);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test --lib facts
```

Expected: compile error — types not defined.

- [ ] **Step 3: Implement `src/facts.rs`**

```rust
// src/facts.rs
use crate::types::{AgentId, CallId, Op, Role, ToolName, Uri};

// ── Identity facts ────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct AgentFact {
    pub id: AgentId,
    pub display_name: String,
}

#[derive(Clone, Debug)]
pub struct AgentRoleFact {
    pub agent_id: AgentId,
    pub role: Role,
}

#[derive(Clone, Debug)]
pub struct AgentClearanceFact {
    pub agent_id: AgentId,
    pub clearance: String,
}

#[derive(Clone, Debug)]
pub struct DelegationFact {
    pub agent_id: AgentId,
    pub delegator_id: AgentId,
}

#[derive(Clone, Debug)]
pub struct UserFact {
    pub user_id: String,
    pub agent_id: AgentId,
}

// ── MCP call facts ────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct ToolCallFact {
    pub call_id: CallId,
    pub agent_id: AgentId,
    pub tool_name: ToolName,
}

#[derive(Clone, Debug)]
pub struct CallArgFact {
    pub call_id: CallId,
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug)]
pub struct ToolResultFact {
    pub call_id: CallId,
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug)]
pub struct ResourceAccessFact {
    pub call_id: CallId,
    pub agent_id: AgentId,
    pub uri: Uri,
    pub op: Op,
}

#[derive(Clone, Debug)]
pub struct ResourceMimeFact {
    pub call_id: CallId,
    pub mime_type: String,
}

// ── Content classification facts ──────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct ContentTagFact {
    pub call_id: CallId,
    pub tag: String,
    pub value: String,
}

// ── Environment facts ─────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct TimestampFact {
    pub call_id: CallId,
    pub unix_ts: u64,
}

#[derive(Clone, Debug)]
pub struct CallCountFact {
    pub agent_id: AgentId,
    pub tool_name: ToolName,
    pub window: String,
    pub count: u64,
}

#[derive(Clone, Debug)]
pub struct EnvironmentFact {
    pub key: String,
    pub value: String,
}

// ── FactPackage ───────────────────────────────────────────────────────────────

/// The complete context for one MCP request evaluation.
/// Assembled by the gateway; consumed (read-only) by the evaluator.
#[derive(Clone, Debug, Default)]
pub struct FactPackage {
    // Identity
    pub agents: Vec<AgentFact>,
    pub agent_roles: Vec<AgentRoleFact>,
    pub agent_clearances: Vec<AgentClearanceFact>,
    pub delegations: Vec<DelegationFact>,
    pub users: Vec<UserFact>,
    // MCP call
    pub tool_calls: Vec<ToolCallFact>,
    pub call_args: Vec<CallArgFact>,
    pub tool_results: Vec<ToolResultFact>,
    pub resource_accesses: Vec<ResourceAccessFact>,
    pub resource_mimes: Vec<ResourceMimeFact>,
    // Content classification
    pub content_tags: Vec<ContentTagFact>,
    // Environment
    pub timestamps: Vec<TimestampFact>,
    pub call_counts: Vec<CallCountFact>,
    pub environment: Vec<EnvironmentFact>,
}

impl FactPackage {
    /// Returns the `CallId` of the first `tool_call` fact, if any.
    /// Used by the evaluator for audit records when evaluation fails early.
    pub fn primary_call_id(&self) -> Option<&CallId> {
        self.tool_calls.first().map(|tc| &tc.call_id)
    }

    /// Returns the `AgentId` of the first `tool_call` fact, if any.
    pub fn primary_agent_id(&self) -> Option<&AgentId> {
        self.tool_calls.first().map(|tc| &tc.agent_id)
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test --lib facts
```

Expected: all 3 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/facts.rs
git commit -m "feat: add fact types and FactPackage"
```

---

### Task 5: Decision output types

**Files:**
- Create: `src/decision.rs`

- [ ] **Step 1: Write the failing test**

Add to `src/decision.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AgentId, CallId};
    use crate::error::EngineError;
    use crate::facts::FactPackage;

    #[test]
    fn verdict_is_copy() {
        let v = Verdict::Allow;
        let v2 = v; // Copy, not moved
        assert_eq!(v, v2);
    }

    #[test]
    fn decision_deny_with_audit_effect() {
        let d = Decision {
            verdict: Verdict::Deny,
            effects: vec![Effect::Audit {
                level: AuditLevel::Critical,
                message: Some("test error".to_string()),
            }],
            reason: Some("test".to_string()),
            audit: AuditRecord {
                call_id: CallId("call-1".to_string()),
                agent_id: AgentId("agt-1".to_string()),
                tool_name: None,
                verdict: Verdict::Deny,
                policy_version: "none".to_string(),
                matched_rules: vec![],
                timestamp: None,
            },
        };
        assert_eq!(d.verdict, Verdict::Deny);
        assert!(matches!(d.effects[0], Effect::Audit { level: AuditLevel::Critical, .. }));
    }

    #[test]
    fn audit_record_from_error_uses_unknown_when_no_tool_call() {
        let facts = FactPackage::default();
        let err = EngineError::StoreUninitialized;
        let record = AuditRecord::from_error(&facts, &err);
        assert_eq!(record.call_id.0, "unknown");
        assert_eq!(record.verdict, Verdict::Deny);
    }

    #[test]
    fn audit_record_from_error_extracts_call_info() {
        use crate::facts::{ToolCallFact, TimestampFact};
        use crate::types::ToolName;
        let mut facts = FactPackage::default();
        facts.tool_calls.push(ToolCallFact {
            call_id: CallId("call-42".to_string()),
            agent_id: AgentId("agt-7".to_string()),
            tool_name: ToolName("db_query".to_string()),
        });
        // Decoy timestamp for a different call — must NOT be returned.
        facts.timestamps.push(TimestampFact {
            call_id: CallId("call-99".to_string()),
            unix_ts: 9_999_999_999,
        });
        // Correct timestamp matching call-42.
        facts.timestamps.push(TimestampFact {
            call_id: CallId("call-42".to_string()),
            unix_ts: 1_700_000_001,
        });
        let err = EngineError::Timeout;
        let record = AuditRecord::from_error(&facts, &err);
        assert_eq!(record.call_id.0, "call-42");
        assert_eq!(record.agent_id.0, "agt-7");
        assert_eq!(record.tool_name.as_deref(), Some("db_query"));
        // Must be the timestamp that matches call-42, not the decoy.
        assert_eq!(record.timestamp, Some(1_700_000_001));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test --lib decision
```

Expected: compile error — types not defined.

- [ ] **Step 3: Implement `src/decision.rs`**

```rust
// src/decision.rs
use crate::error::EngineError;
use crate::facts::FactPackage;
use crate::types::{AgentId, CallId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditLevel {
    Standard,
    Elevated,
    Critical,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Effect {
    Redact {
        selector: String,
        classifier: String,
    },
    Mask {
        selector: String,
        pattern: String,
        replacement: String,
    },
    Annotate {
        key: String,
        value: String,
    },
    Audit {
        level: AuditLevel,
        message: Option<String>,
    },
}

#[derive(Clone, Debug)]
pub struct AuditRecord {
    pub call_id: CallId,
    pub agent_id: AgentId,
    pub tool_name: Option<String>,
    pub verdict: Verdict,
    pub policy_version: String,
    pub matched_rules: Vec<String>,
    pub timestamp: Option<u64>,
}

impl AuditRecord {
    /// Build a minimal `AuditRecord` for the fail-closed error path.
    /// Extracts call context from the `FactPackage` if available; falls back to
    /// sentinel values ("unknown") so audit records are always emitted.
    pub fn from_error(facts: &FactPackage, _err: &EngineError) -> Self {
        let (call_id, agent_id, tool_name) = facts
            .tool_calls
            .first()
            .map(|tc| {
                (
                    tc.call_id.clone(),
                    tc.agent_id.clone(),
                    Some(tc.tool_name.0.clone()),
                )
            })
            .unwrap_or_else(|| {
                (
                    CallId("unknown".to_string()),
                    AgentId("unknown".to_string()),
                    None,
                )
            });
        // Look up the timestamp that matches this specific call_id, not just the first
        // timestamp in the vec (which may belong to a different call).
        let timestamp = facts
            .timestamps
            .iter()
            .find(|t| t.call_id == call_id)
            .map(|t| t.unix_ts);
        AuditRecord {
            call_id,
            agent_id,
            tool_name,
            verdict: Verdict::Deny,
            policy_version: "unknown".to_string(),
            matched_rules: vec![],
            timestamp,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Decision {
    pub verdict: Verdict,
    pub effects: Vec<Effect>,
    pub reason: Option<String>,
    pub audit: AuditRecord,
}
```

- [ ] **Step 4: Run all tests to verify they pass**

```bash
cargo test --lib
```

Expected: all tests in `types`, `error`, `facts`, `decision` pass. No compile errors.

- [ ] **Step 5: Commit**

```bash
git add src/decision.rs
git commit -m "feat: add Decision, Verdict, Effect, AuditRecord output types"
```

---

## Chunk 2: Policy Layer

**Covers:** `src/policy/compiled.rs`, `src/policy/store.rs`, `src/policy/watcher.rs`

**Goal:** The policy layer structs and interfaces. `CompiledPolicy` is the output of the DSL compiler (Chunk 4) and the payload held by `PolicyStore`. `PolicyStore` is the `Arc<RwLock<>>` wrapper with read/swap operations. `PolicyWatcher` is the trait the control plane calls to push new policies.

**Design decision (resolves spec open question):** Per-request evaluation uses a **single shared `CompiledPolicy.db`** with request facts passed as CozoDB script parameters — not separate per-request DB instances. The DSL compiler generates a `decision_script: String` (stored in `CompiledPolicy`) that includes inline rule definitions and uses `$param` placeholders for request facts. The evaluator runs `db.run_script(&decision_script, request_params)` per request. The DB is accessed read-only during evaluation; no per-request allocation of policy data.

---

### Task 6: CompiledPolicy

**Files:**
- Create: `src/policy/compiled.rs`
- Modify: `Cargo.toml` (add `serde_json` — required for `cozo::DbInstance::new` options arg)

- [ ] **Step 1: Add `serde_json` to `Cargo.toml`**

The `cozo::DbInstance::new` constructor takes `options: serde_json::Value` as its third argument.

```toml
[dependencies]
# ... existing entries ...
serde_json = "1"
```

- [ ] **Step 2: Write the failing test**

Add to `src/policy/compiled.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_policy_construction() {
        let db = cozo::DbInstance::new("mem", "", serde_json::json!({})).unwrap();
        let policy = CompiledPolicy {
            version: "v1.0".to_string(),
            db,
            decision_script: "?[] := []".to_string(),
            patterns: std::collections::HashMap::new(),
        };
        assert_eq!(policy.version, "v1.0");
        assert!(policy.patterns.is_empty());
        assert!(!policy.decision_script.is_empty());
    }

    #[test]
    fn cozo_mem_instance_runs_trivial_query() {
        // Smoke-test that the cozo dep is wired correctly and the mem backend works.
        let db = cozo::DbInstance::new("mem", "", serde_json::json!({})).unwrap();
        let result = db.run_script("?[x] := x = 1", Default::default()).unwrap();
        assert_eq!(result.rows.len(), 1);
    }
}
```

> **Note for implementer:** If `cozo::DbInstance::new` signature differs in the version you have, run `cargo doc -p cozo --open` to find the correct constructor. Common alternatives: `cozo::new_cozo_mem()` or `DbInstance::new_with_str("mem", "", "")`. Adjust the test and implementation to match.

- [ ] **Step 3: Run test to verify it fails**

```bash
cargo test --lib policy::compiled
```

Expected: compile error — `CompiledPolicy` not defined.

- [ ] **Step 4: Implement `src/policy/compiled.rs`**

```rust
// src/policy/compiled.rs
use std::collections::HashMap;
use regex::Regex;

/// The output of the DSL compiler. Held by `PolicyStore` and shared
/// (read-only) across all concurrent request evaluations.
///
/// `db` holds policy facts as stored CozoDB relations (role permissions,
/// tool categories, forbidden patterns, etc.).
///
/// `decision_script` is the compiled decision query template. It defines
/// inline Datalog rules and uses `$param` placeholders for per-request facts.
/// The evaluator calls `db.run_script(&decision_script, request_params)`.
///
/// `patterns` holds compiled `Regex` objects keyed by pattern name (e.g.
/// `"sql_injection"`). Pattern source strings are also stored in `db` for
/// auditability, but evaluation uses the pre-compiled `Regex` here, never
/// re-compiling at eval time.
///
/// No `Clone` or `Debug` derives — `cozo::DbInstance` and `regex::Regex`
/// do not implement those traits. This is intentional.
// #[derive(Clone, Debug)] — DO NOT ADD: cozo::DbInstance and regex::Regex are not Clone/Debug
pub struct CompiledPolicy {
    pub version: String,
    pub db: cozo::DbInstance,
    pub decision_script: String,
    pub patterns: HashMap<String, Regex>,
}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cargo test --lib policy::compiled
```

Expected: both tests pass. If `cozo_mem_instance_runs_trivial_query` fails with a field access error on `result`, check the actual field name in `cozo::NamedRows` — it may be `.rows` or `.result` depending on version.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml src/policy/compiled.rs
git commit -m "feat: add CompiledPolicy struct and verify cozo mem backend"
```

---

### Task 7: PolicyStore

**Files:**
- Create: `src/policy/store.rs`

- [ ] **Step 1: Write the failing test**

Add to `src/policy/store.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::compiled::CompiledPolicy;

    fn make_policy(version: &str) -> CompiledPolicy {
        CompiledPolicy {
            version: version.to_string(),
            db: cozo::DbInstance::new("mem", "", serde_json::json!({})).unwrap(),
            decision_script: "?[] := []".to_string(),
            patterns: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn new_store_is_uninitialized() {
        let store = PolicyStore::new();
        assert!(store.read().is_none());
        assert_eq!(store.current_version(), None);
    }

    #[test]
    fn swap_initializes_store() {
        let store = PolicyStore::new();
        store.swap(make_policy("v1"));
        assert!(store.read().is_some());
        assert_eq!(store.current_version(), Some("v1".to_string()));
    }

    #[test]
    fn swap_replaces_existing_policy() {
        let store = PolicyStore::new();
        store.swap(make_policy("v1"));
        store.swap(make_policy("v2"));
        assert_eq!(store.current_version(), Some("v2".to_string()));
    }

    #[test]
    fn clone_shares_underlying_store() {
        let store = PolicyStore::new();
        let store2 = store.clone();
        // Swap via one handle; read via the other.
        store.swap(make_policy("v1"));
        assert_eq!(store2.current_version(), Some("v1".to_string()));
    }

    #[test]
    fn store_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PolicyStore>();
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test --lib policy::store
```

Expected: compile error — `PolicyStore` not defined.

- [ ] **Step 3: Implement `src/policy/store.rs`**

```rust
// src/policy/store.rs
use std::sync::Arc;
use parking_lot::{RwLock, RwLockReadGuard};
use crate::policy::compiled::CompiledPolicy;

/// Thread-safe, shared policy store. Many request evaluations hold a read lock
/// concurrently. Policy pushes take a write lock, swap the policy, and release.
/// Cloning a `PolicyStore` gives another handle to the same underlying data.
#[derive(Clone)]
pub struct PolicyStore {
    inner: Arc<RwLock<Option<CompiledPolicy>>>,
}

impl PolicyStore {
    /// Create a new, uninitialized store. Evaluations against an uninitialized
    /// store immediately return `Deny + Audit(Critical)`.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(None)),
        }
    }

    /// Acquire a shared read lock. Many callers can hold this simultaneously.
    /// The guard is held only for the duration of the evaluation; drop it when done.
    pub fn read(&self) -> RwLockReadGuard<'_, Option<CompiledPolicy>> {
        self.inner.read()
    }

    /// Atomically replace the stored policy. Takes an exclusive write lock.
    /// No request sees a partially-updated policy: either the old or the new,
    /// never a mix.
    pub fn swap(&self, policy: CompiledPolicy) {
        *self.inner.write() = Some(policy);
    }

    /// Returns the version string of the currently loaded policy, if any.
    /// Used by `PolicyWatcher` implementations for idempotency checks.
    pub fn current_version(&self) -> Option<String> {
        self.inner.read().as_ref().map(|p| p.version.clone())
    }
}

impl Default for PolicyStore {
    fn default() -> Self {
        Self::new()
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test --lib policy::store
```

Expected: all 5 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/policy/store.rs
git commit -m "feat: add PolicyStore with Arc<RwLock<Option<CompiledPolicy>>>"
```

---

### Task 8: PolicyWatcher trait and PolicySet

**Files:**
- Create: `src/policy/watcher.rs`

Note: `PolicyWatcher` is a trait. Its implementation (which calls the DSL compiler) lives in the `Engine` struct added in Chunk 5. This task only defines the trait and its associated `PolicySet` type.

- [ ] **Step 1: Write the failing test**

Add to `src/policy/watcher.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // A minimal no-op implementation used only to verify trait bounds.
    struct MockWatcher;
    impl PolicyWatcher for MockWatcher {
        fn push(&self, _policy: PolicySet) -> Result<(), crate::error::PolicyError> {
            Ok(())
        }
    }

    #[test]
    fn policy_set_construction() {
        let ps = PolicySet {
            version:  "v1.0".to_string(),
            source:   "policy \"default\" priority 100 { deny when true; }".to_string(),
            checksum: "sha256:abc123".to_string(),
        };
        assert_eq!(ps.version, "v1.0");
        assert!(!ps.source.is_empty());
    }

    #[test]
    fn policy_watcher_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<MockWatcher>();
    }

    #[test]
    fn policy_watcher_is_object_safe() {
        // Verify the trait can be used as a trait object.
        let w: Box<dyn PolicyWatcher> = Box::new(MockWatcher);
        let ps = PolicySet {
            version:  "v1".to_string(),
            source:   "".to_string(),
            checksum: "".to_string(),
        };
        assert!(w.push(ps).is_ok());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test --lib policy::watcher
```

Expected: compile error — `PolicyWatcher`, `PolicySet` not defined.

- [ ] **Step 3: Implement `src/policy/watcher.rs`**

```rust
// src/policy/watcher.rs
use crate::error::PolicyError;

/// Raw policy payload delivered by the control plane.
/// The DSL source is compiled by the engine before loading into `PolicyStore`.
pub struct PolicySet {
    /// Monotonically increasing version label (e.g. "v1.0", commit SHA, timestamp).
    pub version: String,
    /// Full DSL source text to compile and load.
    pub source: String,
    /// Checksum of `source` (e.g. "sha256:<hex>"). Used by implementations to
    /// skip redundant pushes when the same policy is re-delivered.
    pub checksum: String,
}

/// Interface exposed by the engine to the control plane.
/// The control plane calls `push()` whenever a new policy is available.
/// The engine compiles, validates, and atomically swaps the `PolicyStore`.
///
/// The delivery transport (gRPC watch, HTTP poll, filesystem) is out of scope
/// for this crate. Implementations call `push()` regardless of transport.
pub trait PolicyWatcher: Send + Sync {
    /// Compile and atomically load a new policy.
    ///
    /// On success: the new policy is active for all subsequent evaluations.
    /// On failure: the existing policy remains active; the error is returned.
    /// Idempotency: implementations should compare `policy.version` against
    /// `PolicyStore::current_version()` and return `Ok(())` early if they match,
    /// avoiding a redundant compile + swap when the same version is re-delivered.
    fn push(&self, policy: PolicySet) -> Result<(), PolicyError>;
}
```

- [ ] **Step 4: Run all policy tests to verify they pass**

```bash
cargo test --lib policy
```

Expected: all tests in `policy::compiled`, `policy::store`, `policy::watcher` pass.

- [ ] **Step 5: Run full lib test suite**

```bash
cargo test --lib
```

Expected: all tests pass; no regressions.

- [ ] **Step 6: Commit**

```bash
git add src/policy/watcher.rs
git commit -m "feat: add PolicyWatcher trait and PolicySet"
```

---

## Chunk 3: DSL Parsing

**Covers:** `src/dsl/ast.rs`, `src/dsl/grammar.pest`, `src/dsl/parser.rs`

**Goal:** Given a DSL source string, produce a typed AST. No CozoDB involved yet — this chunk is purely about parsing text into structured Rust types. The compiler (Chunk 4) will walk the AST and produce a `CompiledPolicy`.

**Parsing strategy:** pest PEG parser. The grammar file drives everything. `parser.rs` wraps pest's output into the AST types defined in `ast.rs`. All three files are tightly coupled and built together in one TDD cycle (grammar + parser + AST tests are tested together).

---

### Task 9: DSL AST types

**Files:**
- Create: `src/dsl/ast.rs`

The AST is the output of parsing and the input to compilation. No logic here — pure data.

- [ ] **Step 1: Write the failing test**

Add to `src/dsl/ast.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_decl_construction() {
        let decl = PolicyDecl {
            name: "default-authz".to_string(),
            priority: 100,
            rules: vec![
                PolicyRule::Allow(AllowRule {
                    conditions: vec![AtomCondition {
                        predicate: "tool_call".to_string(),
                        args: vec![
                            Arg::Variable("call_id".to_string()),
                            Arg::Variable("agent_id".to_string()),
                            Arg::Variable("tool_name".to_string()),
                        ],
                    }
                    .into()],
                    effects: vec![],
                }),
                PolicyRule::Deny(DenyRule {
                    conditions: vec![ConditionClause::True],
                    reason: Some("no matching allow rule".to_string()),
                    effects: vec![],
                }),
            ],
        };
        assert_eq!(decl.name, "default-authz");
        assert_eq!(decl.priority, 100);
        assert_eq!(decl.rules.len(), 2);
    }

    #[test]
    fn grant_decl_variants() {
        let call_any = GrantDecl {
            role: "admin".to_string(),
            permission: GrantPermission::CallAny,
        };
        let call_cat = GrantDecl {
            role: "analyst".to_string(),
            permission: GrantPermission::CallCategory("read-only".to_string()),
        };
        let access = GrantDecl {
            role: "analyst".to_string(),
            permission: GrantPermission::AccessPattern("data/public/*".to_string()),
        };
        assert!(matches!(call_any.permission, GrantPermission::CallAny));
        assert!(matches!(call_cat.permission, GrantPermission::CallCategory(_)));
        assert!(matches!(access.permission, GrantPermission::AccessPattern(_)));
    }

    #[test]
    fn condition_clause_from_atom() {
        let atom = AtomCondition {
            predicate: "can_call".to_string(),
            args: vec![
                Arg::Variable("agent_id".to_string()),
                Arg::Variable("tool_name".to_string()),
            ],
        };
        let clause: ConditionClause = atom.into();
        assert!(matches!(clause, ConditionClause::Atom(_)));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test --lib dsl::ast
```

Expected: compile error — AST types not defined.

- [ ] **Step 3: Implement `src/dsl/ast.rs`**

```rust
// src/dsl/ast.rs

/// Top-level declarations in a policy file, in order.
#[derive(Debug, Clone, PartialEq)]
pub enum Declaration {
    Grant(GrantDecl),
    Categorize(CategorizeDecl),
    Classify(ClassifyDecl),
    Pattern(PatternDecl),
    Rule(RuleDecl),
    Policy(PolicyDecl),
}

// ── Policy facts ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct GrantDecl {
    pub role: String,
    pub permission: GrantPermission,
}

#[derive(Debug, Clone, PartialEq)]
pub enum GrantPermission {
    CallAny,
    CallCategory(String),
    AccessPattern(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct CategorizeDecl {
    pub tool: String,
    pub category: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClassifyDecl {
    pub resource_pattern: String,
    pub sensitivity: String,
}

// ── Patterns ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct PatternDecl {
    /// Pattern name without the leading `:` (e.g. `"sql_injection"`).
    pub name: String,
    /// Raw regex source string (without the `r"..."` wrapper).
    pub source: String,
}

// ── Rules ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct RuleDecl {
    pub name: String,
    pub params: Vec<Param>,
    pub conditions: Vec<ConditionClause>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Param {
    Named(String),
    Wildcard,
    NamedWildcard(String),
}

// ── Policy blocks ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct PolicyDecl {
    pub name: String,
    pub priority: u32,
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PolicyRule {
    Allow(AllowRule),
    Deny(DenyRule),
}

#[derive(Debug, Clone, PartialEq)]
pub struct AllowRule {
    pub conditions: Vec<ConditionClause>,
    pub effects: Vec<EffectDecl>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DenyRule {
    pub conditions: Vec<ConditionClause>,
    pub reason: Option<String>,
    pub effects: Vec<EffectDecl>,
}

// ── Conditions ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ConditionClause {
    /// A positive atom: `predicate(args...)`
    Atom(AtomCondition),
    /// Negation: `not predicate(args...)`
    Not(AtomCondition),
    /// Disjunction: `matches(v, :p) or matches(v, :q)` — a flat list of atoms
    /// any one of which satisfies the condition.
    Or(Vec<AtomCondition>),
    /// The literal `true` keyword — used in default-deny fallbacks.
    True,
}

impl From<AtomCondition> for ConditionClause {
    fn from(atom: AtomCondition) -> Self {
        ConditionClause::Atom(atom)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AtomCondition {
    pub predicate: String,
    pub args: Vec<Arg>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Arg {
    StringLit(String),
    Integer(i64),
    Variable(String),
    /// Anonymous wildcard `_`
    Wildcard,
    /// Named wildcard `_foo` — matches anything; name is for readability only
    NamedWildcard(String),
    /// Pattern reference `:name` — resolved to a compiled Regex at eval time
    PatternRef(String),
}

// ── Effects ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum EffectDecl {
    Redact { selector: String, classifier: String },
    Mask   { selector: String, pattern: String, replacement: String },
    Annotate { key: String, value: String },
    Audit { level: AuditLevelDecl },
}

#[derive(Debug, Clone, PartialEq)]
pub enum AuditLevelDecl {
    Standard,
    Elevated,
    Critical,
}

/// A fully parsed policy file.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyFile {
    pub declarations: Vec<Declaration>,
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test --lib dsl::ast
```

Expected: all 3 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/dsl/ast.rs
git commit -m "feat: add DSL AST node types"
```

---

### Task 10: DSL grammar

**Files:**
- Create: `src/dsl/grammar.pest`

The pest grammar is the source of truth for what valid DSL looks like. Write it before the parser so the parser tests drive grammar corrections. Grammar is tested indirectly via the parser tests in Task 11 — there are no standalone grammar tests.

- [ ] **Step 1: Write `src/dsl/grammar.pest`**

```pest
// src/dsl/grammar.pest

// ── Whitespace and comments ───────────────────────────────────────────────────
WHITESPACE = _{ " " | "\t" | "\n" | "\r" }
COMMENT    = _{ "//" ~ (!"\n" ~ ANY)* ~ ("\n" | EOI) }

// ── Primitives ────────────────────────────────────────────────────────────────
ident        = @{ (ASCII_ALPHA | "_") ~ (ASCII_ALPHANUMERIC | "_" | "-")* }
string       = @{ "\"" ~ (!"\"" ~ ANY)* ~ "\"" }
raw_string   = @{ "r\"" ~ (!"\"" ~ ANY)* ~ "\"" }
integer      = @{ ASCII_DIGIT+ }
pattern_ref  = @{ ":" ~ (ASCII_ALPHA | "_") ~ (ASCII_ALPHANUMERIC | "_")* }
wildcard     = @{ "_" ~ (ASCII_ALPHANUMERIC | "_")* }

// ── Top-level ─────────────────────────────────────────────────────────────────
policy_file  =  { SOI ~ declaration* ~ EOI }
declaration  =  { grant_decl | categorize_decl | classify_decl
                | pattern_decl | rule_decl | policy_decl }

// ── Policy facts ──────────────────────────────────────────────────────────────
grant_decl   =  { "grant" ~ "role" ~ string ~ "can" ~ grant_perm ~ ";" }
grant_perm   =  { call_any | call_category | access_pattern }
call_any         = { "call" ~ "tool:any" }
call_category    = { "call" ~ "tool:category" ~ "(" ~ string ~ ")" }
access_pattern   = { "access" ~ "resource:pattern" ~ "(" ~ string ~ ")" }

categorize_decl  = { "categorize" ~ "tool" ~ string ~ "as" ~ string ~ ";" }
classify_decl    = { "classify" ~ "resource" ~ string ~ "as" ~ "sensitivity" ~ string ~ ";" }

// ── Patterns ──────────────────────────────────────────────────────────────────
pattern_decl     = { "pattern" ~ pattern_ref ~ "=" ~ raw_string ~ ";" }

// ── Rules ─────────────────────────────────────────────────────────────────────
rule_decl    =  { "rule" ~ ident ~ "(" ~ param_list ~ ")" ~ ":-" ~ condition_list ~ ";" }
param_list   =  { param ~ ("," ~ param)* }
param        =  { wildcard | ident }

// ── Conditions ────────────────────────────────────────────────────────────────
condition_list  =  { condition ~ ("," ~ condition)* }
// or_condition must be tried before atom_condition so that
//   matches(v, :p) or matches(v, :q)
// parses as one Or clause rather than stopping after the first atom.
condition       = _{ not_condition | or_condition | atom_condition | true_kw }
not_condition   =  { "not" ~ atom_condition }
true_kw         =  { "true" }
or_condition    =  { atom_condition ~ ("or" ~ atom_condition)+ }
atom_condition  =  { ident ~ "(" ~ arg_list? ~ ")" }
arg_list        =  { arg ~ ("," ~ arg)* }

arg             =  { string | integer | pattern_ref | wildcard | ident }

// ── Policy blocks ─────────────────────────────────────────────────────────────
policy_decl  =  { "policy" ~ string ~ "priority" ~ integer ~ "{" ~ policy_rule* ~ "}" }
policy_rule  =  { allow_rule | deny_rule }

allow_rule   =  { "allow" ~ "when" ~ condition_list ~ effect_clause* ~ ";" }
deny_rule    =  { "deny" ~ "when" ~ condition_list ~ reason_clause? ~ effect_clause* ~ ";" }

reason_clause   = { "reason" ~ string }
effect_clause   = { "effect" ~ effect_type }
effect_type     = { redact_effect | mask_effect | annotate_effect | audit_effect }

redact_effect   = { "Redact" ~ "(" ~ "selector:" ~ string ~ "," ~ "classifier:" ~ string ~ ")" }
mask_effect     = { "Mask"   ~ "(" ~ "selector:" ~ string ~ "," ~ "pattern:"    ~ string ~ ","
                              ~ "replacement:" ~ string ~ ")" }
annotate_effect = { "Annotate" ~ "(" ~ "key:" ~ string ~ "," ~ "value:" ~ string ~ ")" }
audit_effect    = { "Audit" ~ "(" ~ "level:" ~ audit_level ~ ")" }
audit_level     = { "Critical" | "Elevated" | "Standard" }
```

> **Grammar notes for implementer:**
> - `WHITESPACE` and `COMMENT` rules prefixed with `_` are silent — pest consumes them automatically between tokens.
> - `@{ }` rules are atomic — no implicit whitespace inside them. Used for `ident`, `string`, `raw_string`, `integer`, `pattern_ref`, `wildcard`.
> - `condition` is a silent rule (`_{ }`) so it collapses into its matched child in the parse tree. This means `parse_condition` receives pairs with rule `not_condition`, `or_condition`, `atom_condition`, or `true_kw` directly — not wrapped in a `condition` pair.
> - **`raw_string` limitation:** the rule `@{ "r\"" ~ (!"\"" ~ ANY)* ~ "\"" }` cannot match regex patterns that contain a literal `"` character (it stops at the first interior `"`). The spec's example patterns do not contain `"`, so this is not a problem for the current use cases. If future patterns need literal `"` characters, the grammar will need an escape mechanism.
> - If the grammar produces parse errors on valid DSL, run `cargo test --test dsl_tests -- --nocapture` and inspect the pest error output.

- [ ] **Step 2: Verify the grammar file exists and is non-empty**

```bash
wc -l src/dsl/grammar.pest
```

Expected: 50+ lines.

- [ ] **Step 3: Commit**

```bash
git add src/dsl/grammar.pest
git commit -m "feat: add DSL pest PEG grammar"
```

---

### Task 11: DSL parser

**Files:**
- Create: `src/dsl/parser.rs`
- Modify: `src/dsl/mod.rs` (expose `parse` function)

The parser wraps pest's generated output into the AST types. `parse(source: &str) -> Result<PolicyFile, PolicyError>` is the public interface.

- [ ] **Step 1: Write the failing tests**

Create `tests/dsl_tests.rs` with the parser tests (integration-style, using the public `parse` function):

```rust
// tests/dsl_tests.rs
use datalog_noodle::dsl_parse;  // re-exported from lib in Step 5

// ── Helpers ───────────────────────────────────────────────────────────────────

fn parse_ok(src: &str) -> datalog_noodle::dsl::PolicyFile {
    datalog_noodle::dsl_parse(src).expect("expected parse to succeed")
}

fn parse_err(src: &str) -> datalog_noodle::PolicyError {
    datalog_noodle::dsl_parse(src).expect_err("expected parse to fail")
}

// ── Grant declarations ────────────────────────────────────────────────────────

#[test]
fn parse_grant_call_any() {
    let src = r#"grant role "admin" can call tool:any;"#;
    let file = parse_ok(src);
    use datalog_noodle::dsl::ast::{Declaration, GrantDecl, GrantPermission};
    assert_eq!(file.declarations.len(), 1);
    assert!(matches!(
        &file.declarations[0],
        Declaration::Grant(GrantDecl { permission: GrantPermission::CallAny, .. })
    ));
}

#[test]
fn parse_grant_call_category() {
    let src = r#"grant role "analyst" can call tool:category("read-only");"#;
    let file = parse_ok(src);
    use datalog_noodle::dsl::ast::{Declaration, GrantDecl, GrantPermission};
    assert!(matches!(
        &file.declarations[0],
        Declaration::Grant(GrantDecl {
            permission: GrantPermission::CallCategory(cat),
            ..
        }) if cat == "read-only"
    ));
}

#[test]
fn parse_pattern_decl() {
    let src = r#"pattern :sql_injection = r"(?i)(drop|delete)\s+table";"#;
    let file = parse_ok(src);
    use datalog_noodle::dsl::ast::{Declaration, PatternDecl};
    assert!(matches!(
        &file.declarations[0],
        Declaration::Pattern(PatternDecl { name, .. }) if name == "sql_injection"
    ));
}

#[test]
fn parse_rule_decl() {
    let src = r#"
        rule can_call(agent, tool) :-
            agent_role(agent, role),
            tool_category(tool, cat),
            role_permission(role, "call", cat);
    "#;
    let file = parse_ok(src);
    use datalog_noodle::dsl::ast::Declaration;
    assert!(matches!(&file.declarations[0], Declaration::Rule(_)));
    if let Declaration::Rule(r) = &file.declarations[0] {
        assert_eq!(r.name, "can_call");
        assert_eq!(r.params.len(), 2);
        assert_eq!(r.conditions.len(), 3);
    }
}

#[test]
fn parse_policy_block_allow_and_deny() {
    let src = r#"
        policy "default-authz" priority 100 {
            allow when
                tool_call(call_id, agent_id, tool_name),
                can_call(agent_id, tool_name);

            deny when true
                reason "no matching allow rule";
        }
    "#;
    let file = parse_ok(src);
    use datalog_noodle::dsl::ast::{Declaration, PolicyRule};
    assert_eq!(file.declarations.len(), 1);
    if let Declaration::Policy(p) = &file.declarations[0] {
        assert_eq!(p.name, "default-authz");
        assert_eq!(p.priority, 100);
        assert_eq!(p.rules.len(), 2);
        assert!(matches!(p.rules[0], PolicyRule::Allow(_)));
        assert!(matches!(p.rules[1], PolicyRule::Deny(_)));
    } else {
        panic!("expected Policy declaration");
    }
}

#[test]
fn parse_policy_block_with_effects() {
    let src = r#"
        policy "pii-handling" priority 150 {
            allow when
                tool_call(call_id, agent_id, _tool),
                content_tag(call_id, "pii", "high"),
                can_call(agent_id, _tool)
                effect Redact(selector: "response.content", classifier: "pii")
                effect Audit(level: Elevated);
        }
    "#;
    let file = parse_ok(src);
    use datalog_noodle::dsl::ast::{Declaration, PolicyRule, EffectDecl, AuditLevelDecl};
    if let Declaration::Policy(p) = &file.declarations[0] {
        if let PolicyRule::Allow(allow) = &p.rules[0] {
            assert_eq!(allow.effects.len(), 2);
            assert!(matches!(allow.effects[0], EffectDecl::Redact { .. }));
            assert!(matches!(
                allow.effects[1],
                EffectDecl::Audit { level: AuditLevelDecl::Elevated }
            ));
        } else { panic!("expected Allow rule"); }
    } else { panic!("expected Policy declaration"); }
}

#[test]
fn parse_or_condition_in_rule() {
    let src = r#"
        rule has_forbidden_arg(call_id) :-
            call_arg(call_id, _, value),
            matches(value, :sql_injection) or matches(value, :path_traversal);
    "#;
    let file = parse_ok(src);
    use datalog_noodle::dsl::ast::{Declaration, ConditionClause};
    if let Declaration::Rule(r) = &file.declarations[0] {
        assert!(r.conditions.iter().any(|c| matches!(c, ConditionClause::Or(_))));
    }
}

// ── Not conditions ────────────────────────────────────────────────────────────

#[test]
fn parse_not_condition_in_policy() {
    let src = r#"
        policy "pii-handling" priority 150 {
            deny when
                tool_call(call_id, agent_id, _tool),
                content_tag(call_id, "pii", "high"),
                not can_call(agent_id, _tool)
                reason "agent not permitted and PII present"
                effect Audit(level: Critical);
        }
    "#;
    let file = parse_ok(src);
    use datalog_noodle::dsl::ast::{Declaration, PolicyRule, ConditionClause};
    if let Declaration::Policy(p) = &file.declarations[0] {
        if let PolicyRule::Deny(deny) = &p.rules[0] {
            assert!(deny.conditions.iter().any(|c| matches!(c, ConditionClause::Not(_))));
            assert_eq!(deny.reason.as_deref(), Some("agent not permitted and PII present"));
        } else { panic!("expected Deny rule"); }
    } else { panic!("expected Policy declaration"); }
}

// ── Categorize and classify declarations ─────────────────────────────────────

#[test]
fn parse_categorize_decl() {
    let src = r#"
        categorize tool "db_query" as "read-only";
        categorize tool "db_write" as "write";
    "#;
    let file = parse_ok(src);
    use datalog_noodle::dsl::ast::{Declaration, CategorizeDecl};
    assert_eq!(file.declarations.len(), 2);
    assert!(matches!(
        &file.declarations[0],
        Declaration::Categorize(CategorizeDecl { tool, category })
        if tool == "db_query" && category == "read-only"
    ));
}

#[test]
fn parse_classify_decl() {
    let src = r#"
        classify resource "data/finance/*" as sensitivity "high";
        classify resource "data/public/*"  as sensitivity "low";
    "#;
    let file = parse_ok(src);
    use datalog_noodle::dsl::ast::{Declaration, ClassifyDecl};
    assert_eq!(file.declarations.len(), 2);
    assert!(matches!(
        &file.declarations[0],
        Declaration::Classify(ClassifyDecl { resource_pattern, sensitivity })
        if resource_pattern == "data/finance/*" && sensitivity == "high"
    ));
}

// ── Error cases ───────────────────────────────────────────────────────────────

#[test]
fn parse_error_missing_semicolon() {
    let src = r#"grant role "admin" can call tool:any"#;
    let err = parse_err(src);
    assert!(matches!(err, datalog_noodle::PolicyError::Parse(_)));
}

#[test]
fn parse_error_unknown_keyword() {
    let src = r#"forbid role "guest" from everything;"#;
    let err = parse_err(src);
    assert!(matches!(err, datalog_noodle::PolicyError::Parse(_)));
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test --test dsl_tests
```

Expected: compile error — `dsl_parse` and `dsl` module not accessible from test.

- [ ] **Step 3: Implement `src/dsl/parser.rs`**

```rust
// src/dsl/parser.rs
use pest::Parser;
use pest::iterators::Pair;
use pest_derive::Parser;
use crate::error::PolicyError;
use crate::dsl::ast::*;

#[derive(Parser)]
#[grammar = "dsl/grammar.pest"]
struct DslParser;

/// Parse a DSL source string into a `PolicyFile` AST.
/// Returns `PolicyError::Parse` on any syntax error.
pub fn parse(source: &str) -> Result<PolicyFile, PolicyError> {
    let pairs = DslParser::parse(Rule::policy_file, source)
        .map_err(|e| PolicyError::Parse(e.to_string()))?;
    let mut declarations = Vec::new();
    for pair in pairs {
        match pair.as_rule() {
            Rule::declaration => {
                let inner = pair.into_inner().next().unwrap();
                declarations.push(parse_declaration(inner)?);
            }
            Rule::EOI => {}
            _ => {}
        }
    }
    Ok(PolicyFile { declarations })
}

fn parse_declaration(pair: Pair<Rule>) -> Result<Declaration, PolicyError> {
    match pair.as_rule() {
        Rule::grant_decl      => Ok(Declaration::Grant(parse_grant(pair)?)),
        Rule::categorize_decl => Ok(Declaration::Categorize(parse_categorize(pair)?)),
        Rule::classify_decl   => Ok(Declaration::Classify(parse_classify(pair)?)),
        Rule::pattern_decl    => Ok(Declaration::Pattern(parse_pattern(pair)?)),
        Rule::rule_decl       => Ok(Declaration::Rule(parse_rule_decl(pair)?)),
        Rule::policy_decl     => Ok(Declaration::Policy(parse_policy_decl(pair)?)),
        r => Err(PolicyError::Parse(format!("unexpected rule: {:?}", r))),
    }
}

fn parse_grant(pair: Pair<Rule>) -> Result<GrantDecl, PolicyError> {
    let mut inner = pair.into_inner();
    let role = unquote(inner.next().unwrap().as_str());
    let perm_pair = inner.next().unwrap().into_inner().next().unwrap();
    let permission = match perm_pair.as_rule() {
        Rule::call_any      => GrantPermission::CallAny,
        Rule::call_category => {
            let s = unquote(perm_pair.into_inner().next().unwrap().as_str());
            GrantPermission::CallCategory(s)
        }
        Rule::access_pattern => {
            let s = unquote(perm_pair.into_inner().next().unwrap().as_str());
            GrantPermission::AccessPattern(s)
        }
        r => return Err(PolicyError::Parse(format!("unexpected grant perm: {:?}", r))),
    };
    Ok(GrantDecl { role, permission })
}

fn parse_categorize(pair: Pair<Rule>) -> Result<CategorizeDecl, PolicyError> {
    let mut inner = pair.into_inner();
    let tool     = unquote(inner.next().unwrap().as_str());
    let category = unquote(inner.next().unwrap().as_str());
    Ok(CategorizeDecl { tool, category })
}

fn parse_classify(pair: Pair<Rule>) -> Result<ClassifyDecl, PolicyError> {
    let mut inner = pair.into_inner();
    let resource_pattern = unquote(inner.next().unwrap().as_str());
    let sensitivity      = unquote(inner.next().unwrap().as_str());
    Ok(ClassifyDecl { resource_pattern, sensitivity })
}

fn parse_pattern(pair: Pair<Rule>) -> Result<PatternDecl, PolicyError> {
    let mut inner = pair.into_inner();
    let name_tok = inner.next().unwrap().as_str(); // ":sql_injection"
    let name     = name_tok.trim_start_matches(':').to_string();
    let raw      = inner.next().unwrap().as_str();  // r"..."
    let source   = raw
        .trim_start_matches("r\"")
        .trim_end_matches('"')
        .to_string();
    Ok(PatternDecl { name, source })
}

fn parse_rule_decl(pair: Pair<Rule>) -> Result<RuleDecl, PolicyError> {
    let mut inner = pair.into_inner();
    let name   = inner.next().unwrap().as_str().to_string();
    let params = parse_param_list(inner.next().unwrap())?;
    let conditions = parse_condition_list(inner.next().unwrap())?;
    Ok(RuleDecl { name, params, conditions })
}

fn parse_param_list(pair: Pair<Rule>) -> Result<Vec<Param>, PolicyError> {
    // Each child of `param_list` is a `param` pair. Each `param` wraps
    // either a `wildcard` or an `ident`. Dispatch on the inner rule variant
    // rather than inspecting raw text, so future grammar changes don't silently
    // break this.
    pair.into_inner().map(|param_pair| {
        let inner = param_pair.into_inner().next().unwrap();
        match inner.as_rule() {
            Rule::wildcard => {
                let s = inner.as_str();
                if s == "_" {
                    Ok(Param::Wildcard)
                } else {
                    Ok(Param::NamedWildcard(s[1..].to_string()))
                }
            }
            Rule::ident => Ok(Param::Named(inner.as_str().to_string())),
            r => Err(PolicyError::Parse(format!("unexpected param rule: {:?}", r))),
        }
    }).collect()
}

fn parse_condition_list(pair: Pair<Rule>) -> Result<Vec<ConditionClause>, PolicyError> {
    pair.into_inner().map(parse_condition).collect()
}

fn parse_condition(pair: Pair<Rule>) -> Result<ConditionClause, PolicyError> {
    match pair.as_rule() {
        Rule::atom_condition => Ok(ConditionClause::Atom(parse_atom(pair)?)),
        Rule::not_condition  => {
            let inner = pair.into_inner().next().unwrap();
            Ok(ConditionClause::Not(parse_atom(inner)?))
        }
        Rule::or_condition   => {
            let atoms: Result<Vec<_>, _> = pair.into_inner().map(parse_atom).collect();
            Ok(ConditionClause::Or(atoms?))
        }
        Rule::true_kw        => Ok(ConditionClause::True),
        r => Err(PolicyError::Parse(format!("unexpected condition: {:?}", r))),
    }
}

fn parse_atom(pair: Pair<Rule>) -> Result<AtomCondition, PolicyError> {
    let mut inner = pair.into_inner();
    let predicate = inner.next().unwrap().as_str().to_string();
    let args = match inner.next() {
        Some(arg_list) => arg_list.into_inner().map(parse_arg).collect::<Result<_, _>>()?,
        None           => vec![],
    };
    Ok(AtomCondition { predicate, args })
}

fn parse_arg(pair: Pair<Rule>) -> Result<Arg, PolicyError> {
    match pair.as_rule() {
        Rule::string      => Ok(Arg::StringLit(unquote(pair.as_str()))),
        Rule::integer     => Ok(Arg::Integer(pair.as_str().parse().unwrap())),
        Rule::pattern_ref => Ok(Arg::PatternRef(pair.as_str().trim_start_matches(':').to_string())),
        Rule::wildcard    => {
            let s = pair.as_str();
            if s == "_" {
                Ok(Arg::Wildcard)
            } else {
                Ok(Arg::NamedWildcard(s[1..].to_string()))
            }
        }
        Rule::ident       => Ok(Arg::Variable(pair.as_str().to_string())),
        r => Err(PolicyError::Parse(format!("unexpected arg: {:?}", r))),
    }
}

fn parse_policy_decl(pair: Pair<Rule>) -> Result<PolicyDecl, PolicyError> {
    let mut inner = pair.into_inner();
    let name     = unquote(inner.next().unwrap().as_str());
    let priority = inner.next().unwrap().as_str().parse::<u32>().unwrap();
    let rules: Result<Vec<_>, _> = inner.map(parse_policy_rule).collect();
    Ok(PolicyDecl { name, priority, rules: rules? })
}

fn parse_policy_rule(pair: Pair<Rule>) -> Result<PolicyRule, PolicyError> {
    let inner = pair.into_inner().next().unwrap();
    match inner.as_rule() {
        Rule::allow_rule => Ok(PolicyRule::Allow(parse_allow_rule(inner)?)),
        Rule::deny_rule  => Ok(PolicyRule::Deny(parse_deny_rule(inner)?)),
        r => Err(PolicyError::Parse(format!("unexpected policy rule: {:?}", r))),
    }
}

fn parse_allow_rule(pair: Pair<Rule>) -> Result<AllowRule, PolicyError> {
    let mut conditions = Vec::new();
    let mut effects    = Vec::new();
    for child in pair.into_inner() {
        match child.as_rule() {
            Rule::condition_list => conditions = parse_condition_list(child)?,
            Rule::effect_clause  => effects.push(parse_effect_clause(child)?),
            _ => {}
        }
    }
    Ok(AllowRule { conditions, effects })
}

fn parse_deny_rule(pair: Pair<Rule>) -> Result<DenyRule, PolicyError> {
    let mut conditions = Vec::new();
    let mut reason     = None;
    let mut effects    = Vec::new();
    for child in pair.into_inner() {
        match child.as_rule() {
            Rule::condition_list => conditions = parse_condition_list(child)?,
            Rule::reason_clause  => {
                reason = Some(unquote(child.into_inner().next().unwrap().as_str()));
            }
            Rule::effect_clause  => effects.push(parse_effect_clause(child)?),
            _ => {}
        }
    }
    Ok(DenyRule { conditions, reason, effects })
}

fn parse_effect_clause(pair: Pair<Rule>) -> Result<EffectDecl, PolicyError> {
    let effect = pair.into_inner().next().unwrap();
    let inner_effect = effect.into_inner().next().unwrap();
    match inner_effect.as_rule() {
        Rule::redact_effect => {
            let mut i = inner_effect.into_inner();
            Ok(EffectDecl::Redact {
                selector:   unquote(i.next().unwrap().as_str()),
                classifier: unquote(i.next().unwrap().as_str()),
            })
        }
        Rule::mask_effect => {
            let mut i = inner_effect.into_inner();
            Ok(EffectDecl::Mask {
                selector:    unquote(i.next().unwrap().as_str()),
                pattern:     unquote(i.next().unwrap().as_str()),
                replacement: unquote(i.next().unwrap().as_str()),
            })
        }
        Rule::annotate_effect => {
            let mut i = inner_effect.into_inner();
            Ok(EffectDecl::Annotate {
                key:   unquote(i.next().unwrap().as_str()),
                value: unquote(i.next().unwrap().as_str()),
            })
        }
        Rule::audit_effect => {
            let level_str = inner_effect.into_inner().next().unwrap().as_str();
            let level = match level_str {
                "Critical" => AuditLevelDecl::Critical,
                "Elevated" => AuditLevelDecl::Elevated,
                "Standard" => AuditLevelDecl::Standard,
                s => return Err(PolicyError::Parse(format!("unknown audit level: {}", s))),
            };
            Ok(EffectDecl::Audit { level })
        }
        r => Err(PolicyError::Parse(format!("unexpected effect: {:?}", r))),
    }
}

/// Strip exactly one surrounding double-quote on each side from a `string` token.
/// The `string` grammar rule always produces exactly one leading and one trailing `"`.
fn unquote(s: &str) -> String {
    s[1..s.len() - 1].to_string()
}
```

- [ ] **Step 4: Update `src/dsl/mod.rs` to expose the parse function and make `ast` public**

```rust
// src/dsl/mod.rs
pub mod ast;                    // public so integration tests can use dsl::ast::*
pub(crate) mod compiler;
pub(crate) mod parser;

pub(crate) use parser::parse;

pub use ast::PolicyFile;        // convenience re-export
```

- [ ] **Step 5: Update `src/lib.rs` to make the `dsl` module public and expose `dsl_parse`**

In `src/lib.rs`, change the `dsl` module declaration from `pub(crate)` to `pub`:

```rust
// src/lib.rs  (replace the existing pub(crate) mod dsl line)
pub mod dsl;                    // was pub(crate) — making it public exposes dsl::ast to tests
```

Then add the `dsl_parse` free function (no new module block needed):

```rust
/// Parse a DSL source string into a `PolicyFile` AST.
/// Exposed for integration tests and gateway use.
pub fn dsl_parse(source: &str) -> Result<dsl::ast::PolicyFile, error::PolicyError> {
    dsl::parser::parse(source)
}
```

The integration tests access `datalog_noodle::dsl::ast::*` via the now-public `dsl` module and call `datalog_noodle::dsl_parse(...)`. No module name conflict occurs.

- [ ] **Step 6: Run the integration tests**

```bash
cargo test --test dsl_tests
```

Expected: all 12 tests pass. If a test fails due to parse errors, run with `-- --nocapture` and inspect the pest error output. Common fixes:
- Grammar rule name mismatch (check `Rule::` variants match the grammar rule names)
- Ambiguous rule ordering in the grammar (try reordering alternatives)
- `unquote` stripping the wrong characters (check `pair.as_str()` for a quoted string includes the quotes)

- [ ] **Step 7: Run full test suite**

```bash
cargo test
```

Expected: all tests pass.

- [ ] **Step 8: Commit**

```bash
git add src/dsl/ast.rs src/dsl/grammar.pest src/dsl/parser.rs src/dsl/mod.rs src/lib.rs tests/dsl_tests.rs
git commit -m "feat: add DSL parser (pest grammar + AST + parse function)"
```
