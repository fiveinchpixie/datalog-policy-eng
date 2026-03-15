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

---

## Chunk 4: DSL Compilation

**Covers:** `src/dsl/compiler.rs`

**Goal:** Transform a validated `PolicyFile` AST into a `CompiledPolicy` — a CozoDB instance preloaded with policy facts and a `decision_script` string that encodes all decision logic as parameterized Datalog.

**Compilation pipeline:**
1. Validate: check undefined pattern references; undefined rule references are permitted (CozoDB will error at eval time)
2. Create CozoDB stored relations for policy facts
3. Compile `PatternDecl` → `Regex` objects in `CompiledPolicy.patterns` + insert source into CozoDB `forbidden_pattern` relation for auditability
4. Compile `GrantDecl`, `CategorizeDecl`, `ClassifyDecl` → insert rows into stored relations
5. Build `decision_script`: a single Cozo script that binds request facts from `$params`, defines inline rules from DSL `rule` blocks, encodes priority-ordered decision logic, and ends with `?[verdict, reason, effects_json, block_name] := ...`

**Key design decisions baked into the generated script:**
- Request facts arrive as `$param` vectors (e.g., `tool_call[call_id, agent_id, tool_name] <- $tool_calls`)
- `matched_value[value, pattern_name] <- $matched_values` is populated by the evaluator's builtins pre-pass — the compiler rewrites every `matches(value, :pattern_name)` condition to `matched_value[value, "pattern_name"]`
- Stored policy fact relations are accessed with the `*relation_name[...]` prefix in Cozo; request fact relations (from params) have no prefix
- `Or` conditions in rule bodies are expanded to multiple rule heads (one per Or arm)
- Priority ordering: for each block at priority P, its sub-rules include `not b_{higher_block}_matched[call_id]` guards; deny beats allow at equal priority via separate decision rules
- `deny when true` compiles `ConditionClause::True` to `tool_call[call_id, _, _]` to bind `call_id`
- Effects are serialized to a JSON string embedded in the Cozo rule head

---

### Task 12: DSL Compiler

**Files:**
- Create: `src/dsl/compiler.rs`
- Modify: `src/dsl/mod.rs` (expose `compile` function)
- Modify: `src/lib.rs` (expose `dsl_compile` free function)
- Modify: `tests/dsl_tests.rs` (add compiler tests)

- [ ] **Step 1: Write failing validation error tests**

Add to `tests/dsl_tests.rs`:

```rust
// ── Compiler validation errors ────────────────────────────────────────────────

#[test]
fn compile_error_undefined_pattern_ref() {
    let src = r#"
        rule bad(call_id) :-
            call_arg(call_id, _, value),
            matches(value, :undefined_pattern);
    "#;
    let err = datalog_noodle::dsl_compile(src, "v1")
        .expect_err("expected compile error");
    assert!(
        matches!(err, datalog_noodle::PolicyError::Compile(_)),
        "expected PolicyError::Compile, got {:?}", err
    );
    let msg = err.to_string();
    assert!(
        msg.contains("undefined_pattern"),
        "error message should name the undefined pattern, got: {}", msg
    );
}

#[test]
fn compile_error_invalid_regex() {
    // Regex with unclosed bracket — fails at Regex::new time
    let src = r#"pattern :bad = r"[unclosed";"#;
    let err = datalog_noodle::dsl_compile(src, "v1")
        .expect_err("expected compile error");
    assert!(matches!(err, datalog_noodle::PolicyError::Compile(_)));
}

#[test]
fn compile_error_allow_when_true() {
    // `allow when true` is a security hole — unconditionally allows every call.
    // Only `deny when true` is permitted.
    let src = r#"
        policy "bad" priority 100 {
            allow when true;
        }
    "#;
    let err = datalog_noodle::dsl_compile(src, "v1")
        .expect_err("expected compile error for allow when true");
    assert!(matches!(err, datalog_noodle::PolicyError::Compile(_)));
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("allow when true") || msg.contains("not permitted"),
        "error should mention allow-when-true restriction, got: {}", err
    );
}

#[test]
fn compile_error_or_in_policy_block() {
    // Or conditions are not supported directly in policy blocks.
    // Authors must extract Or logic into a `rule` declaration.
    let src = r#"
        pattern :p1 = r"foo";
        pattern :p2 = r"bar";
        policy "bad" priority 100 {
            deny when
                tool_call(call_id, _, _),
                matches(v, :p1) or matches(v, :p2);
        }
    "#;
    let err = datalog_noodle::dsl_compile(src, "v1")
        .expect_err("expected compile error for Or in policy block");
    assert!(matches!(err, datalog_noodle::PolicyError::Compile(_)));
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("or") || msg.contains("policy block"),
        "error message should mention Or or policy block restriction, got: {}", err
    );
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test --test dsl_tests compile_error
```

Expected: compile error — `dsl_compile` not defined.

- [ ] **Step 3: Implement `src/dsl/compiler.rs` — validation and skeleton**

```rust
// src/dsl/compiler.rs
use std::collections::{HashMap, HashSet};
use regex::Regex;
use crate::dsl::ast::*;
use crate::error::PolicyError;
use crate::policy::compiled::CompiledPolicy;

/// Predicate names that map to CozoDB *stored* relations.
/// These are prefixed with `*` in generated Cozo queries.
/// Request-fact predicates (tool_call, agent_role, call_arg, etc.) have no prefix.
///
/// This list covers all policy fact relations defined in the spec, even those
/// not yet inserted by this compiler (e.g. clearance_grants, tag_effect).
/// If a stored relation is missing from this list, rules that reference it will
/// silently emit it without the `*` prefix and fail at eval time with a
/// "relation not found" error rather than a compile-time error.
const STORED_RELATIONS: &[&str] = &[
    "role_permission",
    "tool_category",
    "resource_sensitivity",
    "forbidden_pattern",
    "clearance_grants",
    "forbidden_arg_key",
    "allowed_domain",
    "tag_effect",
    "sensitivity_effect",
];

/// Compile a DSL source string into a `CompiledPolicy`.
///
/// Returns `PolicyError::Parse` on syntax errors (from the parser).
/// Returns `PolicyError::Compile` on semantic errors (undefined patterns, invalid regex, etc.).
pub fn compile(source: &str, version: &str) -> Result<CompiledPolicy, PolicyError> {
    let ast = crate::dsl::parser::parse(source)?;
    compile_ast(ast, version)
}

fn compile_ast(file: PolicyFile, version: &str) -> Result<CompiledPolicy, PolicyError> {
    validate(&file)?;
    let db = cozo::DbInstance::new("mem", "", serde_json::json!({}))
        .map_err(|e| PolicyError::Compile(format!("failed to create CozoDB: {}", e)))?;
    init_db(&db)?;
    let patterns = compile_patterns(&file, &db)?;
    compile_policy_facts(&file, &db)?;
    let decision_script = build_decision_script(&file)?;
    Ok(CompiledPolicy { version: version.to_string(), db, decision_script, patterns })
}

// ── Validation ────────────────────────────────────────────────────────────────

fn validate(file: &PolicyFile) -> Result<(), PolicyError> {
    let declared_patterns: HashSet<&str> = file.declarations.iter()
        .filter_map(|d| match d {
            Declaration::Pattern(p) => Some(p.name.as_str()),
            _ => None,
        })
        .collect();

    for decl in &file.declarations {
        match decl {
            Declaration::Rule(r) => {
                // Rule names must be valid CozoDB identifiers: letters, digits, underscores.
                // The grammar allows hyphens in idents, but CozoDB rejects them.
                if !r.name.chars().next().map(|c| c.is_alphabetic() || c == '_').unwrap_or(false)
                    || !r.name.chars().all(|c| c.is_alphanumeric() || c == '_')
                {
                    return Err(PolicyError::Compile(format!(
                        "rule name `{}` is not a valid CozoDB identifier; \
                         use only letters, digits, and underscores (no hyphens)",
                        r.name
                    )));
                }
                let or_count = r.conditions.iter()
                    .filter(|c| matches!(c, ConditionClause::Or(_)))
                    .count();
                if or_count > 1 {
                    return Err(PolicyError::Compile(format!(
                        "rule `{}` has {} Or conditions; at most one Or group is supported per rule. \
                         Split into separate rule declarations instead.",
                        r.name, or_count
                    )));
                }
                // `True` is only valid as the sole condition in a policy-block `deny when true`.
                // In a rule body it introduces an unbound `call_id` variable at eval time.
                if r.conditions.iter().any(|c| matches!(c, ConditionClause::True)) {
                    return Err(PolicyError::Compile(format!(
                        "rule `{}` uses `true` as a condition; `true` is only valid in policy \
                         blocks as the sole condition in `deny when true`",
                        r.name
                    )));
                }
                for cond in &r.conditions {
                    check_pattern_refs(cond, &declared_patterns)?;
                }
            }
            Declaration::Policy(p) => {
                for rule in &p.rules {
                    let conditions = match rule {
                        PolicyRule::Allow(a) => &a.conditions,
                        PolicyRule::Deny(d) => &d.conditions,
                    };
                    // `allow when true` is a security hole: it unconditionally allows every
                    // call in the block. Only `deny when true` is valid (default-deny fallback).
                    if matches!(rule, PolicyRule::Allow(_))
                        && conditions.iter().any(|c| matches!(c, ConditionClause::True))
                    {
                        return Err(PolicyError::Compile(
                            "`allow when true` is not permitted; `true` may only appear \
                             in `deny when true` as the default-deny fallback".to_string()
                        ));
                    }
                    for cond in conditions {
                        check_pattern_refs(cond, &declared_patterns)?;
                        // Or conditions in policy blocks are not supported.
                        // The Cozo compiler cannot expand them to multiple decision rule
                        // heads automatically in that context. Authors must use a `rule`
                        // declaration to express the Or logic.
                        if matches!(cond, ConditionClause::Or(_)) {
                            return Err(PolicyError::Compile(
                                "Or conditions are not allowed directly in policy blocks; \
                                 extract the logic into a `rule` declaration instead".to_string()
                            ));
                        }
                    }
                    // `True` must be the sole condition (mixing it with others is nonsensical).
                    if conditions.iter().any(|c| matches!(c, ConditionClause::True))
                        && conditions.len() > 1
                    {
                        return Err(PolicyError::Compile(
                            "`true` cannot be mixed with other conditions; \
                             use it alone as `deny when true` for the default-deny fallback"
                                .to_string()
                        ));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn check_pattern_refs(cond: &ConditionClause, declared: &HashSet<&str>) -> Result<(), PolicyError> {
    let atoms: Vec<&AtomCondition> = match cond {
        ConditionClause::Atom(a) => vec![a],
        ConditionClause::Not(a) => vec![a],
        ConditionClause::Or(atoms) => atoms.iter().collect(),
        ConditionClause::True => return Ok(()),
    };
    for atom in atoms {
        if atom.predicate == "matches" {
            for arg in &atom.args {
                if let Arg::PatternRef(name) = arg {
                    if !declared.contains(name.as_str()) {
                        return Err(PolicyError::Compile(format!(
                            "undefined pattern :{name}; declare it with `pattern :{name} = r\"...\";`"
                        )));
                    }
                }
            }
        }
    }
    Ok(())
}
```

- [ ] **Step 4a: Wire up `dsl_compile` in `mod.rs` and `lib.rs`**

Chunk 3 Task 11 Step 4 already wrote `src/dsl/mod.rs` with `pub(crate) mod compiler;` present. Add only the `use` re-export line — do NOT add a second `mod compiler;` declaration:

```rust
// src/dsl/mod.rs — add only this line (mod compiler; already present from Chunk 3)
pub(crate) use compiler::compile;
```

In `src/lib.rs`, add:
```rust
/// Compile a DSL source string into a `CompiledPolicy`.
pub fn dsl_compile(source: &str, version: &str) -> Result<policy::compiled::CompiledPolicy, error::PolicyError> {
    dsl::compiler::compile(source, version)
}
```

- [ ] **Step 4b: Run validation tests to verify they pass**

```bash
cargo test --test dsl_tests compile_error
```

Expected: all 3 `compile_error_*` tests pass.

- [ ] **Step 4c: Verify the cozo `run_script` param type**

Before writing tests that pass params to `run_script`, check the actual API:

```bash
cargo doc -p cozo --open
```

Find `DbInstance::run_script`. The third argument (params) is one of:
- `BTreeMap<String, cozo::DataValue>` — use `cozo::DataValue::List(vec![])`
- `BTreeMap<String, serde_json::Value>` — use `serde_json::json!([])`

Update all `run_script` param arguments in Steps 5 and 7 to match. The tests as written assume `cozo::DataValue`; substitute `serde_json::json!([])` if needed.

- [ ] **Step 5: Write failing compilation success tests**

Add to `src/dsl/compiler.rs` (inside `#[cfg(test)] mod tests`):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_minimal_policy() {
        let src = r#"policy "default-deny" priority 100 { deny when true reason "no rule matched"; }"#;
        let policy = compile(src, "v1").expect("compile succeeded");
        assert_eq!(policy.version, "v1");
        // decision_script must reference the block
        assert!(
            policy.decision_script.contains("b_default_deny"),
            "decision_script missing block name: {}", policy.decision_script
        );
    }

    #[test]
    fn compile_pattern_creates_regex() {
        let src = r#"pattern :sql_injection = r"(?i)(drop|delete)\s+table";"#;
        let policy = compile(src, "v1").expect("compile succeeded");
        assert!(policy.patterns.contains_key("sql_injection"));
        assert!(policy.patterns["sql_injection"].is_match("DROP TABLE users"));
        assert!(!policy.patterns["sql_injection"].is_match("SELECT * FROM users"));
    }

    #[test]
    fn compile_grant_stored_in_cozo() {
        let src = r#"grant role "analyst" can call tool:category("read-only");"#;
        let policy = compile(src, "v1").expect("compile succeeded");
        let result = policy.db
            .run_script("?[role, action, rp] := *role_permission[role, action, rp]", Default::default())
            .expect("query succeeded");
        assert_eq!(result.rows.len(), 1);
    }

    #[test]
    fn compile_categorize_stored_in_cozo() {
        let src = r#"categorize tool "db_query" as "read-only";"#;
        let policy = compile(src, "v1").expect("compile succeeded");
        let result = policy.db
            .run_script("?[tn, cat] := *tool_category[tn, cat]", Default::default())
            .expect("query succeeded");
        assert_eq!(result.rows.len(), 1);
    }

    #[test]
    fn compile_classify_stored_in_cozo() {
        let src = r#"classify resource "data/finance/*" as sensitivity "high";"#;
        let policy = compile(src, "v1").expect("compile succeeded");
        let result = policy.db
            .run_script("?[up, lvl] := *resource_sensitivity[up, lvl]", Default::default())
            .expect("query succeeded");
        assert_eq!(result.rows.len(), 1);
    }

    #[test]
    fn compile_decision_script_no_syntax_error() {
        // Compile a representative policy and verify the generated decision_script
        // actually executes in CozoDB with no errors.
        // Supply empty param vectors for each request fact type — this lets CozoDB run
        // the full script (rather than failing on a missing-param error) and confirms
        // both syntax and structural correctness. Zero rows are expected since there
        // are no request facts to match against.
        use std::collections::BTreeMap;
        let src = r#"
            grant role "analyst" can call tool:category("read-only");
            categorize tool "db_query" as "read-only";
            rule can_call(agent, tool) :-
                agent_role(agent, role),
                tool_category(tool, cat),
                role_permission(role, "call", cat);
            policy "default-authz" priority 100 {
                allow when
                    tool_call(call_id, agent_id, tool_name),
                    can_call(agent_id, tool_name);
                deny when true
                    reason "no matching allow rule";
            }
        "#;
        let policy = compile(src, "v1").expect("compile succeeded");
        // Supply empty param vectors for every request fact binding in REQUEST_FACT_BINDINGS.
        // The `cozo::DataValue::List(vec![])` value represents an empty relation.
        // If the cozo version in use expects `BTreeMap<String, serde_json::Value>` instead,
        // replace `cozo::DataValue::List(vec![])` with `serde_json::json!([])`.
        // Check `cargo doc -p cozo --open` for the exact `run_script` param type.
        let mut params: BTreeMap<String, cozo::DataValue> = BTreeMap::new();
        for key in &[
            "tool_calls", "agents", "agent_roles", "agent_clearances", "delegations", "users",
            "call_args", "tool_results", "resource_accesses", "resource_mimes",
            "content_tags", "timestamps", "call_counts", "environment", "matched_values",
        ] {
            params.insert(key.to_string(), cozo::DataValue::List(vec![]));
        }
        let result = policy.db.run_script(&policy.decision_script, params)
            .unwrap_or_else(|e| panic!(
                "decision_script failed:\n{}\n\nError: {}", policy.decision_script, e
            ));
        // No request facts → no rules fire → zero output rows.
        assert_eq!(result.rows.len(), 0, "expected empty result with no request facts");
    }

    #[test]
    fn compile_pattern_also_stored_in_cozo() {
        // Verify pattern source is inserted into the forbidden_pattern CozoDB relation
        // for auditability, in addition to being compiled into the patterns HashMap.
        let src = r#"pattern :sql_injection = r"(?i)(drop|delete)\s+table";"#;
        let policy = compile(src, "v1").expect("compile succeeded");
        let result = policy.db
            .run_script("?[name, source] := *forbidden_pattern[name, source]", Default::default())
            .expect("query succeeded");
        assert_eq!(result.rows.len(), 1, "pattern source should be stored in forbidden_pattern");
    }

    #[test]
    fn compile_matches_rewrites_to_matched_value() {
        let src = r#"
            pattern :sql_injection = r"(?i)(drop|delete)\s+table";
            rule has_forbidden_arg(call_id) :-
                call_arg(call_id, _, value),
                matches(value, :sql_injection);
        "#;
        let policy = compile(src, "v1").expect("compile succeeded");
        assert!(
            policy.decision_script.contains("matched_value"),
            "matches() should be rewritten to matched_value, got: {}",
            policy.decision_script
        );
        assert!(
            !policy.decision_script.contains("matches("),
            "raw matches() should not appear in decision_script"
        );
    }
}
```

- [ ] **Step 6: Run tests to verify they fail**

```bash
cargo test --lib dsl::compiler
```

Expected: compile errors — `init_db`, `compile_patterns`, etc. not defined.

- [ ] **Step 7: Implement the full compiler**

Add the remaining functions to `src/dsl/compiler.rs`:

```rust
// ── DB initialization ─────────────────────────────────────────────────────────

fn init_db(db: &cozo::DbInstance) -> Result<(), PolicyError> {
    // Each :create is a separate system script. CozoDB requires one system op per call.
    // All nine spec-defined policy fact relations are created here so that:
    // (a) STORED_RELATIONS prefix rewriting is correct for all of them, and
    // (b) DSL rules referencing any of them produce valid scripts at compile time.
    let creates = [
        ":create role_permission {role: String, action: String, resource_pattern: String}",
        ":create tool_category {tool_name: String, category: String}",
        ":create resource_sensitivity {uri_pattern: String, level: String}",
        ":create forbidden_pattern {name: String, source: String}",
        ":create clearance_grants {clearance: String, privilege: String}",
        ":create forbidden_arg_key {tool_name: String, key: String}",
        ":create allowed_domain {uri_pattern: String}",
        ":create tag_effect {tag: String, value: String, effect: String}",
        ":create sensitivity_effect {level: String, effect: String}",
    ];
    for stmt in &creates {
        db.run_script(stmt, Default::default())
            .map_err(|e| PolicyError::Compile(format!("DB init error on `{stmt}`: {e}")))?;
    }
    Ok(())
}

// ── Pattern compilation ───────────────────────────────────────────────────────

fn compile_patterns(
    file: &PolicyFile,
    db: &cozo::DbInstance,
) -> Result<HashMap<String, Regex>, PolicyError> {
    let mut patterns = HashMap::new();
    for decl in &file.declarations {
        if let Declaration::Pattern(p) = decl {
            let regex = Regex::new(&p.source)
                .map_err(|e| PolicyError::Compile(format!("invalid regex :{}: {}", p.name, e)))?;
            patterns.insert(p.name.clone(), regex);
            // Store source for auditability
            let script = format!(
                "?[name, source] <- [[{}, {}]]\n:put forbidden_pattern {{name, source}}",
                cozo_str(&p.name),
                cozo_str(&p.source)
            );
            db.run_script(&script, Default::default())
                .map_err(|e| PolicyError::Compile(format!("pattern insert error: {e}")))?;
        }
    }
    Ok(patterns)
}

// ── Policy fact compilation ───────────────────────────────────────────────────

fn compile_policy_facts(file: &PolicyFile, db: &cozo::DbInstance) -> Result<(), PolicyError> {
    for decl in &file.declarations {
        match decl {
            Declaration::Grant(g)      => compile_grant(g, db)?,
            Declaration::Categorize(c) => compile_categorize(c, db)?,
            Declaration::Classify(c)   => compile_classify(c, db)?,
            _ => {}
        }
    }
    Ok(())
}

fn compile_grant(g: &GrantDecl, db: &cozo::DbInstance) -> Result<(), PolicyError> {
    let (action, resource_pattern) = match &g.permission {
        GrantPermission::CallAny          => ("call".to_string(), "*".to_string()),
        GrantPermission::CallCategory(c)  => ("call".to_string(), c.clone()),
        GrantPermission::AccessPattern(p) => ("access".to_string(), p.clone()),
    };
    let script = format!(
        "?[role, action, resource_pattern] <- [[{}, {}, {}]]\n\
         :put role_permission {{role, action, resource_pattern}}",
        cozo_str(&g.role), cozo_str(&action), cozo_str(&resource_pattern)
    );
    db.run_script(&script, Default::default())
        .map_err(|e| PolicyError::Compile(format!("grant insert error: {e}")))?;
    Ok(())
}

fn compile_categorize(c: &CategorizeDecl, db: &cozo::DbInstance) -> Result<(), PolicyError> {
    let script = format!(
        "?[tool_name, category] <- [[{}, {}]]\n\
         :put tool_category {{tool_name, category}}",
        cozo_str(&c.tool), cozo_str(&c.category)
    );
    db.run_script(&script, Default::default())
        .map_err(|e| PolicyError::Compile(format!("categorize insert error: {e}")))?;
    Ok(())
}

fn compile_classify(c: &ClassifyDecl, db: &cozo::DbInstance) -> Result<(), PolicyError> {
    let script = format!(
        "?[uri_pattern, level] <- [[{}, {}]]\n\
         :put resource_sensitivity {{uri_pattern, level}}",
        cozo_str(&c.resource_pattern), cozo_str(&c.sensitivity)
    );
    db.run_script(&script, Default::default())
        .map_err(|e| PolicyError::Compile(format!("classify insert error: {e}")))?;
    Ok(())
}

// ── Decision script generation ────────────────────────────────────────────────

/// The fixed preamble that binds all request fact types from `$params`.
/// The evaluator's `facts_loader.rs` is responsible for populating these params.
/// `$matched_values` is populated by `builtins.rs` before the script runs.
/// Preamble section of the decision script: binds all spec-defined request fact types
/// from CozoDB `$params`. The evaluator's `facts_loader.rs` builds the
/// `BTreeMap<String, DataValue>` for these keys. `$matched_values` is populated
/// by `builtins.rs` before the script runs. Every key listed here must be supplied
/// by the evaluator even if empty, so that the script's inline rules can reference
/// any of them safely.
const REQUEST_FACT_BINDINGS: &str = "\
tool_call[call_id, agent_id, tool_name] <- $tool_calls\n\
agent[agent_id, display_name] <- $agents\n\
agent_role[agent_id, role] <- $agent_roles\n\
agent_clearance[agent_id, clearance] <- $agent_clearances\n\
delegated_by[agent_id, delegator_id] <- $delegations\n\
user[user_id, agent_id] <- $users\n\
call_arg[call_id, key, value] <- $call_args\n\
tool_result[call_id, key, value] <- $tool_results\n\
resource_access[call_id, res_agent_id, uri, op] <- $resource_accesses\n\
resource_mime[call_id, mime_type] <- $resource_mimes\n\
content_tag[call_id, tag, tag_value] <- $content_tags\n\
timestamp[call_id, unix_ts] <- $timestamps\n\
call_count[agent_id, tool_name, window, count] <- $call_counts\n\
environment[key, value] <- $environment\n\
matched_value[value, pattern_name] <- $matched_values\n";

fn build_decision_script(file: &PolicyFile) -> Result<String, PolicyError> {
    let mut parts: Vec<String> = vec![REQUEST_FACT_BINDINGS.to_string()];

    // Inline rule definitions from DSL `rule` declarations
    for decl in &file.declarations {
        if let Declaration::Rule(r) = decl {
            parts.extend(compile_rule_to_cozo(r)?);
        }
    }

    // Policy blocks — sorted highest priority first
    let mut policies: Vec<&PolicyDecl> = file.declarations.iter()
        .filter_map(|d| if let Declaration::Policy(p) = d { Some(p) } else { None })
        .collect();
    policies.sort_by(|a, b| b.priority.cmp(&a.priority));

    let mut higher_block_names: Vec<&str> = Vec::new();
    for policy in &policies {
        parts.extend(compile_policy_block(policy, &higher_block_names)?);
        higher_block_names.push(&policy.name);
    }

    // Named union rule collects output from all policy blocks.
    // Using a named intermediate rule (rather than multiple `?[...]` heads)
    // is unambiguous in CozoDB and avoids relying on multi-head `?[...]` union semantics.
    // Due to stratified negation, at most one block fires per call_id.
    for policy in &policies {
        let safe = sanitize_name(&policy.name);
        parts.push(format!(
            "decision_output[call_id, verdict, reason, effects_json, block_name] := \
             b_{safe}_decision[call_id, verdict, reason, effects_json], block_name = {}",
            cozo_str(&policy.name)
        ));
    }
    // The final query outputs 4 columns: verdict, reason, effects_json, block_name.
    // `call_id` is intentionally dropped from the output — the evaluator (Chunk 5)
    // already holds `call_id` from the `FactPackage` and does not need it echoed back.
    // `block_name` becomes `AuditRecord.matched_rules`. `effects_json` is a JSON
    // string the evaluator parses back to `Vec<Effect>`.
    parts.push(
        "?[verdict, reason, effects_json, block_name] := \
         decision_output[_, verdict, reason, effects_json, block_name]"
            .to_string(),
    );

    Ok(parts.join("\n"))
}

/// Turn policy name "content-safety" into a valid Cozo identifier segment "content_safety".
fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' })
        .collect()
}

/// Compile a `RuleDecl` to one or more Cozo rule strings.
/// `Or` conditions are expanded: each arm becomes a separate rule with the same head.
fn compile_rule_to_cozo(r: &RuleDecl) -> Result<Vec<String>, PolicyError> {
    let params: Vec<String> = r.params.iter().map(compile_param_str).collect();
    let head = format!("{}[{}]", r.name, params.join(", "));

    let non_or: Vec<&ConditionClause> = r.conditions.iter()
        .filter(|c| !matches!(c, ConditionClause::Or(_)))
        .collect();
    let or_groups: Vec<&Vec<AtomCondition>> = r.conditions.iter()
        .filter_map(|c| if let ConditionClause::Or(atoms) = c { Some(atoms) } else { None })
        .collect();

    let base_body: Vec<String> = non_or.iter()
        .map(|c| compile_condition_str(c))
        .collect::<Result<Vec<_>, _>>()?;

    if or_groups.is_empty() {
        // Simple case — no Or conditions
        let rule = if base_body.is_empty() {
            // Unconditional rule (shouldn't appear in normal DSL, but safe)
            format!("{head} := true")
        } else {
            format!("{head} := {}", base_body.join(", "))
        };
        Ok(vec![rule])
    } else {
        // Validation ensures at most one Or group per rule (checked in validate()).
        // Expand the single Or group: one rule per arm, each sharing the non-Or body.
        // Multiple rules with the same head are valid CozoDB — they produce a union.
        let or_atoms = or_groups[0];
        if or_atoms.is_empty() {
            return Err(PolicyError::Compile(format!(
                "rule `{}` has an empty Or group — this is a parser bug or an invalid AST",
                r.name
            )));
        }
        let rules = or_atoms.iter().map(|atom| {
            let mut body = base_body.clone();
            body.push(compile_atom_str(atom));
            format!("{head} := {}", body.join(", "))
        }).collect();
        Ok(rules)
    }
}

/// Compile one policy block into Cozo rule strings.
///
/// For block "pii-handling" at priority 150, with "content-safety" already matched
/// at priority 200, generates rules like:
///
/// ```
/// b_pii_handling_deny_1[call_id, reason, effects] :=
///     <deny conditions>, not b_content_safety_matched[call_id], reason = "...", effects = "..."
/// b_pii_handling_allow_0[call_id, reason, effects] :=
///     <allow conditions>, not b_content_safety_matched[call_id], reason = "", effects = "..."
/// b_pii_handling_decision[call_id, "Deny", reason, effects] :=
///     b_pii_handling_deny_1[call_id, reason, effects]
/// b_pii_handling_decision[call_id, "Allow", reason, effects] :=
///     b_pii_handling_allow_0[call_id, reason, effects],
///     not b_pii_handling_deny_1[call_id, _, _]
/// b_pii_handling_matched[call_id] := b_pii_handling_decision[call_id, _, _, _]
/// ```
fn compile_policy_block(policy: &PolicyDecl, higher_blocks: &[&str]) -> Result<Vec<String>, PolicyError> {
    let safe = sanitize_name(&policy.name);

    // The stratified-negation guards that prevent this block from firing
    // when a higher-priority block already matched.
    let higher_guards: Vec<String> = higher_blocks.iter()
        .map(|name| format!("not b_{}_matched[call_id]", sanitize_name(name)))
        .collect();
    let higher_guard_suffix = if higher_guards.is_empty() {
        String::new()
    } else {
        format!(", {}", higher_guards.join(", "))
    };

    let mut lines: Vec<String> = Vec::new();
    let mut deny_rule_names: Vec<String> = Vec::new();
    let mut allow_rule_names: Vec<String> = Vec::new();

    for (idx, rule) in policy.rules.iter().enumerate() {
        match rule {
            PolicyRule::Allow(allow) => {
                let rule_name = format!("b_{safe}_allow_{idx}");
                let effects_json = compile_effects_json(&allow.effects);
                let body = compile_conditions_str(&allow.conditions)?;
                lines.push(format!(
                    r#"{rule_name}[call_id, reason, effects] := {body}{higher_guard_suffix}, reason = "", effects = {}"#,
                    cozo_str(&effects_json)
                ));
                allow_rule_names.push(rule_name);
            }
            PolicyRule::Deny(deny) => {
                let rule_name = format!("b_{safe}_deny_{idx}");
                let effects_json = compile_effects_json(&deny.effects);
                let reason = deny.reason.as_deref().unwrap_or("");
                let body = compile_conditions_str(&deny.conditions)?;
                lines.push(format!(
                    "{rule_name}[call_id, reason, effects] := {body}{higher_guard_suffix}, reason = {}, effects = {}",
                    cozo_str(reason),
                    cozo_str(&effects_json)
                ));
                deny_rule_names.push(rule_name);
            }
        }
    }

    // Decision rules: Deny beats Allow at equal priority
    for deny_rule in &deny_rule_names {
        lines.push(format!(
            r#"b_{safe}_decision[call_id, "Deny", reason, effects] := {deny_rule}[call_id, reason, effects]"#
        ));
    }
    for allow_rule in &allow_rule_names {
        let not_deny: Vec<String> = deny_rule_names.iter()
            .map(|dr| format!("not {dr}[call_id, _, _]"))
            .collect();
        let deny_guard = if not_deny.is_empty() {
            String::new()
        } else {
            format!(", {}", not_deny.join(", "))
        };
        lines.push(format!(
            r#"b_{safe}_decision[call_id, "Allow", reason, effects] := {allow_rule}[call_id, reason, effects]{deny_guard}"#
        ));
    }

    // Matched marker for stratification by lower-priority blocks
    lines.push(format!(
        "b_{safe}_matched[call_id] := b_{safe}_decision[call_id, _, _, _]"
    ));

    Ok(lines)
}

// ── Condition/atom compilation ────────────────────────────────────────────────

/// Compile a condition list to a comma-joined body string.
/// `ConditionClause::True` is compiled as `tool_call[call_id, _, _]` to bind `call_id`.
/// `ConditionClause::Or` is rejected — it must be expanded at the rule level; its
/// presence here indicates a bug or a missing validation step.
fn compile_conditions_str(conditions: &[ConditionClause]) -> Result<String, PolicyError> {
    if conditions.is_empty()
        || (conditions.len() == 1 && conditions[0] == ConditionClause::True)
    {
        return Ok("tool_call[call_id, _, _]".to_string());
    }
    let parts: Vec<String> = conditions.iter()
        .map(compile_condition_str)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(parts.join(", "))
}

fn compile_condition_str(cond: &ConditionClause) -> Result<String, PolicyError> {
    match cond {
        ConditionClause::Atom(atom) => Ok(compile_atom_str(atom)),
        ConditionClause::Not(atom) => Ok(format!("not {}", compile_atom_str(atom))),
        ConditionClause::True => Ok("tool_call[call_id, _, _]".to_string()),
        ConditionClause::Or(_) => Err(PolicyError::Compile(
            "Or conditions are not supported in policy blocks; \
             use a `rule` declaration to express the Or logic, then reference the rule here"
                .to_string()
        )),
    }
}

/// Compile an `AtomCondition` to a Cozo condition string.
/// - `matches(value, :pattern)` → `matched_value[value, "pattern"]`
/// - Stored relation predicates → `*predicate[args...]`
/// - Request fact and inline rule predicates → `predicate[args...]`
fn compile_atom_str(atom: &AtomCondition) -> String {
    if atom.predicate == "matches" {
        if let (Some(value_arg), Some(Arg::PatternRef(name))) =
            (atom.args.first(), atom.args.get(1))
        {
            return format!("matched_value[{}, {}]", compile_arg_str(value_arg), cozo_str(name));
        }
    }
    let prefix = if STORED_RELATIONS.contains(&atom.predicate.as_str()) { "*" } else { "" };
    let args: Vec<String> = atom.args.iter().map(compile_arg_str).collect();
    format!("{prefix}{}[{}]", atom.predicate, args.join(", "))
}

fn compile_arg_str(arg: &Arg) -> String {
    match arg {
        Arg::Variable(name)      => name.clone(),
        Arg::Wildcard            => "_".to_string(),
        Arg::NamedWildcard(name) => format!("_{name}"),
        Arg::StringLit(s)        => cozo_str(s),
        Arg::Integer(n)          => n.to_string(),
        Arg::PatternRef(name)    => cozo_str(name), // fallback; matches() should be caught first
    }
}

fn compile_param_str(param: &Param) -> String {
    match param {
        Param::Named(name)       => name.clone(),
        Param::Wildcard          => "_".to_string(),
        Param::NamedWildcard(n)  => format!("_{n}"),
    }
}

// ── Effects serialization ─────────────────────────────────────────────────────

/// Serialize a list of `EffectDecl` to a JSON string embedded in the Cozo script.
/// The evaluator parses this string back to `Vec<Effect>` after reading the query output.
fn compile_effects_json(effects: &[EffectDecl]) -> String {
    if effects.is_empty() {
        return "[]".to_string();
    }
    let items: Vec<serde_json::Value> = effects.iter().map(effect_to_json).collect();
    // serde_json::to_string on a Vec<Value> built entirely from json!() literals is infallible.
    // Using expect() (not unwrap_or_else) so that any impossible failure is loud, not silent.
    // Silent fallback to "[]" would drop effects from decisions without any error signal,
    // violating the spec's "errors are never silently swallowed" invariant.
    serde_json::to_string(&items).expect("effects serialization cannot fail: all values are JSON literals")
}

fn effect_to_json(e: &EffectDecl) -> serde_json::Value {
    match e {
        EffectDecl::Redact { selector, classifier } => serde_json::json!({
            "type": "Redact", "selector": selector, "classifier": classifier
        }),
        EffectDecl::Mask { selector, pattern, replacement } => serde_json::json!({
            "type": "Mask", "selector": selector, "pattern": pattern, "replacement": replacement
        }),
        EffectDecl::Annotate { key, value } => serde_json::json!({
            "type": "Annotate", "key": key, "value": value
        }),
        EffectDecl::Audit { level } => serde_json::json!({
            "type": "Audit",
            "level": match level {
                AuditLevelDecl::Standard  => "Standard",
                AuditLevelDecl::Elevated  => "Elevated",
                AuditLevelDecl::Critical  => "Critical",
            }
        }),
    }
}

// ── CozoDB string literal helper ──────────────────────────────────────────────

/// Wrap a string as a CozoDB string literal (JSON-compatible).
/// Escapes backslashes and double-quotes.
fn cozo_str(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}
```

- [ ] **Step 8: Run all compiler tests to verify they pass**

```bash
cargo test --lib dsl::compiler
```

Expected: all 7 unit tests pass.

> **Debugging notes for implementer:**
> - If a `compile_grant_stored_in_cozo` or similar test fails with "relation not found", verify that `init_db` runs the `:create` scripts before any `:put` scripts.
> - If `compile_decision_script_no_syntax_error` fails, `unwrap_or_else` will print the full decision_script. Inspect the generated Cozo — common issues: double `*` prefix on inline rule names, unquoted string literals, wrong bracket type (`()` vs `[]`).
> - **`run_script` arity:** All `run_script` calls in this chunk use `(script, params)` — the same 2-arg form established and approved in Chunk 2, Task 6 (`cozo_mem_instance_runs_trivial_query`). If the version of cozo in `Cargo.toml` has a 3-arg form including `ScriptMutability`, add `cozo::ScriptMutability::Mutable` as the third argument on every `:put` and `:create` call and `cozo::ScriptMutability::Immutable` on every query-only call. Run `cargo doc -p cozo --open` to check the actual signature.
> - **`DbInstance::new` signature:** May differ by patch version — see note in Chunk 2, Task 6. If it doesn't accept a `serde_json::Value` third arg, try `cozo::new_cozo_mem()`.
> - The `result.rows` field on `cozo::NamedRows` may be named differently — check the cozo crate docs for the correct field name if `result.rows` doesn't compile.

- [ ] **Step 9: Run the integration tests**

```bash
cargo test --test dsl_tests
```

Expected: all previously passing tests still pass; new `compile_error_*` tests pass.
`tests/dsl_tests.rs` total: 16 tests (12 parser tests from Chunk 3 + 4 `compile_error_*` tests).
The 8 unit tests in `src/dsl/compiler.rs` run separately under `cargo test --lib dsl::compiler` and are not counted here.

- [ ] **Step 10: Run full test suite**

```bash
cargo test
```

Expected: all tests pass; no regressions from Chunks 1–3.

- [ ] **Step 11: Commit**

```bash
git add src/dsl/compiler.rs src/dsl/mod.rs src/lib.rs tests/dsl_tests.rs
git commit -m "feat: add DSL compiler (AST → CompiledPolicy)"
```

---

## Chunk 5: Evaluator

**Covers:** `src/evaluator/facts_loader.rs`, `src/evaluator/builtins.rs`, `src/evaluator/engine.rs`, `src/evaluator/mod.rs`, `src/lib.rs` (add `Engine` re-export)

**Goal:** The evaluation engine that turns `FactPackage + PolicyStore → Decision`. `facts_loader.rs` serializes request facts to CozoDB params. `builtins.rs` runs the regex pre-pass that resolves `matches()` calls. `engine.rs` holds the core `evaluate_inner()` logic. `mod.rs` provides the public `Engine` struct with its fail-closed `evaluate()` and `PolicyWatcher` implementation.

---

### Task 13: `src/evaluator/facts_loader.rs`

**Files:**
- Create: `src/evaluator/facts_loader.rs`
- Modify: `src/evaluator/mod.rs` (wire submodules)

The facts loader converts a `FactPackage` into the `BTreeMap<String, DataValue>` that CozoDB's `run_script` expects. Each map key matches a `$param_name` in the `REQUEST_FACT_BINDINGS` preamble compiled into the decision script (see `src/dsl/compiler.rs`).

- [ ] **Step 1: Update `src/evaluator/mod.rs`**

Replace the stub content with:

```rust
// src/evaluator/mod.rs
mod builtins;
pub(super) mod engine;
mod facts_loader;
```

The full `Engine` public API will be added in Task 15. This stub wires all three submodules so they compile together.

- [ ] **Step 2: Write the failing tests**

Add to `src/evaluator/facts_loader.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::*;
    use crate::types::*;

    #[test]
    fn all_fifteen_params_present_even_with_empty_facts() {
        let params = load_facts(&FactPackage::default(), vec![]);
        // These 15 keys match the $param placeholders in REQUEST_FACT_BINDINGS
        // in src/dsl/compiler.rs. Adding a fact type there requires adding it here.
        let expected_keys = [
            "agents", "agent_roles", "agent_clearances", "delegations", "users",
            "tool_calls", "call_args", "tool_results", "resource_accesses", "resource_mimes",
            "content_tags", "timestamps", "call_counts", "environment", "matched_values",
        ];
        for key in &expected_keys {
            assert!(params.contains_key(*key), "missing CozoDB param: {key}");
        }
        assert_eq!(params.len(), 15);
    }

    #[test]
    fn tool_call_converts_to_list_of_lists() {
        let pkg = FactPackage {
            tool_calls: vec![ToolCallFact {
                call_id: CallId("call-1".to_string()),
                agent_id: AgentId("agt-1".to_string()),
                tool_name: ToolName("db_query".to_string()),
            }],
            ..Default::default()
        };
        let params = load_facts(&pkg, vec![]);
        let rows = match &params["tool_calls"] {
            cozo::DataValue::List(rows) => rows,
            other => panic!("expected List, got {:?}", other),
        };
        assert_eq!(rows.len(), 1);
        let row = match &rows[0] {
            cozo::DataValue::List(row) => row,
            other => panic!("expected List row, got {:?}", other),
        };
        // schema: [call_id, agent_id, tool_name]
        assert_eq!(row.len(), 3);
        assert_eq!(row[0], cozo::DataValue::Str("call-1".into()));
        assert_eq!(row[1], cozo::DataValue::Str("agt-1".into()));
        assert_eq!(row[2], cozo::DataValue::Str("db_query".into()));
    }

    #[test]
    fn timestamp_unix_ts_converts_to_numeric_not_string() {
        let mut pkg = FactPackage::default();
        pkg.timestamps.push(TimestampFact {
            call_id: CallId("call-1".to_string()),
            unix_ts: 1_700_000_000,
        });
        let params = load_facts(&pkg, vec![]);
        let rows = match &params["timestamps"] {
            cozo::DataValue::List(rows) => rows,
            other => panic!("expected List, got {:?}", other),
        };
        let row = match &rows[0] {
            cozo::DataValue::List(row) => row,
            other => panic!("expected List row, got {:?}", other),
        };
        // row schema: [call_id, unix_ts] — unix_ts must be Num, not Str
        assert!(
            matches!(row[1], cozo::DataValue::Num(_)),
            "unix_ts must be DataValue::Num, got {:?}", row[1]
        );
    }

    #[test]
    fn matched_values_converts_to_list_of_string_pairs() {
        let pairs = vec![
            ("DROP TABLE users".to_string(), "sql_injection".to_string()),
        ];
        let params = load_facts(&FactPackage::default(), pairs);
        let rows = match &params["matched_values"] {
            cozo::DataValue::List(rows) => rows,
            other => panic!("expected List, got {:?}", other),
        };
        assert_eq!(rows.len(), 1);
        let pair = match &rows[0] {
            cozo::DataValue::List(pair) => pair,
            other => panic!("expected List pair, got {:?}", other),
        };
        // schema: [value, pattern_name]
        assert_eq!(pair.len(), 2);
        assert_eq!(pair[0], cozo::DataValue::Str("DROP TABLE users".into()));
        assert_eq!(pair[1], cozo::DataValue::Str("sql_injection".into()));
    }
}
```

- [ ] **Step 3: Run to verify failure**

```bash
cargo test --lib evaluator::facts_loader
```

Expected: compile error — `load_facts` not defined.

- [ ] **Step 4: Implement `src/evaluator/facts_loader.rs`**

```rust
// src/evaluator/facts_loader.rs
use std::collections::BTreeMap;
use cozo::DataValue;
use crate::facts::*;

/// Convert a `FactPackage` to CozoDB script parameters.
///
/// Returns a `BTreeMap<String, DataValue>` where each key matches a `$param_name`
/// in the compiled decision script's REQUEST_FACT_BINDINGS preamble. All 15 keys
/// are always present; empty fact lists produce `DataValue::List(vec![])`.
///
/// `matched_values` is the output of the builtins pre-pass (pairs of
/// `(value_string, pattern_name)` where the regex matched).
pub(super) fn load_facts(
    facts: &FactPackage,
    matched_values: Vec<(String, String)>,
) -> BTreeMap<String, DataValue> {
    let mut p = BTreeMap::new();

    // Identity
    p.insert("agents".to_string(),
        rows(facts.agents.iter().map(|f| vec![s(&f.id.0), s(&f.display_name)])));
    p.insert("agent_roles".to_string(),
        rows(facts.agent_roles.iter().map(|f| vec![s(&f.agent_id.0), s(&f.role.0)])));
    p.insert("agent_clearances".to_string(),
        rows(facts.agent_clearances.iter().map(|f| vec![s(&f.agent_id.0), s(&f.clearance)])));
    p.insert("delegations".to_string(),
        rows(facts.delegations.iter().map(|f| vec![s(&f.agent_id.0), s(&f.delegator_id.0)])));
    p.insert("users".to_string(),
        rows(facts.users.iter().map(|f| vec![s(&f.user_id), s(&f.agent_id.0)])));

    // MCP call
    p.insert("tool_calls".to_string(),
        rows(facts.tool_calls.iter().map(|f| {
            vec![s(&f.call_id.0), s(&f.agent_id.0), s(&f.tool_name.0)]
        })));
    p.insert("call_args".to_string(),
        rows(facts.call_args.iter().map(|f| vec![s(&f.call_id.0), s(&f.key), s(&f.value)])));
    p.insert("tool_results".to_string(),
        rows(facts.tool_results.iter().map(|f| vec![s(&f.call_id.0), s(&f.key), s(&f.value)])));
    p.insert("resource_accesses".to_string(),
        rows(facts.resource_accesses.iter().map(|f| {
            vec![s(&f.call_id.0), s(&f.agent_id.0), s(&f.uri.0), s(f.op.as_str())]
        })));
    p.insert("resource_mimes".to_string(),
        rows(facts.resource_mimes.iter().map(|f| vec![s(&f.call_id.0), s(&f.mime_type)])));

    // Content classification
    p.insert("content_tags".to_string(),
        rows(facts.content_tags.iter().map(|f| vec![s(&f.call_id.0), s(&f.tag), s(&f.value)])));

    // Environment
    p.insert("timestamps".to_string(),
        rows(facts.timestamps.iter().map(|f| vec![s(&f.call_id.0), n(f.unix_ts)])));
    p.insert("call_counts".to_string(),
        rows(facts.call_counts.iter().map(|f| {
            vec![s(&f.agent_id.0), s(&f.tool_name.0), s(&f.window), n(f.count)]
        })));
    p.insert("environment".to_string(),
        rows(facts.environment.iter().map(|f| vec![s(&f.key), s(&f.value)])));

    // Builtins pre-pass: matched_value pairs from regex evaluation
    p.insert("matched_values".to_string(),
        rows(matched_values.iter().map(|(val, name)| vec![s(val), s(name)])));

    p
}

// ── DataValue constructors ────────────────────────────────────────────────────

/// `&str` → `DataValue::Str`.
/// `SmartString` (cozo's internal string type) implements `From<&str>`,
/// so `.into()` is the idiomatic conversion.
fn s(v: &str) -> DataValue {
    DataValue::Str(v.into())
}

/// `u64` → `DataValue::Num(cozo::Num::Int(n))`.
/// Timestamps and call counts are stored as signed 64-bit integers in CozoDB.
fn n(v: u64) -> DataValue {
    DataValue::Num(cozo::Num::Int(v as i64))
}

/// Build a `DataValue::List` of rows from an iterator of column-value vectors.
/// Each inner `vec![col0, col1, ...]` becomes a `DataValue::List` row.
fn rows(iter: impl Iterator<Item = Vec<DataValue>>) -> DataValue {
    DataValue::List(iter.map(DataValue::List).collect())
}
```

> **Note for implementer:**
> - If `DataValue::Str(v.into())` doesn't compile, `SmartString` may need an explicit import: `use smartstring::SmartString;` then `DataValue::Str(SmartString::from(v))`. Run `cargo doc -p cozo --open` to see the exact variant type.
> - If `cozo::Num` is not in scope, try `use cozo::Num;`. If `Num` isn't re-exported at the crate root, check the cozo docs for the full path (e.g. `cozo::data::value::Num`).
> - `BTreeMap` is the established param type from prior chunks. If the cozo version you have expects `HashMap`, check `cargo doc -p cozo --open` for the `run_script` signature and adjust accordingly.

- [ ] **Step 5: Run tests to verify they pass**

```bash
cargo test --lib evaluator::facts_loader
```

Expected: all 4 tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/evaluator/facts_loader.rs src/evaluator/mod.rs
git commit -m "feat: add facts_loader (FactPackage → CozoDB params)"
```

---

### Task 14: `src/evaluator/builtins.rs`

**Files:**
- Create: `src/evaluator/builtins.rs`

The builtins pre-pass resolves `matches(value, :pattern)` calls before the CozoDB query runs. It collects all string values from the `FactPackage` that could flow into a `matches()` expression, tests each against each compiled `Regex`, and returns matching `(value, pattern_name)` pairs. These pairs populate `$matched_values` in the decision script, making `matched_value[value, "pattern_name"]` true in the Datalog query.

- [ ] **Step 1: Write the failing tests**

Add to `src/evaluator/builtins.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use regex::Regex;
    use crate::facts::{CallArgFact, FactPackage, ToolResultFact};
    use crate::types::CallId;

    fn pats(pairs: &[(&str, &str)]) -> HashMap<String, Regex> {
        pairs.iter()
            .map(|(name, pat)| (name.to_string(), Regex::new(pat).unwrap()))
            .collect()
    }

    #[test]
    fn no_patterns_returns_empty_without_inspecting_facts() {
        // Short-circuit: if there are no patterns, result is always empty
        // regardless of FactPackage contents.
        let mut facts = FactPackage::default();
        facts.call_args.push(CallArgFact {
            call_id: CallId("c".to_string()),
            key: "q".to_string(),
            value: "DROP TABLE users".to_string(),
        });
        let result = compute_matched_values(&facts, &HashMap::new());
        assert!(result.is_empty());
    }

    #[test]
    fn no_string_values_returns_empty() {
        // Empty FactPackage has no call_args, tool_results, etc.
        let facts = FactPackage::default();
        let p = pats(&[("sql_injection", r"(?i)(drop|delete)\s+table")]);
        let result = compute_matched_values(&facts, &p);
        assert!(result.is_empty());
    }

    #[test]
    fn matching_call_arg_value_returns_pair() {
        let mut facts = FactPackage::default();
        facts.call_args.push(CallArgFact {
            call_id: CallId("c".to_string()),
            key: "query".to_string(),
            value: "DROP TABLE users".to_string(),
        });
        let p = pats(&[("sql_injection", r"(?i)(drop|delete)\s+table")]);
        let result = compute_matched_values(&facts, &p);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "DROP TABLE users");
        assert_eq!(result[0].1, "sql_injection");
    }

    #[test]
    fn non_matching_value_is_excluded() {
        let mut facts = FactPackage::default();
        facts.call_args.push(CallArgFact {
            call_id: CallId("c".to_string()),
            key: "query".to_string(),
            value: "SELECT * FROM users".to_string(), // safe query
        });
        let p = pats(&[("sql_injection", r"(?i)(drop|delete)\s+table")]);
        let result = compute_matched_values(&facts, &p);
        assert!(result.is_empty());
    }

    #[test]
    fn tool_result_value_is_tested() {
        let mut facts = FactPackage::default();
        facts.tool_results.push(ToolResultFact {
            call_id: CallId("c".to_string()),
            key: "content".to_string(),
            value: "sk-abc123def456ghi789jkl012mno345pqr678stu901".to_string(),
        });
        let p = pats(&[("secret_key", r"sk-[a-zA-Z0-9]{32,}")]);
        let result = compute_matched_values(&facts, &p);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].1, "secret_key");
    }
}
```

- [ ] **Step 2: Run to verify failure**

```bash
cargo test --lib evaluator::builtins
```

Expected: compile error — `compute_matched_values` not defined.

- [ ] **Step 3: Implement `src/evaluator/builtins.rs`**

```rust
// src/evaluator/builtins.rs
use std::collections::HashMap;
use regex::Regex;
use crate::facts::FactPackage;

/// Run the regex pre-pass over the `FactPackage`.
///
/// Tests every string value that could flow into a `matches(value, :pattern)`
/// DSL expression against each compiled `Regex`. Returns `(value, pattern_name)`
/// pairs where the regex matched.
///
/// The result becomes the `$matched_values` CozoDB parameter, populating the
/// `matched_value[value, pattern_name]` relation that `matches()` rewrites to.
///
/// Tested value sources (conservative superset of what DSL rules typically use):
/// - `call_args.value`    — most common target (e.g. checking args for SQL injection)
/// - `tool_results.value` — for response-time policies (e.g. detecting secret keys)
/// - `content_tags.value` — tag values from external classifiers
/// - `environment.value`  — deployment environment variable values
///
/// If `patterns` is empty, returns `vec![]` without inspecting the FactPackage.
pub(super) fn compute_matched_values(
    facts: &FactPackage,
    patterns: &HashMap<String, Regex>,
) -> Vec<(String, String)> {
    if patterns.is_empty() {
        return Vec::new();
    }

    let values = collect_string_values(facts);
    let mut matched = Vec::new();

    for value in &values {
        for (name, regex) in patterns {
            if regex.is_match(value) {
                matched.push((value.clone(), name.clone()));
            }
        }
    }

    matched
}

/// Collect all string values that are candidates for pattern matching.
/// Returns a sorted, deduplicated list.
fn collect_string_values(facts: &FactPackage) -> Vec<String> {
    let mut values: Vec<String> = Vec::new();
    for f in &facts.call_args    { values.push(f.value.clone()); }
    for f in &facts.tool_results { values.push(f.value.clone()); }
    for f in &facts.content_tags { values.push(f.value.clone()); }
    for f in &facts.environment  { values.push(f.value.clone()); }
    values.sort_unstable();
    values.dedup();
    values
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test --lib evaluator::builtins
```

Expected: all 5 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/evaluator/builtins.rs
git commit -m "feat: add builtins regex pre-pass (compute_matched_values)"
```

---

### Task 15: `src/evaluator/engine.rs`, `src/evaluator/mod.rs`, `src/lib.rs`

**Files:**
- Create: `src/evaluator/engine.rs`
- Modify: `src/evaluator/mod.rs` (add `Engine` struct, `PolicyWatcher` impl, tests)
- Modify: `src/lib.rs` (add `pub use evaluator::Engine;`)

`engine.rs` contains `evaluate_inner()`: acquires the read lock, runs builtins pre-pass, builds CozoDB params, executes the decision script, maps rows to a `Decision`. `mod.rs` wraps it in the public `Engine` struct with fail-closed `evaluate()` and `PolicyWatcher` implementation.

- [ ] **Step 1: Write the failing tests**

Replace `src/evaluator/mod.rs` with:

```rust
// src/evaluator/mod.rs
mod builtins;
pub(super) mod engine;
mod facts_loader;

use crate::decision::{AuditLevel, AuditRecord, Decision, Effect, Verdict};
use crate::error::PolicyError;
use crate::facts::FactPackage;
use crate::policy::store::PolicyStore;
use crate::policy::watcher::{PolicySet, PolicyWatcher};

/// The authorization engine. Owns a `PolicyStore` and implements `PolicyWatcher`.
///
/// Cheap to clone — all clones share the same underlying `PolicyStore`.
/// Create one per process; clone handles to share across threads.
#[derive(Clone)]
pub struct Engine {
    store: PolicyStore,
}

impl Engine {
    pub fn new() -> Self {
        Self { store: PolicyStore::new() }
    }

    /// Evaluate a `FactPackage` against the loaded policy.
    ///
    /// Never panics, never fails open. If any error occurs — store uninitialized,
    /// CozoDB error, malformed facts — returns `Deny + Audit(Critical)`.
    pub fn evaluate(&self, facts: &FactPackage) -> Decision {
        engine::evaluate_inner(facts, &self.store)
            .unwrap_or_else(|err| Decision {
                verdict: Verdict::Deny,
                effects: vec![Effect::Audit {
                    level: AuditLevel::Critical,
                    message: Some(err.to_string()),
                }],
                reason: Some("evaluation error".to_string()),
                audit: AuditRecord::from_error(facts, &err),
            })
    }

    /// Returns the version string of the currently loaded policy, if any.
    pub fn current_version(&self) -> Option<String> {
        self.store.current_version()
    }
}

impl Default for Engine {
    fn default() -> Self { Self::new() }
}

impl PolicyWatcher for Engine {
    fn push(&self, policy: PolicySet) -> Result<(), PolicyError> {
        // Idempotency: skip compile+swap if this version is already loaded.
        if self.store.current_version().as_deref() == Some(&policy.version) {
            return Ok(());
        }
        let compiled = crate::dsl::compiler::compile(&policy.source, &policy.version)?;
        self.store.swap(compiled);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::{AgentRoleFact, FactPackage, ToolCallFact};
    use crate::types::{AgentId, CallId, Role, ToolName};

    // ── Test helpers ──────────────────────────────────────────────────────────

    fn one_call() -> FactPackage {
        FactPackage {
            tool_calls: vec![ToolCallFact {
                call_id: CallId("call-1".to_string()),
                agent_id: AgentId("agt-1".to_string()),
                tool_name: ToolName("test_tool".to_string()),
            }],
            ..Default::default()
        }
    }

    fn one_call_with_role(role: &str) -> FactPackage {
        let mut pkg = one_call();
        pkg.agent_roles.push(AgentRoleFact {
            agent_id: AgentId("agt-1".to_string()),
            role: Role(role.to_string()),
        });
        pkg
    }

    fn push_policy(engine: &Engine, version: &str, source: &str) {
        engine.push(PolicySet {
            version: version.to_string(),
            source: source.to_string(),
            checksum: String::new(),
        }).expect("test policy must compile");
    }

    // ── Test policies ─────────────────────────────────────────────────────────

    /// Default-deny: fires on any tool_call, always returns Deny.
    const DENY_ALL: &str = r#"
policy "default" priority 100 {
    deny when true
        reason "no matching allow rule";
}
"#;

    /// Allow when the calling agent has role "tester"; no deny rule in this block.
    /// A call with agent_role "tester" → Allow.
    /// A call without that role → no rows from this policy → fail-closed Deny.
    const ALLOW_TESTER_ROLE: &str = r#"
policy "default" priority 100 {
    allow when
        tool_call(call_id, agent_id, _),
        agent_role(agent_id, "tester");
}
"#;

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[test]
    fn engine_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Engine>();
    }

    #[test]
    fn engine_clone_shares_store() {
        let engine = Engine::new();
        let clone = engine.clone();
        push_policy(&engine, "v1", DENY_ALL);
        // Both handles point to the same store — must see the same version.
        assert_eq!(engine.current_version(), clone.current_version());
    }

    #[test]
    fn evaluate_uninitialized_store_returns_deny_audit_critical() {
        let engine = Engine::new(); // no push — store holds None
        let decision = engine.evaluate(&one_call());
        assert_eq!(decision.verdict, Verdict::Deny);
        assert!(
            decision.effects.iter().any(|e| matches!(e,
                Effect::Audit { level: AuditLevel::Critical, .. }
            )),
            "expected Audit(Critical) effect, got: {:?}", decision.effects
        );
    }

    #[test]
    fn push_valid_policy_succeeds() {
        let engine = Engine::new();
        let result = engine.push(PolicySet {
            version: "v1".to_string(),
            source: DENY_ALL.to_string(),
            checksum: String::new(),
        });
        assert!(result.is_ok());
        assert_eq!(engine.current_version(), Some("v1".to_string()));
    }

    #[test]
    fn push_invalid_policy_leaves_store_unchanged() {
        let engine = Engine::new();
        push_policy(&engine, "v1", DENY_ALL);
        // Push a malformed policy — must fail and leave "v1" still loaded.
        let result = engine.push(PolicySet {
            version: "v2".to_string(),
            source: "this is not valid DSL !!!".to_string(),
            checksum: String::new(),
        });
        assert!(result.is_err(), "invalid policy should return Err");
        assert_eq!(engine.current_version(), Some("v1".to_string()));
    }

    #[test]
    fn push_same_version_is_idempotent() {
        let engine = Engine::new();
        push_policy(&engine, "v1", DENY_ALL);
        // Same version with broken source — idempotency check must fire before compile.
        let result = engine.push(PolicySet {
            version: "v1".to_string(),
            source: "this is not valid DSL !!!".to_string(),
            checksum: String::new(),
        });
        assert!(result.is_ok(), "same version must skip compile and return Ok");
    }

    #[test]
    fn evaluate_deny_when_true_returns_deny() {
        let engine = Engine::new();
        push_policy(&engine, "v1", DENY_ALL);
        let decision = engine.evaluate(&one_call());
        assert_eq!(decision.verdict, Verdict::Deny);
    }

    #[test]
    fn evaluate_deny_when_true_populates_reason() {
        let engine = Engine::new();
        push_policy(&engine, "v1", DENY_ALL);
        let decision = engine.evaluate(&one_call());
        assert_eq!(decision.reason.as_deref(), Some("no matching allow rule"));
    }

    #[test]
    fn evaluate_allow_rule_returns_allow() {
        let engine = Engine::new();
        push_policy(&engine, "v1", ALLOW_TESTER_ROLE);
        // Agent has role "tester" → allow rule fires → Allow.
        let decision = engine.evaluate(&one_call_with_role("tester"));
        assert_eq!(decision.verdict, Verdict::Allow);
    }

    #[test]
    fn evaluate_allow_rule_without_matching_role_returns_deny() {
        let engine = Engine::new();
        push_policy(&engine, "v1", ALLOW_TESTER_ROLE);
        // Agent has no roles → allow rule does not fire → no rows → fail-closed Deny.
        // This exercises the `parse_decision` "no rows" error path, which is a
        // critical security property: missing policy match must never produce Allow.
        let decision = engine.evaluate(&one_call());
        assert_eq!(decision.verdict, Verdict::Deny);
        assert!(
            decision.effects.iter().any(|e| matches!(e,
                Effect::Audit { level: AuditLevel::Critical, .. }
            )),
            "no-match path must produce Audit(Critical), got: {:?}", decision.effects
        );
    }
}
```

- [ ] **Step 2: Run to verify failure**

```bash
cargo test --lib evaluator
```

Expected: compile errors — `engine::evaluate_inner` not defined; `Engine` struct/methods not yet implemented. The test module compiles but all `engine::` calls fail.

- [ ] **Step 3: Implement `src/evaluator/engine.rs`**

```rust
// src/evaluator/engine.rs
use cozo::DataValue;
use crate::decision::{AuditLevel, AuditRecord, Decision, Effect, Verdict};
use crate::error::EngineError;
use crate::facts::FactPackage;
use crate::policy::store::PolicyStore;
use crate::types::{AgentId, CallId};

/// Core evaluation logic. Acquires a shared read lock on the policy store,
/// runs the builtins pre-pass, builds CozoDB params, executes the compiled
/// decision script, and maps the result rows to a `Decision`.
///
/// Returns `Err` on any failure — the caller (`Engine::evaluate`) maps every
/// error to `Deny + Audit(Critical)` without ever failing open.
pub(super) fn evaluate_inner(
    facts: &FactPackage,
    store: &PolicyStore,
) -> Result<Decision, EngineError> {
    // Acquire shared read lock. Many requests hold this concurrently with zero
    // contention. Policy pushes (rare) take the exclusive write lock separately.
    // The lock is held for the entire duration of this function.
    let guard = store.read();

    // Fail-closed: no policy loaded yet → immediate Deny.
    let policy = guard.as_ref().ok_or(EngineError::StoreUninitialized)?;

    // Builtins pre-pass: resolve matches() calls before running the Cozo script.
    let matched_values = super::builtins::compute_matched_values(facts, &policy.patterns);

    // Build CozoDB script params from the FactPackage + builtins results.
    let params = super::facts_loader::load_facts(facts, matched_values);

    // Run the compiled decision script against the shared policy DB.
    let result = policy.db
        .run_script(&policy.decision_script, params)
        .map_err(|e| EngineError::Cozo(e.to_string()))?;

    // Map result rows to a Decision.
    // `policy` borrows from `guard`, so `guard` stays alive through this call.
    // The read lock is released when `evaluate_inner` returns (not before).
    parse_decision(result, facts, &policy.version)
}

/// Map CozoDB result rows to a `Decision`.
///
/// Expected output schema (from `?[verdict, reason, effects_json, block_name]`
/// in the compiled decision script):
///   - `verdict`:      "Allow" | "Deny"
///   - `reason`:       reason string, or "" if none
///   - `effects_json`: JSON-encoded `Vec<Effect>` (e.g. `[]`, `[{"type":"Audit",...}]`)
///   - `block_name`:   name of the matching policy block (for audit trail)
fn parse_decision(
    result: cozo::NamedRows,
    facts: &FactPackage,
    policy_version: &str,
) -> Result<Decision, EngineError> {
    // No rows means no policy rule matched (policy missing a deny-when-true fallback).
    // Fail closed: treat as evaluation error → caller maps to Deny.
    let row = result.rows.first().ok_or_else(|| EngineError::Cozo(
        "decision script returned no rows — \
         policy has no rule matching this call (missing deny-when-true fallback?)"
            .to_string()
    ))?;

    // Column 0: verdict
    let verdict_str = match row.first() {
        Some(DataValue::Str(s)) => s.as_str().to_owned(),
        other => return Err(EngineError::Cozo(
            format!("unexpected type for verdict column: {:?}", other)
        )),
    };
    let verdict = match verdict_str.as_str() {
        "Allow" => Verdict::Allow,
        "Deny"  => Verdict::Deny,
        other   => return Err(EngineError::Cozo(
            format!("unexpected verdict value '{}': expected 'Allow' or 'Deny'", other)
        )),
    };

    // Column 1: reason (empty string → None)
    let reason = match row.get(1) {
        Some(DataValue::Str(s)) if !s.is_empty() => Some(s.to_string()),
        _ => None,
    };

    // Column 2: effects_json
    let effects = match row.get(2) {
        Some(DataValue::Str(s)) => parse_effects_json(s.as_str())?,
        _ => Vec::new(),
    };

    // Column 3: block_name (the policy block that produced this decision)
    let block_name = match row.get(3) {
        Some(DataValue::Str(s)) => s.to_string(),
        _ => String::new(),
    };

    // Build AuditRecord from FactPackage context.
    let (call_id, agent_id, tool_name) = facts.tool_calls.first()
        .map(|tc| (
            tc.call_id.clone(),
            tc.agent_id.clone(),
            Some(tc.tool_name.0.clone()),
        ))
        .unwrap_or_else(|| (
            CallId("unknown".to_string()),
            AgentId("unknown".to_string()),
            None,
        ));

    let timestamp = facts.timestamps.iter()
        .find(|t| t.call_id == call_id)
        .map(|t| t.unix_ts);

    let audit = AuditRecord {
        call_id,
        agent_id,
        tool_name,
        verdict,
        policy_version: policy_version.to_string(),
        matched_rules: if block_name.is_empty() { vec![] } else { vec![block_name] },
        timestamp,
    };

    Ok(Decision { verdict, effects, reason, audit })
}

/// Parse a JSON-encoded effects string back to `Vec<Effect>`.
fn parse_effects_json(json_str: &str) -> Result<Vec<Effect>, EngineError> {
    if json_str == "[]" || json_str.is_empty() {
        return Ok(Vec::new());
    }
    let values: Vec<serde_json::Value> = serde_json::from_str(json_str)
        .map_err(|e| EngineError::Cozo(
            format!("failed to parse effects JSON '{}': {}", json_str, e)
        ))?;
    values.iter().map(json_to_effect).collect()
}

fn json_to_effect(v: &serde_json::Value) -> Result<Effect, EngineError> {
    let ty = v["type"].as_str()
        .ok_or_else(|| EngineError::Cozo("effect missing 'type' field".to_string()))?;
    match ty {
        "Redact" => Ok(Effect::Redact {
            selector:   v["selector"].as_str().unwrap_or("").to_string(),
            classifier: v["classifier"].as_str().unwrap_or("").to_string(),
        }),
        "Mask" => Ok(Effect::Mask {
            selector:    v["selector"].as_str().unwrap_or("").to_string(),
            pattern:     v["pattern"].as_str().unwrap_or("").to_string(),
            replacement: v["replacement"].as_str().unwrap_or("").to_string(),
        }),
        "Annotate" => Ok(Effect::Annotate {
            key:   v["key"].as_str().unwrap_or("").to_string(),
            value: v["value"].as_str().unwrap_or("").to_string(),
        }),
        "Audit" => Ok(Effect::Audit {
            level: match v["level"].as_str() {
                Some("Elevated") => AuditLevel::Elevated,
                Some("Critical") => AuditLevel::Critical,
                _                => AuditLevel::Standard,
            },
            message: v.get("message").and_then(|m| m.as_str()).map(|s| s.to_string()),
        }),
        other => Err(EngineError::Cozo(format!("unknown effect type: '{}'", other))),
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::store::PolicyStore;
    use crate::facts::{FactPackage, ToolCallFact};
    use crate::types::{AgentId, CallId, ToolName};

    fn one_call() -> FactPackage {
        FactPackage {
            tool_calls: vec![ToolCallFact {
                call_id: CallId("call-1".to_string()),
                agent_id: AgentId("agt-1".to_string()),
                tool_name: ToolName("test_tool".to_string()),
            }],
            ..Default::default()
        }
    }

    #[test]
    fn uninitialized_store_returns_store_uninitialized_err() {
        let store = PolicyStore::new(); // no swap — holds None
        let result = evaluate_inner(&one_call(), &store);
        assert!(
            matches!(result, Err(EngineError::StoreUninitialized)),
            "expected StoreUninitialized, got: {:?}", result
        );
    }

    #[test]
    fn deny_all_policy_returns_deny_decision() {
        let store = PolicyStore::new();
        let compiled = crate::dsl::compiler::compile(
            r#"policy "default" priority 100 { deny when true reason "blocked"; }"#,
            "v1",
        ).expect("test policy must compile");
        store.swap(compiled);

        let result = evaluate_inner(&one_call(), &store);
        let decision = result.expect("evaluate_inner must succeed with a valid policy");
        assert_eq!(decision.verdict, Verdict::Deny);
        assert_eq!(decision.reason.as_deref(), Some("blocked"));
        assert_eq!(decision.audit.policy_version, "v1");
        assert_eq!(decision.audit.matched_rules, vec!["default".to_string()]);
    }
}
```

- [ ] **Step 4: Run evaluator tests to verify they pass**

```bash
cargo test --lib evaluator
```

Expected:
- `evaluator::engine::tests`: 2 tests pass
- `evaluator::mod::tests`: 10 tests pass
- `evaluator::facts_loader::tests`: 4 tests pass (no regression)
- `evaluator::builtins::tests`: 5 tests pass (no regression)
- Total: 21 tests pass in the `evaluator` module.

> **Debugging notes for implementer:**
> - **`DataValue::Str` comparison**: `s.as_str()` on `SmartString<LazyCompact>` returns `&str`. If `.as_str()` isn't available, try `&*s` (via Deref) or `s.as_ref()`.
> - **`result.rows` field**: Confirmed in Chunk 2's `cozo_mem_instance_runs_trivial_query` test. If `NamedRows` has a different field name, run `cargo doc -p cozo --open`.
> - **`evaluate_allow_rule_returns_allow` returns Deny instead**: Add a temporary `eprintln!("decision_script={}", policy.decision_script)` inside `evaluate_inner` before `run_script` to inspect the compiled Cozo. Check that `agent_role[agent_id, "tester"]` is in the decision script and that the `$agent_roles` param contains the row `["agt-1", "tester"]`.
> - **`evaluate_deny_when_true_populates_reason` returns `None`**: The `True` condition compiles to `tool_call[call_id, _, _]` — the reason comes from the `deny` rule's `reason` field embedded as a string in the Cozo body. If reason is missing, check `compile_policy_block` in `compiler.rs` to verify the reason string is correctly quoted with `cozo_str()`.
> - **`parse_effects_json` fails with a real policy**: Add `eprintln!("effects_json={:?}", json_str)` before the `serde_json::from_str` call to inspect the raw string. Double-escaping (e.g. `[{\\\"type\\\"...}]`) means `compile_effects_json` in `compiler.rs` produced incorrectly escaped output.

- [ ] **Step 5: Add `Engine` re-export to `src/lib.rs`**

Read `src/lib.rs`. It ends with `pub use policy::store::PolicyStore;`. Add:

```rust
pub use evaluator::Engine;
```

- [ ] **Step 6: Run full test suite**

```bash
cargo test --lib
```

Expected: all tests pass; no regressions from Chunks 1–4.

- [ ] **Step 7: Commit**

```bash
git add src/evaluator/engine.rs src/evaluator/mod.rs src/lib.rs
git commit -m "feat: add evaluation engine (Engine, evaluate_inner, PolicyWatcher)"
```
