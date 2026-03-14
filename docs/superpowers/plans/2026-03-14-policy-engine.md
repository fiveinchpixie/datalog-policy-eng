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
