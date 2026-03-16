# noodle CLI/REPL Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a `noodle` binary that provides an interactive REPL and one-shot evaluation mode for the `datalog-noodle` policy engine.

**Architecture:** The binary lives at `src/bin/noodle.rs` and depends on a `cli` module inside the library crate. The CLI module contains four focused files: `facts_json.rs` (JSON → FactPackage), `output.rs` (Decision → terminal), `repl.rs` (interactive loop), and `oneshot.rs` (batch eval). New dependencies: `clap` (arg parsing), `rustyline` (line editing).

**Tech Stack:** Rust 2021 edition; `clap = "4"` (derive); `rustyline = "15"`; existing `serde_json = "1"`

**Spec:** `docs/superpowers/specs/2026-03-15-noodle-cli-design.md`

**Note:** The spec lists `Op` values `"create"` and `"list"` but the `Op` enum in `src/types.rs` only has `Read`, `Write`, `Delete`, `Execute`. The `facts_json` parser will accept the 4 values that actually exist.

---

## File Structure

```
Cargo.toml                  # Modify: add clap, rustyline deps + [[bin]] section
src/
  lib.rs                    # Modify: add `pub mod cli;`
  cli/
    mod.rs                  # Create: re-exports
    facts_json.rs           # Create: JSON → FactPackage conversion
    output.rs               # Create: Decision → formatted terminal output
    repl.rs                 # Create: REPL loop + command dispatch
    oneshot.rs              # Create: one-shot evaluation
  bin/
    noodle.rs               # Create: main(), clap arg parsing, dispatch
```

---

## Chunk 1: Scaffold + facts_json

### Task 1: Add dependencies and binary target

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Update Cargo.toml**

Add `clap` and `rustyline` to `[dependencies]` and add the `[[bin]]` section:

```toml
[dependencies]
cozo       = { version = "0.7", default-features = false, features = ["minimal", "requests", "rayon"] }
pest       = "2"
pest_derive = "2"
regex      = "1"
parking_lot = "0.12"
thiserror  = "1"
serde_json = "1"
clap       = { version = "4", features = ["derive"] }
rustyline  = "15"

[[bin]]
name = "noodle"
path = "src/bin/noodle.rs"
```

- [ ] **Step 2: Create stub binary and cli module**

Create `src/cli/mod.rs`:

```rust
pub mod facts_json;
pub mod output;
pub mod repl;
pub mod oneshot;
```

Create `src/cli/facts_json.rs`, `src/cli/output.rs`, `src/cli/repl.rs`, `src/cli/oneshot.rs` as empty files (just a comment header).

Create `src/bin/noodle.rs`:

```rust
fn main() {
    println!("noodle: not yet implemented");
}
```

Add `pub mod cli;` to `src/lib.rs`.

- [ ] **Step 3: Verify it compiles**

Run: `cargo build`
Expected: Compiles with no errors. `target/debug/noodle` binary exists.

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml src/lib.rs src/cli/ src/bin/
git commit -m "feat(cli): scaffold noodle binary and cli module"
```

### Task 2: Implement facts_json — JSON to FactPackage conversion

**Files:**
- Create: `src/cli/facts_json.rs`
- Test: inline `#[cfg(test)]` module

This is the core data conversion module. It takes a `serde_json::Value` and produces a `FactPackage`. Each JSON key maps to an array of tuples. Missing keys default to empty vecs. Invalid tuple lengths or type mismatches produce clear error messages.

- [ ] **Step 1: Write failing tests for facts_json**

In `src/cli/facts_json.rs`:

```rust
use crate::facts::*;
use crate::types::*;

#[derive(Debug)]
pub struct FactsJsonError(pub String);

impl std::fmt::Display for FactsJsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub fn parse_facts_json(value: &serde_json::Value) -> Result<FactPackage, FactsJsonError> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_object_returns_default_package() {
        let v: serde_json::Value = serde_json::json!({});
        let pkg = parse_facts_json(&v).unwrap();
        assert!(pkg.tool_calls.is_empty());
        assert!(pkg.agent_roles.is_empty());
    }

    #[test]
    fn tool_calls_parsed() {
        let v = serde_json::json!({
            "tool_calls": [["call-1", "agt-1", "db_query"]]
        });
        let pkg = parse_facts_json(&v).unwrap();
        assert_eq!(pkg.tool_calls.len(), 1);
        assert_eq!(pkg.tool_calls[0].call_id, CallId("call-1".to_string()));
        assert_eq!(pkg.tool_calls[0].agent_id, AgentId("agt-1".to_string()));
        assert_eq!(pkg.tool_calls[0].tool_name, ToolName("db_query".to_string()));
    }

    #[test]
    fn agent_roles_parsed() {
        let v = serde_json::json!({
            "agent_roles": [["agt-1", "analyst"]]
        });
        let pkg = parse_facts_json(&v).unwrap();
        assert_eq!(pkg.agent_roles.len(), 1);
        assert_eq!(pkg.agent_roles[0].agent_id, AgentId("agt-1".to_string()));
        assert_eq!(pkg.agent_roles[0].role, Role("analyst".to_string()));
    }

    #[test]
    fn timestamps_parsed_with_integer() {
        let v = serde_json::json!({
            "timestamps": [["call-1", 1700000000]]
        });
        let pkg = parse_facts_json(&v).unwrap();
        assert_eq!(pkg.timestamps.len(), 1);
        assert_eq!(pkg.timestamps[0].unix_ts, 1_700_000_000);
    }

    #[test]
    fn resource_accesses_parsed_with_op() {
        let v = serde_json::json!({
            "resource_accesses": [["call-1", "agt-1", "data/users", "read"]]
        });
        let pkg = parse_facts_json(&v).unwrap();
        assert_eq!(pkg.resource_accesses.len(), 1);
        assert_eq!(pkg.resource_accesses[0].op, Op::Read);
    }

    #[test]
    fn invalid_op_returns_error() {
        let v = serde_json::json!({
            "resource_accesses": [["call-1", "agt-1", "data/users", "invalid_op"]]
        });
        let result = parse_facts_json(&v);
        assert!(result.is_err());
        assert!(result.unwrap_err().0.contains("invalid_op"));
    }

    #[test]
    fn wrong_tuple_length_returns_error() {
        let v = serde_json::json!({
            "tool_calls": [["call-1", "agt-1"]]  // missing tool_name
        });
        let result = parse_facts_json(&v);
        assert!(result.is_err());
        assert!(result.unwrap_err().0.contains("tool_calls"));
    }

    #[test]
    fn missing_keys_default_to_empty() {
        let v = serde_json::json!({
            "tool_calls": [["call-1", "agt-1", "db_query"]]
        });
        let pkg = parse_facts_json(&v).unwrap();
        assert!(pkg.agents.is_empty());
        assert!(pkg.agent_clearances.is_empty());
        assert!(pkg.call_args.is_empty());
        assert!(pkg.environment.is_empty());
    }

    #[test]
    fn call_counts_parsed_with_integer_count() {
        let v = serde_json::json!({
            "call_counts": [["agt-1", "db_query", "1h", 42]]
        });
        let pkg = parse_facts_json(&v).unwrap();
        assert_eq!(pkg.call_counts.len(), 1);
        assert_eq!(pkg.call_counts[0].count, 42);
        assert_eq!(pkg.call_counts[0].window, "1h");
    }

    #[test]
    fn all_14_fact_types_parsed() {
        let v = serde_json::json!({
            "agents": [["agt-1", "Bot"]],
            "agent_roles": [["agt-1", "analyst"]],
            "agent_clearances": [["agt-1", "secret"]],
            "delegations": [["agt-1", "agt-0"]],
            "users": [["user-1", "agt-1"]],
            "tool_calls": [["call-1", "agt-1", "tool"]],
            "call_args": [["call-1", "k", "v"]],
            "tool_results": [["call-1", "k", "v"]],
            "resource_accesses": [["call-1", "agt-1", "uri", "read"]],
            "resource_mimes": [["call-1", "application/json"]],
            "content_tags": [["call-1", "pii", "high"]],
            "timestamps": [["call-1", 1000]],
            "call_counts": [["agt-1", "tool", "1h", 5]],
            "environment": [["region", "us-east-1"]]
        });
        let pkg = parse_facts_json(&v).unwrap();
        assert_eq!(pkg.agents.len(), 1);
        assert_eq!(pkg.agent_roles.len(), 1);
        assert_eq!(pkg.agent_clearances.len(), 1);
        assert_eq!(pkg.delegations.len(), 1);
        assert_eq!(pkg.users.len(), 1);
        assert_eq!(pkg.tool_calls.len(), 1);
        assert_eq!(pkg.call_args.len(), 1);
        assert_eq!(pkg.tool_results.len(), 1);
        assert_eq!(pkg.resource_accesses.len(), 1);
        assert_eq!(pkg.resource_mimes.len(), 1);
        assert_eq!(pkg.content_tags.len(), 1);
        assert_eq!(pkg.timestamps.len(), 1);
        assert_eq!(pkg.call_counts.len(), 1);
        assert_eq!(pkg.environment.len(), 1);
    }

    #[test]
    fn all_four_op_values_accepted() {
        for (op_str, expected) in [("read", Op::Read), ("write", Op::Write), ("delete", Op::Delete), ("execute", Op::Execute)] {
            let v = serde_json::json!({"resource_accesses": [["c", "a", "u", op_str]]});
            let pkg = parse_facts_json(&v).unwrap();
            assert_eq!(pkg.resource_accesses[0].op, expected);
        }
    }

    #[test]
    fn non_object_returns_error() {
        let v = serde_json::json!([1, 2, 3]);
        assert!(parse_facts_json(&v).is_err());
    }

    #[test]
    fn non_array_fact_key_returns_error() {
        let v = serde_json::json!({"tool_calls": "not an array"});
        assert!(parse_facts_json(&v).is_err());
    }

    #[test]
    fn non_string_in_tuple_returns_error() {
        let v = serde_json::json!({"tool_calls": [[123, "agt-1", "tool"]]});
        assert!(parse_facts_json(&v).is_err());
    }

    #[test]
    fn null_key_treated_as_empty() {
        let v = serde_json::json!({"tool_calls": null});
        let pkg = parse_facts_json(&v).unwrap();
        assert!(pkg.tool_calls.is_empty());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test cli::facts_json`
Expected: All tests fail with `not yet implemented`

- [ ] **Step 3: Implement parse_facts_json**

Replace the `todo!()` in `parse_facts_json` with the full implementation. Use helper functions to keep it DRY:

```rust
use crate::facts::*;
use crate::types::*;

#[derive(Debug)]
pub struct FactsJsonError(pub String);

impl std::fmt::Display for FactsJsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub fn parse_facts_json(value: &serde_json::Value) -> Result<FactPackage, FactsJsonError> {
    let obj = value.as_object().ok_or_else(|| FactsJsonError("expected JSON object".to_string()))?;

    Ok(FactPackage {
        agents: parse_tuples(obj, "agents", 2, |t| Ok(AgentFact {
            id: AgentId(str_at(t, 0)?),
            display_name: str_at(t, 1)?,
        }))?,
        agent_roles: parse_tuples(obj, "agent_roles", 2, |t| Ok(AgentRoleFact {
            agent_id: AgentId(str_at(t, 0)?),
            role: Role(str_at(t, 1)?),
        }))?,
        agent_clearances: parse_tuples(obj, "agent_clearances", 2, |t| Ok(AgentClearanceFact {
            agent_id: AgentId(str_at(t, 0)?),
            clearance: str_at(t, 1)?,
        }))?,
        delegations: parse_tuples(obj, "delegations", 2, |t| Ok(DelegationFact {
            agent_id: AgentId(str_at(t, 0)?),
            delegator_id: AgentId(str_at(t, 1)?),
        }))?,
        users: parse_tuples(obj, "users", 2, |t| Ok(UserFact {
            user_id: str_at(t, 0)?,
            agent_id: AgentId(str_at(t, 1)?),
        }))?,
        tool_calls: parse_tuples(obj, "tool_calls", 3, |t| Ok(ToolCallFact {
            call_id: CallId(str_at(t, 0)?),
            agent_id: AgentId(str_at(t, 1)?),
            tool_name: ToolName(str_at(t, 2)?),
        }))?,
        call_args: parse_tuples(obj, "call_args", 3, |t| Ok(CallArgFact {
            call_id: CallId(str_at(t, 0)?),
            key: str_at(t, 1)?,
            value: str_at(t, 2)?,
        }))?,
        tool_results: parse_tuples(obj, "tool_results", 3, |t| Ok(ToolResultFact {
            call_id: CallId(str_at(t, 0)?),
            key: str_at(t, 1)?,
            value: str_at(t, 2)?,
        }))?,
        resource_accesses: parse_tuples(obj, "resource_accesses", 4, |t| Ok(ResourceAccessFact {
            call_id: CallId(str_at(t, 0)?),
            agent_id: AgentId(str_at(t, 1)?),
            uri: Uri(str_at(t, 2)?),
            op: parse_op(&str_at(t, 3)?)?,
        }))?,
        resource_mimes: parse_tuples(obj, "resource_mimes", 2, |t| Ok(ResourceMimeFact {
            call_id: CallId(str_at(t, 0)?),
            mime_type: str_at(t, 1)?,
        }))?,
        content_tags: parse_tuples(obj, "content_tags", 3, |t| Ok(ContentTagFact {
            call_id: CallId(str_at(t, 0)?),
            tag: str_at(t, 1)?,
            value: str_at(t, 2)?,
        }))?,
        timestamps: parse_tuples(obj, "timestamps", 2, |t| Ok(TimestampFact {
            call_id: CallId(str_at(t, 0)?),
            unix_ts: uint_at(t, 1, "timestamps")?,
        }))?,
        call_counts: parse_tuples(obj, "call_counts", 4, |t| Ok(CallCountFact {
            agent_id: AgentId(str_at(t, 0)?),
            tool_name: ToolName(str_at(t, 1)?),
            window: str_at(t, 2)?,
            count: uint_at(t, 3, "call_counts")?,
        }))?,
        environment: parse_tuples(obj, "environment", 2, |t| Ok(EnvironmentFact {
            key: str_at(t, 0)?,
            value: str_at(t, 1)?,
        }))?,
    })
}

fn parse_tuples<T, F>(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    expected_len: usize,
    convert: F,
) -> Result<Vec<T>, FactsJsonError>
where
    F: Fn(&[serde_json::Value]) -> Result<T, FactsJsonError>,
{
    let arr = match obj.get(key) {
        Some(serde_json::Value::Array(a)) => a,
        Some(serde_json::Value::Null) | None => return Ok(Vec::new()),
        Some(other) => return Err(FactsJsonError(format!("{key}: expected array, got {}", other))),
    };
    arr.iter().enumerate().map(|(i, row)| {
        let tuple = row.as_array().ok_or_else(|| {
            FactsJsonError(format!("{key}[{i}]: expected array tuple"))
        })?;
        if tuple.len() != expected_len {
            return Err(FactsJsonError(format!(
                "{key}[{i}]: expected {expected_len} fields, got {}", tuple.len()
            )));
        }
        convert(tuple)
    }).collect()
}

fn str_at(tuple: &[serde_json::Value], idx: usize) -> Result<String, FactsJsonError> {
    tuple[idx].as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| FactsJsonError(format!("expected string at position {idx}, got {}", tuple[idx])))
}

fn uint_at(tuple: &[serde_json::Value], idx: usize, key: &str) -> Result<u64, FactsJsonError> {
    tuple[idx].as_u64()
        .ok_or_else(|| FactsJsonError(format!("{key}: expected integer at position {idx}, got {}", tuple[idx])))
}

fn parse_op(s: &str) -> Result<Op, FactsJsonError> {
    match s {
        "read"    => Ok(Op::Read),
        "write"   => Ok(Op::Write),
        "delete"  => Ok(Op::Delete),
        "execute" => Ok(Op::Execute),
        other     => Err(FactsJsonError(format!(
            "invalid op \"{other}\": expected read, write, delete, or execute"
        ))),
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test cli::facts_json`
Expected: All 15 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/cli/facts_json.rs
git commit -m "feat(cli): implement JSON to FactPackage conversion"
```

---

## Chunk 2: Output formatting

### Task 3: Implement output — Decision to terminal display

**Files:**
- Create: `src/cli/output.rs`
- Test: inline `#[cfg(test)]` module

Formats a `Decision` for terminal display. ANSI color codes for Allow (green) / Deny (red), gated on a `use_color: bool` parameter (caller checks `std::io::IsTerminal`).

- [ ] **Step 1: Write failing tests**

In `src/cli/output.rs`:

```rust
use crate::decision::*;
use crate::types::*;

/// Format a Decision for terminal display.
pub fn format_decision(d: &Decision, use_color: bool) -> String {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_decision(verdict: Verdict, reason: Option<&str>, block: &str, effects: Vec<Effect>) -> Decision {
        Decision {
            verdict,
            effects,
            reason: reason.map(|s| s.to_string()),
            audit: AuditRecord {
                call_id: CallId("call-1".to_string()),
                agent_id: AgentId("agt-1".to_string()),
                tool_name: Some("db_query".to_string()),
                verdict,
                policy_version: "v3".to_string(),
                matched_rules: if block.is_empty() { vec![] } else { vec![block.to_string()] },
                timestamp: None,
            },
        }
    }

    #[test]
    fn allow_no_color() {
        let d = make_decision(Verdict::Allow, None, "authz", vec![]);
        let out = format_decision(&d, false);
        assert!(out.contains("Allow"));
        assert!(out.contains("[block: authz]"));
        assert!(out.contains("call-1 | agt-1 | db_query | v3"));
        assert!(!out.contains("\x1b["));
    }

    #[test]
    fn deny_with_reason_no_color() {
        let d = make_decision(Verdict::Deny, Some("no matching allow rule"), "authz", vec![]);
        let out = format_decision(&d, false);
        assert!(out.contains("Deny"));
        assert!(out.contains("reason: \"no matching allow rule\""));
    }

    #[test]
    fn allow_with_color() {
        let d = make_decision(Verdict::Allow, None, "authz", vec![]);
        let out = format_decision(&d, true);
        assert!(out.contains("\x1b[32m")); // green
        assert!(out.contains("\x1b[0m"));  // reset
    }

    #[test]
    fn deny_with_color() {
        let d = make_decision(Verdict::Deny, Some("blocked"), "authz", vec![]);
        let out = format_decision(&d, true);
        assert!(out.contains("\x1b[31m")); // red
    }

    #[test]
    fn effects_displayed() {
        let d = make_decision(Verdict::Allow, None, "pii", vec![
            Effect::Redact { selector: "response.content".to_string(), classifier: "pii".to_string() },
        ]);
        let out = format_decision(&d, false);
        assert!(out.contains("effects: Redact(response.content, pii)"));
    }

    #[test]
    fn no_block_shows_none() {
        let d = make_decision(Verdict::Deny, Some("err"), "", vec![]);
        let out = format_decision(&d, false);
        assert!(out.contains("[block: <none>]"));
    }

    #[test]
    fn multiple_effects() {
        let d = make_decision(Verdict::Allow, None, "multi", vec![
            Effect::Redact { selector: "a".to_string(), classifier: "b".to_string() },
            Effect::Audit { level: AuditLevel::Elevated, message: None },
        ]);
        let out = format_decision(&d, false);
        assert!(out.contains("effects: Redact(a, b)"));
        assert!(out.contains("Audit(Elevated)"));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test cli::output`
Expected: All tests fail with `not yet implemented`

- [ ] **Step 3: Implement format_decision**

```rust
use crate::decision::*;
use crate::types::*;

const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const RESET: &str = "\x1b[0m";

pub fn format_decision(d: &Decision, use_color: bool) -> String {
    let mut out = String::new();

    let block = d.audit.matched_rules.first()
        .map(|s| s.as_str())
        .unwrap_or("<none>");

    // Verdict line
    let (icon, verdict_str, color) = match d.verdict {
        Verdict::Allow => ("\u{2713}", "Allow", GREEN),
        Verdict::Deny  => ("\u{2717}", "Deny ", RED),
    };

    if use_color {
        out.push_str(&format!("{color}{icon} {verdict_str}{RESET}  [block: {block}]"));
    } else {
        out.push_str(&format!("{icon} {verdict_str}  [block: {block}]"));
    }

    if let Some(reason) = &d.reason {
        out.push_str(&format!("  reason: \"{reason}\""));
    }
    out.push('\n');

    // Effects
    for (i, effect) in d.effects.iter().enumerate() {
        if i == 0 {
            out.push_str(&format!("  effects: {}\n", format_effect(effect)));
        } else {
            out.push_str(&format!("           {}\n", format_effect(effect)));
        }
    }

    // Audit line
    let tool = d.audit.tool_name.as_deref().unwrap_or("<none>");
    out.push_str(&format!(
        "  audit: {} | {} | {} | {}\n",
        d.audit.call_id.0, d.audit.agent_id.0, tool, d.audit.policy_version
    ));

    out
}

fn format_effect(e: &Effect) -> String {
    match e {
        Effect::Redact { selector, classifier } => format!("Redact({selector}, {classifier})"),
        Effect::Mask { selector, pattern, replacement } => format!("Mask({selector}, {pattern}, {replacement})"),
        Effect::Annotate { key, value } => format!("Annotate({key}, {value})"),
        Effect::Audit { level, message } => {
            let lvl = match level {
                AuditLevel::Standard => "Standard",
                AuditLevel::Elevated => "Elevated",
                AuditLevel::Critical => "Critical",
            };
            match message {
                Some(msg) => format!("Audit({lvl}: {msg})"),
                None => format!("Audit({lvl})"),
            }
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test cli::output`
Expected: All 7 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/cli/output.rs
git commit -m "feat(cli): implement decision output formatting"
```

---

## Chunk 3: REPL + one-shot + main

### Task 4: Implement oneshot mode

**Files:**
- Create: `src/cli/oneshot.rs`

One-shot mode: reads a policy file and facts JSON file, evaluates, prints decision, returns exit code.

- [ ] **Step 1: Implement oneshot::run**

```rust
use std::path::Path;
use std::io::IsTerminal;
use crate::cli::facts_json;
use crate::cli::output;
use crate::{Engine, PolicySet, PolicyWatcher};

/// Run one-shot evaluation. Returns process exit code: 0=Allow, 1=Deny, 2=error.
pub fn run(policy_path: &Path, facts_path: &Path) -> i32 {
    let engine = Engine::new();

    let source = match std::fs::read_to_string(policy_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read policy file {}: {}", policy_path.display(), e);
            return 2;
        }
    };

    if let Err(e) = engine.push(PolicySet {
        version: "v1".to_string(),
        source,
        checksum: String::new(),
    }) {
        eprintln!("error: policy compilation failed: {e}");
        return 2;
    }

    let json_str = match std::fs::read_to_string(facts_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read facts file {}: {}", facts_path.display(), e);
            return 2;
        }
    };

    let json_value: serde_json::Value = match serde_json::from_str(&json_str) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: invalid JSON in {}: {}", facts_path.display(), e);
            return 2;
        }
    };

    let facts = match facts_json::parse_facts_json(&json_value) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: invalid fact format: {e}");
            return 2;
        }
    };

    let decision = engine.evaluate(&facts);
    let use_color = std::io::stdout().is_terminal();
    print!("{}", output::format_decision(&decision, use_color));

    match decision.verdict {
        crate::Verdict::Allow => 0,
        crate::Verdict::Deny  => 1,
    }
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo build`
Expected: Compiles. (Integration testing happens via the binary in Task 6.)

- [ ] **Step 3: Commit**

```bash
git add src/cli/oneshot.rs
git commit -m "feat(cli): implement one-shot evaluation mode"
```

### Task 5: Implement REPL

**Files:**
- Create: `src/cli/repl.rs`

The REPL owns an `Engine`, a policy file path, a version counter, and a `rustyline::Editor`. It reads lines, dispatches `:` commands or accumulates JSON input and evaluates.

- [ ] **Step 1: Implement repl::run**

```rust
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use rustyline::error::ReadlineError;
use crate::cli::facts_json;
use crate::cli::output;
use crate::{Engine, PolicySet, PolicyWatcher, Verdict};

struct ReplState {
    engine: Engine,
    policy_path: Option<PathBuf>,
    version_counter: u32,
}

impl ReplState {
    fn new() -> Self {
        Self {
            engine: Engine::new(),
            policy_path: None,
            version_counter: 0,
        }
    }

    fn load_policy(&mut self, path: &Path) -> Result<(), String> {
        let source = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        self.version_counter += 1;
        let version = format!("v{}", self.version_counter);
        self.engine.push(PolicySet {
            version: version.clone(),
            source,
            checksum: String::new(),
        }).map_err(|e| format!("compile error: {e}"))?;
        self.policy_path = Some(path.to_path_buf());
        eprintln!("loaded {} ({})", path.display(), version);
        Ok(())
    }
}

pub fn run(initial_policy: Option<&Path>) {
    let mut state = ReplState::new();
    let use_color = std::io::stdout().is_terminal();

    if let Some(path) = initial_policy {
        if let Err(e) = state.load_policy(path) {
            eprintln!("error: {e}");
        }
    }

    let mut rl = rustyline::DefaultEditor::new().expect("failed to initialize readline");
    let mut json_buf = String::new();
    let mut brace_depth: i32 = 0;

    loop {
        let prompt = if json_buf.is_empty() { "noodle> " } else { "...     " };
        let line = match rl.readline(prompt) {
            Ok(line) => line,
            Err(ReadlineError::Eof) => break,
            Err(ReadlineError::Interrupted) => {
                json_buf.clear();
                brace_depth = 0;
                continue;
            }
            Err(e) => {
                eprintln!("readline error: {e}");
                break;
            }
        };

        // Blank line while accumulating → cancel
        if !json_buf.is_empty() && line.trim().is_empty() {
            json_buf.clear();
            brace_depth = 0;
            eprintln!("(input cancelled)");
            continue;
        }

        let trimmed = line.trim();

        // Commands (only when not accumulating JSON)
        if json_buf.is_empty() && trimmed.starts_with(':') {
            rl.add_history_entry(&line).ok();
            handle_command(trimmed, &mut state, use_color);
            continue;
        }

        // JSON accumulation
        json_buf.push_str(&line);
        json_buf.push('\n');
        for ch in line.chars() {
            match ch {
                '{' | '[' => brace_depth += 1,
                '}' | ']' => brace_depth -= 1,
                _ => {}
            }
        }

        if brace_depth > 0 {
            continue; // keep reading
        }

        // Balanced — evaluate
        rl.add_history_entry(json_buf.trim()).ok();
        evaluate_json(&json_buf, &state, use_color);
        json_buf.clear();
        brace_depth = 0;
    }
}

fn handle_command(input: &str, state: &mut ReplState, use_color: bool) {
    let parts: Vec<&str> = input.splitn(2, ' ').collect();
    match parts[0] {
        ":quit" | ":q" => std::process::exit(0),
        ":help" | ":h" => print_help(),
        ":load" => {
            if let Some(path) = parts.get(1).map(|s| s.trim()) {
                if let Err(e) = state.load_policy(Path::new(path)) {
                    eprintln!("error: {e}");
                }
            } else {
                eprintln!("usage: :load <path>");
            }
        }
        ":reload" | ":r" => {
            if let Some(path) = state.policy_path.clone() {
                if let Err(e) = state.load_policy(&path) {
                    eprintln!("error: {e}");
                }
            } else {
                eprintln!("no policy loaded; use :load <path> first");
            }
        }
        ":policy" | ":p" => {
            match (&state.policy_path, state.engine.current_version()) {
                (Some(path), Some(ver)) => println!("policy: {} ({})", path.display(), ver),
                _ => println!("no policy loaded"),
            }
        }
        ":example" | ":e" => print_example(),
        other => eprintln!("unknown command: {other}  (type :help for commands)"),
    }
}

fn evaluate_json(json_str: &str, state: &ReplState, use_color: bool) {
    if state.engine.current_version().is_none() {
        eprintln!("no policy loaded; use :load <path> first");
        return;
    }
    let value: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("JSON parse error: {e}");
            return;
        }
    };
    let facts = match facts_json::parse_facts_json(&value) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("fact error: {e}");
            return;
        }
    };
    let decision = state.engine.evaluate(&facts);
    print!("{}", output::format_decision(&decision, use_color));
}

fn print_help() {
    println!("Commands:");
    println!("  :load <path>   Load or replace policy from a .dl file");
    println!("  :reload        Reload current policy file");
    println!("  :policy        Show loaded policy info");
    println!("  :example       Print an example JSON fact package");
    println!("  :help          Show this help");
    println!("  :quit          Exit (also Ctrl-D)");
    println!();
    println!("Type or paste a JSON fact package to evaluate it.");
    println!("Multiline JSON is supported — input continues until braces balance.");
    println!("A blank line while typing JSON cancels the input.");
}

fn print_example() {
    println!(r#"{{
  "tool_calls": [["call-1", "agt-1", "db_query"]],
  "agent_roles": [["agt-1", "analyst"]],
  "resource_accesses": [["call-1", "agt-1", "data/users", "read"]],
  "timestamps": [["call-1", 1700000000]]
}}"#);
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo build`
Expected: Compiles with no errors.

- [ ] **Step 3: Commit**

```bash
git add src/cli/repl.rs
git commit -m "feat(cli): implement interactive REPL"
```

### Task 6: Implement main entry point

**Files:**
- Modify: `src/bin/noodle.rs`

- [ ] **Step 1: Implement main with clap**

```rust
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "noodle", about = "Interactive policy engine REPL")]
struct Args {
    /// Policy DSL file to load
    policy: Option<PathBuf>,

    /// Facts JSON file to evaluate (enables one-shot mode)
    facts: Option<PathBuf>,
}

fn main() {
    let args = Args::parse();

    match (&args.policy, &args.facts) {
        (Some(policy), Some(facts)) => {
            let code = datalog_noodle::cli::oneshot::run(policy, facts);
            std::process::exit(code);
        }
        (policy, None) => {
            datalog_noodle::cli::repl::run(policy.as_deref());
        }
        (None, Some(_)) => {
            eprintln!("error: facts file requires a policy file");
            eprintln!("usage: noodle [POLICY] [FACTS]");
            std::process::exit(2);
        }
    }
}
```

- [ ] **Step 2: Build and run smoke test**

Run: `cargo build && ./target/debug/noodle --help`
Expected: Shows help with positional args.

- [ ] **Step 3: Commit**

```bash
git add src/bin/noodle.rs
git commit -m "feat(cli): implement noodle main entry point with clap"
```

### Task 7: End-to-end smoke test

**Files:**
- Create: `tests/fixtures/test.dl` (test policy)
- Create: `tests/fixtures/test_facts.json` (test facts)

- [ ] **Step 1: Create test fixtures**

`tests/fixtures/test.dl`:

```
policy "authz" priority 100 {
    allow when
        tool_call(call_id, agent_id, _),
        agent_role(agent_id, "analyst");
    deny when true reason "no matching allow rule";
}
```

`tests/fixtures/test_facts.json`:

```json
{
  "tool_calls": [["call-1", "agt-1", "db_query"]],
  "agent_roles": [["agt-1", "analyst"]]
}
```

- [ ] **Step 2: Run one-shot mode and verify**

Run: `cargo run -- tests/fixtures/test.dl tests/fixtures/test_facts.json; echo "exit: $?"`
Expected output:

```
✓ Allow  [block: authz]
  audit: call-1 | agt-1 | db_query | v1
exit: 0
```

- [ ] **Step 3: Test deny case**

Create `tests/fixtures/test_facts_deny.json`:

```json
{
  "tool_calls": [["call-1", "agt-1", "db_query"]],
  "agent_roles": [["agt-1", "intern"]]
}
```

Run: `cargo run -- tests/fixtures/test.dl tests/fixtures/test_facts_deny.json; echo "exit: $?"`
Expected output:

```
✗ Deny   [block: authz]  reason: "no matching allow rule"
  audit: call-1 | agt-1 | db_query | v1
exit: 1
```

- [ ] **Step 4: Test error case (bad policy file)**

Run: `cargo run -- nonexistent.dl tests/fixtures/test_facts.json; echo "exit: $?"`
Expected: Error message to stderr, `exit: 2`

- [ ] **Step 5: Verify all existing tests still pass**

Run: `cargo test`
Expected: All 96 existing tests + new facts_json and output tests pass.

- [ ] **Step 6: Commit**

```bash
git add tests/fixtures/
git commit -m "feat(cli): add test fixtures and verify end-to-end smoke test"
```
