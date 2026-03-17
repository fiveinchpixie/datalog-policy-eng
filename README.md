# datalog-noodle

A zero-trust Datalog policy engine for MCP (Model Context Protocol) agentic workflows. Policies are authored in a custom DSL, compiled to [CozoDB](https://www.cozodb.org/) queries, and evaluated synchronously against per-request fact packages. The engine never fails open: any error during evaluation produces `Deny + Audit(Critical)`.

## Quick Start

```bash
cargo build              # build library + noodle CLI
cargo test               # run all tests
cargo run                # start the interactive REPL
```

## The `noodle` CLI

The `noodle` binary provides an interactive REPL and one-shot evaluation mode.

```bash
noodle                           # start REPL with no policy
noodle policy.dl                 # start REPL with a policy pre-loaded
noodle policy.dl facts.json      # one-shot: evaluate and exit (0=Allow, 1=Deny, 2=error)
```

### REPL Commands

| Command          | Description                                      |
|------------------|--------------------------------------------------|
| `:load <path>`   | Load or replace policy from a `.dl` file         |
| `:reload`        | Reload current policy file                       |
| `:watch <path>`  | Watch a policy file for changes (auto-reload)    |
| `:unwatch`       | Stop watching                                    |
| `:policy`        | Show loaded policy info                          |
| `:example`       | Print an example JSON fact package               |
| `:help`          | Show help                                        |
| `:quit`          | Exit (also Ctrl-D)                               |

Type or paste a JSON fact package to evaluate it against the loaded policy. Multiline JSON is supported -- input continues until braces balance. A blank line cancels multiline input.

### File Watching

`:watch policy.dl` polls the file every 2 seconds. When the file content changes (detected via SHA-256 checksum), the policy is recompiled and hot-swapped. If the new policy has syntax errors, the old policy stays active and the error is printed.

```
noodle> :watch policy.dl
watching policy.dl (poll every 2s)
[watch] reloaded policy.dl (watch-v2)     # appears when file changes
[watch] compile error in policy.dl: ...   # appears on bad syntax
```

## Policy DSL

Policies are written in a custom DSL that compiles to CozoDB Datalog queries.

### Policy Blocks

A policy block has a name, a priority (higher = evaluated first), and a set of allow/deny rules:

```
policy "authz" priority 100 {
    allow when
        tool_call(call_id, agent_id, _),
        agent_role(agent_id, "analyst");
    deny when true reason "no matching allow rule";
}
```

- `allow` rules take precedence over `deny` rules within the same block
- `deny when true` is the standard default-deny fallback
- Higher-priority policy blocks are evaluated before lower-priority ones

### Conditions

Conditions are Datalog-style atoms joined by commas (AND). Variables start with a lowercase letter, `_` is a wildcard.

```
tool_call(call_id, agent_id, tool_name)    # bind variables
agent_role(agent_id, "analyst")            # match a literal
not agent_role(agent_id, "admin")          # negation
```

### Built-in Fact Predicates

These predicates match against the request's `FactPackage`:

| Predicate | Arguments |
|-----------|-----------|
| `tool_call` | `(call_id, agent_id, tool_name)` |
| `agent_role` | `(agent_id, role)` |
| `agent_clearance` | `(agent_id, clearance)` |
| `agent` | `(agent_id, display_name)` |
| `delegated_by` | `(agent_id, delegator_id)` |
| `user` | `(user_id, agent_id)` |
| `call_arg` | `(call_id, key, value)` |
| `tool_result` | `(call_id, key, value)` |
| `resource_access` | `(call_id, agent_id, uri, op)` — op: read, write, create, delete, list, execute |
| `resource_mime` | `(call_id, mime_type)` |
| `content_tag` | `(call_id, tag, value)` |
| `timestamp` | `(call_id, unix_ts)` |
| `call_count` | `(agent_id, tool_name, window, count)` |
| `environment` | `(key, value)` |

### Rules

Named reusable rules with parameters, defined outside policy blocks:

```
rule can_call(agent, tool) :-
    agent_role(agent, role),
    tool_category(tool, cat),
    role_permission(role, "call", cat);
```

Rules can use `or` for disjunction:

```
rule is_privileged(agent) :-
    agent_role(agent, "admin") or agent_role(agent, "superuser");
```

### Grants, Categories, and Classifications

Declare policy facts that rules can query:

```
// Role-based permissions
grant role "analyst" can call tool:category("read-only");
grant role "admin" can call tool:any;
grant role "analyst" can access resource:pattern("data/public/*");

// Tool categorization
categorize tool "db_query" as "read-only";
categorize tool "db_write" as "write";

// Resource sensitivity
classify resource "data/finance/*" as sensitivity "high";
```

These are stored in the compiled policy's CozoDB instance and queried via `role_permission`, `tool_category`, and `resource_sensitivity` predicates.

### Pattern Matching

Regex patterns for input validation:

```
pattern :sql_injection = r"(?i)(drop|delete)\s+table";

rule has_forbidden_arg(call_id) :-
    call_arg(call_id, _, value),
    matches(value, :sql_injection);

policy "input-scan" priority 200 {
    deny when
        tool_call(call_id, _, _),
        has_forbidden_arg(call_id)
        reason "SQL injection detected";
}
```

The `matches(value, :pattern_name)` predicate is rewritten at compile time to use a regex pre-pass.

### Effects

Rules can attach effects to their decisions:

```
allow when
    tool_call(call_id, agent_id, _),
    agent_role(agent_id, "analyst")
    effect Redact(selector: "response.content", classifier: "pii")
    effect Audit(level: Standard);

deny when true
    reason "blocked"
    effect Audit(level: Elevated);
```

Available effects:

| Effect | Parameters |
|--------|-----------|
| `Redact` | `selector`, `classifier` |
| `Mask` | `selector`, `pattern`, `replacement` |
| `Annotate` | `key`, `value` |
| `Audit` | `level` (`Standard`, `Elevated`, `Critical`) |

### Multi-Policy Priority

Multiple policy blocks can coexist. Higher-priority blocks are evaluated first. If a higher-priority block produces a decision, lower-priority blocks are skipped:

```
// Priority 200: input scanning (checked first)
policy "input-scan" priority 200 {
    deny when
        tool_call(call_id, _, _),
        has_forbidden_arg(call_id)
        reason "SQL injection detected";
}

// Priority 100: role-based access (checked second)
policy "authz" priority 100 {
    allow when
        tool_call(call_id, agent_id, tool_name),
        can_call(agent_id, tool_name);
    deny when true reason "no matching allow rule";
}
```

## Library API

```rust
use datalog_noodle::{Engine, FactPackage, PolicySet, PolicyWatcher, Verdict};
use datalog_noodle::facts::*;
use datalog_noodle::types::*;

// Create engine and load a policy
let engine = Engine::new();
engine.push(PolicySet {
    version: "v1".to_string(),
    source: r#"
        policy "authz" priority 100 {
            allow when
                tool_call(call_id, agent_id, _),
                agent_role(agent_id, "analyst");
            deny when true reason "no matching allow rule";
        }
    "#.to_string(),
    checksum: String::new(),
}).expect("policy compiles");

// Build a fact package for the request
let facts = FactPackage {
    tool_calls: vec![ToolCallFact {
        call_id: CallId("call-1".to_string()),
        agent_id: AgentId("agt-1".to_string()),
        tool_name: ToolName("db_query".to_string()),
    }],
    agent_roles: vec![AgentRoleFact {
        agent_id: AgentId("agt-1".to_string()),
        role: Role("analyst".to_string()),
    }],
    ..Default::default()
};

// Evaluate
let decision = engine.evaluate(&facts);
assert_eq!(decision.verdict, Verdict::Allow);
```

### Key Types

- **`Engine`** -- the main entry point. `Clone + Send + Sync`. All clones share the same policy store.
- **`PolicySet`** -- a policy source string with version and checksum, passed to `Engine::push()`.
- **`FactPackage`** -- all facts for one request evaluation (tool calls, roles, resources, etc.).
- **`Decision`** -- the evaluation result: `Verdict` (Allow/Deny), `effects`, `reason`, `AuditRecord`.
- **`PolicyFileWatcher`** -- watches a `.dl` file and auto-reloads on changes.

### Concurrency

`Engine` is thread-safe. Multiple threads can evaluate concurrently while a separate thread pushes policy updates. The policy store uses `Arc<parking_lot::RwLock>` -- reads never block each other.

```rust
use datalog_noodle::policy::file_watcher::{PolicyFileWatcher, WatchEvent};

let engine = Engine::new();
let watcher = PolicyFileWatcher::start(
    Path::new("policy.dl"),
    engine.clone(),
    Duration::from_secs(2),
    |event| match event {
        WatchEvent::Reloaded { version, .. } => println!("reloaded: {version}"),
        WatchEvent::CompileError { error, .. } => eprintln!("error: {error}"),
        WatchEvent::IoError { error, .. } => eprintln!("io error: {error}"),
    },
).expect("initial load");

// engine.evaluate(&facts) works concurrently with the watcher
```

## Fact JSON Format

The `noodle` CLI accepts facts as JSON. Each key maps to an array of tuples:

```json
{
  "tool_calls": [["call-1", "agt-1", "db_query"]],
  "agent_roles": [["agt-1", "analyst"]],
  "resource_accesses": [["call-1", "agt-1", "data/users", "read"]],
  "call_args": [["call-1", "query", "SELECT * FROM users"]],
  "timestamps": [["call-1", 1700000000]]
}
```

Missing keys default to empty arrays. See `docs/superpowers/specs/2026-03-15-noodle-cli-design.md` for the complete field reference.

## Architecture

```
FactPackage  ──>  Engine::evaluate()  ──>  Decision (Verdict + Effects + AuditRecord)
                       |
                  PolicyStore
                       |
                  CompiledPolicy (CozoDB instance + decision script + regex patterns)
                       |
                  DSL compiler (parse → AST → CozoScript)
```

The engine embeds an in-memory CozoDB instance per compiled policy. Per-request facts are passed as CozoScript parameters -- no mutation of the policy DB during evaluation.
