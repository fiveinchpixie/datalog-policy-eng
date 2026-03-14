# Policy Engine Design

**Project:** datalog-noodle
**Date:** 2026-03-14
**Subsystem:** 1 of N — Datalog Policy Engine (core)
**Status:** Draft

---

## Overview

`datalog-noodle` is a zero-trust authorization system for securing agentic MCP workflows end-to-end. This spec covers **Subsystem 1: the Datalog policy engine** — the core evaluation library that takes a request context and a policy set and produces a structured authorization decision.

The engine is a pure function: `facts + rules → decision`. It never touches the network, filesystem, or clock. All context travels with the request as facts. The gateway owns execution of effects; the engine owns reasoning.

---

## Scope

### In scope

- **Fact Assembler** — canonical fact types and the `FactPackage` struct the gateway builds per request
- **Policy Store** — in-memory CozoDB instance holding compiled policy rules, updated atomically by the control plane
- **Evaluator** — stateless evaluation of `FactPackage` against `PolicyStore`, returning a `Decision`
- **Decision type** — `Verdict + Vec<Effect> + AuditRecord`
- **Policy DSL** — human-readable policy language that compiles to CozoDB relations
- **DSL Compiler** — parser and compiler from DSL source to CozoDB queries
- **Policy Watcher** — the embedded side of the control plane interface (push receiver)
- **Effect Executor trait** — interface the gateway implements; defined here, implemented elsewhere

### Out of scope (future specs)

- **Control Plane** (Spec 2) — policy authoring, versioning, storage, admin API, push delivery
- **Gateway Integration** (Spec 3) — MCP proxy, fact assembly from live requests, effect execution
- **Content Classifiers** (Spec 4) — PII detection, domain tagging, data sensitivity labelling

---

## Architecture

The engine is embedded in the gateway process as a Rust library crate. Policy rules live in a shared `PolicyStore` (in-memory CozoDB) updated asynchronously by the control plane. Per-request evaluation is synchronous, stateless, and uses a short-lived CozoDB scratchpad for request facts.

```
┌─────────────────────────────────────────────────────────────┐
│                   Gateway Process (Rust)                    │
│                                                             │
│   MCP Request                                               │
│   ──────────▶  ┌──────────────┐   FactPackage              │
│                │  Fact        │──────────────▶ ┌─────────┐ │
│                │  Assembler   │                │         │ │
│                └──────────────┘                │Evaluator│ │
│                                                │         │ │
│                ┌──────────────┐   Decision     │(CozoDB) │ │
│   Response     │  Effect      │◀────────────── │         │ │
│   ◀──────────  │  Executor    │                └────▲────┘ │
│                └──────────────┘                     │       │
│                                                     │ rules │
│                                          ┌──────────┴────┐  │
│                                          │ Policy Store  │  │
│                                          │   (CozoDB)    │  │
│                                          └──────▲────────┘  │
└─────────────────────────────────────────────────┼───────────┘
                                                   │ push
                                        ┌──────────┴────────┐
                                        │  Policy Watcher   │
                                        │  (control plane   │
                                        │   client)         │
                                        └──────────▲────────┘
                                                   │
                              ┌────────────────────┴────────┐
                              │  Control Plane (future spec) │
                              └──────────────────────────────┘
```

**Startup state:** The `PolicyStore` holds `None` on startup (`Arc<RwLock<Option<CompiledPolicy>>>`). Any evaluation against an uninitialized store immediately returns `Deny + Audit(Critical)` without opening a scratchpad. The first successful `push()` call initializes the store.

**Key design principle:** The `PolicyStore` is protected by an `Arc<RwLock<Option<CompiledPolicy>>>`. Many requests hold read locks concurrently with zero contention. Policy pushes (rare) take a write lock, compile and validate the new policy atomically, swap the store, and release. No request ever sees a partially-updated policy.

---

## Fact Model

Facts are the complete context available to the engine during evaluation. They divide into two groups:

### Request facts (assembled per-request by the gateway)

**Identity**

| Fact | Fields | Description |
|---|---|---|
| `agent` | `AgentId, DisplayName` | An agent exists in this request |
| `agent_role` | `AgentId, Role` | An agent holds a role |
| `agent_clearance` | `AgentId, Clearance` | An agent has a special clearance |
| `delegated_by` | `AgentId, DelegatorId` | Agent was spawned by another agent |
| `user` | `UserId, AgentId` | Human user associated with an agent |

**MCP call structure**

| Fact | Fields | Description |
|---|---|---|
| `tool_call` | `CallId, AgentId, ToolName` | A tool is being called |
| `call_arg` | `CallId, Key, Value` | An argument to the tool call |
| `tool_result` | `CallId, Key, Value` | A value in the tool response (response-time policies) |
| `resource_access` | `CallId, AgentId, Uri, Op` | A resource access request |
| `resource_mime` | `CallId, MimeType` | MIME type of a resource |

**Content classification** (from external classifiers, asserted as facts)

| Fact | Fields | Description |
|---|---|---|
| `content_tag` | `CallId, Tag, Value` | A classification tag on this call |

Examples: `content_tag("call-1", "pii", "high")`, `content_tag("call-1", "domain", "finance")`

**Environment / context**

| Fact | Fields | Description |
|---|---|---|
| `timestamp` | `CallId, UnixTs` | When the call occurred — engine has no clock |
| `call_count` | `AgentId, ToolName, Window, Count` | Rate context from external counter |
| `environment` | `Key, Value` | Deployment environment variables |

### Policy facts (compiled from DSL, loaded into PolicyStore)

| Fact | Fields | Description |
|---|---|---|
| `role_permission` | `Role, Action, ResourcePattern` | What actions a role permits |
| `tool_category` | `ToolName, Category` | Tool classification |
| `resource_sensitivity` | `UriPattern, Level` | Resource sensitivity level |
| `clearance_grants` | `Clearance, Privilege` | What a clearance unlocks |
| `forbidden_pattern` | `Name, Source` | Named forbidden content patterns — source string stored in CozoDB; compiled `Regex` objects live in `CompiledPolicy.patterns: HashMap<String, Regex>` |
| `forbidden_arg_key` | `ToolName, Key` | Forbidden argument keys per tool |
| `allowed_domain` | `UriPattern` | Permitted resource domains |
| `tag_effect` | `Tag, Value, Effect` | Effect to apply when a content tag matches |
| `sensitivity_effect` | `Level, Effect` | Effect to apply at a given sensitivity level |

**Fact principles:**
- Facts are immutable within an evaluation — nothing is written during query execution
- Time is a fact, not a syscall — the gateway asserts `timestamp`, the engine never calls the clock
- Pattern source strings are stored as CozoDB relations; compiled `Regex` objects live in `CompiledPolicy.patterns: HashMap<String, Regex>`, keyed by pattern name. The `matches()` built-in resolves names through this map at eval time — it never queries CozoDB for the pattern.
- Content tags are assertions from external classifiers — the engine never inspects raw content

---

## Decision Schema

```rust
pub struct Decision {
    pub verdict: Verdict,
    pub effects: Vec<Effect>,
    pub reason:  Option<String>,
    pub audit:   AuditRecord,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny,
}

pub enum Effect {
    Redact   { selector: String, classifier: String },
    Mask     { selector: String, pattern: String, replacement: String },
    Annotate { key: String, value: String },
    Audit    { level: AuditLevel, message: Option<String> },
}

pub enum AuditLevel {
    Standard,
    Elevated,
    Critical,
}

pub struct AuditRecord {
    pub call_id:        CallId,
    pub agent_id:       AgentId,
    pub tool_name:      Option<String>,
    pub verdict:        Verdict,
    pub policy_version: String,
    pub matched_rules:  Vec<String>,
    pub timestamp:      Option<u64>,  // from timestamp fact if present
}
```

**`CompiledPolicy` — the output of the DSL compiler and payload of `PolicyStore`:**

```rust
pub struct CompiledPolicy {
    pub version:  String,                    // from PolicySet.version
    pub db:       cozo::DbInstance,          // in-memory CozoDB holding policy relations and rules
    pub patterns: HashMap<String, Regex>,    // compiled regexes keyed by pattern name
}
```

The `db` field holds all policy facts (role permissions, tool categories, etc.) and compiled rule queries. The `patterns` map is the Rust-side storage for compiled `Regex` objects; pattern source strings are also stored in `db` for auditability. The `PolicyStore` is `Arc<RwLock<Option<CompiledPolicy>>>` — `None` until the first successful `push()`.

**Effect semantics:**
- `Redact` — remove a field from the MCP response before it reaches the agent. `selector` is a dot-path into the response payload.
- `Mask` — replace matched content with `replacement` (e.g. `****`). Preserves structure; useful for credit card numbers.
- `Annotate` — attach metadata to the response. Downstream agents and audit systems see it; content is unchanged.
- `Audit` — elevate the audit level for this decision. `Elevated` and `Critical` trigger alerts or special log routing.

Effects compose. A single `Decision` can carry multiple effects. `Deny` decisions can carry effects too — a `Deny + Audit(Critical)` flags a potential attack.

---

## Policy DSL

The policy DSL is the authoring surface. It abstracts the CozoDB/Cozo dialect; policy authors never write Cozo directly. The DSL compiles to CozoDB relations and queries loaded into `PolicyStore`.

### Structure

A policy file has four sections, in order:

1. **Policy facts** — base knowledge declarations
2. **Patterns** — named regexes compiled at load time
3. **Rules** — derived predicates (Datalog rules over fact vocabulary)
4. **Policy blocks** — named allow/deny/effect decision rules, evaluated in priority order

### Syntax

```
// ── Policy Facts ───────────────────────────────────────────────────────

grant role "analyst"  can call   tool:category("read-only");
grant role "analyst"  can access resource:pattern("data/public/*");
grant role "admin"    can call   tool:any;

categorize tool "db_query"  as "read-only";
categorize tool "db_write"  as "write";

classify resource "data/finance/*" as sensitivity "high";
classify resource "data/public/*"  as sensitivity "low";

// ── Patterns (compiled at load time) ──────────────────────────────────

pattern :sql_injection  = r"(?i)(drop|delete|truncate)\s+table";
pattern :path_traversal = r"\.\.[/\\]";
pattern :secret_key     = r"sk-[a-zA-Z0-9]{32,}";

// ── Rules (derived predicates) ─────────────────────────────────────────

rule can_call(agent, tool) :-
    agent_role(agent, role),
    tool_category(tool, cat),
    role_permission(role, "call", cat);

rule can_call(agent, _tool) :-     // admins can call anything
    agent_clearance(agent, "admin");

rule has_forbidden_arg(call_id) :-
    call_arg(call_id, _, value),
    matches(value, :sql_injection) or
    matches(value, :path_traversal) or
    matches(value, :secret_key);

// ── Policies ───────────────────────────────────────────────────────────

policy "content-safety" priority 200 {
    // Mode B: structural pattern match on call args
    deny when has_forbidden_arg(call_id)
        reason "forbidden pattern in call arguments"
        effect Audit(level: Critical);
}

policy "pii-handling" priority 150 {
    // Mode A (tag-based) + Mode C (transformational)
    allow when
        tool_call(call_id, agent_id, _tool),
        content_tag(call_id, "pii", "high"),
        can_call(agent_id, _tool)
        effect Redact(selector: "response.content", classifier: "pii")
        effect Audit(level: Elevated);

    deny when
        tool_call(call_id, agent_id, _tool),
        content_tag(call_id, "pii", "high"),
        not can_call(agent_id, _tool)
        reason "agent not permitted and PII present"
        effect Audit(level: Critical);
}

policy "default-authz" priority 100 {
    allow when
        tool_call(call_id, agent_id, tool_name),
        can_call(agent_id, tool_name);

    deny when true
        reason "no matching allow rule";   // default-deny fallback
}
```

### Built-in predicates

The DSL exposes one built-in predicate not backed by a CozoDB relation:

**`matches(value: String, pattern: PatternRef) -> bool`**

- `PatternRef` is a pattern name using `:name` syntax (e.g. `:sql_injection`)
- Resolution: the DSL compiler rewrites `matches` calls into Rust-side regex evaluation against `CompiledPolicy.patterns`. It is not translated to a CozoDB query.
- At eval time, the Evaluator resolves the pattern name in `CompiledPolicy.patterns`, applies the compiled `Regex` to `value`, and returns the boolean result.
- If the pattern name is undefined, the DSL compiler returns an error at load time — `matches` with an unknown pattern name never reaches eval.

### Priority and conflict resolution

Policy blocks are evaluated in descending priority order. Evaluation is **first-match-wins**: the first block that produces a verdict (Allow or Deny) for the call terminates evaluation; lower-priority blocks are not consulted.

If two policy blocks share the same priority and both match, **Deny beats Allow**. This preserves the zero-trust invariant at equal priority.

A `deny when true` at the end of the lowest-priority block is the canonical default-deny fallback. Its `priority 100` value is lower than safety policies but is always reached if no prior block matched.

### Content filtering modes

All three modes are expressed uniformly in the same DSL:

- **Mode A (tag-based):** `content_tag(call_id, "pii", "high")` — reason over tags asserted by external classifiers
- **Mode B (structural):** `matches(value, :sql_injection)` over `call_arg` facts — inspect call arguments inline
- **Mode C (transformational):** `allow when ... effect Redact(...)` — allow with declared response transformation

### Compilation

The DSL compiler runs at policy load time (never at eval time):

1. Parse DSL source → AST
2. Validate: unknown predicates, undefined patterns, circular rules, missing fallback
3. Compile fact declarations → CozoDB stored relations
4. Compile rules → CozoDB rule queries
5. Compile patterns → compiled `Regex` objects stored in `CompiledPolicy.patterns: HashMap<String, Regex>`; source strings stored as CozoDB relation for auditability
6. Compile policy blocks → CozoDB decision queries
7. Package as `CompiledPolicy` and hand to `PolicyStore` for atomic swap

If any step fails, the error is returned to the caller and the existing policy remains active.

---

## Evaluation Flow

Each evaluation is independent and stateless. The gateway assembles a `FactPackage`, calls `evaluate()`, receives a `Decision`, and executes effects. No state persists between calls inside the engine.

```
1.  Gateway assembles FactPackage from MCP request context
2.  Evaluator acquires shared read lock on PolicyStore
        (non-blocking; many requests evaluate concurrently)
3.  Open fresh in-memory CozoDB scratchpad
        (cheap Rust struct allocation; holds only request facts)
4.  Load FactPackage into scratchpad as temporary relations
5.  Run compiled decision query
        (joins scratchpad request facts with PolicyStore policy rules)
6.  Collect derived allow / deny / effect relations
7.  Map to Decision struct
8.  Drop scratchpad — request facts never persist
9.  Release read lock
10. Return Decision to gateway
11. Gateway applies effects, emits audit record, completes or rejects call
```

The `PolicyStore` is never written to during evaluation. Only policy pushes (step 2 of the control plane flow) take a write lock.

---

## Control Plane Interface

The engine exposes a `PolicyWatcher` trait. The control plane client (delivery mechanism TBD in Spec 2) calls `push()` when new policy is available.

```rust
pub trait PolicyWatcher: Send + Sync {
    fn push(&self, policy: PolicySet) -> Result<(), PolicyError>;
}

pub struct PolicySet {
    pub version:  String,
    pub source:   String,   // DSL source text
    pub checksum: String,   // for idempotency — skip if already loaded
}
```

**Push flow:**

1. Control plane calls `push(PolicySet)`
2. DSL Compiler parses and compiles `PolicySet.source`
3. If compilation fails: return `Err(PolicyError)`, existing policy unchanged
4. If compilation succeeds: acquire write lock on `PolicyStore`, swap `Arc`, release lock
5. Return `Ok(())`

The engine never exposes an outbound connection. It is purely reactive to pushes. The control plane delivery transport (gRPC watch, HTTP, filesystem) is outside this spec.

---

## Error Handling

**The engine is fail-closed.** Any error at any point in evaluation returns `Deny + Audit(Critical)`. There is no fail-open path.

```rust
fn evaluate(facts: &FactPackage) -> Decision {
    evaluate_inner(facts).unwrap_or_else(|err| Decision {
        verdict: Verdict::Deny,
        effects: vec![Effect::Audit {
            level: AuditLevel::Critical,
            message: Some(err.to_string()),
        }],
        reason: Some("evaluation error".to_string()),
        audit: AuditRecord::from_error(facts, &err),
    })
}
```

The signature takes `&FactPackage` (borrowed) so the reference remains valid inside the error closure. Taking ownership has no benefit since evaluation does not consume the fact package.

Error cases and their handling:

| Condition | Response |
|---|---|
| `PolicyStore` uninitialized (no push received yet) | `Deny + Audit(Critical)` — no scratchpad opened |
| CozoDB evaluation error | `Deny + Audit(Critical)` |
| Evaluation timeout | `Deny + Audit(Critical)` |
| Fact assembly error | `Deny + Audit(Critical)` |
| DSL compilation error on push | Reject push, keep existing policy, return `Err` |
| Malformed `FactPackage` | `Deny + Audit(Critical)` |

Errors are never silently swallowed. Every error path emits an audit record with the error detail for observability.

---

## Testing Strategy

The evaluator's pure-function nature makes testing straightforward: given a `FactPackage` and a loaded policy, assert a `Decision`. No mocks, no network, no gateway required.

### Four testing layers

**1. Evaluator scenario tests** — the primary correctness proof. Declarative, table-driven, human-readable. Each scenario is a named test case that a security engineer can review:

```rust
// analyst cannot call a write tool
facts: agent("agt-1", "analyst") + tool_call("call-1", "agt-1", "db_write")
expect: Deny, reason contains "permission"

// pii present → allow with redact effect
facts: agent("agt-1", "analyst") + tool_call("call-1", "agt-1", "db_query") + content_tag("call-1", "pii", "high")
expect: Allow, effects contains Redact("response.content", "pii")

// forbidden pattern in arg → deny regardless of role
facts: agent("agt-1", "admin") + tool_call("call-1", "agt-1", "db_write") + call_arg("call-1", "q", "DROP TABLE users")
expect: Deny, effects contains Audit(Critical)
```

**2. DSL compiler tests** — given DSL source, expect compiled relations or a structured error. Covers: syntax errors, semantic errors (unknown predicate, undefined pattern, circular rules), valid compilation, and round-trip correctness (parse → compile → evaluate → expected decision).

**3. Fail-closed tests** — every error path must produce `Deny + Audit(Critical)`. Deliberately corrupt the `FactPackage`, poison the CozoDB scratchpad, push a malformed policy. Verify the invariant holds unconditionally.

**4. Concurrency tests** — N requests in flight while a policy push occurs. Verify no request sees a torn read, and all decisions are consistent with either the old or new policy — never a mix.

---

## Open Questions (deferred to implementation planning)

- Exact CozoDB API for joining a per-request scratchpad against a persistent policy store — evaluate whether to use a single shared DB with parameterized queries, or truly separate in-memory instances per request
- Evaluation timeout budget — how long before a slow CozoDB query triggers fail-closed
- `PolicySet.checksum` strategy for idempotency — SHA-256 of source, or content-addressed
- Whether `tool_result` facts (response-time policies) require a second evaluation call or are included in the initial call with a two-phase flow
