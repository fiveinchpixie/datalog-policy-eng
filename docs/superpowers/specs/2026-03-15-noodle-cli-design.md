# noodle CLI/REPL Design

## Overview

A binary target (`noodle`) for the `datalog-noodle` crate that provides both an interactive REPL and one-shot evaluation mode. The REPL lets users load policy files, paste JSON fact packages, and see decisions instantly. One-shot mode evaluates a single fact file against a policy and exits with a meaningful exit code.

## Usage

```
noodle                      # REPL, no policy loaded
noodle <policy.dl>          # REPL, policy pre-loaded
noodle <policy.dl> <facts.json>  # one-shot eval, exit 0=Allow 1=Deny 2=error
```

Arguments are positional: first arg is always a policy file path, second is a facts JSON file path. No subcommands.

## REPL Mode

### Input handling

Any line starting with `:` is a command. All other input is accumulated as JSON. The REPL detects incomplete JSON by tracking brace/bracket depth: if a line ends with unbalanced `{`/`[`, the REPL switches to a continuation prompt (`...`) and keeps reading until braces balance. A blank line while accumulating cancels the input.

### Commands

| Command | Description |
|---------|-------------|
| `:load <path>` | Load or replace policy from a DSL file |
| `:reload` | Reload current policy file (bumps version string) |
| `:policy` | Show loaded policy info: version, source path |
| `:example` | Print an example JSON fact package |
| `:help` | List available commands |
| `:quit` | Exit (also Ctrl-D) |

`:reload` reads the file at the previously loaded path and pushes it as a new `PolicySet` with a monotonically incrementing version string (`v1`, `v2`, ...). The `checksum` field is set to an empty string (unused).

### Decision output format

Allow:
```
✓ Allow  [block: authz]
  effects: Redact(response.content, pii)
  audit: call-1 | agt-1 | db_query | v3
```

Deny:
```
✗ Deny   [block: authz]  reason: "no matching allow rule"
  audit: call-1 | agt-1 | db_query | v3
```

Field mapping:
- `[block: ...]` — first entry of `AuditRecord.matched_rules`, or `<none>` if empty
- `reason` — `Decision.reason`, omitted if `None`
- `effects` — each `Effect` on its own line, omitted if empty
- `audit` line — `call_id | agent_id | tool_name | policy_version` from `AuditRecord`

Color: Allow line in green, Deny line in red. Uses ANSI escape codes directly (no color library). Disabled when stdout is not a TTY (checked via `std::io::IsTerminal`).

### Error handling

Parse errors and policy load errors print to stderr and return to the prompt. The REPL never exits on error.

### Line editing

Uses `rustyline` for readline-style line editing and history. History persists for the session (not across sessions).

## One-Shot Mode

Triggered when both a policy file and a facts JSON file are provided as arguments.

1. Load and compile the policy file
2. Read and parse the facts JSON file
3. Evaluate
4. Print the decision to stdout (same format as REPL)
5. Exit with code: 0 = Allow, 1 = Deny, 2 = error

Errors (bad policy, bad JSON, missing file) print to stderr and exit 2.

## Fact JSON Format

Flat structure mirroring `FactPackage`. Each key maps to an array of tuples (arrays of values). Missing keys default to empty arrays.

### Tuple field reference

All 14 fact types and their positional fields:

| JSON key | Tuple fields (positional) |
|----------|--------------------------|
| `agents` | `[id, display_name]` |
| `agent_roles` | `[agent_id, role]` |
| `agent_clearances` | `[agent_id, clearance]` |
| `delegations` | `[agent_id, delegator_id]` |
| `users` | `[user_id, agent_id]` |
| `tool_calls` | `[call_id, agent_id, tool_name]` |
| `call_args` | `[call_id, key, value]` |
| `tool_results` | `[call_id, key, value]` |
| `resource_accesses` | `[call_id, agent_id, uri, op]` |
| `resource_mimes` | `[call_id, mime_type]` |
| `content_tags` | `[call_id, tag, value]` |
| `timestamps` | `[call_id, unix_ts]` (unix_ts is an integer) |
| `call_counts` | `[agent_id, tool_name, window, count]` (count is an integer) |
| `environment` | `[key, value]` |

All fields are strings except where noted as integer. The `op` field in `resource_accesses` accepts: `"read"`, `"write"`, `"create"`, `"delete"`, `"list"`, `"execute"`.

### Example

```json
{
  "agents": [["agt-1", "Analyst Bot"]],
  "tool_calls": [["call-1", "agt-1", "db_query"]],
  "agent_roles": [["agt-1", "analyst"]],
  "resource_accesses": [["call-1", "agt-1", "data/users", "read"]],
  "call_args": [["call-1", "query", "SELECT * FROM users"]],
  "content_tags": [["call-1", "pii", "high"]],
  "timestamps": [["call-1", 1700000000]]
}
```

## Architecture

### Crate changes

- Add `[[bin]]` section to `Cargo.toml` with `name = "noodle"` and `path = "src/bin/noodle.rs"`
- Add dependencies: `clap`, `rustyline`
- `serde_json` is already a dependency

### File structure

```
src/
  bin/
    noodle.rs       # main(), arg parsing, dispatch to repl or one-shot
  cli/
    mod.rs          # re-exports
    repl.rs         # REPL loop, command dispatch
    oneshot.rs      # one-shot evaluation
    facts_json.rs   # JSON → FactPackage conversion
    output.rs       # Decision → formatted terminal output
```

### Module responsibilities

- **`noodle.rs`**: Parse CLI args with clap (positional `policy` and `facts` args), dispatch to `repl::run()` or `oneshot::run()`.
- **`repl.rs`**: Owns the `rustyline::Editor`, `Engine`, current policy file path, and version counter. Reads lines, handles multiline JSON accumulation, dispatches commands or evaluates.
- **`oneshot.rs`**: Reads files, compiles policy, parses facts, evaluates, prints, exits.
- **`facts_json.rs`**: Parses a `serde_json::Value` into a `FactPackage`. Handles the tuple-array format, defaults missing keys to empty vecs. Reports clear errors on wrong tuple length or type mismatches.
- **`output.rs`**: Formats a `Decision` for terminal display. Uses ANSI codes for color when stdout is a TTY.

### Dependency choices

- **clap** (derive mode): Minimal arg parsing, positional args only.
- **rustyline**: Readline library for line editing, Ctrl-C/Ctrl-D handling, session history.
- **serde_json**: Already a dependency. Used to parse fact JSON input.
- No `serde::Deserialize` on the library fact structs — the tuple-array JSON format doesn't map naturally to derive. A manual `facts_json` module is cleaner and avoids polluting the library types.
- No color library — ANSI codes emitted directly, gated on `std::io::IsTerminal`.
