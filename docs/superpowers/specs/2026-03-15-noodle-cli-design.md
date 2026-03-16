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

Any line starting with `:` is a command. Everything else is treated as a JSON fact package and evaluated against the loaded policy.

### Commands

| Command | Description |
|---------|-------------|
| `:load <path>` | Load or replace policy from a DSL file |
| `:reload` | Reload current policy file (bumps version string) |
| `:policy` | Show loaded policy info: version, source path |
| `:example` | Print an example JSON fact package |
| `:help` | List available commands |
| `:quit` | Exit (also Ctrl-D) |

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

Flat structure mirroring `FactPackage`. Each key maps to an array of tuples (arrays of values):

```json
{
  "tool_calls": [["call-1", "agt-1", "db_query"]],
  "agent_roles": [["agt-1", "analyst"]],
  "resource_accesses": [["call-1", "agt-1", "data/users", "read"]],
  "call_args": [["call-1", "query", "SELECT * FROM users"]],
  "content_tags": [["call-1", "pii", "high"]],
  "timestamps": [["call-1", 1700000000]]
}
```

Missing keys default to empty arrays. All 15 fact types are supported:
- Identity: `agents`, `agent_roles`, `agent_clearances`, `delegations`, `users`
- MCP call: `tool_calls`, `call_args`, `tool_results`, `resource_accesses`, `resource_mimes`
- Content: `content_tags`
- Environment: `timestamps`, `call_counts`, `environment`

Tuple fields match the struct field order in `facts.rs`. Strings for string fields, integers for numeric fields (e.g., `unix_ts`, `count`).

## Architecture

### Crate changes

- Add `[[bin]]` section to `Cargo.toml` with `name = "noodle"` and `path = "src/bin/noodle.rs"`
- Add dependencies: `clap`, `serde` + `serde_json` (already present), `rustyline`
- Add `Deserialize` support for `FactPackage` via a custom deserializer or a thin JSON-to-FactPackage conversion module

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
- **`repl.rs`**: Owns the `rustyline::Editor`, `Engine`, and current policy file path. Reads lines, dispatches commands or evaluates JSON input.
- **`oneshot.rs`**: Reads files, compiles policy, parses facts, evaluates, prints, exits.
- **`facts_json.rs`**: Parses a JSON value into a `FactPackage`. Handles the tuple-array format, defaults missing keys to empty vecs.
- **`output.rs`**: Formats a `Decision` for terminal display. Handles color (Allow=green, Deny=red) if stdout is a TTY.

### Dependency choices

- **clap** (derive mode): Minimal arg parsing, no subcommands needed, just positional args.
- **rustyline**: Mature readline library for Rust. Provides line editing, Ctrl-C/Ctrl-D handling, history.
- **serde_json**: Already a dependency. Used to parse fact JSON input.
- No `serde::Deserialize` on the fact structs — the tuple-array JSON format doesn't map naturally to derive. A manual `facts_json` module is simpler and avoids polluting the library types with serde derives.
