# Policy Linting Design

## Overview

A linter for the policy DSL that catches common mistakes: unused declarations, missing fallbacks, shadowed blocks, and unreachable rules. The linter operates on the parsed AST (no CozoDB involved) and returns structured `LintWarning` values. The CLI surfaces results via a `noodle lint policy.dl` subcommand and a `:lint` REPL command.

## Library: `src/dsl/linter.rs`

### API

```rust
pub fn lint(file: &PolicyFile) -> Vec<LintWarning>

pub struct LintWarning {
    pub kind: LintKind,
    pub message: String,
}

pub enum LintKind {
    MissingDefaultDeny,
    UnusedPattern,
    UnusedRule,
    UnusedGrant,
    UnusedCategorize,
    UnusedClassify,
    ShadowedPolicyBlock,
    EmptyPolicyBlock,
    UnreachableDeny,
}
```

The function is public, re-exported from `src/dsl/mod.rs`. It takes a `&PolicyFile` (the parsed AST) and returns zero or more warnings. It does not fail — it always produces a result.

`LintWarning` implements `Display` using the format `warning[{kind}]: {message}`. This is shared between the CLI subcommand and the REPL `:lint` command.

### Helpers

The linter needs to walk all `AtomCondition` nodes across rules and policy blocks to collect referenced predicates and pattern names. The compiler's `validate()` function does similar pattern-ref walking. A shared helper `collect_all_predicates(file) -> HashSet<String>` and `collect_pattern_refs(file) -> HashSet<String>` should be extracted into a utility used by both the linter and the compiler. Alternatively, the linter may duplicate the traversal since it's simple and the linter has different concerns — either approach is acceptable.

### Lint checks

#### 1. MissingDefaultDeny

A policy block has allow rules but no `deny when true` fallback. Without this, unmatched requests produce no decision row from that block.

Detection: For each `PolicyDecl`, if it contains at least one `PolicyRule::Allow` but no `PolicyRule::Deny` whose conditions are `[ConditionClause::True]`, emit a warning.

Message: `policy block "{name}" has allow rules but no deny-when-true fallback; unmatched requests will fail closed`

#### 2. UnusedPattern

A `pattern :name` declaration whose name never appears as a `PatternRef` argument in any `matches()` call across all rules and policy block conditions.

Detection: Collect all declared pattern names from `Declaration::Pattern`. Walk all `AtomCondition` nodes in all rules and policy blocks, collecting pattern names from `PatternRef` args in `matches()` predicates. Any declared name not in the referenced set is unused.

Message: `pattern :{name} is declared but never used`

#### 3. UnusedRule

A `rule name(...)` declaration that is not reachable from any policy block.

Detection: Collect all declared rule names from `Declaration::Rule`. Collect all predicates referenced directly in policy block conditions. A rule is "used" if its name appears as a predicate in any policy block condition. Rules that are only referenced by other rules but never reachable from a policy block are considered unused. (This is a simple one-hop check from policy blocks, not a full reachability graph — a rule referenced only by another unused rule is also flagged.)

Message: `rule "{name}" is declared but never referenced from a policy block`

#### 4. UnusedGrant

A `grant` declaration exists but no rule or policy condition references the `role_permission` predicate.

Detection: If any `Declaration::Grant` exists, check if `role_permission` appears as a predicate anywhere in rules or policy blocks. If not, emit one warning (not per-grant — a single warning for the whole category).

Message: `grant declarations exist but no rule references role_permission`

#### 5. UnusedCategorize

Same pattern as UnusedGrant: `categorize` declarations exist but `tool_category` is never referenced.

Message: `categorize declarations exist but no rule references tool_category`

#### 6. UnusedClassify

Same pattern: `classify` declarations exist but `resource_sensitivity` is never referenced.

Message: `classify declarations exist but no rule references resource_sensitivity`

#### 7. ShadowedPolicyBlock

A lower-priority policy block that can never produce a decision because a higher-priority block always matches first.

Detection: Sort policy blocks by priority descending. A block "matches all requests" if it contains any `deny when true` rule (regardless of whether it also has allow rules — the deny-when-true fallback ensures it produces a decision for every call_id that has a tool_call). If a higher-priority block matches all requests, all lower-priority blocks are shadowed.

Message: `policy block "{name}" (priority {p}) is shadowed by higher-priority block "{other}" (priority {hp}) which matches all requests`

#### 8. EmptyPolicyBlock

A policy block with zero rules.

Detection: `policy.rules.is_empty()`

Message: `policy block "{name}" has no rules`

#### 9. UnreachableDeny

A deny rule in a policy block that can never produce a decision because a broader allow rule in the same block always takes precedence (allow beats deny in same block).

Detection: Within a single policy block, check if any allow rule's conditions are a superset of (or match all cases of) a deny rule. Simplified check: if the block has an allow rule whose conditions consist only of `tool_call(_, _, _)` (one atom, all wildcards/variables) or whose conditions are empty or `[True]`, then all deny rules in the same block are unreachable. (Note: `allow when true` is rejected by compiler validation, so only the `tool_call`-only case is practically reachable.)

Message: `deny rule in policy block "{name}" is unreachable because a broader allow rule always takes precedence`

## CLI

### `noodle lint` subcommand

Usage: `noodle lint <policy.dl>`

1. Parse the policy file
2. Run `lint()` on the AST
3. Print warnings to stdout using `LintWarning::Display`
4. Print summary line: `N warnings` or `no warnings`
5. Exit code: 0 if no warnings, 1 if warnings found

Parse errors are printed to stderr and exit code 2 (same as other error cases).

### `:lint` REPL command

Usage: `:lint` (no arguments — lints the currently loaded policy file)

1. Re-reads and re-parses the file at `state.policy_path`
2. Runs `lint()` on the AST
3. Prints warnings to stdout using `LintWarning::Display`
4. Prints summary line
5. If no policy is loaded, prints "no policy loaded" to stderr

The `:lint` command is added to `handle_command` and documented in `print_help()`.

### Arg parsing changes

The current CLI uses clap with positional args. Add an optional `Subcommand` enum to clap:

```rust
#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    /// Policy DSL file to load
    policy: Option<PathBuf>,

    /// Facts JSON file to evaluate (enables one-shot mode)
    facts: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Lint a policy file for common issues
    Lint { policy: PathBuf },
}
```

When `args.command` is `Some(Command::Lint { policy })`, run the lint subcommand. Otherwise, existing positional-arg behavior is unchanged. This gives proper `--help` documentation for both modes.

### Output format

```
warning[UnusedPattern]: pattern :sql_injection is declared but never used
warning[MissingDefaultDeny]: policy block "authz" has allow rules but no deny-when-true fallback; unmatched requests will fail closed
warning[EmptyPolicyBlock]: policy block "unused" has no rules

3 warnings
```

No color — lint output should be easy to grep/parse.

## Testing

Unit tests in `src/dsl/linter.rs` with `#[cfg(test)]`:

- Each lint check gets at least one positive test (warning produced) and one negative test (no warning when the issue is absent)
- Test that `lint()` returns an empty vec for a well-formed policy
- Test that multiple warnings can be returned from a single policy

No integration test files needed — inline unit tests are sufficient.
