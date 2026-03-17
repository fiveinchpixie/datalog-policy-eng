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

### Lint checks

#### 1. MissingDefaultDeny

A policy block has allow rules but no `deny when true` fallback. Without this, unmatched requests produce no decision row from that block.

Detection: For each `PolicyDecl`, if it contains at least one `PolicyRule::Allow` but no `PolicyRule::Deny` whose conditions are `[ConditionClause::True]`, emit a warning.

Message: `policy block "{name}" has allow rules but no deny-when-true fallback; unmatched requests will fail closed`

#### 2. UnusedPattern

A `pattern :name` declaration whose name never appears as a `PatternRef` argument in any `matches()` call across all rules and policy block conditions.

Detection: Collect all declared pattern names from `Declaration::Pattern`. Walk all `AtomCondition` nodes in all rules and policy blocks. For each `matches(value, :pattern_name)` call, record the pattern name. Any declared name not referenced is unused.

Message: `pattern :{name} is declared but never used`

#### 3. UnusedRule

A `rule name(...)` declaration whose name never appears as a predicate in any policy block condition or other rule's body.

Detection: Collect all declared rule names from `Declaration::Rule`. Walk all `AtomCondition` nodes in policy blocks and other rules. Any declared name not appearing as a predicate is unused.

Message: `rule "{name}" is declared but never used`

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

Detection: Sort policy blocks by priority descending. For each block, check if any higher-priority block has a `deny when true` or covers all tool_calls unconditionally (i.e., has a rule matching `tool_call(_, _, _)` with no further restricting conditions beyond that). If so, the lower-priority block is shadowed.

Simplified approach: if a higher-priority block contains `deny when true` as one of its rules, it produces a decision for every request, shadowing all lower-priority blocks. Note: a block with `allow when ... ; deny when true` also matches everything.

Message: `policy block "{name}" (priority {p}) is shadowed by higher-priority block "{other}" (priority {hp}) which matches all requests`

#### 8. EmptyPolicyBlock

A policy block with zero rules.

Detection: `policy.rules.is_empty()`

Message: `policy block "{name}" has no rules`

#### 9. UnreachableDeny

A deny rule in a policy block that can never produce a decision because a broader allow rule in the same block always takes precedence (allow beats deny in same block).

Detection: Within a single policy block, if there is an allow rule whose conditions are a subset of (or equal to) a deny rule's conditions, the deny is unreachable. Simplified check: if the block has an allow rule with only `tool_call(call_id, _, _)` as its condition (matches all calls), then any deny rule in the same block is unreachable because the allow will always fire first.

Message: `deny rule in policy block "{name}" is unreachable because a broader allow rule always takes precedence`

## CLI

### `noodle lint` subcommand

Usage: `noodle lint <policy.dl>`

1. Parse the policy file
2. Run `lint()` on the AST
3. Print warnings to stdout
4. Print summary line: `N warnings` or `no warnings`
5. Exit code: 0 if no warnings, 1 if warnings found

Parse errors are printed to stderr and exit code 2 (same as other error cases).

### `:lint` REPL command

Usage: `:lint` (no arguments — lints the currently loaded policy file)

1. Re-reads and re-parses the file at `state.policy_path`
2. Runs `lint()` on the AST
3. Prints warnings to stdout
4. If no policy is loaded, prints "no policy loaded" to stderr

### Arg parsing changes

The current CLI uses positional args only (`noodle [policy] [facts]`). To add `lint`:

- In `src/bin/noodle.rs`, check if the first positional argument is the literal string `"lint"`. If so, treat the second positional arg as the policy file path and run the lint subcommand.
- Otherwise, existing behavior is unchanged.

This avoids adding clap subcommands, keeping the arg parsing simple.

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
