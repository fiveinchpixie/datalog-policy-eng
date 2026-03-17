use std::collections::HashSet;
use std::fmt;

use crate::dsl::ast::*;

#[derive(Debug, Clone, PartialEq, Eq)]
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

impl fmt::Display for LintKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            LintKind::MissingDefaultDeny => "MissingDefaultDeny",
            LintKind::UnusedPattern => "UnusedPattern",
            LintKind::UnusedRule => "UnusedRule",
            LintKind::UnusedGrant => "UnusedGrant",
            LintKind::UnusedCategorize => "UnusedCategorize",
            LintKind::UnusedClassify => "UnusedClassify",
            LintKind::ShadowedPolicyBlock => "ShadowedPolicyBlock",
            LintKind::EmptyPolicyBlock => "EmptyPolicyBlock",
            LintKind::UnreachableDeny => "UnreachableDeny",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone)]
pub struct LintWarning {
    pub kind: LintKind,
    pub message: String,
}

impl fmt::Display for LintWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "warning[{}]: {}", self.kind, self.message)
    }
}

pub fn lint(file: &PolicyFile) -> Vec<LintWarning> {
    let mut warnings = Vec::new();
    let all_predicates = collect_all_predicates(file);
    let policy_predicates = collect_policy_block_predicates(file);
    check_missing_default_deny(file, &mut warnings);
    check_unused_patterns(file, &mut warnings);
    check_unused_rules(file, &policy_predicates, &mut warnings);
    check_unused_grants(file, &all_predicates, &mut warnings);
    check_unused_categorize(file, &all_predicates, &mut warnings);
    check_unused_classify(file, &all_predicates, &mut warnings);
    check_shadowed_policy_blocks(file, &mut warnings);
    check_empty_policy_blocks(file, &mut warnings);
    check_unreachable_deny(file, &mut warnings);
    warnings
}

fn collect_all_predicates(file: &PolicyFile) -> HashSet<String> {
    let mut preds = HashSet::new();
    for decl in &file.declarations {
        match decl {
            Declaration::Rule(r) => {
                collect_predicates_from_conditions(&r.conditions, &mut preds);
            }
            Declaration::Policy(p) => {
                for rule in &p.rules {
                    let conditions = match rule {
                        PolicyRule::Allow(a) => &a.conditions,
                        PolicyRule::Deny(d) => &d.conditions,
                    };
                    collect_predicates_from_conditions(conditions, &mut preds);
                }
            }
            _ => {}
        }
    }
    preds
}

fn collect_policy_block_predicates(file: &PolicyFile) -> HashSet<String> {
    let mut preds = HashSet::new();
    for decl in &file.declarations {
        if let Declaration::Policy(p) = decl {
            for rule in &p.rules {
                let conditions = match rule {
                    PolicyRule::Allow(a) => &a.conditions,
                    PolicyRule::Deny(d) => &d.conditions,
                };
                collect_predicates_from_conditions(conditions, &mut preds);
            }
        }
    }
    preds
}

fn collect_predicates_from_conditions(conditions: &[ConditionClause], preds: &mut HashSet<String>) {
    for cond in conditions {
        match cond {
            ConditionClause::Atom(a) => { preds.insert(a.predicate.clone()); }
            ConditionClause::Not(a) => { preds.insert(a.predicate.clone()); }
            ConditionClause::Or(atoms) => {
                for a in atoms { preds.insert(a.predicate.clone()); }
            }
            ConditionClause::True => {}
        }
    }
}

fn collect_referenced_patterns(file: &PolicyFile) -> HashSet<String> {
    let mut refs = HashSet::new();
    let mut visit = |conditions: &[ConditionClause]| {
        for cond in conditions {
            let atoms: Vec<&AtomCondition> = match cond {
                ConditionClause::Atom(a) => vec![a],
                ConditionClause::Not(a) => vec![a],
                ConditionClause::Or(atoms) => atoms.iter().collect(),
                ConditionClause::True => vec![],
            };
            for atom in atoms {
                if atom.predicate == "matches" {
                    for arg in &atom.args {
                        if let Arg::PatternRef(name) = arg {
                            refs.insert(name.clone());
                        }
                    }
                }
            }
        }
    };
    for decl in &file.declarations {
        match decl {
            Declaration::Rule(r) => visit(&r.conditions),
            Declaration::Policy(p) => {
                for rule in &p.rules {
                    match rule {
                        PolicyRule::Allow(a) => visit(&a.conditions),
                        PolicyRule::Deny(d) => visit(&d.conditions),
                    }
                }
            }
            _ => {}
        }
    }
    refs
}

fn allow_matches_all(allow: &AllowRule) -> bool {
    if allow.conditions.is_empty() {
        return true;
    }
    if allow.conditions.len() == 1 {
        if let ConditionClause::True = &allow.conditions[0] {
            return true;
        }
        if let ConditionClause::Atom(a) = &allow.conditions[0] {
            if a.predicate == "tool_call" && a.args.iter().all(|arg| matches!(arg, Arg::Variable(_) | Arg::Wildcard | Arg::NamedWildcard(_))) {
                return true;
            }
        }
    }
    false
}

fn block_matches_all(policy: &PolicyDecl) -> bool {
    policy.rules.iter().any(|r| {
        if let PolicyRule::Deny(d) = r {
            d.conditions.len() == 1 && d.conditions[0] == ConditionClause::True
        } else {
            false
        }
    })
}

fn check_missing_default_deny(file: &PolicyFile, warnings: &mut Vec<LintWarning>) {
    for decl in &file.declarations {
        if let Declaration::Policy(p) = decl {
            let has_allow = p.rules.iter().any(|r| matches!(r, PolicyRule::Allow(_)));
            let has_deny_true = p.rules.iter().any(|r| {
                if let PolicyRule::Deny(d) = r {
                    d.conditions.len() == 1 && d.conditions[0] == ConditionClause::True
                } else {
                    false
                }
            });
            if has_allow && !has_deny_true {
                warnings.push(LintWarning {
                    kind: LintKind::MissingDefaultDeny,
                    message: format!(
                        "policy block \"{}\" has allow rules but no deny-when-true fallback; unmatched requests will fail closed",
                        p.name
                    ),
                });
            }
        }
    }
}

fn check_unused_patterns(file: &PolicyFile, warnings: &mut Vec<LintWarning>) {
    let referenced = collect_referenced_patterns(file);
    for decl in &file.declarations {
        if let Declaration::Pattern(p) = decl {
            if !referenced.contains(&p.name) {
                warnings.push(LintWarning {
                    kind: LintKind::UnusedPattern,
                    message: format!("pattern :{} is declared but never used", p.name),
                });
            }
        }
    }
}

fn check_unused_rules(file: &PolicyFile, policy_predicates: &HashSet<String>, warnings: &mut Vec<LintWarning>) {
    for decl in &file.declarations {
        if let Declaration::Rule(r) = decl {
            if !policy_predicates.contains(&r.name) {
                warnings.push(LintWarning {
                    kind: LintKind::UnusedRule,
                    message: format!("rule \"{}\" is declared but never referenced from a policy block", r.name),
                });
            }
        }
    }
}

fn check_unused_grants(file: &PolicyFile, all_predicates: &HashSet<String>, warnings: &mut Vec<LintWarning>) {
    let has_grants = file.declarations.iter().any(|d| matches!(d, Declaration::Grant(_)));
    if has_grants && !all_predicates.contains("role_permission") {
        warnings.push(LintWarning {
            kind: LintKind::UnusedGrant,
            message: "grant declarations exist but no rule references role_permission".to_string(),
        });
    }
}

fn check_unused_categorize(file: &PolicyFile, all_predicates: &HashSet<String>, warnings: &mut Vec<LintWarning>) {
    let has = file.declarations.iter().any(|d| matches!(d, Declaration::Categorize(_)));
    if has && !all_predicates.contains("tool_category") {
        warnings.push(LintWarning {
            kind: LintKind::UnusedCategorize,
            message: "categorize declarations exist but no rule references tool_category".to_string(),
        });
    }
}

fn check_unused_classify(file: &PolicyFile, all_predicates: &HashSet<String>, warnings: &mut Vec<LintWarning>) {
    let has = file.declarations.iter().any(|d| matches!(d, Declaration::Classify(_)));
    if has && !all_predicates.contains("resource_sensitivity") {
        warnings.push(LintWarning {
            kind: LintKind::UnusedClassify,
            message: "classify declarations exist but no rule references resource_sensitivity".to_string(),
        });
    }
}

fn check_shadowed_policy_blocks(file: &PolicyFile, warnings: &mut Vec<LintWarning>) {
    let mut policies: Vec<&PolicyDecl> = file.declarations.iter()
        .filter_map(|d| if let Declaration::Policy(p) = d { Some(p) } else { None })
        .collect();
    policies.sort_by(|a, b| b.priority.cmp(&a.priority));
    for i in 0..policies.len() {
        if block_matches_all(policies[i]) {
            for j in (i + 1)..policies.len() {
                warnings.push(LintWarning {
                    kind: LintKind::ShadowedPolicyBlock,
                    message: format!(
                        "policy block \"{}\" (priority {}) is shadowed by higher-priority block \"{}\" (priority {}) which matches all requests",
                        policies[j].name, policies[j].priority,
                        policies[i].name, policies[i].priority,
                    ),
                });
            }
            break;
        }
    }
}

fn check_empty_policy_blocks(file: &PolicyFile, warnings: &mut Vec<LintWarning>) {
    for decl in &file.declarations {
        if let Declaration::Policy(p) = decl {
            if p.rules.is_empty() {
                warnings.push(LintWarning {
                    kind: LintKind::EmptyPolicyBlock,
                    message: format!("policy block \"{}\" has no rules", p.name),
                });
            }
        }
    }
}

fn check_unreachable_deny(file: &PolicyFile, warnings: &mut Vec<LintWarning>) {
    for decl in &file.declarations {
        if let Declaration::Policy(p) = decl {
            let has_catch_all_allow = p.rules.iter().any(|r| {
                if let PolicyRule::Allow(a) = r { allow_matches_all(a) } else { false }
            });
            if has_catch_all_allow {
                let has_deny = p.rules.iter().any(|r| matches!(r, PolicyRule::Deny(_)));
                if has_deny {
                    warnings.push(LintWarning {
                        kind: LintKind::UnreachableDeny,
                        message: format!(
                            "deny rule in policy block \"{}\" is unreachable because a broader allow rule always takes precedence",
                            p.name
                        ),
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(src: &str) -> PolicyFile {
        crate::dsl::parser::parse(src).expect("test policy must parse")
    }

    fn lint_kinds(src: &str) -> Vec<LintKind> {
        lint(&parse(src)).into_iter().map(|w| w.kind).collect()
    }

    #[test]
    fn clean_policy_no_warnings() {
        let warnings = lint_kinds(r#"
            policy "authz" priority 100 {
                allow when tool_call(call_id, agent_id, _), agent_role(agent_id, "analyst");
                deny when true reason "fallback";
            }
        "#);
        assert!(warnings.is_empty(), "expected no warnings, got: {:?}", warnings);
    }

    #[test]
    fn missing_default_deny_flagged() {
        let warnings = lint_kinds(r#"
            policy "authz" priority 100 {
                allow when tool_call(call_id, agent_id, _), agent_role(agent_id, "analyst");
            }
        "#);
        assert!(warnings.contains(&LintKind::MissingDefaultDeny));
    }

    #[test]
    fn missing_default_deny_not_flagged_when_present() {
        let warnings = lint_kinds(r#"
            policy "authz" priority 100 {
                allow when tool_call(call_id, agent_id, _), agent_role(agent_id, "analyst");
                deny when true reason "fallback";
            }
        "#);
        assert!(!warnings.contains(&LintKind::MissingDefaultDeny));
    }

    #[test]
    fn deny_only_block_no_missing_default_deny() {
        let warnings = lint_kinds(r#"
            policy "d" priority 100 { deny when true reason "blocked"; }
        "#);
        assert!(!warnings.contains(&LintKind::MissingDefaultDeny));
    }

    #[test]
    fn unused_pattern_flagged() {
        let warnings = lint_kinds(r#"
            pattern :unused_pat = r"foo";
            policy "d" priority 100 { deny when true reason "blocked"; }
        "#);
        assert!(warnings.contains(&LintKind::UnusedPattern));
    }

    #[test]
    fn used_pattern_not_flagged() {
        let warnings = lint_kinds(r#"
            pattern :sql = r"(?i)drop";
            rule bad(call_id) :- call_arg(call_id, _, value), matches(value, :sql);
            policy "d" priority 100 {
                deny when tool_call(call_id, _, _), bad(call_id) reason "bad";
            }
        "#);
        assert!(!warnings.contains(&LintKind::UnusedPattern));
    }

    #[test]
    fn unused_rule_flagged() {
        let warnings = lint_kinds(r#"
            rule orphan(x) :- agent_role(x, "admin");
            policy "d" priority 100 { deny when true reason "blocked"; }
        "#);
        assert!(warnings.contains(&LintKind::UnusedRule));
    }

    #[test]
    fn used_rule_not_flagged() {
        let warnings = lint_kinds(r#"
            rule is_admin(agent) :- agent_role(agent, "admin");
            policy "authz" priority 100 {
                allow when tool_call(call_id, agent_id, _), is_admin(agent_id);
                deny when true reason "fallback";
            }
        "#);
        assert!(!warnings.contains(&LintKind::UnusedRule));
    }

    #[test]
    fn unused_grant_flagged() {
        let warnings = lint_kinds(r#"
            grant role "admin" can call tool:any;
            policy "d" priority 100 { deny when true reason "blocked"; }
        "#);
        assert!(warnings.contains(&LintKind::UnusedGrant));
    }

    #[test]
    fn used_grant_not_flagged() {
        let warnings = lint_kinds(r#"
            grant role "admin" can call tool:any;
            rule can_call(agent, tool) :- agent_role(agent, role), role_permission(role, "call", "*"), tool_call(_, agent, tool);
            policy "authz" priority 100 {
                allow when tool_call(call_id, agent_id, tool), can_call(agent_id, tool);
                deny when true reason "fallback";
            }
        "#);
        assert!(!warnings.contains(&LintKind::UnusedGrant));
    }

    #[test]
    fn unused_categorize_flagged() {
        let warnings = lint_kinds(r#"
            categorize tool "db_query" as "read-only";
            policy "d" priority 100 { deny when true reason "blocked"; }
        "#);
        assert!(warnings.contains(&LintKind::UnusedCategorize));
    }

    #[test]
    fn used_categorize_not_flagged() {
        let warnings = lint_kinds(r#"
            categorize tool "db_query" as "read-only";
            rule can_call(agent, tool) :- agent_role(agent, role), tool_category(tool, cat), role_permission(role, "call", cat);
            policy "authz" priority 100 {
                allow when tool_call(call_id, agent_id, tool), can_call(agent_id, tool);
                deny when true reason "fallback";
            }
        "#);
        assert!(!warnings.contains(&LintKind::UnusedCategorize));
    }

    #[test]
    fn unused_classify_flagged() {
        let warnings = lint_kinds(r#"
            classify resource "data/*" as sensitivity "high";
            policy "d" priority 100 { deny when true reason "blocked"; }
        "#);
        assert!(warnings.contains(&LintKind::UnusedClassify));
    }

    #[test]
    fn used_classify_not_flagged() {
        let warnings = lint_kinds(r#"
            classify resource "data/*" as sensitivity "high";
            rule is_sensitive(call_id) :- resource_access(call_id, _, uri, _), resource_sensitivity(uri, "high");
            policy "guard" priority 100 {
                deny when tool_call(call_id, _, _), is_sensitive(call_id) reason "sensitive";
            }
        "#);
        assert!(!warnings.contains(&LintKind::UnusedClassify));
    }

    #[test]
    fn shadowed_block_flagged() {
        let warnings = lint_kinds(r#"
            policy "high" priority 200 { deny when true reason "always"; }
            policy "low" priority 100 {
                allow when tool_call(call_id, agent_id, _), agent_role(agent_id, "analyst");
                deny when true reason "fallback";
            }
        "#);
        assert!(warnings.contains(&LintKind::ShadowedPolicyBlock));
    }

    #[test]
    fn non_shadowed_blocks_not_flagged() {
        let warnings = lint_kinds(r#"
            policy "high" priority 200 {
                deny when tool_call(call_id, _, _), content_tag(call_id, "pii", "high") reason "pii";
            }
            policy "low" priority 100 {
                allow when tool_call(call_id, agent_id, _), agent_role(agent_id, "analyst");
                deny when true reason "fallback";
            }
        "#);
        assert!(!warnings.contains(&LintKind::ShadowedPolicyBlock));
    }

    #[test]
    fn empty_block_flagged() {
        let warnings = lint_kinds(r#"
            policy "empty" priority 100 {}
        "#);
        assert!(warnings.contains(&LintKind::EmptyPolicyBlock));
    }

    #[test]
    fn non_empty_block_not_flagged() {
        let warnings = lint_kinds(r#"
            policy "d" priority 100 { deny when true reason "blocked"; }
        "#);
        assert!(!warnings.contains(&LintKind::EmptyPolicyBlock));
    }

    #[test]
    fn unreachable_deny_flagged() {
        let warnings = lint_kinds(r#"
            policy "bad" priority 100 {
                allow when tool_call(call_id, agent_id, _);
                deny when tool_call(call_id, _, _), content_tag(call_id, "pii", "high") reason "pii";
            }
        "#);
        assert!(warnings.contains(&LintKind::UnreachableDeny));
    }

    #[test]
    fn deny_not_unreachable_when_allow_is_specific() {
        let warnings = lint_kinds(r#"
            policy "ok" priority 100 {
                allow when tool_call(call_id, agent_id, _), agent_role(agent_id, "analyst");
                deny when true reason "fallback";
            }
        "#);
        assert!(!warnings.contains(&LintKind::UnreachableDeny));
    }

    #[test]
    fn multiple_warnings_returned() {
        let warnings = lint_kinds(r#"
            pattern :unused = r"foo";
            rule orphan(x) :- agent_role(x, "admin");
            policy "empty" priority 100 {}
        "#);
        assert!(warnings.contains(&LintKind::UnusedPattern));
        assert!(warnings.contains(&LintKind::UnusedRule));
        assert!(warnings.contains(&LintKind::EmptyPolicyBlock));
    }

    #[test]
    fn warning_display_format() {
        let w = LintWarning {
            kind: LintKind::UnusedPattern,
            message: "pattern :foo is declared but never used".to_string(),
        };
        assert_eq!(w.to_string(), "warning[UnusedPattern]: pattern :foo is declared but never used");
    }
}
