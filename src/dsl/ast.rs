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
    pub name: String,
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
    Atom(AtomCondition),
    Not(AtomCondition),
    Or(Vec<AtomCondition>),
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
    Wildcard,
    NamedWildcard(String),
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
