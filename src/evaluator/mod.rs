// src/evaluator/mod.rs
mod builtins;
pub(super) mod engine;
mod facts_loader;

use crate::decision::{AuditLevel, AuditRecord, Decision, Effect, Verdict};
use crate::error::PolicyError;
use crate::facts::FactPackage;
use crate::policy::store::PolicyStore;
use crate::policy::watcher::{PolicySet, PolicyWatcher};

/// The authorization engine. Owns a `PolicyStore` and implements `PolicyWatcher`.
///
/// Cheap to clone — all clones share the same underlying `PolicyStore`.
#[derive(Clone)]
pub struct Engine {
    store: PolicyStore,
}

impl Engine {
    pub fn new() -> Self {
        Self { store: PolicyStore::new() }
    }

    /// Evaluate a `FactPackage` against the loaded policy.
    ///
    /// Never panics, never fails open. If any error occurs returns `Deny + Audit(Critical)`.
    pub fn evaluate(&self, facts: &FactPackage) -> Decision {
        engine::evaluate_inner(facts, &self.store)
            .unwrap_or_else(|err| Decision {
                verdict: Verdict::Deny,
                effects: vec![Effect::Audit {
                    level: AuditLevel::Critical,
                    message: Some(err.to_string()),
                }],
                reason: Some("evaluation error".to_string()),
                audit: AuditRecord::from_error(facts, &err),
            })
    }

    /// Returns the version string of the currently loaded policy, if any.
    pub fn current_version(&self) -> Option<String> {
        self.store.current_version()
    }
}

impl Default for Engine {
    fn default() -> Self { Self::new() }
}

impl PolicyWatcher for Engine {
    fn push(&self, policy: PolicySet) -> Result<(), PolicyError> {
        if self.store.current_version().as_deref() == Some(&policy.version) {
            return Ok(());
        }
        let compiled = crate::dsl::compiler::compile(&policy.source, &policy.version)?;
        self.store.swap(compiled);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::{AgentRoleFact, FactPackage, ToolCallFact};
    use crate::types::{AgentId, CallId, Role, ToolName};

    fn one_call() -> FactPackage {
        FactPackage {
            tool_calls: vec![ToolCallFact {
                call_id: CallId("call-1".to_string()),
                agent_id: AgentId("agt-1".to_string()),
                tool_name: ToolName("test_tool".to_string()),
            }],
            ..Default::default()
        }
    }

    fn one_call_with_role(role: &str) -> FactPackage {
        let mut pkg = one_call();
        pkg.agent_roles.push(AgentRoleFact {
            agent_id: AgentId("agt-1".to_string()),
            role: Role(role.to_string()),
        });
        pkg
    }

    fn push_policy(engine: &Engine, version: &str, source: &str) {
        engine.push(PolicySet {
            version: version.to_string(),
            source: source.to_string(),
            checksum: String::new(),
        }).expect("test policy must compile");
    }

    const DENY_ALL: &str = r#"
policy "default" priority 100 {
    deny when true
        reason "no matching allow rule";
}
"#;

    const ALLOW_TESTER_ROLE: &str = r#"
policy "default" priority 100 {
    allow when
        tool_call(call_id, agent_id, _),
        agent_role(agent_id, "tester");
}
"#;

    #[test]
    fn engine_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Engine>();
    }

    #[test]
    fn engine_clone_shares_store() {
        let engine = Engine::new();
        let clone = engine.clone();
        push_policy(&engine, "v1", DENY_ALL);
        assert_eq!(engine.current_version(), clone.current_version());
    }

    #[test]
    fn evaluate_uninitialized_store_returns_deny_audit_critical() {
        let engine = Engine::new();
        let decision = engine.evaluate(&one_call());
        assert_eq!(decision.verdict, Verdict::Deny);
        assert!(
            decision.effects.iter().any(|e| matches!(e,
                Effect::Audit { level: AuditLevel::Critical, .. }
            )),
            "expected Audit(Critical) effect, got: {:?}", decision.effects
        );
    }

    #[test]
    fn push_valid_policy_succeeds() {
        let engine = Engine::new();
        let result = engine.push(PolicySet {
            version: "v1".to_string(),
            source: DENY_ALL.to_string(),
            checksum: String::new(),
        });
        assert!(result.is_ok());
        assert_eq!(engine.current_version(), Some("v1".to_string()));
    }

    #[test]
    fn push_invalid_policy_leaves_store_unchanged() {
        let engine = Engine::new();
        push_policy(&engine, "v1", DENY_ALL);
        let result = engine.push(PolicySet {
            version: "v2".to_string(),
            source: "this is not valid DSL !!!".to_string(),
            checksum: String::new(),
        });
        assert!(result.is_err());
        assert_eq!(engine.current_version(), Some("v1".to_string()));
    }

    #[test]
    fn push_same_version_is_idempotent() {
        let engine = Engine::new();
        push_policy(&engine, "v1", DENY_ALL);
        let result = engine.push(PolicySet {
            version: "v1".to_string(),
            source: "this is not valid DSL !!!".to_string(),
            checksum: String::new(),
        });
        assert!(result.is_ok());
    }

    #[test]
    fn evaluate_deny_when_true_returns_deny() {
        let engine = Engine::new();
        push_policy(&engine, "v1", DENY_ALL);
        let decision = engine.evaluate(&one_call());
        assert_eq!(decision.verdict, Verdict::Deny);
    }

    #[test]
    fn evaluate_deny_when_true_populates_reason() {
        let engine = Engine::new();
        push_policy(&engine, "v1", DENY_ALL);
        let decision = engine.evaluate(&one_call());
        assert_eq!(decision.reason.as_deref(), Some("no matching allow rule"));
    }

    #[test]
    fn evaluate_allow_rule_returns_allow() {
        let engine = Engine::new();
        push_policy(&engine, "v1", ALLOW_TESTER_ROLE);
        let decision = engine.evaluate(&one_call_with_role("tester"));
        assert_eq!(decision.verdict, Verdict::Allow);
    }

    #[test]
    fn evaluate_allow_rule_without_matching_role_returns_deny() {
        let engine = Engine::new();
        push_policy(&engine, "v1", ALLOW_TESTER_ROLE);
        let decision = engine.evaluate(&one_call());
        assert_eq!(decision.verdict, Verdict::Deny);
        assert!(
            decision.effects.iter().any(|e| matches!(e,
                Effect::Audit { level: AuditLevel::Critical, .. }
            )),
            "no-match path must produce Audit(Critical), got: {:?}", decision.effects
        );
    }
}
