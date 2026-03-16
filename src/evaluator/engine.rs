// src/evaluator/engine.rs
use cozo::DataValue;
use crate::decision::{AuditLevel, AuditRecord, Decision, Effect, Verdict};
use crate::error::EngineError;
use crate::facts::FactPackage;
use crate::policy::store::PolicyStore;
use crate::types::{AgentId, CallId};

pub(super) fn evaluate_inner(
    facts: &FactPackage,
    store: &PolicyStore,
) -> Result<Decision, EngineError> {
    let guard = store.read();
    let policy = guard.as_ref().ok_or(EngineError::StoreUninitialized)?;

    let matched_values = super::builtins::compute_matched_values(facts, &policy.patterns);
    let params = super::facts_loader::load_facts(facts, matched_values);

    let result = policy.db
        .run_script(&policy.decision_script, params, cozo::ScriptMutability::Immutable)
        .map_err(|e| EngineError::Cozo(e.to_string()))?;

    parse_decision(result, facts, &policy.version)
}

fn parse_decision(
    result: cozo::NamedRows,
    facts: &FactPackage,
    policy_version: &str,
) -> Result<Decision, EngineError> {
    let row = result.rows.first().ok_or_else(|| EngineError::Cozo(
        "decision script returned no rows — \
         policy has no rule matching this call (missing deny-when-true fallback?)"
            .to_string()
    ))?;

    let verdict_str = match row.first() {
        Some(DataValue::Str(s)) => s.as_str().to_owned(),
        other => return Err(EngineError::Cozo(
            format!("unexpected type for verdict column: {:?}", other)
        )),
    };
    let verdict = match verdict_str.as_str() {
        "Allow" => Verdict::Allow,
        "Deny"  => Verdict::Deny,
        other   => return Err(EngineError::Cozo(
            format!("unexpected verdict value '{}': expected 'Allow' or 'Deny'", other)
        )),
    };

    let reason = match row.get(1) {
        Some(DataValue::Str(s)) if !s.is_empty() => Some(s.to_string()),
        _ => None,
    };

    let effects = match row.get(2) {
        Some(DataValue::Str(s)) => parse_effects_json(s.as_str())?,
        _ => Vec::new(),
    };

    let block_name = match row.get(3) {
        Some(DataValue::Str(s)) => s.to_string(),
        _ => String::new(),
    };

    let (call_id, agent_id, tool_name) = facts.tool_calls.first()
        .map(|tc| (
            tc.call_id.clone(),
            tc.agent_id.clone(),
            Some(tc.tool_name.0.clone()),
        ))
        .unwrap_or_else(|| (
            CallId("unknown".to_string()),
            AgentId("unknown".to_string()),
            None,
        ));

    let timestamp = facts.timestamps.iter()
        .find(|t| t.call_id == call_id)
        .map(|t| t.unix_ts);

    let audit = AuditRecord {
        call_id,
        agent_id,
        tool_name,
        verdict,
        policy_version: policy_version.to_string(),
        matched_rules: if block_name.is_empty() { vec![] } else { vec![block_name] },
        timestamp,
    };

    Ok(Decision { verdict, effects, reason, audit })
}

fn parse_effects_json(json_str: &str) -> Result<Vec<Effect>, EngineError> {
    if json_str == "[]" || json_str.is_empty() {
        return Ok(Vec::new());
    }
    let values: Vec<serde_json::Value> = serde_json::from_str(json_str)
        .map_err(|e| EngineError::Cozo(
            format!("failed to parse effects JSON '{}': {}", json_str, e)
        ))?;
    values.iter().map(json_to_effect).collect()
}

fn json_to_effect(v: &serde_json::Value) -> Result<Effect, EngineError> {
    let ty = v["type"].as_str()
        .ok_or_else(|| EngineError::Cozo("effect missing 'type' field".to_string()))?;
    match ty {
        "Redact" => Ok(Effect::Redact {
            selector:   v["selector"].as_str().unwrap_or("").to_string(),
            classifier: v["classifier"].as_str().unwrap_or("").to_string(),
        }),
        "Mask" => Ok(Effect::Mask {
            selector:    v["selector"].as_str().unwrap_or("").to_string(),
            pattern:     v["pattern"].as_str().unwrap_or("").to_string(),
            replacement: v["replacement"].as_str().unwrap_or("").to_string(),
        }),
        "Annotate" => Ok(Effect::Annotate {
            key:   v["key"].as_str().unwrap_or("").to_string(),
            value: v["value"].as_str().unwrap_or("").to_string(),
        }),
        "Audit" => Ok(Effect::Audit {
            level: match v["level"].as_str() {
                Some("Elevated") => AuditLevel::Elevated,
                Some("Critical") => AuditLevel::Critical,
                _                => AuditLevel::Standard,
            },
            message: v.get("message").and_then(|m| m.as_str()).map(|s| s.to_string()),
        }),
        other => Err(EngineError::Cozo(format!("unknown effect type: '{}'", other))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::store::PolicyStore;
    use crate::facts::{FactPackage, ToolCallFact};
    use crate::types::{AgentId, CallId, ToolName};

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

    #[test]
    fn uninitialized_store_returns_store_uninitialized_err() {
        let store = PolicyStore::new();
        let result = evaluate_inner(&one_call(), &store);
        assert!(
            matches!(result, Err(EngineError::StoreUninitialized)),
            "expected StoreUninitialized, got: {:?}", result
        );
    }

    #[test]
    fn deny_all_policy_returns_deny_decision() {
        let store = PolicyStore::new();
        let compiled = crate::dsl::compiler::compile(
            r#"policy "default" priority 100 { deny when true reason "blocked"; }"#,
            "v1",
        ).expect("test policy must compile");
        store.swap(compiled);

        let result = evaluate_inner(&one_call(), &store);
        let decision = result.expect("evaluate_inner must succeed with a valid policy");
        assert_eq!(decision.verdict, Verdict::Deny);
        assert_eq!(decision.reason.as_deref(), Some("blocked"));
        assert_eq!(decision.audit.policy_version, "v1");
        assert_eq!(decision.audit.matched_rules, vec!["default".to_string()]);
    }
}
