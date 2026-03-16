// src/decision.rs
use crate::error::EngineError;
use crate::facts::FactPackage;
use crate::types::{AgentId, CallId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditLevel {
    Standard,
    Elevated,
    Critical,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Effect {
    Redact {
        selector: String,
        classifier: String,
    },
    Mask {
        selector: String,
        pattern: String,
        replacement: String,
    },
    Annotate {
        key: String,
        value: String,
    },
    Audit {
        level: AuditLevel,
        message: Option<String>,
    },
}

#[derive(Clone, Debug)]
pub struct AuditRecord {
    pub call_id: CallId,
    pub agent_id: AgentId,
    pub tool_name: Option<String>,
    pub verdict: Verdict,
    pub policy_version: String,
    pub matched_rules: Vec<String>,
    pub timestamp: Option<u64>,
}

impl AuditRecord {
    /// Build a minimal `AuditRecord` for the fail-closed error path.
    pub fn from_error(facts: &FactPackage, _err: &EngineError) -> Self {
        let (call_id, agent_id, tool_name) = facts
            .tool_calls
            .first()
            .map(|tc| {
                (
                    tc.call_id.clone(),
                    tc.agent_id.clone(),
                    Some(tc.tool_name.0.clone()),
                )
            })
            .unwrap_or_else(|| {
                (
                    CallId("unknown".to_string()),
                    AgentId("unknown".to_string()),
                    None,
                )
            });
        let timestamp = facts
            .timestamps
            .iter()
            .find(|t| t.call_id == call_id)
            .map(|t| t.unix_ts);
        AuditRecord {
            call_id,
            agent_id,
            tool_name,
            verdict: Verdict::Deny,
            policy_version: "unknown".to_string(),
            matched_rules: vec![],
            timestamp,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Decision {
    pub verdict: Verdict,
    pub effects: Vec<Effect>,
    pub reason: Option<String>,
    pub audit: AuditRecord,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AgentId, CallId};
    use crate::error::EngineError;
    use crate::facts::FactPackage;

    #[test]
    fn verdict_is_copy() {
        let v = Verdict::Allow;
        let v2 = v;
        assert_eq!(v, v2);
    }

    #[test]
    fn decision_deny_with_audit_effect() {
        let d = Decision {
            verdict: Verdict::Deny,
            effects: vec![Effect::Audit {
                level: AuditLevel::Critical,
                message: Some("test error".to_string()),
            }],
            reason: Some("test".to_string()),
            audit: AuditRecord {
                call_id: CallId("call-1".to_string()),
                agent_id: AgentId("agt-1".to_string()),
                tool_name: None,
                verdict: Verdict::Deny,
                policy_version: "none".to_string(),
                matched_rules: vec![],
                timestamp: None,
            },
        };
        assert_eq!(d.verdict, Verdict::Deny);
        assert!(matches!(d.effects[0], Effect::Audit { level: AuditLevel::Critical, .. }));
    }

    #[test]
    fn audit_record_from_error_uses_unknown_when_no_tool_call() {
        let facts = FactPackage::default();
        let err = EngineError::StoreUninitialized;
        let record = AuditRecord::from_error(&facts, &err);
        assert_eq!(record.call_id.0, "unknown");
        assert_eq!(record.verdict, Verdict::Deny);
    }

    #[test]
    fn audit_record_from_error_extracts_call_info() {
        use crate::facts::{ToolCallFact, TimestampFact};
        use crate::types::ToolName;
        let mut facts = FactPackage::default();
        facts.tool_calls.push(ToolCallFact {
            call_id: CallId("call-42".to_string()),
            agent_id: AgentId("agt-7".to_string()),
            tool_name: ToolName("db_query".to_string()),
        });
        facts.timestamps.push(TimestampFact {
            call_id: CallId("call-99".to_string()),
            unix_ts: 9_999_999_999,
        });
        facts.timestamps.push(TimestampFact {
            call_id: CallId("call-42".to_string()),
            unix_ts: 1_700_000_001,
        });
        let err = EngineError::Timeout;
        let record = AuditRecord::from_error(&facts, &err);
        assert_eq!(record.call_id.0, "call-42");
        assert_eq!(record.agent_id.0, "agt-7");
        assert_eq!(record.tool_name.as_deref(), Some("db_query"));
        assert_eq!(record.timestamp, Some(1_700_000_001));
    }
}
