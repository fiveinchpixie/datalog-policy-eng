// src/facts.rs
use crate::types::{AgentId, CallId, Op, Role, ToolName, Uri};

// ── Identity facts ────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct AgentFact {
    pub id: AgentId,
    pub display_name: String,
}

#[derive(Clone, Debug)]
pub struct AgentRoleFact {
    pub agent_id: AgentId,
    pub role: Role,
}

#[derive(Clone, Debug)]
pub struct AgentClearanceFact {
    pub agent_id: AgentId,
    pub clearance: String,
}

#[derive(Clone, Debug)]
pub struct DelegationFact {
    pub agent_id: AgentId,
    pub delegator_id: AgentId,
}

#[derive(Clone, Debug)]
pub struct UserFact {
    pub user_id: String,
    pub agent_id: AgentId,
}

// ── MCP call facts ────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct ToolCallFact {
    pub call_id: CallId,
    pub agent_id: AgentId,
    pub tool_name: ToolName,
}

#[derive(Clone, Debug)]
pub struct CallArgFact {
    pub call_id: CallId,
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug)]
pub struct ToolResultFact {
    pub call_id: CallId,
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug)]
pub struct ResourceAccessFact {
    pub call_id: CallId,
    pub agent_id: AgentId,
    pub uri: Uri,
    pub op: Op,
}

#[derive(Clone, Debug)]
pub struct ResourceMimeFact {
    pub call_id: CallId,
    pub mime_type: String,
}

// ── Content classification facts ──────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct ContentTagFact {
    pub call_id: CallId,
    pub tag: String,
    pub value: String,
}

// ── Environment facts ─────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct TimestampFact {
    pub call_id: CallId,
    pub unix_ts: u64,
}

#[derive(Clone, Debug)]
pub struct CallCountFact {
    pub agent_id: AgentId,
    pub tool_name: ToolName,
    pub window: String,
    pub count: u64,
}

#[derive(Clone, Debug)]
pub struct EnvironmentFact {
    pub key: String,
    pub value: String,
}

// ── FactPackage ───────────────────────────────────────────────────────────────

/// The complete context for one MCP request evaluation.
/// Assembled by the gateway; consumed (read-only) by the evaluator.
#[derive(Clone, Debug, Default)]
pub struct FactPackage {
    // Identity
    pub agents: Vec<AgentFact>,
    pub agent_roles: Vec<AgentRoleFact>,
    pub agent_clearances: Vec<AgentClearanceFact>,
    pub delegations: Vec<DelegationFact>,
    pub users: Vec<UserFact>,
    // MCP call
    pub tool_calls: Vec<ToolCallFact>,
    pub call_args: Vec<CallArgFact>,
    pub tool_results: Vec<ToolResultFact>,
    pub resource_accesses: Vec<ResourceAccessFact>,
    pub resource_mimes: Vec<ResourceMimeFact>,
    // Content classification
    pub content_tags: Vec<ContentTagFact>,
    // Environment
    pub timestamps: Vec<TimestampFact>,
    pub call_counts: Vec<CallCountFact>,
    pub environment: Vec<EnvironmentFact>,
}

impl FactPackage {
    /// Returns the `CallId` of the first `tool_call` fact, if any.
    pub fn primary_call_id(&self) -> Option<&CallId> {
        self.tool_calls.first().map(|tc| &tc.call_id)
    }

    /// Returns the `AgentId` of the first `tool_call` fact, if any.
    pub fn primary_agent_id(&self) -> Option<&AgentId> {
        self.tool_calls.first().map(|tc| &tc.agent_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AgentId, CallId, Role, ToolName};

    fn minimal_package() -> FactPackage {
        FactPackage {
            agents: vec![AgentFact {
                id: AgentId("agt-1".to_string()),
                display_name: "Analyst Bot".to_string(),
            }],
            agent_roles: vec![AgentRoleFact {
                agent_id: AgentId("agt-1".to_string()),
                role: Role("analyst".to_string()),
            }],
            agent_clearances: vec![],
            delegations: vec![],
            users: vec![],
            tool_calls: vec![ToolCallFact {
                call_id: CallId("call-1".to_string()),
                agent_id: AgentId("agt-1".to_string()),
                tool_name: ToolName("db_query".to_string()),
            }],
            call_args: vec![],
            tool_results: vec![],
            resource_accesses: vec![],
            resource_mimes: vec![],
            content_tags: vec![],
            timestamps: vec![TimestampFact {
                call_id: CallId("call-1".to_string()),
                unix_ts: 1_700_000_000,
            }],
            call_counts: vec![],
            environment: vec![],
        }
    }

    #[test]
    fn package_construction() {
        let pkg = minimal_package();
        assert_eq!(pkg.agents.len(), 1);
        assert_eq!(pkg.tool_calls[0].tool_name.0, "db_query");
    }

    #[test]
    fn package_primary_call_id() {
        let pkg = minimal_package();
        assert_eq!(pkg.primary_call_id(), Some(&CallId("call-1".to_string())));
    }

    #[test]
    fn package_primary_call_id_empty() {
        let pkg = FactPackage::default();
        assert_eq!(pkg.primary_call_id(), None);
    }
}
