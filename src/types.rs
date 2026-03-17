// src/types.rs

/// Unique identifier for a single MCP tool call within an evaluation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CallId(pub String);

/// Unique identifier for an agent (the entity making the call).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AgentId(pub String);

/// A role name as declared in the policy DSL (e.g. "analyst", "admin").
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Role(pub String);

/// The name of an MCP tool (e.g. "db_query", "db_write").
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ToolName(pub String);

/// A resource URI (e.g. "data/finance/report.csv").
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Uri(pub String);

/// The operation being performed on a resource.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Op {
    Read,
    Write,
    Create,
    Delete,
    List,
    Execute,
}

impl Op {
    pub fn as_str(&self) -> &'static str {
        match self {
            Op::Read    => "read",
            Op::Write   => "write",
            Op::Create  => "create",
            Op::Delete  => "delete",
            Op::List    => "list",
            Op::Execute => "execute",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_id_equality() {
        let a = CallId("call-1".to_string());
        let b = CallId("call-1".to_string());
        let c = CallId("call-2".to_string());
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn op_debug() {
        assert_eq!(format!("{:?}", Op::Read), "Read");
        assert_eq!(format!("{:?}", Op::Write), "Write");
    }

    #[test]
    fn newtypes_are_hashable() {
        use std::collections::HashMap;
        let mut m: HashMap<AgentId, u32> = HashMap::new();
        m.insert(AgentId("agt-1".to_string()), 1);
        assert_eq!(m[&AgentId("agt-1".to_string())], 1);
    }
}
