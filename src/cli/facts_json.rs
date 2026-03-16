use crate::facts::*;
use crate::types::*;

#[derive(Debug)]
pub struct FactsJsonError(pub String);

impl std::fmt::Display for FactsJsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub fn parse_facts_json(value: &serde_json::Value) -> Result<FactPackage, FactsJsonError> {
    let obj = value.as_object().ok_or_else(|| FactsJsonError("expected JSON object".to_string()))?;

    Ok(FactPackage {
        agents: parse_tuples(obj, "agents", 2, |t| Ok(AgentFact {
            id: AgentId(str_at(t, 0)?),
            display_name: str_at(t, 1)?,
        }))?,
        agent_roles: parse_tuples(obj, "agent_roles", 2, |t| Ok(AgentRoleFact {
            agent_id: AgentId(str_at(t, 0)?),
            role: Role(str_at(t, 1)?),
        }))?,
        agent_clearances: parse_tuples(obj, "agent_clearances", 2, |t| Ok(AgentClearanceFact {
            agent_id: AgentId(str_at(t, 0)?),
            clearance: str_at(t, 1)?,
        }))?,
        delegations: parse_tuples(obj, "delegations", 2, |t| Ok(DelegationFact {
            agent_id: AgentId(str_at(t, 0)?),
            delegator_id: AgentId(str_at(t, 1)?),
        }))?,
        users: parse_tuples(obj, "users", 2, |t| Ok(UserFact {
            user_id: str_at(t, 0)?,
            agent_id: AgentId(str_at(t, 1)?),
        }))?,
        tool_calls: parse_tuples(obj, "tool_calls", 3, |t| Ok(ToolCallFact {
            call_id: CallId(str_at(t, 0)?),
            agent_id: AgentId(str_at(t, 1)?),
            tool_name: ToolName(str_at(t, 2)?),
        }))?,
        call_args: parse_tuples(obj, "call_args", 3, |t| Ok(CallArgFact {
            call_id: CallId(str_at(t, 0)?),
            key: str_at(t, 1)?,
            value: str_at(t, 2)?,
        }))?,
        tool_results: parse_tuples(obj, "tool_results", 3, |t| Ok(ToolResultFact {
            call_id: CallId(str_at(t, 0)?),
            key: str_at(t, 1)?,
            value: str_at(t, 2)?,
        }))?,
        resource_accesses: parse_tuples(obj, "resource_accesses", 4, |t| Ok(ResourceAccessFact {
            call_id: CallId(str_at(t, 0)?),
            agent_id: AgentId(str_at(t, 1)?),
            uri: Uri(str_at(t, 2)?),
            op: parse_op(&str_at(t, 3)?)?,
        }))?,
        resource_mimes: parse_tuples(obj, "resource_mimes", 2, |t| Ok(ResourceMimeFact {
            call_id: CallId(str_at(t, 0)?),
            mime_type: str_at(t, 1)?,
        }))?,
        content_tags: parse_tuples(obj, "content_tags", 3, |t| Ok(ContentTagFact {
            call_id: CallId(str_at(t, 0)?),
            tag: str_at(t, 1)?,
            value: str_at(t, 2)?,
        }))?,
        timestamps: parse_tuples(obj, "timestamps", 2, |t| Ok(TimestampFact {
            call_id: CallId(str_at(t, 0)?),
            unix_ts: uint_at(t, 1, "timestamps")?,
        }))?,
        call_counts: parse_tuples(obj, "call_counts", 4, |t| Ok(CallCountFact {
            agent_id: AgentId(str_at(t, 0)?),
            tool_name: ToolName(str_at(t, 1)?),
            window: str_at(t, 2)?,
            count: uint_at(t, 3, "call_counts")?,
        }))?,
        environment: parse_tuples(obj, "environment", 2, |t| Ok(EnvironmentFact {
            key: str_at(t, 0)?,
            value: str_at(t, 1)?,
        }))?,
    })
}

fn parse_tuples<T, F>(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    expected_len: usize,
    convert: F,
) -> Result<Vec<T>, FactsJsonError>
where
    F: Fn(&[serde_json::Value]) -> Result<T, FactsJsonError>,
{
    let arr = match obj.get(key) {
        Some(serde_json::Value::Array(a)) => a,
        Some(serde_json::Value::Null) | None => return Ok(Vec::new()),
        Some(other) => return Err(FactsJsonError(format!("{key}: expected array, got {}", other))),
    };
    arr.iter().enumerate().map(|(i, row)| {
        let tuple = row.as_array().ok_or_else(|| {
            FactsJsonError(format!("{key}[{i}]: expected array tuple"))
        })?;
        if tuple.len() != expected_len {
            return Err(FactsJsonError(format!(
                "{key}[{i}]: expected {expected_len} fields, got {}", tuple.len()
            )));
        }
        convert(tuple)
    }).collect()
}

fn str_at(tuple: &[serde_json::Value], idx: usize) -> Result<String, FactsJsonError> {
    tuple[idx].as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| FactsJsonError(format!("expected string at position {idx}, got {}", tuple[idx])))
}

fn uint_at(tuple: &[serde_json::Value], idx: usize, key: &str) -> Result<u64, FactsJsonError> {
    tuple[idx].as_u64()
        .ok_or_else(|| FactsJsonError(format!("{key}: expected integer at position {idx}, got {}", tuple[idx])))
}

fn parse_op(s: &str) -> Result<Op, FactsJsonError> {
    match s {
        "read"    => Ok(Op::Read),
        "write"   => Ok(Op::Write),
        "delete"  => Ok(Op::Delete),
        "execute" => Ok(Op::Execute),
        other     => Err(FactsJsonError(format!(
            "invalid op \"{other}\": expected read, write, delete, or execute"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_object_returns_default_package() {
        let v: serde_json::Value = serde_json::json!({});
        let pkg = parse_facts_json(&v).unwrap();
        assert!(pkg.tool_calls.is_empty());
        assert!(pkg.agent_roles.is_empty());
    }

    #[test]
    fn tool_calls_parsed() {
        let v = serde_json::json!({"tool_calls": [["call-1", "agt-1", "db_query"]]});
        let pkg = parse_facts_json(&v).unwrap();
        assert_eq!(pkg.tool_calls.len(), 1);
        assert_eq!(pkg.tool_calls[0].call_id, CallId("call-1".to_string()));
        assert_eq!(pkg.tool_calls[0].agent_id, AgentId("agt-1".to_string()));
        assert_eq!(pkg.tool_calls[0].tool_name, ToolName("db_query".to_string()));
    }

    #[test]
    fn agent_roles_parsed() {
        let v = serde_json::json!({"agent_roles": [["agt-1", "analyst"]]});
        let pkg = parse_facts_json(&v).unwrap();
        assert_eq!(pkg.agent_roles[0].agent_id, AgentId("agt-1".to_string()));
        assert_eq!(pkg.agent_roles[0].role, Role("analyst".to_string()));
    }

    #[test]
    fn timestamps_parsed_with_integer() {
        let v = serde_json::json!({"timestamps": [["call-1", 1700000000]]});
        let pkg = parse_facts_json(&v).unwrap();
        assert_eq!(pkg.timestamps[0].unix_ts, 1_700_000_000);
    }

    #[test]
    fn resource_accesses_parsed_with_op() {
        let v = serde_json::json!({"resource_accesses": [["call-1", "agt-1", "data/users", "read"]]});
        let pkg = parse_facts_json(&v).unwrap();
        assert_eq!(pkg.resource_accesses[0].op, Op::Read);
    }

    #[test]
    fn invalid_op_returns_error() {
        let v = serde_json::json!({"resource_accesses": [["call-1", "agt-1", "data/users", "invalid_op"]]});
        let result = parse_facts_json(&v);
        assert!(result.is_err());
        assert!(result.unwrap_err().0.contains("invalid_op"));
    }

    #[test]
    fn wrong_tuple_length_returns_error() {
        let v = serde_json::json!({"tool_calls": [["call-1", "agt-1"]]});
        let result = parse_facts_json(&v);
        assert!(result.is_err());
        assert!(result.unwrap_err().0.contains("tool_calls"));
    }

    #[test]
    fn missing_keys_default_to_empty() {
        let v = serde_json::json!({"tool_calls": [["call-1", "agt-1", "db_query"]]});
        let pkg = parse_facts_json(&v).unwrap();
        assert!(pkg.agents.is_empty());
        assert!(pkg.agent_clearances.is_empty());
        assert!(pkg.call_args.is_empty());
        assert!(pkg.environment.is_empty());
    }

    #[test]
    fn call_counts_parsed_with_integer_count() {
        let v = serde_json::json!({"call_counts": [["agt-1", "db_query", "1h", 42]]});
        let pkg = parse_facts_json(&v).unwrap();
        assert_eq!(pkg.call_counts[0].count, 42);
        assert_eq!(pkg.call_counts[0].window, "1h");
    }

    #[test]
    fn all_14_fact_types_parsed() {
        let v = serde_json::json!({
            "agents": [["agt-1", "Bot"]],
            "agent_roles": [["agt-1", "analyst"]],
            "agent_clearances": [["agt-1", "secret"]],
            "delegations": [["agt-1", "agt-0"]],
            "users": [["user-1", "agt-1"]],
            "tool_calls": [["call-1", "agt-1", "tool"]],
            "call_args": [["call-1", "k", "v"]],
            "tool_results": [["call-1", "k", "v"]],
            "resource_accesses": [["call-1", "agt-1", "uri", "read"]],
            "resource_mimes": [["call-1", "application/json"]],
            "content_tags": [["call-1", "pii", "high"]],
            "timestamps": [["call-1", 1000]],
            "call_counts": [["agt-1", "tool", "1h", 5]],
            "environment": [["region", "us-east-1"]]
        });
        let pkg = parse_facts_json(&v).unwrap();
        assert_eq!(pkg.agents.len(), 1);
        assert_eq!(pkg.agent_roles.len(), 1);
        assert_eq!(pkg.agent_clearances.len(), 1);
        assert_eq!(pkg.delegations.len(), 1);
        assert_eq!(pkg.users.len(), 1);
        assert_eq!(pkg.tool_calls.len(), 1);
        assert_eq!(pkg.call_args.len(), 1);
        assert_eq!(pkg.tool_results.len(), 1);
        assert_eq!(pkg.resource_accesses.len(), 1);
        assert_eq!(pkg.resource_mimes.len(), 1);
        assert_eq!(pkg.content_tags.len(), 1);
        assert_eq!(pkg.timestamps.len(), 1);
        assert_eq!(pkg.call_counts.len(), 1);
        assert_eq!(pkg.environment.len(), 1);
    }

    #[test]
    fn all_four_op_values_accepted() {
        for (op_str, expected) in [("read", Op::Read), ("write", Op::Write), ("delete", Op::Delete), ("execute", Op::Execute)] {
            let v = serde_json::json!({"resource_accesses": [["c", "a", "u", op_str]]});
            let pkg = parse_facts_json(&v).unwrap();
            assert_eq!(pkg.resource_accesses[0].op, expected);
        }
    }

    #[test]
    fn non_object_returns_error() {
        let v = serde_json::json!([1, 2, 3]);
        assert!(parse_facts_json(&v).is_err());
    }

    #[test]
    fn non_array_fact_key_returns_error() {
        let v = serde_json::json!({"tool_calls": "not an array"});
        assert!(parse_facts_json(&v).is_err());
    }

    #[test]
    fn non_string_in_tuple_returns_error() {
        let v = serde_json::json!({"tool_calls": [[123, "agt-1", "tool"]]});
        assert!(parse_facts_json(&v).is_err());
    }

    #[test]
    fn null_key_treated_as_empty() {
        let v = serde_json::json!({"tool_calls": null});
        let pkg = parse_facts_json(&v).unwrap();
        assert!(pkg.tool_calls.is_empty());
    }
}
