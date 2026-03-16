// src/evaluator/facts_loader.rs
use std::collections::BTreeMap;
use cozo::DataValue;
use crate::facts::*;

pub(super) fn load_facts(
    facts: &FactPackage,
    matched_values: Vec<(String, String)>,
) -> BTreeMap<String, DataValue> {
    let mut p = BTreeMap::new();

    // Identity
    p.insert("agents".to_string(),
        rows(facts.agents.iter().map(|f| vec![s(&f.id.0), s(&f.display_name)])));
    p.insert("agent_roles".to_string(),
        rows(facts.agent_roles.iter().map(|f| vec![s(&f.agent_id.0), s(&f.role.0)])));
    p.insert("agent_clearances".to_string(),
        rows(facts.agent_clearances.iter().map(|f| vec![s(&f.agent_id.0), s(&f.clearance)])));
    p.insert("delegations".to_string(),
        rows(facts.delegations.iter().map(|f| vec![s(&f.agent_id.0), s(&f.delegator_id.0)])));
    p.insert("users".to_string(),
        rows(facts.users.iter().map(|f| vec![s(&f.user_id), s(&f.agent_id.0)])));

    // MCP call
    p.insert("tool_calls".to_string(),
        rows(facts.tool_calls.iter().map(|f| {
            vec![s(&f.call_id.0), s(&f.agent_id.0), s(&f.tool_name.0)]
        })));
    p.insert("call_args".to_string(),
        rows(facts.call_args.iter().map(|f| vec![s(&f.call_id.0), s(&f.key), s(&f.value)])));
    p.insert("tool_results".to_string(),
        rows(facts.tool_results.iter().map(|f| vec![s(&f.call_id.0), s(&f.key), s(&f.value)])));
    p.insert("resource_accesses".to_string(),
        rows(facts.resource_accesses.iter().map(|f| {
            vec![s(&f.call_id.0), s(&f.agent_id.0), s(&f.uri.0), s(f.op.as_str())]
        })));
    p.insert("resource_mimes".to_string(),
        rows(facts.resource_mimes.iter().map(|f| vec![s(&f.call_id.0), s(&f.mime_type)])));

    // Content classification
    p.insert("content_tags".to_string(),
        rows(facts.content_tags.iter().map(|f| vec![s(&f.call_id.0), s(&f.tag), s(&f.value)])));

    // Environment
    p.insert("timestamps".to_string(),
        rows(facts.timestamps.iter().map(|f| vec![s(&f.call_id.0), n(f.unix_ts)])));
    p.insert("call_counts".to_string(),
        rows(facts.call_counts.iter().map(|f| {
            vec![s(&f.agent_id.0), s(&f.tool_name.0), s(&f.window), n(f.count)]
        })));
    p.insert("environment".to_string(),
        rows(facts.environment.iter().map(|f| vec![s(&f.key), s(&f.value)])));

    // Builtins pre-pass
    p.insert("matched_values".to_string(),
        rows(matched_values.iter().map(|(val, name)| vec![s(val), s(name)])));

    p
}

fn s(v: &str) -> DataValue {
    DataValue::Str(v.into())
}

fn n(v: u64) -> DataValue {
    DataValue::Num(cozo::Num::Int(v as i64))
}

fn rows(iter: impl Iterator<Item = Vec<DataValue>>) -> DataValue {
    DataValue::List(iter.map(DataValue::List).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    #[test]
    fn all_fifteen_params_present_even_with_empty_facts() {
        let params = load_facts(&FactPackage::default(), vec![]);
        let expected_keys = [
            "agents", "agent_roles", "agent_clearances", "delegations", "users",
            "tool_calls", "call_args", "tool_results", "resource_accesses", "resource_mimes",
            "content_tags", "timestamps", "call_counts", "environment", "matched_values",
        ];
        for key in &expected_keys {
            assert!(params.contains_key(*key), "missing CozoDB param: {key}");
        }
        assert_eq!(params.len(), 15);
    }

    #[test]
    fn tool_call_converts_to_list_of_lists() {
        let pkg = FactPackage {
            tool_calls: vec![ToolCallFact {
                call_id: CallId("call-1".to_string()),
                agent_id: AgentId("agt-1".to_string()),
                tool_name: ToolName("db_query".to_string()),
            }],
            ..Default::default()
        };
        let params = load_facts(&pkg, vec![]);
        let rows = match &params["tool_calls"] {
            cozo::DataValue::List(rows) => rows,
            other => panic!("expected List, got {:?}", other),
        };
        assert_eq!(rows.len(), 1);
        let row = match &rows[0] {
            cozo::DataValue::List(row) => row,
            other => panic!("expected List row, got {:?}", other),
        };
        assert_eq!(row.len(), 3);
        assert_eq!(row[0], cozo::DataValue::Str("call-1".into()));
        assert_eq!(row[1], cozo::DataValue::Str("agt-1".into()));
        assert_eq!(row[2], cozo::DataValue::Str("db_query".into()));
    }

    #[test]
    fn timestamp_unix_ts_converts_to_numeric_not_string() {
        let mut pkg = FactPackage::default();
        pkg.timestamps.push(TimestampFact {
            call_id: CallId("call-1".to_string()),
            unix_ts: 1_700_000_000,
        });
        let params = load_facts(&pkg, vec![]);
        let rows = match &params["timestamps"] {
            cozo::DataValue::List(rows) => rows,
            other => panic!("expected List, got {:?}", other),
        };
        let row = match &rows[0] {
            cozo::DataValue::List(row) => row,
            other => panic!("expected List row, got {:?}", other),
        };
        assert!(
            matches!(row[1], cozo::DataValue::Num(_)),
            "unix_ts must be DataValue::Num, got {:?}", row[1]
        );
    }

    #[test]
    fn matched_values_converts_to_list_of_string_pairs() {
        let pairs = vec![
            ("DROP TABLE users".to_string(), "sql_injection".to_string()),
        ];
        let params = load_facts(&FactPackage::default(), pairs);
        let rows = match &params["matched_values"] {
            cozo::DataValue::List(rows) => rows,
            other => panic!("expected List, got {:?}", other),
        };
        assert_eq!(rows.len(), 1);
        let pair = match &rows[0] {
            cozo::DataValue::List(pair) => pair,
            other => panic!("expected List pair, got {:?}", other),
        };
        assert_eq!(pair.len(), 2);
        assert_eq!(pair[0], cozo::DataValue::Str("DROP TABLE users".into()));
        assert_eq!(pair[1], cozo::DataValue::Str("sql_injection".into()));
    }
}
