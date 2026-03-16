// src/evaluator/builtins.rs
use std::collections::HashMap;
use regex::Regex;
use crate::facts::FactPackage;

pub(super) fn compute_matched_values(
    facts: &FactPackage,
    patterns: &HashMap<String, Regex>,
) -> Vec<(String, String)> {
    if patterns.is_empty() {
        return Vec::new();
    }

    let values = collect_string_values(facts);
    let mut matched = Vec::new();

    for value in &values {
        for (name, regex) in patterns {
            if regex.is_match(value) {
                matched.push((value.clone(), name.clone()));
            }
        }
    }

    matched
}

fn collect_string_values(facts: &FactPackage) -> Vec<String> {
    let mut values: Vec<String> = Vec::new();
    for f in &facts.call_args    { values.push(f.value.clone()); }
    for f in &facts.tool_results { values.push(f.value.clone()); }
    for f in &facts.content_tags { values.push(f.value.clone()); }
    for f in &facts.environment  { values.push(f.value.clone()); }
    values.sort_unstable();
    values.dedup();
    values
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use regex::Regex;
    use crate::facts::{CallArgFact, FactPackage, ToolResultFact};
    use crate::types::CallId;

    fn pats(pairs: &[(&str, &str)]) -> HashMap<String, Regex> {
        pairs.iter()
            .map(|(name, pat)| (name.to_string(), Regex::new(pat).unwrap()))
            .collect()
    }

    #[test]
    fn no_patterns_returns_empty_without_inspecting_facts() {
        let mut facts = FactPackage::default();
        facts.call_args.push(CallArgFact {
            call_id: CallId("c".to_string()),
            key: "q".to_string(),
            value: "DROP TABLE users".to_string(),
        });
        let result = compute_matched_values(&facts, &HashMap::new());
        assert!(result.is_empty());
    }

    #[test]
    fn no_string_values_returns_empty() {
        let facts = FactPackage::default();
        let p = pats(&[("sql_injection", r"(?i)(drop|delete)\s+table")]);
        let result = compute_matched_values(&facts, &p);
        assert!(result.is_empty());
    }

    #[test]
    fn matching_call_arg_value_returns_pair() {
        let mut facts = FactPackage::default();
        facts.call_args.push(CallArgFact {
            call_id: CallId("c".to_string()),
            key: "query".to_string(),
            value: "DROP TABLE users".to_string(),
        });
        let p = pats(&[("sql_injection", r"(?i)(drop|delete)\s+table")]);
        let result = compute_matched_values(&facts, &p);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "DROP TABLE users");
        assert_eq!(result[0].1, "sql_injection");
    }

    #[test]
    fn non_matching_value_is_excluded() {
        let mut facts = FactPackage::default();
        facts.call_args.push(CallArgFact {
            call_id: CallId("c".to_string()),
            key: "query".to_string(),
            value: "SELECT * FROM users".to_string(),
        });
        let p = pats(&[("sql_injection", r"(?i)(drop|delete)\s+table")]);
        let result = compute_matched_values(&facts, &p);
        assert!(result.is_empty());
    }

    #[test]
    fn tool_result_value_is_tested() {
        let mut facts = FactPackage::default();
        facts.tool_results.push(ToolResultFact {
            call_id: CallId("c".to_string()),
            key: "content".to_string(),
            value: "sk-abc123def456ghi789jkl012mno345pqr678stu901".to_string(),
        });
        let p = pats(&[("secret_key", r"sk-[a-zA-Z0-9]{32,}")]);
        let result = compute_matched_values(&facts, &p);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].1, "secret_key");
    }
}
