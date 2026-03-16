// src/dsl/compiler.rs
use std::collections::{HashMap, HashSet};
use regex::Regex;
use cozo::ScriptMutability;
use crate::dsl::ast::*;
use crate::error::PolicyError;
use crate::policy::compiled::CompiledPolicy;

const STORED_RELATIONS: &[&str] = &[
    "role_permission",
    "tool_category",
    "resource_sensitivity",
    "forbidden_pattern",
    "clearance_grants",
    "forbidden_arg_key",
    "allowed_domain",
    "tag_effect",
    "sensitivity_effect",
];

pub fn compile(source: &str, version: &str) -> Result<CompiledPolicy, PolicyError> {
    let ast = crate::dsl::parser::parse(source)?;
    compile_ast(ast, version)
}

fn compile_ast(file: PolicyFile, version: &str) -> Result<CompiledPolicy, PolicyError> {
    validate(&file)?;
    let db = cozo::DbInstance::new("mem", "", "")
        .map_err(|e| PolicyError::Compile(format!("failed to create CozoDB: {}", e)))?;
    init_db(&db)?;
    let patterns = compile_patterns(&file, &db)?;
    compile_policy_facts(&file, &db)?;
    let decision_script = build_decision_script(&file)?;
    Ok(CompiledPolicy { version: version.to_string(), db, decision_script, patterns })
}

// ── Validation ────────────────────────────────────────────────────────────────

fn validate(file: &PolicyFile) -> Result<(), PolicyError> {
    let declared_patterns: HashSet<&str> = file.declarations.iter()
        .filter_map(|d| match d {
            Declaration::Pattern(p) => Some(p.name.as_str()),
            _ => None,
        })
        .collect();

    for decl in &file.declarations {
        match decl {
            Declaration::Rule(r) => {
                if !r.name.chars().next().map(|c| c.is_alphabetic() || c == '_').unwrap_or(false)
                    || !r.name.chars().all(|c| c.is_alphanumeric() || c == '_')
                {
                    return Err(PolicyError::Compile(format!(
                        "rule name `{}` is not a valid CozoDB identifier; \
                         use only letters, digits, and underscores (no hyphens)",
                        r.name
                    )));
                }
                let or_count = r.conditions.iter()
                    .filter(|c| matches!(c, ConditionClause::Or(_)))
                    .count();
                if or_count > 1 {
                    return Err(PolicyError::Compile(format!(
                        "rule `{}` has {} Or conditions; at most one Or group is supported per rule.",
                        r.name, or_count
                    )));
                }
                if r.conditions.iter().any(|c| matches!(c, ConditionClause::True)) {
                    return Err(PolicyError::Compile(format!(
                        "rule `{}` uses `true` as a condition; `true` is only valid in policy \
                         blocks as the sole condition in `deny when true`",
                        r.name
                    )));
                }
                for cond in &r.conditions {
                    check_pattern_refs(cond, &declared_patterns)?;
                }
            }
            Declaration::Policy(p) => {
                for rule in &p.rules {
                    let conditions = match rule {
                        PolicyRule::Allow(a) => &a.conditions,
                        PolicyRule::Deny(d) => &d.conditions,
                    };
                    if matches!(rule, PolicyRule::Allow(_))
                        && conditions.iter().any(|c| matches!(c, ConditionClause::True))
                    {
                        return Err(PolicyError::Compile(
                            "`allow when true` is not permitted; `true` may only appear \
                             in `deny when true` as the default-deny fallback".to_string()
                        ));
                    }
                    for cond in conditions {
                        check_pattern_refs(cond, &declared_patterns)?;
                        if matches!(cond, ConditionClause::Or(_)) {
                            return Err(PolicyError::Compile(
                                "Or conditions are not allowed directly in policy blocks; \
                                 extract the logic into a `rule` declaration instead".to_string()
                            ));
                        }
                    }
                    if conditions.iter().any(|c| matches!(c, ConditionClause::True))
                        && conditions.len() > 1
                    {
                        return Err(PolicyError::Compile(
                            "`true` cannot be mixed with other conditions".to_string()
                        ));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn check_pattern_refs(cond: &ConditionClause, declared: &HashSet<&str>) -> Result<(), PolicyError> {
    let atoms: Vec<&AtomCondition> = match cond {
        ConditionClause::Atom(a) => vec![a],
        ConditionClause::Not(a) => vec![a],
        ConditionClause::Or(atoms) => atoms.iter().collect(),
        ConditionClause::True => return Ok(()),
    };
    for atom in atoms {
        if atom.predicate == "matches" {
            for arg in &atom.args {
                if let Arg::PatternRef(name) = arg {
                    if !declared.contains(name.as_str()) {
                        return Err(PolicyError::Compile(format!(
                            "undefined pattern :{name}; declare it with `pattern :{name} = r\"...\";`"
                        )));
                    }
                }
            }
        }
    }
    Ok(())
}

// ── DB initialization ─────────────────────────────────────────────────────────

fn init_db(db: &cozo::DbInstance) -> Result<(), PolicyError> {
    let creates = [
        ":create role_permission {role: String, action: String, resource_pattern: String}",
        ":create tool_category {tool_name: String, category: String}",
        ":create resource_sensitivity {uri_pattern: String, level: String}",
        ":create forbidden_pattern {name: String, source: String}",
        ":create clearance_grants {clearance: String, privilege: String}",
        ":create forbidden_arg_key {tool_name: String, key: String}",
        ":create allowed_domain {uri_pattern: String}",
        ":create tag_effect {tag: String, value: String, effect: String}",
        ":create sensitivity_effect {level: String, effect: String}",
    ];
    for stmt in &creates {
        db.run_script(stmt, Default::default(), ScriptMutability::Mutable)
            .map_err(|e| PolicyError::Compile(format!("DB init error on `{stmt}`: {e}")))?;
    }
    Ok(())
}

// ── Pattern compilation ───────────────────────────────────────────────────────

fn compile_patterns(
    file: &PolicyFile,
    db: &cozo::DbInstance,
) -> Result<HashMap<String, Regex>, PolicyError> {
    let mut patterns = HashMap::new();
    for decl in &file.declarations {
        if let Declaration::Pattern(p) = decl {
            let regex = Regex::new(&p.source)
                .map_err(|e| PolicyError::Compile(format!("invalid regex :{}: {}", p.name, e)))?;
            patterns.insert(p.name.clone(), regex);
            let script = format!(
                "?[name, source] <- [[{}, {}]]\n:put forbidden_pattern {{name, source}}",
                cozo_str(&p.name),
                cozo_str(&p.source)
            );
            db.run_script(&script, Default::default(), ScriptMutability::Mutable)
                .map_err(|e| PolicyError::Compile(format!("pattern insert error: {e}")))?;
        }
    }
    Ok(patterns)
}

// ── Policy fact compilation ───────────────────────────────────────────────────

fn compile_policy_facts(file: &PolicyFile, db: &cozo::DbInstance) -> Result<(), PolicyError> {
    for decl in &file.declarations {
        match decl {
            Declaration::Grant(g)      => compile_grant(g, db)?,
            Declaration::Categorize(c) => compile_categorize(c, db)?,
            Declaration::Classify(c)   => compile_classify(c, db)?,
            _ => {}
        }
    }
    Ok(())
}

fn compile_grant(g: &GrantDecl, db: &cozo::DbInstance) -> Result<(), PolicyError> {
    let (action, resource_pattern) = match &g.permission {
        GrantPermission::CallAny          => ("call".to_string(), "*".to_string()),
        GrantPermission::CallCategory(c)  => ("call".to_string(), c.clone()),
        GrantPermission::AccessPattern(p) => ("access".to_string(), p.clone()),
    };
    let script = format!(
        "?[role, action, resource_pattern] <- [[{}, {}, {}]]\n\
         :put role_permission {{role, action, resource_pattern}}",
        cozo_str(&g.role), cozo_str(&action), cozo_str(&resource_pattern)
    );
    db.run_script(&script, Default::default(), ScriptMutability::Mutable)
        .map_err(|e| PolicyError::Compile(format!("grant insert error: {e}")))?;
    Ok(())
}

fn compile_categorize(c: &CategorizeDecl, db: &cozo::DbInstance) -> Result<(), PolicyError> {
    let script = format!(
        "?[tool_name, category] <- [[{}, {}]]\n\
         :put tool_category {{tool_name, category}}",
        cozo_str(&c.tool), cozo_str(&c.category)
    );
    db.run_script(&script, Default::default(), ScriptMutability::Mutable)
        .map_err(|e| PolicyError::Compile(format!("categorize insert error: {e}")))?;
    Ok(())
}

fn compile_classify(c: &ClassifyDecl, db: &cozo::DbInstance) -> Result<(), PolicyError> {
    let script = format!(
        "?[uri_pattern, level] <- [[{}, {}]]\n\
         :put resource_sensitivity {{uri_pattern, level}}",
        cozo_str(&c.resource_pattern), cozo_str(&c.sensitivity)
    );
    db.run_script(&script, Default::default(), ScriptMutability::Mutable)
        .map_err(|e| PolicyError::Compile(format!("classify insert error: {e}")))?;
    Ok(())
}

// ── Decision script generation ────────────────────────────────────────────────

const REQUEST_FACT_BINDINGS: &str = "\
tool_call[call_id, agent_id, tool_name] <- $tool_calls\n\
agent[agent_id, display_name] <- $agents\n\
agent_role[agent_id, role] <- $agent_roles\n\
agent_clearance[agent_id, clearance] <- $agent_clearances\n\
delegated_by[agent_id, delegator_id] <- $delegations\n\
user[user_id, agent_id] <- $users\n\
call_arg[call_id, key, value] <- $call_args\n\
tool_result[call_id, key, value] <- $tool_results\n\
resource_access[call_id, res_agent_id, uri, op] <- $resource_accesses\n\
resource_mime[call_id, mime_type] <- $resource_mimes\n\
content_tag[call_id, tag, tag_value] <- $content_tags\n\
timestamp[call_id, unix_ts] <- $timestamps\n\
call_count[agent_id, tool_name, window, count] <- $call_counts\n\
environment[key, value] <- $environment\n\
matched_value[value, pattern_name] <- $matched_values\n";

fn build_decision_script(file: &PolicyFile) -> Result<String, PolicyError> {
    let mut parts: Vec<String> = vec![REQUEST_FACT_BINDINGS.to_string()];

    for decl in &file.declarations {
        if let Declaration::Rule(r) = decl {
            parts.extend(compile_rule_to_cozo(r)?);
        }
    }

    let mut policies: Vec<&PolicyDecl> = file.declarations.iter()
        .filter_map(|d| if let Declaration::Policy(p) = d { Some(p) } else { None })
        .collect();
    policies.sort_by(|a, b| b.priority.cmp(&a.priority));

    let mut higher_block_names: Vec<&str> = Vec::new();
    for policy in &policies {
        parts.extend(compile_policy_block(policy, &higher_block_names)?);
        higher_block_names.push(&policy.name);
    }

    for policy in &policies {
        let safe = sanitize_name(&policy.name);
        parts.push(format!(
            "decision_output[call_id, verdict, reason, effects_json, block_name] := \
             b_{safe}_decision[call_id, verdict, reason, effects_json], block_name = {}",
            cozo_str(&policy.name)
        ));
    }
    parts.push(
        "?[verdict, reason, effects_json, block_name] := \
         decision_output[_, verdict, reason, effects_json, block_name]"
            .to_string(),
    );

    Ok(parts.join("\n"))
}

fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' })
        .collect()
}

fn compile_rule_to_cozo(r: &RuleDecl) -> Result<Vec<String>, PolicyError> {
    let params: Vec<String> = r.params.iter().map(compile_param_str).collect();
    let head = format!("{}[{}]", r.name, params.join(", "));

    let non_or: Vec<&ConditionClause> = r.conditions.iter()
        .filter(|c| !matches!(c, ConditionClause::Or(_)))
        .collect();
    let or_groups: Vec<&Vec<AtomCondition>> = r.conditions.iter()
        .filter_map(|c| if let ConditionClause::Or(atoms) = c { Some(atoms) } else { None })
        .collect();

    let base_body: Vec<String> = non_or.iter()
        .map(|c| compile_condition_str(c))
        .collect::<Result<Vec<_>, _>>()?;

    if or_groups.is_empty() {
        let rule = if base_body.is_empty() {
            format!("{head} := true")
        } else {
            format!("{head} := {}", base_body.join(", "))
        };
        Ok(vec![rule])
    } else {
        let or_atoms = or_groups[0];
        if or_atoms.is_empty() {
            return Err(PolicyError::Compile(format!(
                "rule `{}` has an empty Or group", r.name
            )));
        }
        let rules = or_atoms.iter().map(|atom| {
            let mut body = base_body.clone();
            body.push(compile_atom_str(atom));
            format!("{head} := {}", body.join(", "))
        }).collect();
        Ok(rules)
    }
}

fn compile_policy_block(policy: &PolicyDecl, higher_blocks: &[&str]) -> Result<Vec<String>, PolicyError> {
    let safe = sanitize_name(&policy.name);

    let higher_guards: Vec<String> = higher_blocks.iter()
        .map(|name| format!("not b_{}_matched[call_id]", sanitize_name(name)))
        .collect();
    let higher_guard_suffix = if higher_guards.is_empty() {
        String::new()
    } else {
        format!(", {}", higher_guards.join(", "))
    };

    let mut lines: Vec<String> = Vec::new();
    let mut deny_rule_names: Vec<String> = Vec::new();
    let mut allow_rule_names: Vec<String> = Vec::new();

    for (idx, rule) in policy.rules.iter().enumerate() {
        match rule {
            PolicyRule::Allow(allow) => {
                let rule_name = format!("b_{safe}_allow_{idx}");
                let effects_json = compile_effects_json(&allow.effects);
                let body = compile_conditions_str(&allow.conditions)?;
                lines.push(format!(
                    r#"{rule_name}[call_id, reason, effects] := {body}{higher_guard_suffix}, reason = "", effects = {}"#,
                    cozo_str(&effects_json)
                ));
                allow_rule_names.push(rule_name);
            }
            PolicyRule::Deny(deny) => {
                let rule_name = format!("b_{safe}_deny_{idx}");
                let effects_json = compile_effects_json(&deny.effects);
                let reason = deny.reason.as_deref().unwrap_or("");
                let body = compile_conditions_str(&deny.conditions)?;
                lines.push(format!(
                    "{rule_name}[call_id, reason, effects] := {body}{higher_guard_suffix}, reason = {}, effects = {}",
                    cozo_str(reason),
                    cozo_str(&effects_json)
                ));
                deny_rule_names.push(rule_name);
            }
        }
    }

    // Allow rules fire unconditionally — allow takes precedence over deny.
    for allow_rule in &allow_rule_names {
        lines.push(format!(
            r#"b_{safe}_decision[call_id, verdict, reason, effects] := {allow_rule}[call_id, reason, effects], verdict = "Allow""#
        ));
    }
    // Deny rules fire only when no allow rule matched for the same call_id.
    for deny_rule in &deny_rule_names {
        let not_allow: Vec<String> = allow_rule_names.iter()
            .map(|ar| format!("not {ar}[call_id, _, _]"))
            .collect();
        let allow_guard = if not_allow.is_empty() {
            String::new()
        } else {
            format!(", {}", not_allow.join(", "))
        };
        lines.push(format!(
            r#"b_{safe}_decision[call_id, verdict, reason, effects] := {deny_rule}[call_id, reason, effects]{allow_guard}, verdict = "Deny""#
        ));
    }

    lines.push(format!(
        "b_{safe}_matched[call_id] := b_{safe}_decision[call_id, _, _, _]"
    ));

    Ok(lines)
}

// ── Condition/atom compilation ────────────────────────────────────────────────

fn compile_conditions_str(conditions: &[ConditionClause]) -> Result<String, PolicyError> {
    if conditions.is_empty()
        || (conditions.len() == 1 && conditions[0] == ConditionClause::True)
    {
        return Ok("tool_call[call_id, _, _]".to_string());
    }
    let parts: Vec<String> = conditions.iter()
        .map(compile_condition_str)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(parts.join(", "))
}

fn compile_condition_str(cond: &ConditionClause) -> Result<String, PolicyError> {
    match cond {
        ConditionClause::Atom(atom) => Ok(compile_atom_str(atom)),
        ConditionClause::Not(atom) => Ok(format!("not {}", compile_atom_str(atom))),
        ConditionClause::True => Ok("tool_call[call_id, _, _]".to_string()),
        ConditionClause::Or(_) => Err(PolicyError::Compile(
            "Or conditions are not supported in policy blocks".to_string()
        )),
    }
}

fn compile_atom_str(atom: &AtomCondition) -> String {
    if atom.predicate == "matches" {
        if let (Some(value_arg), Some(Arg::PatternRef(name))) =
            (atom.args.first(), atom.args.get(1))
        {
            return format!("matched_value[{}, {}]", compile_arg_str(value_arg), cozo_str(name));
        }
    }
    let prefix = if STORED_RELATIONS.contains(&atom.predicate.as_str()) { "*" } else { "" };
    let args: Vec<String> = atom.args.iter().map(compile_arg_str).collect();
    format!("{prefix}{}[{}]", atom.predicate, args.join(", "))
}

fn compile_arg_str(arg: &Arg) -> String {
    match arg {
        Arg::Variable(name)      => name.clone(),
        Arg::Wildcard            => "_".to_string(),
        Arg::NamedWildcard(name) => format!("_{name}"),
        Arg::StringLit(s)        => cozo_str(s),
        Arg::Integer(n)          => n.to_string(),
        Arg::PatternRef(name)    => cozo_str(name),
    }
}

fn compile_param_str(param: &Param) -> String {
    match param {
        Param::Named(name)       => name.clone(),
        Param::Wildcard          => "_".to_string(),
        Param::NamedWildcard(n)  => format!("_{n}"),
    }
}

// ── Effects serialization ─────────────────────────────────────────────────────

fn compile_effects_json(effects: &[EffectDecl]) -> String {
    if effects.is_empty() {
        return "[]".to_string();
    }
    let items: Vec<serde_json::Value> = effects.iter().map(effect_to_json).collect();
    serde_json::to_string(&items).expect("effects serialization cannot fail")
}

fn effect_to_json(e: &EffectDecl) -> serde_json::Value {
    match e {
        EffectDecl::Redact { selector, classifier } => serde_json::json!({
            "type": "Redact", "selector": selector, "classifier": classifier
        }),
        EffectDecl::Mask { selector, pattern, replacement } => serde_json::json!({
            "type": "Mask", "selector": selector, "pattern": pattern, "replacement": replacement
        }),
        EffectDecl::Annotate { key, value } => serde_json::json!({
            "type": "Annotate", "key": key, "value": value
        }),
        EffectDecl::Audit { level } => serde_json::json!({
            "type": "Audit",
            "level": match level {
                AuditLevelDecl::Standard  => "Standard",
                AuditLevelDecl::Elevated  => "Elevated",
                AuditLevelDecl::Critical  => "Critical",
            }
        }),
    }
}

fn cozo_str(s: &str) -> String {
    if s.contains('"') {
        // CozoDB supports single-quoted strings; use them when the value contains double quotes.
        let escaped = s.replace('\'', "''");
        format!("'{escaped}'")
    } else {
        format!("\"{s}\"")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_minimal_policy() {
        let src = r#"policy "default-deny" priority 100 { deny when true reason "no rule matched"; }"#;
        let policy = compile(src, "v1").expect("compile succeeded");
        assert_eq!(policy.version, "v1");
        assert!(
            policy.decision_script.contains("b_default_deny"),
            "decision_script missing block name: {}", policy.decision_script
        );
    }

    #[test]
    fn compile_pattern_creates_regex() {
        let src = r#"pattern :sql_injection = r"(?i)(drop|delete)\s+table";"#;
        let policy = compile(src, "v1").expect("compile succeeded");
        assert!(policy.patterns.contains_key("sql_injection"));
        assert!(policy.patterns["sql_injection"].is_match("DROP TABLE users"));
        assert!(!policy.patterns["sql_injection"].is_match("SELECT * FROM users"));
    }

    #[test]
    fn compile_grant_stored_in_cozo() {
        let src = r#"grant role "analyst" can call tool:category("read-only");"#;
        let policy = compile(src, "v1").expect("compile succeeded");
        let result = policy.db
            .run_script("?[role, action, rp] := *role_permission[role, action, rp]", Default::default(), ScriptMutability::Immutable)
            .expect("query succeeded");
        assert_eq!(result.rows.len(), 1);
    }

    #[test]
    fn compile_categorize_stored_in_cozo() {
        let src = r#"categorize tool "db_query" as "read-only";"#;
        let policy = compile(src, "v1").expect("compile succeeded");
        let result = policy.db
            .run_script("?[tn, cat] := *tool_category[tn, cat]", Default::default(), ScriptMutability::Immutable)
            .expect("query succeeded");
        assert_eq!(result.rows.len(), 1);
    }

    #[test]
    fn compile_classify_stored_in_cozo() {
        let src = r#"classify resource "data/finance/*" as sensitivity "high";"#;
        let policy = compile(src, "v1").expect("compile succeeded");
        let result = policy.db
            .run_script("?[up, lvl] := *resource_sensitivity[up, lvl]", Default::default(), ScriptMutability::Immutable)
            .expect("query succeeded");
        assert_eq!(result.rows.len(), 1);
    }

    #[test]
    fn compile_decision_script_no_syntax_error() {
        use std::collections::BTreeMap;
        let src = r#"
            grant role "analyst" can call tool:category("read-only");
            categorize tool "db_query" as "read-only";
            rule can_call(agent, tool) :-
                agent_role(agent, role),
                tool_category(tool, cat),
                role_permission(role, "call", cat);
            policy "default-authz" priority 100 {
                allow when
                    tool_call(call_id, agent_id, tool_name),
                    can_call(agent_id, tool_name);
                deny when true
                    reason "no matching allow rule";
            }
        "#;
        let policy = compile(src, "v1").expect("compile succeeded");
        let mut params: BTreeMap<String, cozo::DataValue> = BTreeMap::new();
        for key in &[
            "tool_calls", "agents", "agent_roles", "agent_clearances", "delegations", "users",
            "call_args", "tool_results", "resource_accesses", "resource_mimes",
            "content_tags", "timestamps", "call_counts", "environment", "matched_values",
        ] {
            params.insert(key.to_string(), cozo::DataValue::List(vec![]));
        }
        let result = policy.db.run_script(&policy.decision_script, params, ScriptMutability::Immutable)
            .unwrap_or_else(|e| panic!(
                "decision_script failed:\n{}\n\nError: {}", policy.decision_script, e
            ));
        assert_eq!(result.rows.len(), 0, "expected empty result with no request facts");
    }

    #[test]
    fn compile_pattern_also_stored_in_cozo() {
        let src = r#"pattern :sql_injection = r"(?i)(drop|delete)\s+table";"#;
        let policy = compile(src, "v1").expect("compile succeeded");
        let result = policy.db
            .run_script("?[name, source] := *forbidden_pattern[name, source]", Default::default(), ScriptMutability::Immutable)
            .expect("query succeeded");
        assert_eq!(result.rows.len(), 1);
    }

    #[test]
    fn compile_matches_rewrites_to_matched_value() {
        let src = r#"
            pattern :sql_injection = r"(?i)(drop|delete)\s+table";
            rule has_forbidden_arg(call_id) :-
                call_arg(call_id, _, value),
                matches(value, :sql_injection);
        "#;
        let policy = compile(src, "v1").expect("compile succeeded");
        assert!(
            policy.decision_script.contains("matched_value"),
            "matches() should be rewritten to matched_value"
        );
        assert!(
            !policy.decision_script.contains("matches("),
            "raw matches() should not appear in decision_script"
        );
    }
}

