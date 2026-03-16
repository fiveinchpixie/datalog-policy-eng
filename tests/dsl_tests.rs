// tests/dsl_tests.rs
// ── Helpers ───────────────────────────────────────────────────────────────────

fn parse_ok(src: &str) -> datalog_noodle::dsl::PolicyFile {
    datalog_noodle::dsl_parse(src).expect("expected parse to succeed")
}

fn parse_err(src: &str) -> datalog_noodle::PolicyError {
    datalog_noodle::dsl_parse(src).expect_err("expected parse to fail")
}

// ── Grant declarations ────────────────────────────────────────────────────────

#[test]
fn parse_grant_call_any() {
    let src = r#"grant role "admin" can call tool:any;"#;
    let file = parse_ok(src);
    use datalog_noodle::dsl::ast::{Declaration, GrantDecl, GrantPermission};
    assert_eq!(file.declarations.len(), 1);
    assert!(matches!(
        &file.declarations[0],
        Declaration::Grant(GrantDecl { permission: GrantPermission::CallAny, .. })
    ));
}

#[test]
fn parse_grant_call_category() {
    let src = r#"grant role "analyst" can call tool:category("read-only");"#;
    let file = parse_ok(src);
    use datalog_noodle::dsl::ast::{Declaration, GrantDecl, GrantPermission};
    assert!(matches!(
        &file.declarations[0],
        Declaration::Grant(GrantDecl {
            permission: GrantPermission::CallCategory(cat),
            ..
        }) if cat == "read-only"
    ));
}

#[test]
fn parse_pattern_decl() {
    let src = r#"pattern :sql_injection = r"(?i)(drop|delete)\s+table";"#;
    let file = parse_ok(src);
    use datalog_noodle::dsl::ast::{Declaration, PatternDecl};
    assert!(matches!(
        &file.declarations[0],
        Declaration::Pattern(PatternDecl { name, .. }) if name == "sql_injection"
    ));
}

#[test]
fn parse_rule_decl() {
    let src = r#"
        rule can_call(agent, tool) :-
            agent_role(agent, role),
            tool_category(tool, cat),
            role_permission(role, "call", cat);
    "#;
    let file = parse_ok(src);
    use datalog_noodle::dsl::ast::Declaration;
    assert!(matches!(&file.declarations[0], Declaration::Rule(_)));
    if let Declaration::Rule(r) = &file.declarations[0] {
        assert_eq!(r.name, "can_call");
        assert_eq!(r.params.len(), 2);
        assert_eq!(r.conditions.len(), 3);
    }
}

#[test]
fn parse_policy_block_allow_and_deny() {
    let src = r#"
        policy "default-authz" priority 100 {
            allow when
                tool_call(call_id, agent_id, tool_name),
                can_call(agent_id, tool_name);

            deny when true
                reason "no matching allow rule";
        }
    "#;
    let file = parse_ok(src);
    use datalog_noodle::dsl::ast::{Declaration, PolicyRule};
    assert_eq!(file.declarations.len(), 1);
    if let Declaration::Policy(p) = &file.declarations[0] {
        assert_eq!(p.name, "default-authz");
        assert_eq!(p.priority, 100);
        assert_eq!(p.rules.len(), 2);
        assert!(matches!(p.rules[0], PolicyRule::Allow(_)));
        assert!(matches!(p.rules[1], PolicyRule::Deny(_)));
    } else {
        panic!("expected Policy declaration");
    }
}

#[test]
fn parse_policy_block_with_effects() {
    let src = r#"
        policy "pii-handling" priority 150 {
            allow when
                tool_call(call_id, agent_id, _tool),
                content_tag(call_id, "pii", "high"),
                can_call(agent_id, _tool)
                effect Redact(selector: "response.content", classifier: "pii")
                effect Audit(level: Elevated);
        }
    "#;
    let file = parse_ok(src);
    use datalog_noodle::dsl::ast::{Declaration, PolicyRule, EffectDecl, AuditLevelDecl};
    if let Declaration::Policy(p) = &file.declarations[0] {
        if let PolicyRule::Allow(allow) = &p.rules[0] {
            assert_eq!(allow.effects.len(), 2);
            assert!(matches!(allow.effects[0], EffectDecl::Redact { .. }));
            assert!(matches!(
                allow.effects[1],
                EffectDecl::Audit { level: AuditLevelDecl::Elevated }
            ));
        } else { panic!("expected Allow rule"); }
    } else { panic!("expected Policy declaration"); }
}

#[test]
fn parse_or_condition_in_rule() {
    let src = r#"
        rule has_forbidden_arg(call_id) :-
            call_arg(call_id, _, value),
            matches(value, :sql_injection) or matches(value, :path_traversal);
    "#;
    let file = parse_ok(src);
    use datalog_noodle::dsl::ast::{Declaration, ConditionClause};
    if let Declaration::Rule(r) = &file.declarations[0] {
        assert!(r.conditions.iter().any(|c| matches!(c, ConditionClause::Or(_))));
    }
}

#[test]
fn parse_not_condition_in_policy() {
    let src = r#"
        policy "pii-handling" priority 150 {
            deny when
                tool_call(call_id, agent_id, _tool),
                content_tag(call_id, "pii", "high"),
                not can_call(agent_id, _tool)
                reason "agent not permitted and PII present"
                effect Audit(level: Critical);
        }
    "#;
    let file = parse_ok(src);
    use datalog_noodle::dsl::ast::{Declaration, PolicyRule, ConditionClause};
    if let Declaration::Policy(p) = &file.declarations[0] {
        if let PolicyRule::Deny(deny) = &p.rules[0] {
            assert!(deny.conditions.iter().any(|c| matches!(c, ConditionClause::Not(_))));
            assert_eq!(deny.reason.as_deref(), Some("agent not permitted and PII present"));
        } else { panic!("expected Deny rule"); }
    } else { panic!("expected Policy declaration"); }
}

#[test]
fn parse_categorize_decl() {
    let src = r#"
        categorize tool "db_query" as "read-only";
        categorize tool "db_write" as "write";
    "#;
    let file = parse_ok(src);
    use datalog_noodle::dsl::ast::{Declaration, CategorizeDecl};
    assert_eq!(file.declarations.len(), 2);
    assert!(matches!(
        &file.declarations[0],
        Declaration::Categorize(CategorizeDecl { tool, category })
        if tool == "db_query" && category == "read-only"
    ));
}

#[test]
fn parse_classify_decl() {
    let src = r#"
        classify resource "data/finance/*" as sensitivity "high";
        classify resource "data/public/*"  as sensitivity "low";
    "#;
    let file = parse_ok(src);
    use datalog_noodle::dsl::ast::{Declaration, ClassifyDecl};
    assert_eq!(file.declarations.len(), 2);
    assert!(matches!(
        &file.declarations[0],
        Declaration::Classify(ClassifyDecl { resource_pattern, sensitivity })
        if resource_pattern == "data/finance/*" && sensitivity == "high"
    ));
}

#[test]
fn parse_error_missing_semicolon() {
    let src = r#"grant role "admin" can call tool:any"#;
    let err = parse_err(src);
    assert!(matches!(err, datalog_noodle::PolicyError::Parse(_)));
}

#[test]
fn parse_error_unknown_keyword() {
    let src = r#"forbid role "guest" from everything;"#;
    let err = parse_err(src);
    assert!(matches!(err, datalog_noodle::PolicyError::Parse(_)));
}

// ── Compiler validation errors ────────────────────────────────────────────────

#[test]
fn compile_error_undefined_pattern_ref() {
    let src = r#"
        rule bad(call_id) :-
            call_arg(call_id, _, value),
            matches(value, :undefined_pattern);
    "#;
    let err = datalog_noodle::dsl_compile(src, "v1")
        .expect_err("expected compile error");
    assert!(
        matches!(err, datalog_noodle::PolicyError::Compile(_)),
        "expected PolicyError::Compile, got {:?}", err
    );
    let msg = err.to_string();
    assert!(
        msg.contains("undefined_pattern"),
        "error message should name the undefined pattern, got: {}", msg
    );
}

#[test]
fn compile_error_invalid_regex() {
    let src = r#"pattern :bad = r"[unclosed";"#;
    let err = datalog_noodle::dsl_compile(src, "v1")
        .expect_err("expected compile error");
    assert!(matches!(err, datalog_noodle::PolicyError::Compile(_)));
}

#[test]
fn compile_error_allow_when_true() {
    let src = r#"
        policy "bad" priority 100 {
            allow when true;
        }
    "#;
    let err = datalog_noodle::dsl_compile(src, "v1")
        .expect_err("expected compile error for allow when true");
    assert!(matches!(err, datalog_noodle::PolicyError::Compile(_)));
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("allow when true") || msg.contains("not permitted"),
        "error should mention allow-when-true restriction, got: {}", err
    );
}

#[test]
fn compile_error_or_in_policy_block() {
    let src = r#"
        pattern :p1 = r"foo";
        pattern :p2 = r"bar";
        policy "bad" priority 100 {
            deny when
                tool_call(call_id, _, _),
                matches(v, :p1) or matches(v, :p2);
        }
    "#;
    let err = datalog_noodle::dsl_compile(src, "v1")
        .expect_err("expected compile error for Or in policy block");
    assert!(matches!(err, datalog_noodle::PolicyError::Compile(_)));
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("or") || msg.contains("policy block"),
        "error message should mention Or or policy block restriction, got: {}", err
    );
}
