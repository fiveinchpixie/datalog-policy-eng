// tests/scenario_tests.rs
//
// End-to-end evaluator correctness tests. Each test constructs a policy DSL
// source, pushes it into an Engine via PolicyWatcher::push, builds a
// FactPackage, calls Engine::evaluate, and asserts on the resulting Decision.

use datalog_noodle::{
    AuditLevel, Decision, Effect, Engine, FactPackage, Verdict,
};
use datalog_noodle::policy::watcher::{PolicySet, PolicyWatcher};
use datalog_noodle::facts::*;
use datalog_noodle::types::*;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn engine_with(version: &str, source: &str) -> Engine {
    let engine = Engine::new();
    engine
        .push(PolicySet {
            version: version.to_string(),
            source: source.to_string(),
            checksum: String::new(),
        })
        .expect("test policy must compile");
    engine
}

fn one_call(agent: &str, tool: &str) -> FactPackage {
    FactPackage {
        tool_calls: vec![ToolCallFact {
            call_id: CallId("call-1".to_string()),
            agent_id: AgentId(agent.to_string()),
            tool_name: ToolName(tool.to_string()),
        }],
        ..Default::default()
    }
}

fn one_call_with_role(agent: &str, tool: &str, role: &str) -> FactPackage {
    let mut pkg = one_call(agent, tool);
    pkg.agent_roles.push(AgentRoleFact {
        agent_id: AgentId(agent.to_string()),
        role: Role(role.to_string()),
    });
    pkg
}

fn assert_deny(d: &Decision) {
    assert_eq!(d.verdict, Verdict::Deny, "expected Deny, got {:?}", d);
}

fn assert_allow(d: &Decision) {
    assert_eq!(d.verdict, Verdict::Allow, "expected Allow, got {:?}", d);
}

// ── Scenario: deny-when-true default deny ────────────────────────────────────

#[test]
fn deny_when_true_is_catch_all() {
    let engine = engine_with("v1", r#"
        policy "default" priority 100 {
            deny when true reason "no matching allow rule";
        }
    "#);
    let d = engine.evaluate(&one_call("agt-1", "any_tool"));
    assert_deny(&d);
    assert_eq!(d.reason.as_deref(), Some("no matching allow rule"));
    assert_eq!(d.audit.policy_version, "v1");
    assert_eq!(d.audit.matched_rules, vec!["default"]);
}

// ── Scenario: role-based allow ───────────────────────────────────────────────

#[test]
fn allow_when_role_matches() {
    let engine = engine_with("v1", r#"
        policy "authz" priority 100 {
            allow when
                tool_call(call_id, agent_id, _),
                agent_role(agent_id, "analyst");
            deny when true reason "no matching allow rule";
        }
    "#);
    let d = engine.evaluate(&one_call_with_role("agt-1", "db_query", "analyst"));
    assert_allow(&d);
    assert_eq!(d.audit.matched_rules, vec!["authz"]);
}

#[test]
fn deny_when_role_does_not_match() {
    let engine = engine_with("v1", r#"
        policy "authz" priority 100 {
            allow when
                tool_call(call_id, agent_id, _),
                agent_role(agent_id, "analyst");
            deny when true reason "no matching allow rule";
        }
    "#);
    let d = engine.evaluate(&one_call_with_role("agt-1", "db_query", "intern"));
    assert_deny(&d);
    assert_eq!(d.reason.as_deref(), Some("no matching allow rule"));
}

#[test]
fn deny_when_no_role_at_all() {
    let engine = engine_with("v1", r#"
        policy "authz" priority 100 {
            allow when
                tool_call(call_id, agent_id, _),
                agent_role(agent_id, "analyst");
            deny when true reason "no matching allow rule";
        }
    "#);
    let d = engine.evaluate(&one_call("agt-1", "db_query"));
    assert_deny(&d);
}

// ── Scenario: grant + categorize + derived rule ──────────────────────────────

const RBAC_POLICY: &str = r#"
    grant role "analyst" can call tool:category("read-only");
    categorize tool "db_query" as "read-only";
    categorize tool "db_write" as "write";

    rule can_call(agent, tool) :-
        agent_role(agent, role),
        tool_category(tool, cat),
        role_permission(role, "call", cat);

    policy "default-authz" priority 100 {
        allow when
            tool_call(call_id, agent_id, tool_name),
            can_call(agent_id, tool_name);
        deny when true reason "no matching allow rule";
    }
"#;

#[test]
fn rbac_allow_analyst_read_only_tool() {
    let engine = engine_with("v1", RBAC_POLICY);
    let d = engine.evaluate(&one_call_with_role("agt-1", "db_query", "analyst"));
    assert_allow(&d);
}

#[test]
fn rbac_deny_analyst_write_tool() {
    let engine = engine_with("v1", RBAC_POLICY);
    let d = engine.evaluate(&one_call_with_role("agt-1", "db_write", "analyst"));
    assert_deny(&d);
}

#[test]
fn rbac_deny_unknown_role() {
    let engine = engine_with("v1", RBAC_POLICY);
    let d = engine.evaluate(&one_call_with_role("agt-1", "db_query", "intern"));
    assert_deny(&d);
}

// ── Scenario: deny with effects ──────────────────────────────────────────────

#[test]
fn deny_with_audit_effect() {
    let engine = engine_with("v1", r#"
        policy "audit-all" priority 100 {
            deny when true
                reason "blocked"
                effect Audit(level: Elevated);
        }
    "#);
    let d = engine.evaluate(&one_call("agt-1", "db_query"));
    assert_deny(&d);
    assert!(
        d.effects.iter().any(|e| matches!(e, Effect::Audit { level: AuditLevel::Elevated, .. })),
        "expected Audit(Elevated) effect, got: {:?}", d.effects
    );
}

#[test]
fn allow_with_redact_effect() {
    let engine = engine_with("v1", r#"
        policy "pii" priority 100 {
            allow when
                tool_call(call_id, agent_id, _),
                agent_role(agent_id, "analyst")
                effect Redact(selector: "response.content", classifier: "pii");
        }
    "#);
    let d = engine.evaluate(&one_call_with_role("agt-1", "db_query", "analyst"));
    assert_allow(&d);
    assert!(
        d.effects.iter().any(|e| matches!(e,
            Effect::Redact { selector, classifier }
            if selector == "response.content" && classifier == "pii"
        )),
        "expected Redact effect, got: {:?}", d.effects
    );
}

#[test]
fn allow_with_annotate_effect() {
    let engine = engine_with("v1", r#"
        policy "tag" priority 100 {
            allow when
                tool_call(call_id, agent_id, _),
                agent_role(agent_id, "analyst")
                effect Annotate(key: "reviewed_by", value: "policy-engine");
        }
    "#);
    let d = engine.evaluate(&one_call_with_role("agt-1", "db_query", "analyst"));
    assert_allow(&d);
    assert!(
        d.effects.iter().any(|e| matches!(e,
            Effect::Annotate { key, value }
            if key == "reviewed_by" && value == "policy-engine"
        )),
        "expected Annotate effect, got: {:?}", d.effects
    );
}

// ── Scenario: not condition in policy block ──────────────────────────────────

#[test]
fn deny_with_not_condition() {
    let engine = engine_with("v1", r#"
        policy "authz" priority 100 {
            deny when
                tool_call(call_id, agent_id, _),
                not agent_role(agent_id, "admin")
                reason "only admins allowed";
        }
    "#);
    // No admin role → deny fires
    let d = engine.evaluate(&one_call_with_role("agt-1", "db_query", "analyst"));
    assert_deny(&d);
    assert_eq!(d.reason.as_deref(), Some("only admins allowed"));

    // Admin role → deny does NOT fire → no rows → fail-closed deny
    let d2 = engine.evaluate(&one_call_with_role("agt-1", "db_query", "admin"));
    assert_deny(&d2); // no allow rule, so still deny via fail-closed
}

// ── Scenario: pattern matching via matches() ─────────────────────────────────

#[test]
fn pattern_match_triggers_deny() {
    let engine = engine_with("v1", r#"
        pattern :sql_injection = r"(?i)(drop|delete)\s+table";

        rule has_forbidden_arg(call_id) :-
            call_arg(call_id, _, value),
            matches(value, :sql_injection);

        policy "input-scan" priority 200 {
            deny when
                tool_call(call_id, _, _),
                has_forbidden_arg(call_id)
                reason "SQL injection detected";
        }

        policy "default" priority 100 {
            allow when
                tool_call(call_id, agent_id, _),
                agent_role(agent_id, "analyst");
            deny when true reason "no matching allow rule";
        }
    "#);

    // Clean input → allow (analyst role)
    let mut clean = one_call_with_role("agt-1", "db_query", "analyst");
    clean.call_args.push(CallArgFact {
        call_id: CallId("call-1".to_string()),
        key: "query".to_string(),
        value: "SELECT * FROM users".to_string(),
    });
    let d = engine.evaluate(&clean);
    assert_allow(&d);

    // Malicious input → deny from higher-priority input-scan policy
    let mut malicious = one_call_with_role("agt-1", "db_query", "analyst");
    malicious.call_args.push(CallArgFact {
        call_id: CallId("call-1".to_string()),
        key: "query".to_string(),
        value: "DROP TABLE users".to_string(),
    });
    let d = engine.evaluate(&malicious);
    assert_deny(&d);
    assert_eq!(d.reason.as_deref(), Some("SQL injection detected"));
    assert_eq!(d.audit.matched_rules, vec!["input-scan"]);
}

// ── Scenario: content_tag based policy ───────────────────────────────────────

#[test]
fn content_tag_triggers_deny() {
    let engine = engine_with("v1", r#"
        policy "pii-guard" priority 200 {
            deny when
                tool_call(call_id, agent_id, _),
                content_tag(call_id, "pii", "high"),
                not agent_role(agent_id, "pii-handler")
                reason "PII content requires pii-handler role"
                effect Audit(level: Critical);
        }
        policy "default" priority 100 {
            allow when
                tool_call(call_id, agent_id, _),
                agent_role(agent_id, "analyst");
            deny when true reason "default deny";
        }
    "#);

    // Analyst with PII content but no pii-handler role → deny
    let mut pkg = one_call_with_role("agt-1", "db_query", "analyst");
    pkg.content_tags.push(ContentTagFact {
        call_id: CallId("call-1".to_string()),
        tag: "pii".to_string(),
        value: "high".to_string(),
    });
    let d = engine.evaluate(&pkg);
    assert_deny(&d);
    assert_eq!(d.reason.as_deref(), Some("PII content requires pii-handler role"));
    assert!(
        d.effects.iter().any(|e| matches!(e, Effect::Audit { level: AuditLevel::Critical, .. })),
        "expected Audit(Critical) effect"
    );

    // Agent with pii-handler role → higher-priority deny doesn't fire → falls through
    let mut pkg2 = one_call_with_role("agt-2", "db_query", "pii-handler");
    pkg2.agent_roles.push(AgentRoleFact {
        agent_id: AgentId("agt-2".to_string()),
        role: Role("analyst".to_string()),
    });
    pkg2.content_tags.push(ContentTagFact {
        call_id: CallId("call-1".to_string()),
        tag: "pii".to_string(),
        value: "high".to_string(),
    });
    let d2 = engine.evaluate(&pkg2);
    assert_allow(&d2);
}

// ── Scenario: policy version update via push ─────────────────────────────────

#[test]
fn policy_update_changes_behavior() {
    let engine = Engine::new();

    // v1: deny all
    engine
        .push(PolicySet {
            version: "v1".to_string(),
            source: r#"policy "d" priority 100 { deny when true reason "v1 deny"; }"#.to_string(),
            checksum: String::new(),
        })
        .unwrap();
    let d = engine.evaluate(&one_call("agt-1", "tool"));
    assert_deny(&d);
    assert_eq!(d.audit.policy_version, "v1");

    // v2: allow analysts
    engine
        .push(PolicySet {
            version: "v2".to_string(),
            source: r#"
                policy "d" priority 100 {
                    allow when tool_call(call_id, agent_id, _), agent_role(agent_id, "analyst");
                    deny when true reason "v2 deny";
                }
            "#.to_string(),
            checksum: String::new(),
        })
        .unwrap();
    let d = engine.evaluate(&one_call_with_role("agt-1", "tool", "analyst"));
    assert_allow(&d);
    assert_eq!(d.audit.policy_version, "v2");
}

// ── Scenario: audit record fields ────────────────────────────────────────────

#[test]
fn audit_record_populated_correctly() {
    let engine = engine_with("v42", r#"
        policy "authz" priority 100 {
            deny when true reason "denied";
        }
    "#);
    let mut pkg = one_call("agt-7", "db_query");
    pkg.timestamps.push(TimestampFact {
        call_id: CallId("call-1".to_string()),
        unix_ts: 1_700_000_000,
    });
    let d = engine.evaluate(&pkg);
    assert_eq!(d.audit.call_id, CallId("call-1".to_string()));
    assert_eq!(d.audit.agent_id, AgentId("agt-7".to_string()));
    assert_eq!(d.audit.tool_name.as_deref(), Some("db_query"));
    assert_eq!(d.audit.policy_version, "v42");
    assert_eq!(d.audit.timestamp, Some(1_700_000_000));
    assert_eq!(d.audit.matched_rules, vec!["authz"]);
}

// ── Scenario: multiple policies with different priorities ────────────────────

#[test]
fn higher_priority_policy_takes_precedence() {
    let engine = engine_with("v1", r#"
        policy "high" priority 200 {
            deny when
                tool_call(call_id, _, _),
                content_tag(call_id, "malware", "true")
                reason "malware detected";
        }
        policy "low" priority 100 {
            allow when
                tool_call(call_id, agent_id, _),
                agent_role(agent_id, "analyst");
            deny when true reason "no matching allow rule";
        }
    "#);

    // Analyst without malware tag → high-priority policy doesn't match → low-priority allows
    let d = engine.evaluate(&one_call_with_role("agt-1", "tool", "analyst"));
    assert_allow(&d);

    // Analyst with malware tag → high-priority deny fires
    let mut pkg = one_call_with_role("agt-1", "tool", "analyst");
    pkg.content_tags.push(ContentTagFact {
        call_id: CallId("call-1".to_string()),
        tag: "malware".to_string(),
        value: "true".to_string(),
    });
    let d = engine.evaluate(&pkg);
    assert_deny(&d);
    assert_eq!(d.reason.as_deref(), Some("malware detected"));
    assert_eq!(d.audit.matched_rules, vec!["high"]);
}

// ── Scenario: grant role "admin" can call tool:any ───────────────────────────

#[test]
fn grant_call_any_allows_all_tools() {
    let engine = engine_with("v1", r#"
        grant role "admin" can call tool:any;

        rule can_call(agent, tool) :-
            agent_role(agent, role),
            role_permission(role, "call", "*"),
            tool_call(_, agent, tool);

        policy "authz" priority 100 {
            allow when
                tool_call(call_id, agent_id, tool_name),
                can_call(agent_id, tool_name);
            deny when true reason "no matching allow rule";
        }
    "#);
    let d = engine.evaluate(&one_call_with_role("agt-1", "anything_at_all", "admin"));
    assert_allow(&d);

    let d = engine.evaluate(&one_call_with_role("agt-1", "anything_at_all", "analyst"));
    assert_deny(&d);
}

// ── Scenario: multiple effects on a single rule ──────────────────────────────

#[test]
fn multiple_effects_on_allow() {
    let engine = engine_with("v1", r#"
        policy "multi" priority 100 {
            allow when
                tool_call(call_id, agent_id, _),
                agent_role(agent_id, "analyst")
                effect Redact(selector: "response.body", classifier: "pii")
                effect Annotate(key: "policy", value: "multi")
                effect Audit(level: Standard);
        }
    "#);
    let d = engine.evaluate(&one_call_with_role("agt-1", "tool", "analyst"));
    assert_allow(&d);
    assert_eq!(d.effects.len(), 3);
    assert!(d.effects.iter().any(|e| matches!(e, Effect::Redact { .. })));
    assert!(d.effects.iter().any(|e| matches!(e, Effect::Annotate { .. })));
    assert!(d.effects.iter().any(|e| matches!(e, Effect::Audit { level: AuditLevel::Standard, .. })));
}

// ── Scenario: mask effect ────────────────────────────────────────────────────

#[test]
fn mask_effect_is_returned() {
    let engine = engine_with("v1", r#"
        policy "mask" priority 100 {
            allow when
                tool_call(call_id, agent_id, _),
                agent_role(agent_id, "analyst")
                effect Mask(selector: "response.ssn", pattern: "\\d{3}-\\d{2}-\\d{4}", replacement: "***-**-****");
        }
    "#);
    let d = engine.evaluate(&one_call_with_role("agt-1", "tool", "analyst"));
    assert_allow(&d);
    assert!(
        d.effects.iter().any(|e| matches!(e,
            Effect::Mask { selector, pattern, replacement }
            if selector == "response.ssn"
                && pattern == r"\d{3}-\d{2}-\d{4}"
                && replacement == "***-**-****"
        )),
        "expected Mask effect, got: {:?}", d.effects
    );
}

// ── Scenario: push same version is no-op ─────────────────────────────────────

#[test]
fn push_same_version_skips_recompilation() {
    let engine = engine_with("v1", r#"
        policy "d" priority 100 { deny when true reason "original"; }
    "#);

    // Pushing invalid DSL with same version v1 should succeed (no-op)
    let result = engine.push(PolicySet {
        version: "v1".to_string(),
        source: "this is not valid!!!".to_string(),
        checksum: String::new(),
    });
    assert!(result.is_ok());
    assert_eq!(engine.current_version(), Some("v1".to_string()));
}

// ── Scenario: push invalid policy leaves old policy in place ─────────────────

#[test]
fn push_invalid_policy_does_not_replace_working_policy() {
    let engine = engine_with("v1", r#"
        policy "d" priority 100 {
            allow when tool_call(call_id, agent_id, _), agent_role(agent_id, "analyst");
            deny when true reason "v1 deny";
        }
    "#);

    let result = engine.push(PolicySet {
        version: "v2".to_string(),
        source: "completely broken !!!".to_string(),
        checksum: String::new(),
    });
    assert!(result.is_err());

    // Old policy still works
    let d = engine.evaluate(&one_call_with_role("agt-1", "tool", "analyst"));
    assert_allow(&d);
    assert_eq!(d.audit.policy_version, "v1");
}
