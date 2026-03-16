// tests/fail_closed_tests.rs
//
// Verifies the fail-closed invariant: every error path in Engine::evaluate
// must return Verdict::Deny with at least one Effect::Audit { level: Critical }.

use datalog_noodle::{AuditLevel, Decision, Effect, Engine, FactPackage, Verdict};
use datalog_noodle::policy::watcher::{PolicySet, PolicyWatcher};
use datalog_noodle::facts::*;
use datalog_noodle::types::*;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn assert_fail_closed(d: &Decision) {
    assert_eq!(
        d.verdict,
        Verdict::Deny,
        "fail-closed invariant violated: expected Deny, got Allow. Decision: {:?}",
        d
    );
    assert!(
        d.effects.iter().any(|e| matches!(e,
            Effect::Audit { level: AuditLevel::Critical, .. }
        )),
        "fail-closed invariant violated: expected Audit(Critical) effect, got: {:?}",
        d.effects
    );
}

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

// ── Error path: uninitialized store ──────────────────────────────────────────

#[test]
fn uninitialized_store_returns_deny_audit_critical() {
    let engine = Engine::new(); // no policy pushed
    let d = engine.evaluate(&one_call());
    assert_fail_closed(&d);
    assert!(
        d.reason.as_deref().unwrap_or("").contains("error"),
        "reason should mention evaluation error, got: {:?}", d.reason
    );
}

// ── Error path: uninitialized store with empty facts ─────────────────────────

#[test]
fn uninitialized_store_empty_facts_returns_deny_audit_critical() {
    let engine = Engine::new();
    let d = engine.evaluate(&FactPackage::default());
    assert_fail_closed(&d);
    // With no tool calls, audit record should use "unknown"
    assert_eq!(d.audit.call_id, CallId("unknown".to_string()));
    assert_eq!(d.audit.agent_id, AgentId("unknown".to_string()));
}

// ── Error path: policy with no rules matching (missing default deny) ─────────

#[test]
fn no_matching_rules_returns_deny_audit_critical() {
    // A policy that only has a conditional allow — no deny-when-true fallback.
    // When the condition doesn't match, CozoDB returns 0 rows → error path.
    let engine = Engine::new();
    engine
        .push(PolicySet {
            version: "v1".to_string(),
            source: r#"
                policy "no-fallback" priority 100 {
                    allow when
                        tool_call(call_id, agent_id, _),
                        agent_role(agent_id, "admin");
                }
            "#.to_string(),
            checksum: String::new(),
        })
        .unwrap();

    // Agent without admin role → allow doesn't fire → 0 rows → fail-closed
    let d = engine.evaluate(&one_call());
    assert_fail_closed(&d);
}

// ── Error path: audit record from_error preserves call context ───────────────

#[test]
fn fail_closed_audit_record_preserves_call_context() {
    let engine = Engine::new(); // uninitialized → error path
    let mut pkg = one_call();
    pkg.timestamps.push(TimestampFact {
        call_id: CallId("call-1".to_string()),
        unix_ts: 1_700_000_000,
    });
    let d = engine.evaluate(&pkg);
    assert_fail_closed(&d);
    assert_eq!(d.audit.call_id, CallId("call-1".to_string()));
    assert_eq!(d.audit.agent_id, AgentId("agt-1".to_string()));
    assert_eq!(d.audit.tool_name.as_deref(), Some("test_tool"));
    assert_eq!(d.audit.timestamp, Some(1_700_000_000));
    assert_eq!(d.audit.policy_version, "unknown");
}

// ── Error path: audit record with no tool calls ──────────────────────────────

#[test]
fn fail_closed_no_tool_calls_uses_unknown() {
    let engine = Engine::new();
    let d = engine.evaluate(&FactPackage::default());
    assert_fail_closed(&d);
    assert_eq!(d.audit.call_id.0, "unknown");
    assert_eq!(d.audit.agent_id.0, "unknown");
    assert!(d.audit.tool_name.is_none());
    assert!(d.audit.timestamp.is_none());
}

// ── Error path: critical effect message contains error description ───────────

#[test]
fn fail_closed_effect_message_describes_error() {
    let engine = Engine::new();
    let d = engine.evaluate(&one_call());
    assert_fail_closed(&d);
    let audit_message = d.effects.iter().find_map(|e| match e {
        Effect::Audit { level: AuditLevel::Critical, message } => message.as_ref(),
        _ => None,
    });
    assert!(
        audit_message.is_some(),
        "Audit(Critical) effect should have a message"
    );
    let msg = audit_message.unwrap();
    assert!(
        msg.contains("uninitialized"),
        "error message should describe the error, got: {}", msg
    );
}

// ── Error path: deny verdict is consistent between audit and decision ────────

#[test]
fn fail_closed_verdict_consistent_in_audit_and_decision() {
    let engine = Engine::new();
    let d = engine.evaluate(&one_call());
    assert_fail_closed(&d);
    assert_eq!(
        d.verdict, d.audit.verdict,
        "decision verdict and audit verdict must match"
    );
}

// ── Normal deny (non-error) should NOT have Audit(Critical) by default ───────

#[test]
fn normal_deny_does_not_produce_audit_critical_unless_specified() {
    let engine = Engine::new();
    engine
        .push(PolicySet {
            version: "v1".to_string(),
            source: r#"
                policy "d" priority 100 {
                    deny when true reason "normal deny";
                }
            "#.to_string(),
            checksum: String::new(),
        })
        .unwrap();
    let d = engine.evaluate(&one_call());
    assert_eq!(d.verdict, Verdict::Deny);
    // This is a normal deny, not an error path — should NOT have Audit(Critical)
    // unless the policy explicitly added it.
    let has_critical = d.effects.iter().any(|e| matches!(e,
        Effect::Audit { level: AuditLevel::Critical, .. }
    ));
    assert!(
        !has_critical,
        "normal deny should not produce Audit(Critical) unless policy says so, effects: {:?}",
        d.effects
    );
}

// ── Push error: invalid DSL does not corrupt engine ──────────────────────────

#[test]
fn push_invalid_dsl_then_evaluate_still_works() {
    let engine = Engine::new();
    engine
        .push(PolicySet {
            version: "v1".to_string(),
            source: r#"
                policy "d" priority 100 {
                    allow when tool_call(call_id, agent_id, _), agent_role(agent_id, "tester");
                    deny when true reason "denied";
                }
            "#.to_string(),
            checksum: String::new(),
        })
        .unwrap();

    // Push broken DSL — should error
    let result = engine.push(PolicySet {
        version: "v2".to_string(),
        source: "this is broken !!!".to_string(),
        checksum: String::new(),
    });
    assert!(result.is_err());

    // Engine should still work with v1
    let d = engine.evaluate(&one_call());
    assert_eq!(d.verdict, Verdict::Deny);
    assert_eq!(d.audit.policy_version, "v1");
    assert_eq!(d.reason.as_deref(), Some("denied"));
}
