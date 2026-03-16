use crate::decision::*;

const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const RESET: &str = "\x1b[0m";

pub fn format_decision(d: &Decision, use_color: bool) -> String {
    let mut out = String::new();

    let block = d.audit.matched_rules.first()
        .map(|s| s.as_str())
        .unwrap_or("<none>");

    let (icon, verdict_str, color) = match d.verdict {
        Verdict::Allow => ("\u{2713}", "Allow", GREEN),
        Verdict::Deny  => ("\u{2717}", "Deny ", RED),
    };

    if use_color {
        out.push_str(&format!("{color}{icon} {verdict_str}{RESET}  [block: {block}]"));
    } else {
        out.push_str(&format!("{icon} {verdict_str}  [block: {block}]"));
    }

    if let Some(reason) = &d.reason {
        out.push_str(&format!("  reason: \"{reason}\""));
    }
    out.push('\n');

    for (i, effect) in d.effects.iter().enumerate() {
        if i == 0 {
            out.push_str(&format!("  effects: {}\n", format_effect(effect)));
        } else {
            out.push_str(&format!("           {}\n", format_effect(effect)));
        }
    }

    let tool = d.audit.tool_name.as_deref().unwrap_or("<none>");
    out.push_str(&format!(
        "  audit: {} | {} | {} | {}\n",
        d.audit.call_id.0, d.audit.agent_id.0, tool, d.audit.policy_version
    ));

    out
}

fn format_effect(e: &Effect) -> String {
    match e {
        Effect::Redact { selector, classifier } => format!("Redact({selector}, {classifier})"),
        Effect::Mask { selector, pattern, replacement } => format!("Mask({selector}, {pattern}, {replacement})"),
        Effect::Annotate { key, value } => format!("Annotate({key}, {value})"),
        Effect::Audit { level, message } => {
            let lvl = match level {
                AuditLevel::Standard => "Standard",
                AuditLevel::Elevated => "Elevated",
                AuditLevel::Critical => "Critical",
            };
            match message {
                Some(msg) => format!("Audit({lvl}: {msg})"),
                None => format!("Audit({lvl})"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AgentId, CallId};

    fn make_decision(verdict: Verdict, reason: Option<&str>, block: &str, effects: Vec<Effect>) -> Decision {
        Decision {
            verdict,
            effects,
            reason: reason.map(|s| s.to_string()),
            audit: AuditRecord {
                call_id: CallId("call-1".to_string()),
                agent_id: AgentId("agt-1".to_string()),
                tool_name: Some("db_query".to_string()),
                verdict,
                policy_version: "v3".to_string(),
                matched_rules: if block.is_empty() { vec![] } else { vec![block.to_string()] },
                timestamp: None,
            },
        }
    }

    #[test]
    fn allow_no_color() {
        let d = make_decision(Verdict::Allow, None, "authz", vec![]);
        let out = format_decision(&d, false);
        assert!(out.contains("Allow"));
        assert!(out.contains("[block: authz]"));
        assert!(out.contains("call-1 | agt-1 | db_query | v3"));
        assert!(!out.contains("\x1b["));
    }

    #[test]
    fn deny_with_reason_no_color() {
        let d = make_decision(Verdict::Deny, Some("no matching allow rule"), "authz", vec![]);
        let out = format_decision(&d, false);
        assert!(out.contains("Deny"));
        assert!(out.contains("reason: \"no matching allow rule\""));
    }

    #[test]
    fn allow_with_color() {
        let d = make_decision(Verdict::Allow, None, "authz", vec![]);
        let out = format_decision(&d, true);
        assert!(out.contains("\x1b[32m"));
        assert!(out.contains("\x1b[0m"));
    }

    #[test]
    fn deny_with_color() {
        let d = make_decision(Verdict::Deny, Some("blocked"), "authz", vec![]);
        let out = format_decision(&d, true);
        assert!(out.contains("\x1b[31m"));
    }

    #[test]
    fn effects_displayed() {
        let d = make_decision(Verdict::Allow, None, "pii", vec![
            Effect::Redact { selector: "response.content".to_string(), classifier: "pii".to_string() },
        ]);
        let out = format_decision(&d, false);
        assert!(out.contains("effects: Redact(response.content, pii)"));
    }

    #[test]
    fn no_block_shows_none() {
        let d = make_decision(Verdict::Deny, Some("err"), "", vec![]);
        let out = format_decision(&d, false);
        assert!(out.contains("[block: <none>]"));
    }

    #[test]
    fn multiple_effects() {
        let d = make_decision(Verdict::Allow, None, "multi", vec![
            Effect::Redact { selector: "a".to_string(), classifier: "b".to_string() },
            Effect::Audit { level: AuditLevel::Elevated, message: None },
        ]);
        let out = format_decision(&d, false);
        assert!(out.contains("effects: Redact(a, b)"));
        assert!(out.contains("Audit(Elevated)"));
    }
}
