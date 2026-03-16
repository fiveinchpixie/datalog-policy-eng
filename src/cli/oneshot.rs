use std::path::Path;
use std::io::IsTerminal;
use crate::cli::facts_json;
use crate::cli::output;
use crate::{Engine, PolicySet, PolicyWatcher};

/// Run one-shot evaluation. Returns process exit code: 0=Allow, 1=Deny, 2=error.
pub fn run(policy_path: &Path, facts_path: &Path) -> i32 {
    let engine = Engine::new();

    let source = match std::fs::read_to_string(policy_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read policy file {}: {}", policy_path.display(), e);
            return 2;
        }
    };

    if let Err(e) = engine.push(PolicySet {
        version: "v1".to_string(),
        source,
        checksum: String::new(),
    }) {
        eprintln!("error: policy compilation failed: {e}");
        return 2;
    }

    let json_str = match std::fs::read_to_string(facts_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read facts file {}: {}", facts_path.display(), e);
            return 2;
        }
    };

    let json_value: serde_json::Value = match serde_json::from_str(&json_str) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: invalid JSON in {}: {}", facts_path.display(), e);
            return 2;
        }
    };

    let facts = match facts_json::parse_facts_json(&json_value) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: invalid fact format: {e}");
            return 2;
        }
    };

    let decision = engine.evaluate(&facts);
    let use_color = std::io::stdout().is_terminal();
    print!("{}", output::format_decision(&decision, use_color));

    match decision.verdict {
        crate::Verdict::Allow => 0,
        crate::Verdict::Deny  => 1,
    }
}
