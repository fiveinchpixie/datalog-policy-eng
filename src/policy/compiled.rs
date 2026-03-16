// src/policy/compiled.rs
use std::collections::HashMap;
use regex::Regex;

/// The output of the DSL compiler. Held by `PolicyStore` and shared
/// (read-only) across all concurrent request evaluations.
pub struct CompiledPolicy {
    pub version: String,
    pub db: cozo::DbInstance,
    pub decision_script: String,
    pub patterns: HashMap<String, Regex>,
}

impl std::fmt::Debug for CompiledPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledPolicy")
            .field("version", &self.version)
            .field("decision_script", &self.decision_script)
            .field("patterns", &self.patterns.keys().collect::<Vec<_>>())
            .finish()
    }
}
