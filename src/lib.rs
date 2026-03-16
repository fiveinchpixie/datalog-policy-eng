// src/lib.rs
pub mod decision;
pub mod error;
pub mod facts;
pub mod policy;
pub mod types;

pub mod cli;
pub mod dsl;
pub(crate) mod evaluator;

// Public surface re-exports
pub use decision::{AuditLevel, AuditRecord, Decision, Effect, Verdict};
pub use error::{EngineError, PolicyError};
pub use facts::FactPackage;
pub use policy::watcher::{PolicySet, PolicyWatcher};
pub use policy::store::PolicyStore;
pub use evaluator::Engine;

/// Parse a DSL source string into a `PolicyFile` AST.
pub fn dsl_parse(source: &str) -> Result<dsl::ast::PolicyFile, error::PolicyError> {
    dsl::parser::parse(source)
}

/// Compile a DSL source string into a `CompiledPolicy`.
pub fn dsl_compile(source: &str, version: &str) -> Result<policy::compiled::CompiledPolicy, error::PolicyError> {
    dsl::compiler::compile(source, version)
}
