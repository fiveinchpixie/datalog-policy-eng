// src/error.rs
use thiserror::Error;

/// Errors that occur during request evaluation.
#[derive(Debug, Error)]
pub enum EngineError {
    #[error("policy store uninitialized — no policy has been pushed")]
    StoreUninitialized,

    #[error("CozoDB evaluation error: {0}")]
    Cozo(String),

    #[error("evaluation timed out")]
    Timeout,

    #[error("fact assembly error: {0}")]
    FactAssembly(String),
}

/// Errors that occur during policy load / DSL compilation.
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("DSL parse error: {0}")]
    Parse(String),

    #[error("DSL compile error: {0}")]
    Compile(String),

    #[error("undefined pattern reference: {0}")]
    UndefinedPattern(String),

    #[error("CozoDB store error: {0}")]
    Cozo(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_error_display() {
        let e = EngineError::StoreUninitialized;
        assert!(e.to_string().contains("uninitialized"));
    }

    #[test]
    fn policy_error_preserves_message() {
        let e = PolicyError::Parse("unexpected token at line 3".to_string());
        assert!(e.to_string().contains("line 3"));
    }

    #[test]
    fn policy_error_undefined_pattern() {
        let e = PolicyError::UndefinedPattern("sql_injection".to_string());
        assert!(e.to_string().contains("sql_injection"));
    }
}
