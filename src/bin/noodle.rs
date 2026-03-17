use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "noodle", about = "Interactive policy engine REPL")]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    /// Policy DSL file to load
    policy: Option<PathBuf>,

    /// Facts JSON file to evaluate (enables one-shot mode)
    facts: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Lint a policy file for common issues
    Lint {
        /// Policy DSL file to lint
        policy: PathBuf,
    },
}

fn main() {
    let args = Args::parse();

    if let Some(Command::Lint { policy }) = &args.command {
        let code = run_lint(policy);
        std::process::exit(code);
    }

    match (&args.policy, &args.facts) {
        (Some(policy), Some(facts)) => {
            let code = datalog_noodle::cli::oneshot::run(policy, facts);
            std::process::exit(code);
        }
        (policy, None) => {
            datalog_noodle::cli::repl::run(policy.as_deref());
        }
        (None, Some(_)) => {
            eprintln!("error: facts file requires a policy file");
            eprintln!("usage: noodle [POLICY] [FACTS]");
            std::process::exit(2);
        }
    }
}

fn run_lint(policy_path: &PathBuf) -> i32 {
    let source = match std::fs::read_to_string(policy_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read {}: {e}", policy_path.display());
            return 2;
        }
    };

    let ast = match datalog_noodle::dsl_parse(&source) {
        Ok(ast) => ast,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    let warnings = datalog_noodle::lint(&ast);

    for w in &warnings {
        println!("{w}");
    }

    if warnings.is_empty() {
        println!("no warnings");
        0
    } else {
        println!("\n{} warning{}", warnings.len(), if warnings.len() == 1 { "" } else { "s" });
        1
    }
}
