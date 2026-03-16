use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "noodle", about = "Interactive policy engine REPL")]
struct Args {
    /// Policy DSL file to load
    policy: Option<PathBuf>,

    /// Facts JSON file to evaluate (enables one-shot mode)
    facts: Option<PathBuf>,
}

fn main() {
    let args = Args::parse();

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
