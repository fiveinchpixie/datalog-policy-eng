use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::Duration;
use rustyline::error::ReadlineError;
use crate::cli::facts_json;
use crate::cli::output;
use crate::dsl::linter;
use crate::policy::file_watcher::{PolicyFileWatcher, WatchEvent};
use crate::{Engine, PolicySet, PolicyWatcher};

struct ReplState {
    engine: Engine,
    policy_path: Option<PathBuf>,
    version_counter: u32,
    watcher: Option<PolicyFileWatcher>,
}

impl ReplState {
    fn new() -> Self {
        Self {
            engine: Engine::new(),
            policy_path: None,
            version_counter: 0,
            watcher: None,
        }
    }

    fn load_policy(&mut self, path: &Path) -> Result<(), String> {
        let source = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        self.version_counter += 1;
        let version = format!("v{}", self.version_counter);
        self.engine.push(PolicySet {
            version: version.clone(),
            source,
            checksum: String::new(),
        }).map_err(|e| format!("compile error: {e}"))?;
        self.policy_path = Some(path.to_path_buf());
        eprintln!("loaded {} ({})", path.display(), version);
        Ok(())
    }
}

pub fn run(initial_policy: Option<&Path>) {
    let mut state = ReplState::new();
    let use_color = std::io::stdout().is_terminal();

    if let Some(path) = initial_policy {
        if let Err(e) = state.load_policy(path) {
            eprintln!("error: {e}");
        }
    }

    let mut rl = rustyline::DefaultEditor::new().expect("failed to initialize readline");
    let mut json_buf = String::new();
    let mut brace_depth: i32 = 0;

    loop {
        let prompt = if json_buf.is_empty() { "noodle> " } else { "...     " };
        let line = match rl.readline(prompt) {
            Ok(line) => line,
            Err(ReadlineError::Eof) => break,
            Err(ReadlineError::Interrupted) => {
                json_buf.clear();
                brace_depth = 0;
                continue;
            }
            Err(e) => {
                eprintln!("readline error: {e}");
                break;
            }
        };

        // Blank line while accumulating → cancel
        if !json_buf.is_empty() && line.trim().is_empty() {
            json_buf.clear();
            brace_depth = 0;
            eprintln!("(input cancelled)");
            continue;
        }

        let trimmed = line.trim();

        // Commands (only when not accumulating JSON)
        if json_buf.is_empty() && trimmed.starts_with(':') {
            rl.add_history_entry(&line).ok();
            handle_command(trimmed, &mut state, use_color);
            continue;
        }

        // JSON accumulation
        json_buf.push_str(&line);
        json_buf.push('\n');
        for ch in line.chars() {
            match ch {
                '{' | '[' => brace_depth += 1,
                '}' | ']' => brace_depth -= 1,
                _ => {}
            }
        }

        if brace_depth > 0 {
            continue; // keep reading
        }

        // Balanced — evaluate
        rl.add_history_entry(json_buf.trim()).ok();
        evaluate_json(&json_buf, &state, use_color);
        json_buf.clear();
        brace_depth = 0;
    }
}

fn handle_command(input: &str, state: &mut ReplState, _use_color: bool) {
    let parts: Vec<&str> = input.splitn(2, ' ').collect();
    match parts[0] {
        ":quit" | ":q" => std::process::exit(0),
        ":help" | ":h" => print_help(),
        ":load" => {
            if let Some(path) = parts.get(1).map(|s| s.trim()) {
                if let Err(e) = state.load_policy(Path::new(path)) {
                    eprintln!("error: {e}");
                }
            } else {
                eprintln!("usage: :load <path>");
            }
        }
        ":reload" | ":r" => {
            if let Some(path) = state.policy_path.clone() {
                if let Err(e) = state.load_policy(&path) {
                    eprintln!("error: {e}");
                }
            } else {
                eprintln!("no policy loaded; use :load <path> first");
            }
        }
        ":policy" | ":p" => {
            match (&state.policy_path, state.engine.current_version()) {
                (Some(path), Some(ver)) => println!("policy: {} ({})", path.display(), ver),
                _ => println!("no policy loaded"),
            }
        }
        ":watch" | ":w" => {
            if let Some(path) = parts.get(1).map(|s| s.trim()) {
                // Stop existing watcher if any
                state.watcher.take();
                let file_path = Path::new(path);
                match PolicyFileWatcher::start(
                    file_path,
                    state.engine.clone(),
                    Duration::from_secs(2),
                    |event| match event {
                        WatchEvent::Reloaded { version, path } => {
                            eprintln!("[watch] reloaded {} ({})", path.display(), version);
                        }
                        WatchEvent::CompileError { error, path } => {
                            eprintln!("[watch] compile error in {}: {}", path.display(), error);
                        }
                        WatchEvent::IoError { error, path } => {
                            eprintln!("[watch] I/O error reading {}: {}", path.display(), error);
                        }
                    },
                ) {
                    Ok(w) => {
                        state.policy_path = Some(file_path.to_path_buf());
                        state.watcher = Some(w);
                        eprintln!("watching {} (poll every 2s)", path);
                    }
                    Err(e) => eprintln!("error: {e}"),
                }
            } else {
                eprintln!("usage: :watch <path>");
            }
        }
        ":unwatch" => {
            if state.watcher.take().is_some() {
                eprintln!("stopped watching");
            } else {
                eprintln!("no active watch");
            }
        }
        ":lint" => {
            if let Some(path) = &state.policy_path {
                let source = match std::fs::read_to_string(path) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("error reading {}: {e}", path.display());
                        return;
                    }
                };
                let ast = match crate::dsl::parser::parse(&source) {
                    Ok(a) => a,
                    Err(e) => {
                        eprintln!("parse error: {e}");
                        return;
                    }
                };
                let warnings = linter::lint(&ast);
                for w in &warnings {
                    println!("{w}");
                }
                if warnings.is_empty() {
                    println!("no warnings");
                } else {
                    println!("\n{} warning{}", warnings.len(), if warnings.len() == 1 { "" } else { "s" });
                }
            } else {
                eprintln!("no policy loaded; use :load <path> first");
            }
        }
        ":example" | ":e" => print_example(),
        other => eprintln!("unknown command: {other}  (type :help for commands)"),
    }
}

fn evaluate_json(json_str: &str, state: &ReplState, use_color: bool) {
    if state.engine.current_version().is_none() {
        eprintln!("no policy loaded; use :load <path> first");
        return;
    }
    let value: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("JSON parse error: {e}");
            return;
        }
    };
    let facts = match facts_json::parse_facts_json(&value) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("fact error: {e}");
            return;
        }
    };
    let decision = state.engine.evaluate(&facts);
    print!("{}", output::format_decision(&decision, use_color));
}

fn print_help() {
    println!("Commands:");
    println!("  :load <path>   Load or replace policy from a .dl file");
    println!("  :reload        Reload current policy file");
    println!("  :policy        Show loaded policy info");
    println!("  :example       Print an example JSON fact package");
    println!("  :lint          Lint the current policy for common issues");
    println!("  :watch <path>  Watch a policy file for changes (auto-reload)");
    println!("  :unwatch       Stop watching");
    println!("  :help          Show this help");
    println!("  :quit          Exit (also Ctrl-D)");
    println!();
    println!("Type or paste a JSON fact package to evaluate it.");
    println!("Multiline JSON is supported — input continues until braces balance.");
    println!("A blank line while typing JSON cancels the input.");
}

fn print_example() {
    println!(r#"{{
  "tool_calls": [["call-1", "agt-1", "db_query"]],
  "agent_roles": [["agt-1", "analyst"]],
  "resource_accesses": [["call-1", "agt-1", "data/users", "read"]],
  "timestamps": [["call-1", 1700000000]]
}}"#);
}
