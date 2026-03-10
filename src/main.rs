mod block;
mod fence;
mod hook;
mod install;
mod policy;
mod snapshot;
mod trace;
mod types;

use clap::{Parser, Subcommand};
use colored::Colorize;
use std::path::Path;

#[derive(Parser)]
#[command(name = "railyard", version, about = "The runtime layer for AI agents in production")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Install railyard hooks into Claude Code
    Install {
        /// Protection mode: "chill" (block destructive commands) or "hardcore" (full lockdown)
        #[arg(long, default_value = "chill")]
        mode: String,
    },

    /// Remove railyard hooks from Claude Code
    Uninstall,

    /// Generate a starter railyard.yaml in the current directory
    Init {
        /// Protection mode: "chill" or "hardcore"
        #[arg(long, default_value = "chill")]
        mode: String,
    },

    /// Internal: handle a hook event (reads JSON from stdin)
    Hook {
        #[arg(long)]
        event: String,
    },

    /// Show recent trace logs
    Log {
        /// Show traces for a specific session
        #[arg(long)]
        session: Option<String>,
        /// Number of recent entries to show
        #[arg(short, long, default_value = "20")]
        count: usize,
    },

    /// Rollback file changes from snapshots
    Rollback {
        /// Snapshot ID to rollback
        #[arg(long)]
        id: Option<String>,
        /// Session ID
        #[arg(long)]
        session: Option<String>,
        /// File path to rollback
        #[arg(long)]
        file: Option<String>,
        /// Number of steps to undo
        #[arg(long)]
        steps: Option<usize>,
    },

    /// Show railyard status
    Status,

    /// Interactive policy configuration (launches Claude Code)
    Chat,
}

fn main() {
    let cli = Cli::parse();

    let exit_code = match cli.command {
        Commands::Install { mode } => cmd_install(&mode),
        Commands::Uninstall => cmd_uninstall(),
        Commands::Init { mode } => cmd_init(&mode),
        Commands::Hook { event } => hook::handler::run(&event),
        Commands::Log { session, count } => cmd_log(session, count),
        Commands::Rollback { id, session, file, steps } => cmd_rollback(id, session, file, steps),
        Commands::Status => cmd_status(),
        Commands::Chat => cmd_chat(),
    };

    std::process::exit(exit_code);
}

fn cmd_install(mode: &str) -> i32 {
    let mode = if mode == "hardcore" { "hardcore" } else { "chill" };

    println!("{}", "railyard".bold());
    println!();

    match install::hooks::install_hooks() {
        Ok(msg) => {
            let mode_label = if mode == "hardcore" {
                "hardcore".red().bold().to_string()
            } else {
                "chill".green().bold().to_string()
            };
            let rule_count = if mode == "hardcore" {
                policy::defaults::hardcore_blocklist().len()
            } else {
                policy::defaults::chill_blocklist().len()
            };

            println!("  {} Hooks registered with Claude Code", "✓".green().bold());
            println!("  {} {}", "✓".green().bold(), msg);
            println!("  {} Mode: {} ({} rules)", "✓".green().bold(), mode_label, rule_count);
            if mode == "chill" {
                println!();
                println!("  Blocks destructive commands. No restrictions on file access or network.");
                println!("  For full lockdown: {}", "railyard install --mode hardcore".cyan());
            } else {
                println!();
                println!("  Full lockdown: path fencing, network policy, credential protection.");
                println!("  For relaxed mode: {}", "railyard install --mode chill".cyan());
            }
            0
        }
        Err(e) => {
            eprintln!("  {} {}", "✗".red().bold(), e);
            1
        }
    }
}

fn cmd_uninstall() -> i32 {
    match install::hooks::uninstall_hooks() {
        Ok(msg) => {
            println!("  {} {}", "✓".green().bold(), msg);
            0
        }
        Err(e) => {
            eprintln!("  {} {}", "✗".red().bold(), e);
            1
        }
    }
}

fn cmd_init(mode: &str) -> i32 {
    let policy_path = Path::new("railyard.yaml");
    if policy_path.exists() {
        eprintln!("  {} railyard.yaml already exists", "✗".red().bold());
        return 1;
    }

    let mode = if mode == "hardcore" { "hardcore" } else { "chill" };
    let default_yaml = include_str!("../defaults/railyard.yaml");
    // Inject mode into the generated YAML
    let yaml_with_mode = format!("mode: {}\n{}", mode, default_yaml);

    match std::fs::write(policy_path, yaml_with_mode) {
        Ok(_) => {
            let mode_label = if mode == "hardcore" {
                "hardcore".red().bold().to_string()
            } else {
                "chill".green().bold().to_string()
            };
            println!("  {} Created railyard.yaml (mode: {})", "✓".green().bold(), mode_label);
            println!();
            println!("  Edit this file to customize your policy.");
            println!("  Run {} to configure interactively.", "railyard chat".cyan());
            0
        }
        Err(e) => {
            eprintln!("  {} Failed to create railyard.yaml: {}", "✗".red().bold(), e);
            1
        }
    }
}

fn cmd_log(session: Option<String>, count: usize) -> i32 {
    let cwd = std::env::current_dir().unwrap_or_default();
    let policy = policy::loader::load_policy_or_defaults(&cwd);
    let trace_dir = cwd.join(&policy.trace.directory);

    if let Some(session_id) = session {
        match trace::logger::read_traces(&trace_dir, &session_id) {
            Ok(entries) => {
                if entries.is_empty() {
                    println!("  No traces found for session {}", session_id);
                } else {
                    for entry in entries.iter().rev().take(count).rev() {
                        println!("{}", trace::logger::format_trace_entry(entry));
                    }
                }
                0
            }
            Err(e) => {
                eprintln!("  {} {}", "✗".red().bold(), e);
                1
            }
        }
    } else {
        match trace::logger::list_sessions(&trace_dir) {
            Ok(sessions) => {
                if sessions.is_empty() {
                    println!("  No trace sessions found.");
                    println!("  Traces are created automatically when Claude Code runs with railyard.");
                } else {
                    println!("  {} Sessions with traces:\n", "●".cyan());
                    for s in &sessions {
                        println!("    {}", s);
                    }
                    println!();
                    println!("  View a session: {}", "railyard log --session <id>".cyan());
                }
                0
            }
            Err(e) => {
                eprintln!("  {} {}", "✗".red().bold(), e);
                1
            }
        }
    }
}

fn cmd_rollback(
    id: Option<String>,
    session: Option<String>,
    file: Option<String>,
    steps: Option<usize>,
) -> i32 {
    let cwd = std::env::current_dir().unwrap_or_default();
    let policy = policy::loader::load_policy_or_defaults(&cwd);
    let snap_dir = cwd.join(&policy.snapshot.directory);

    if id.is_none() && file.is_none() && steps.is_none() {
        let session_id = session.unwrap_or_else(|| {
            trace::logger::list_sessions(&cwd.join(&policy.trace.directory))
                .unwrap_or_default()
                .last()
                .cloned()
                .unwrap_or_default()
        });

        if session_id.is_empty() {
            println!("  No snapshots found. Specify --session <id>.");
            return 1;
        }

        match snapshot::rollback::list_snapshots(&snap_dir, &session_id) {
            Ok(lines) => {
                if lines.is_empty() {
                    println!("  No snapshots for session {}", session_id);
                } else {
                    println!("  {} Snapshots for session {}:\n", "●".cyan(), session_id);
                    for line in &lines {
                        println!("{}", line);
                    }
                    println!();
                    println!("  Rollback: {}", "railyard rollback --id <id> --session <session>".cyan());
                    println!("  Undo last N: {}", "railyard rollback --steps 3 --session <session>".cyan());
                }
                0
            }
            Err(e) => {
                eprintln!("  {} {}", "✗".red().bold(), e);
                1
            }
        }
    } else {
        let session_id = session.unwrap_or_default();
        if session_id.is_empty() {
            eprintln!("  {} --session is required for rollback", "✗".red().bold());
            return 1;
        }

        if let Some(steps) = steps {
            match snapshot::rollback::rollback_steps(&snap_dir, &session_id, steps) {
                Ok(msgs) => {
                    for msg in &msgs {
                        println!("  {} {}", "✓".green().bold(), msg);
                    }
                    0
                }
                Err(e) => {
                    eprintln!("  {} {}", "✗".red().bold(), e);
                    1
                }
            }
        } else if let Some(id) = id {
            match snapshot::rollback::rollback_by_id(&snap_dir, &session_id, &id) {
                Ok(msg) => {
                    println!("  {} {}", "✓".green().bold(), msg);
                    0
                }
                Err(e) => {
                    eprintln!("  {} {}", "✗".red().bold(), e);
                    1
                }
            }
        } else if let Some(file) = file {
            match snapshot::rollback::rollback_file(&snap_dir, &session_id, &file) {
                Ok(msg) => {
                    println!("  {} {}", "✓".green().bold(), msg);
                    0
                }
                Err(e) => {
                    eprintln!("  {} {}", "✗".red().bold(), e);
                    1
                }
            }
        } else {
            match snapshot::rollback::rollback_session(&snap_dir, &session_id) {
                Ok(msgs) => {
                    for msg in &msgs {
                        println!("  {} {}", "✓".green().bold(), msg);
                    }
                    0
                }
                Err(e) => {
                    eprintln!("  {} {}", "✗".red().bold(), e);
                    1
                }
            }
        }
    }
}

fn cmd_status() -> i32 {
    println!("{}", "railyard status".bold());
    println!();

    match install::hooks::check_installed() {
        Ok(true) => println!("  {} Hooks installed in Claude Code", "✓".green().bold()),
        Ok(false) => println!("  {} Hooks not installed (run {})", "✗".yellow().bold(), "railyard install".cyan()),
        Err(e) => println!("  {} Could not check hooks: {}", "?".yellow().bold(), e),
    }

    let cwd = std::env::current_dir().unwrap_or_default();
    let loaded_policy = policy::loader::load_policy_or_defaults(&cwd);
    let mode_label = if loaded_policy.mode == "hardcore" {
        "hardcore".red().bold().to_string()
    } else {
        "chill".green().bold().to_string()
    };

    match policy::loader::find_policy_file(&cwd) {
        Some(path) => {
            println!("  {} Policy loaded: {}", "✓".green().bold(), path.display());
            println!("       mode: {}", mode_label);
            println!("       {} blocklist rules", loaded_policy.blocklist.len());
            println!("       {} approve rules", loaded_policy.approve.len());
            println!("       {} allowlist rules", loaded_policy.allowlist.len());
            println!("       fence: {}", if loaded_policy.fence.enabled { "on" } else { "off" });
            println!("       trace: {}", if loaded_policy.trace.enabled { "on" } else { "off" });
            println!("       snapshot: {}", if loaded_policy.snapshot.enabled { "on" } else { "off" });
        }
        None => {
            println!("  {} No railyard.yaml found (using defaults)", "●".cyan().bold());
            println!("       mode: {}", mode_label);
            println!("       {} default blocklist rules active", loaded_policy.blocklist.len());
        }
    }

    println!();
    0
}

fn cmd_chat() -> i32 {
    println!("{}", "railyard chat".bold());
    println!();
    println!("  Launching interactive policy configuration...");
    println!();

    let claude_check = std::process::Command::new("which")
        .arg("claude")
        .output();

    match claude_check {
        Ok(output) if output.status.success() => {
            let prompt = r#"You are the Railyard policy configuration assistant. Help the user create or modify their railyard.yaml policy file.

The user's current working directory has (or will have) a railyard.yaml file. Help them:
1. Add blocklist rules to prevent dangerous commands
2. Add approve rules for commands that need human sign-off
3. Configure path fencing (allowed/denied directories)
4. Configure trace and snapshot settings

The railyard.yaml format is:
```yaml
version: 1
blocklist:
  - name: rule-name
    tool: Bash          # Bash, Write, Edit, Read, or *
    pattern: "regex"    # regex pattern to match
    action: block
    message: "Why it's blocked"
approve:
  - name: rule-name
    tool: Bash
    pattern: "regex"
    action: approve
    message: "Why approval needed"
allowlist:
  - name: rule-name
    tool: Bash
    pattern: "regex"
    action: allow
fence:
  enabled: true
  allowed_paths: []
  denied_paths:
    - "~/.ssh"
    - "~/.aws"
trace:
  enabled: true
  directory: .railyard/traces
snapshot:
  enabled: true
  tools: [Write, Edit]
  directory: .railyard/snapshots
```

Read the current railyard.yaml (if it exists) and help the user modify it based on their needs. Always write valid YAML with valid regex patterns."#;

            let status = std::process::Command::new("claude")
                .arg("--print")
                .arg("-p")
                .arg(prompt)
                .status();

            match status {
                Ok(s) => s.code().unwrap_or(0),
                Err(e) => {
                    eprintln!("  {} Failed to launch claude: {}", "✗".red().bold(), e);
                    1
                }
            }
        }
        _ => {
            eprintln!("  {} Claude Code CLI not found.", "✗".red().bold());
            eprintln!("  Install it: https://docs.anthropic.com/en/docs/claude-code");
            eprintln!();
            eprintln!("  Alternatively, edit railyard.yaml manually.");
            eprintln!("  Run {} to generate a starter config.", "railyard init".cyan());
            1
        }
    }
}
