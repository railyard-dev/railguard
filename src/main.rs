use clap::{Parser, Subcommand};
use colored::Colorize;
use std::path::Path;

use railroad::{configure, coord, context, dashboard, hook, install, policy, replay, snapshot, trace, update};

#[derive(Parser)]
#[command(name = "railroad", version, about = "A secure runtime for AI coding agents.")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Install railroad hooks into Claude Code
    Install,

    /// Remove railroad hooks from Claude Code
    Uninstall,

    /// Generate a starter railroad.yaml in the current directory
    Init,

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

    /// Show session context for rollback (designed for Claude Code to read)
    Context {
        /// Session ID
        #[arg(long)]
        session: String,
        /// Show full diffs (verbose)
        #[arg(short, long)]
        verbose: bool,
    },

    /// Show diff between snapshots and current files
    Diff {
        /// Session ID
        #[arg(long)]
        session: String,
        /// Specific file to diff (optional)
        #[arg(long)]
        file: Option<String>,
    },

    /// Show railroad status
    Status,

    /// Interactive protection configuration
    Configure,

    /// Interactive policy configuration (launches Claude Code)
    Chat,

    /// Live dashboard showing all tool calls and decisions
    Dashboard {
        /// Session ID to monitor (auto-detects latest if omitted)
        #[arg(long)]
        session: Option<String>,
        /// Use streaming output instead of TUI
        #[arg(long)]
        stream: bool,
        /// Show historical entries on startup (streaming mode only)
        #[arg(long)]
        history: bool,
    },

    /// Replay a session — browse tool calls, decisions, and details
    Replay {
        /// Session ID to replay
        #[arg(long)]
        session: String,
    },

    /// Show active file locks across all sessions
    Locks,

    /// Check for updates and install the latest version
    Update {
        /// Only check if an update is available (don't install)
        #[arg(long)]
        check: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    let exit_code = match cli.command {
        Some(Commands::Install) => cmd_install(),
        Some(Commands::Uninstall) => cmd_uninstall(),
        Some(Commands::Init) => cmd_init(),
        Some(Commands::Hook { event }) => hook::handler::run(&event),
        Some(Commands::Log { session, count }) => cmd_log(session, count),
        Some(Commands::Rollback { id, session, file, steps }) => cmd_rollback(id, session, file, steps),
        Some(Commands::Context { session, verbose }) => cmd_context(&session, verbose),
        Some(Commands::Diff { session, file }) => cmd_diff(&session, file),
        Some(Commands::Status) => cmd_status(),
        Some(Commands::Configure) => configure::run_configure(),
        Some(Commands::Chat) => cmd_chat(),
        Some(Commands::Dashboard { session, stream, history }) => {
            if stream {
                dashboard::run_stream(session, history)
            } else {
                dashboard::run(session)
            }
        }
        Some(Commands::Replay { session }) => replay::run(&session),
        Some(Commands::Locks) => cmd_locks(),
        Some(Commands::Update { check }) => update::run_update(check),
        None => {
            // No subcommand: show status
            cmd_status()
        }
    };

    std::process::exit(exit_code);
}

fn cmd_install() -> i32 {
    use dialoguer::{theme::ColorfulTheme, Confirm};

    println!("{}", "railroad".bold());
    println!();

    match install::hooks::install_hooks() {
        Ok(msg) => {
            let rule_count = policy::defaults::default_blocklist().len();

            println!("  {} Hooks registered with Claude Code", "✓".green().bold());
            println!("  {} {}", "✓".green().bold(), msg);
            println!("  {} {} default rules active", "✓".green().bold(), rule_count);

            // Prompt to enable bypass permissions (Railroad replaces it)
            println!();
            println!("  {} We recommend enabling skip permissions — Railroad replaces", "→".cyan().bold());
            println!("    Claude Code's permission system with its own guardrails,");
            println!("    so you won't need to approve every command manually.");
            println!();
            let enable_bypass = Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("  Enable skip permissions?")
                .default(true)
                .interact()
                .unwrap_or(true);

            if enable_bypass {
                match install::hooks::enable_bypass_permissions() {
                    Ok(_) => {
                        println!("  {} Skip permissions enabled — Railroad handles safety now", "✓".green().bold());
                    }
                    Err(e) => {
                        eprintln!("  {} Failed to enable bypass mode: {}", "✗".yellow().bold(), e);
                    }
                }
            }

            println!();
            println!("  Customize with: {}", "railroad init".cyan());
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

fn cmd_init() -> i32 {
    let policy_path = Path::new("railroad.yaml");
    if policy_path.exists() {
        eprintln!("  {} railroad.yaml already exists", "✗".red().bold());
        return 1;
    }

    let default_yaml = include_str!("../defaults/railroad.yaml");

    match std::fs::write(policy_path, default_yaml) {
        Ok(_) => {
            println!("  {} Created railroad.yaml", "✓".green().bold());
            println!();
            println!("  Edit this file to customize your policy.");
            println!("  Run {} to configure interactively.", "railroad chat".cyan());
            0
        }
        Err(e) => {
            eprintln!("  {} Failed to create railroad.yaml: {}", "✗".red().bold(), e);
            1
        }
    }
}

fn cmd_log(session: Option<String>, count: usize) -> i32 {
    let trace_dir = trace::logger::global_trace_dir();

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
                    println!("  Traces are created automatically when Claude Code runs with railroad.");
                } else {
                    println!("  {} Sessions with traces:\n", "●".cyan());
                    for s in &sessions {
                        println!("    {}", s);
                    }
                    println!();
                    println!("  View a session: {}", "railroad log --session <id>".cyan());
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
            trace::logger::list_sessions(&trace::logger::global_trace_dir())
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
                    println!("  Rollback: {}", "railroad rollback --id <id> --session <session>".cyan());
                    println!("  Undo last N: {}", "railroad rollback --steps 3 --session <session>".cyan());
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

fn cmd_context(session_id: &str, verbose: bool) -> i32 {
    let cwd = std::env::current_dir().unwrap_or_default();
    let policy = policy::loader::load_policy_or_defaults(&cwd);
    let trace_dir = trace::logger::global_trace_dir();
    let snap_dir = cwd.join(&policy.snapshot.directory);

    context::print_context(&trace_dir, &snap_dir, session_id, verbose);
    0
}

fn cmd_diff(session_id: &str, file: Option<String>) -> i32 {
    let cwd = std::env::current_dir().unwrap_or_default();
    let policy = policy::loader::load_policy_or_defaults(&cwd);
    let snap_dir = cwd.join(&policy.snapshot.directory);

    context::print_diff(&snap_dir, session_id, file.as_deref());
    0
}

fn cmd_status() -> i32 {
    println!("{}", "railroad status".bold());
    println!();

    match install::hooks::check_installed() {
        Ok(true) => println!("  {} Hooks installed in Claude Code", "✓".green().bold()),
        Ok(false) => println!("  {} Hooks not installed (run {})", "✗".yellow().bold(), "railroad install".cyan()),
        Err(e) => println!("  {} Could not check hooks: {}", "?".yellow().bold(), e),
    }

    let cwd = std::env::current_dir().unwrap_or_default();
    let loaded_policy = policy::loader::load_policy_or_defaults(&cwd);

    match policy::loader::find_policy_file(&cwd) {
        Some(path) => {
            println!("  {} Policy loaded: {}", "✓".green().bold(), path.display());
            println!("       {} blocklist rules", loaded_policy.blocklist.len());
            println!("       {} approve rules", loaded_policy.approve.len());
            println!("       {} allowlist rules", loaded_policy.allowlist.len());
            println!("       fence: {}", if loaded_policy.fence.enabled { "on" } else { "off" });
            println!("       trace: {}", if loaded_policy.trace.enabled { "on" } else { "off" });
            println!("       snapshot: {}", if loaded_policy.snapshot.enabled { "on" } else { "off" });
        }
        None => {
            println!("  {} No railroad.yaml found (using defaults)", "●".cyan().bold());
            println!("       {} default rules active", loaded_policy.blocklist.len());
        }
    }

    println!();
    0
}

fn cmd_locks() -> i32 {
    let locks = coord::lock::list_active_locks();

    if locks.is_empty() {
        println!("  No active file locks.");
        return 0;
    }

    println!("{}", "railroad locks".bold());
    println!();

    // Group by session
    let mut by_session: std::collections::HashMap<String, Vec<&coord::lock::FileLock>> =
        std::collections::HashMap::new();
    for lock in &locks {
        by_session
            .entry(lock.session_id.clone())
            .or_default()
            .push(lock);
    }

    for (session_id, files) in &by_session {
        let short = if session_id.len() > 8 {
            &session_id[..8]
        } else {
            session_id
        };
        println!("  {} Session {}...  ({} files)", "●".cyan(), short, files.len());
        for lock in files {
            let elapsed = chrono::DateTime::parse_from_rfc3339(&lock.last_heartbeat)
                .map(|hb| {
                    let secs = chrono::Utc::now()
                        .signed_duration_since(hb)
                        .num_seconds()
                        .max(0);
                    format!("{}s ago", secs)
                })
                .unwrap_or_else(|_| "?".to_string());
            println!("    {} {} ({})", "→".green(), lock.file_path, elapsed);
        }
        println!();
    }

    0
}

fn cmd_chat() -> i32 {
    println!("{}", "railroad chat".bold());
    println!();
    println!("  Launching interactive policy configuration...");
    println!();

    let claude_check = std::process::Command::new("which")
        .arg("claude")
        .output();

    match claude_check {
        Ok(output) if output.status.success() => {
            let prompt = r#"You are the Railroad policy configuration assistant. Help the user create or modify their railroad.yaml policy file.

The user's current working directory has (or will have) a railroad.yaml file. Help them:
1. Add blocklist rules to prevent dangerous commands
2. Add approve rules for commands that need human sign-off
3. Configure path fencing (allowed/denied directories)
4. Configure trace and snapshot settings

The railroad.yaml format is:
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
  directory: .railroad/traces
snapshot:
  enabled: true
  tools: [Write, Edit]
  directory: .railroad/snapshots
```

Read the current railroad.yaml (if it exists) and help the user modify it based on their needs. Always write valid YAML with valid regex patterns."#;

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
            eprintln!("  Alternatively, edit railroad.yaml manually.");
            eprintln!("  Run {} to generate a starter config.", "railroad init".cyan());
            1
        }
    }
}

