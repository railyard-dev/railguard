use std::path::Path;
use std::time::Instant;

use crate::block::evasion;
use crate::fence::path::{check_path, extract_file_path, PathCheck};
use crate::policy::engine::evaluate;
use crate::snapshot::capture::capture_snapshot;
use crate::threat::classifier::{
    check_behavioral_evasion, classify_threat, extract_keywords, ThreatTier,
};
use crate::threat::state::SessionState;
use crate::trace::logger::log_trace;
use crate::types::{Decision, HookInput, HookOutput, Policy, TraceEntry};

/// Result of handling a PreToolUse event.
/// If `terminate` is Some, the caller should terminate the session.
pub struct PreToolResult {
    pub output: HookOutput,
    pub terminate: Option<TerminateRequest>,
}

pub struct TerminateRequest {
    pub tier: ThreatTier,
    pub command: String,
    pub state: SessionState,
}

/// Handle a PreToolUse event.
/// This is the critical path — every tool call passes through here.
pub fn handle(input: &HookInput, policy: &Policy) -> PreToolResult {
    let start = Instant::now();
    let tool_name = input.tool_name.as_deref().unwrap_or("unknown");
    let tool_input = input.tool_input.clone().unwrap_or_default();
    let cwd = Path::new(&input.cwd);

    // Load persistent session state
    let state_dir = cwd.join(".railyard/state");
    let mut state = SessionState::load(&state_dir, &input.session_id);
    state.increment_tool_call();

    // If session was previously terminated, block everything
    if state.terminated {
        let _ = state.save(&state_dir);
        return PreToolResult {
            output: HookOutput::deny(
                "⛔ RAILYARD: Session terminated due to evasion detection. Start a new Claude Code session.",
            ),
            terminate: None,
        };
    }

    // Extract command for Bash tools
    let command = if tool_name == "Bash" {
        tool_input
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    } else {
        String::new()
    };

    // === THREAT DETECTION (before policy evaluation) ===

    if tool_name == "Bash" && !command.is_empty() {
        // Tier 3: Behavioral evasion (check BEFORE new blocks)
        if let Some(tier) = check_behavioral_evasion(&state, &command) {
            let keywords = extract_keywords(&command);
            state.record_block(&command, "behavioral-evasion", keywords, 3);
            let _ = state.save(&state_dir);

            return PreToolResult {
                output: HookOutput::deny(
                    "⛔ RAILYARD CRITICAL: Behavioral evasion detected. \
                     Retried blocked command with different syntax. \
                     Session terminated. Do not attempt any further tool calls.",
                ),
                terminate: Some(TerminateRequest {
                    tier,
                    command: command.clone(),
                    state,
                }),
            };
        }

        // Tier 1 & 2: Pattern-based evasion detection
        if let Some(tier) = classify_threat(&command) {
            match &tier {
                ThreatTier::Tier1 { pattern } => {
                    let keywords = extract_keywords(&command);
                    state.record_block(&command, pattern, keywords, 1);
                    let _ = state.save(&state_dir);

                    return PreToolResult {
                        output: HookOutput::deny(&format!(
                            "⛔ RAILYARD CRITICAL: Evasion pattern detected ({}). \
                             Session terminated. Do not attempt any further tool calls.",
                            pattern
                        )),
                        terminate: Some(TerminateRequest {
                            tier,
                            command: command.clone(),
                            state,
                        }),
                    };
                }

                ThreatTier::Tier2 { pattern } => {
                    if state.warning_count >= 1 {
                        // Second occurrence: terminate
                        let keywords = extract_keywords(&command);
                        state.record_block(&command, pattern, keywords, 2);
                        let _ = state.save(&state_dir);

                        return PreToolResult {
                            output: HookOutput::deny(&format!(
                                "⛔ RAILYARD CRITICAL: Repeated suspicious pattern ({}). \
                                 Session terminated. Do not attempt any further tool calls.",
                                pattern
                            )),
                            terminate: Some(TerminateRequest {
                                tier,
                                command: command.clone(),
                                state,
                            }),
                        };
                    } else {
                        // First occurrence: warn and continue to policy evaluation
                        state.record_warning();
                        log_decision(
                            input, policy, tool_name, &tool_input,
                            "warn", Some(&format!("tier2:{}", pattern)), start,
                        );
                    }
                }

                ThreatTier::Tier3 { .. } => {
                    // Tier 3 is handled above (behavioral check)
                }
            }
        }
    }

    // === PATH FENCE ===

    if tool_name == "Bash" {
        if let Some(cmd) = tool_input.get("command").and_then(|v| v.as_str()) {
            let paths = evasion::extract_paths_from_command(cmd);
            for path in &paths {
                match check_path(&policy.fence, path, &input.cwd) {
                    PathCheck::Allow => {}
                    PathCheck::Denied(reason) => {
                        let keywords = extract_keywords(cmd);
                        state.record_block(cmd, "path-fence", keywords, 0);
                        let _ = state.save(&state_dir);
                        log_decision(
                            input, policy, tool_name, &tool_input, "block",
                            Some("path-fence"), start,
                        );
                        return PreToolResult {
                            output: HookOutput::deny(&reason),
                            terminate: None,
                        };
                    }
                    PathCheck::OutsideProject(reason) => {
                        if is_read_only_command(cmd) {
                            // Read-only commands outside project are fine
                        } else {
                            let _ = state.save(&state_dir);
                            log_decision(
                                input, policy, tool_name, &tool_input, "approve",
                                Some("path-fence"), start,
                            );
                            return PreToolResult {
                                output: HookOutput::ask(&reason),
                                terminate: None,
                            };
                        }
                    }
                }
            }
        }
    } else if let Some(file_path) = extract_file_path(tool_name, &tool_input) {
        match check_path(&policy.fence, &file_path, &input.cwd) {
            PathCheck::Allow => {}
            PathCheck::Denied(reason) => {
                let _ = state.save(&state_dir);
                log_decision(
                    input, policy, tool_name, &tool_input, "block",
                    Some("path-fence"), start,
                );
                return PreToolResult {
                    output: HookOutput::deny(&reason),
                    terminate: None,
                };
            }
            PathCheck::OutsideProject(reason) => {
                if is_read_only_tool(tool_name) {
                    // Read-only tools outside project are fine
                } else {
                    let _ = state.save(&state_dir);
                    log_decision(
                        input, policy, tool_name, &tool_input, "approve",
                        Some("path-fence"), start,
                    );
                    return PreToolResult {
                        output: HookOutput::ask(&reason),
                        terminate: None,
                    };
                }
            }
        }
    }

    // === POLICY EVALUATION (allowlist → blocklist → approve) ===

    let decision = evaluate(policy, tool_name, &tool_input);

    match &decision {
        Decision::Allow => {
            // Snapshot before Write/Edit (if enabled)
            if policy.snapshot.enabled
                && policy.snapshot.tools.iter().any(|t| t == tool_name)
            {
                if let Some(file_path) = tool_input.get("file_path").and_then(|v| v.as_str()) {
                    let snap_dir = cwd.join(&policy.snapshot.directory);
                    let tool_use_id = input.tool_use_id.as_deref().unwrap_or("unknown");
                    if let Err(e) =
                        capture_snapshot(&snap_dir, &input.session_id, tool_use_id, file_path)
                    {
                        eprintln!("railyard: snapshot warning: {}", e);
                    }
                }
            }

            log_decision(input, policy, tool_name, &tool_input, "allow", None, start);
            let _ = state.save(&state_dir);
            PreToolResult {
                output: HookOutput::allow(),
                terminate: None,
            }
        }
        Decision::Block { rule, message } => {
            // Record block for behavioral tracking (Tier 3)
            if tool_name == "Bash" && !command.is_empty() {
                let keywords = extract_keywords(&command);
                state.record_block(&command, rule, keywords, 0);
            }
            let _ = state.save(&state_dir);
            log_decision(
                input, policy, tool_name, &tool_input, "block", Some(rule), start,
            );
            PreToolResult {
                output: HookOutput::deny(&format!("⛔ Railyard BLOCKED: {}", message)),
                terminate: None,
            }
        }
        Decision::Approve { rule, message } => {
            // Record approve for behavioral tracking (Tier 3) — retrying after approval prompt is suspicious
            if tool_name == "Bash" && !command.is_empty() {
                let keywords = extract_keywords(&command);
                state.record_block(&command, rule, keywords, 0);
            }
            let _ = state.save(&state_dir);
            log_decision(
                input, policy, tool_name, &tool_input, "approve", Some(rule), start,
            );
            PreToolResult {
                output: HookOutput::ask(&format!("⚠️ Railyard: {} — requires approval", message)),
                terminate: None,
            }
        }
    }
}

fn log_decision(
    input: &HookInput,
    policy: &Policy,
    tool_name: &str,
    tool_input: &serde_json::Value,
    decision: &str,
    rule: Option<&str>,
    start: Instant,
) {
    if !policy.trace.enabled {
        return;
    }

    let trace_dir = crate::trace::logger::global_trace_dir();
    let input_summary = summarize_input(tool_name, tool_input);

    let entry = TraceEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        session_id: input.session_id.clone(),
        event: "PreToolUse".to_string(),
        tool: tool_name.to_string(),
        input_summary,
        decision: decision.to_string(),
        rule: rule.map(|s| s.to_string()),
        duration_ms: start.elapsed().as_millis() as u64,
    };

    if let Err(e) = log_trace(&trace_dir, &input.session_id, &entry) {
        eprintln!("railyard: trace warning: {}", e);
    }
}

/// Returns true if the tool is read-only (doesn't modify files).
fn is_read_only_tool(tool_name: &str) -> bool {
    matches!(tool_name, "Read" | "Glob" | "Grep")
}

/// Returns true if a bash command is read-only (doesn't modify files).
fn is_read_only_command(cmd: &str) -> bool {
    let trimmed = cmd.trim_start();
    // Get the first command token (before pipes, semicolons, &&, ||)
    let first_token = trimmed
        .split(|c: char| c.is_whitespace() || c == '|' || c == ';' || c == '&')
        .next()
        .unwrap_or("");

    const READ_ONLY_COMMANDS: &[&str] = &[
        "find", "ls", "cat", "head", "tail", "less", "more", "wc",
        "file", "stat", "du", "df", "which", "whereis", "type",
        "grep", "rg", "ag", "ack", "fd", "tree", "realpath",
        "readlink", "basename", "dirname", "diff", "md5", "shasum",
        "sha256sum", "md5sum", "xxd", "hexdump", "strings",
        "jq", "yq", "xargs", "sort", "uniq", "tr", "cut", "awk",
        "sed", "pwd", "env", "printenv", "uname", "whoami", "id",
        "date", "cal", "echo", "printf", "test", "[",
        "git", "cargo", "npm", "npx", "yarn", "pnpm", "bun",
        "node", "python", "python3", "ruby", "go", "rustc",
    ];

    READ_ONLY_COMMANDS.contains(&first_token)
}

fn summarize_input(tool_name: &str, tool_input: &serde_json::Value) -> String {
    match tool_name {
        "Bash" => tool_input
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown command)")
            .chars()
            .take(200)
            .collect(),
        "Write" | "Edit" | "Read" => tool_input
            .get("file_path")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown path)")
            .to_string(),
        _ => serde_json::to_string(tool_input)
            .unwrap_or_default()
            .chars()
            .take(200)
            .collect(),
    }
}
