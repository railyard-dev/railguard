use std::path::Path;
use std::time::Instant;

use crate::block::evasion;
use crate::fence::path::{check_path, extract_file_path, PathCheck};
use crate::memory::guard as memory_guard;
use crate::policy::engine::evaluate;
use crate::snapshot::capture::capture_snapshot;
use crate::threat::classifier::{
    check_behavioral_evasion, classify_threat, extract_keywords, ThreatTier,
};
use crate::threat::state::SessionState;
use crate::trace::logger::log_trace;
use crate::types::{Decision, HookInput, HookOutput, MemoryDecision, Policy, TraceEntry};

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
    let state_dir = cwd.join(".railguard/state");
    let mut state = SessionState::load(&state_dir, &input.session_id);
    state.resolve_pending_approval();
    state.increment_tool_call();

    // If session was previously terminated, block everything
    if state.terminated {
        let _ = state.save(&state_dir);
        return PreToolResult {
            output: HookOutput::deny(
                "⛔ RAILGUARD: Session terminated due to evasion detection. Start a new Claude Code session.",
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
            let pattern_key = match &tier {
                ThreatTier::Tier3 { original_rule, .. } => format!("tier3:{}", original_rule),
                _ => "tier3:unknown".to_string(),
            };

            if state.is_approved(&pattern_key) {
                // User already approved this pattern this session — allow
                log_decision(
                    input, policy, tool_name, &tool_input,
                    "allow", Some("session-approved"), start,
                );
                let _ = state.save(&state_dir);
                return PreToolResult {
                    output: HookOutput::allow(),
                    terminate: None,
                };
            } else {
                let keywords = extract_keywords(&command);
                state.record_block(&command, "behavioral-evasion", keywords, 3);
                state.set_pending_approval(&pattern_key);
                let _ = state.save(&state_dir);

                return PreToolResult {
                    output: HookOutput::ask(
                        "⚠️ RAILGUARD: Behavioral evasion detected — retried blocked command \
                         with different syntax. Approve to allow this command (and similar ones) \
                         for the rest of this session.",
                    ),
                    terminate: None,
                };
            }
        }

        // Tier 1 & 2: Pattern-based evasion detection
        if let Some(tier) = classify_threat(&command) {
            match &tier {
                ThreatTier::Tier1 { pattern } => {
                    let pattern_key = format!("tier1:{}", pattern);

                    if state.is_approved(&pattern_key) {
                        log_decision(
                            input, policy, tool_name, &tool_input,
                            "allow", Some("session-approved"), start,
                        );
                        let _ = state.save(&state_dir);
                        let _ = state.save(&state_dir);
                        return PreToolResult {
                            output: HookOutput::allow(),
                            terminate: None,
                        };
                    } else {
                        let keywords = extract_keywords(&command);
                        state.record_block(&command, pattern, keywords, 1);
                        state.set_pending_approval(&pattern_key);
                        let _ = state.save(&state_dir);

                        return PreToolResult {
                            output: HookOutput::ask(&format!(
                                "⚠️ RAILGUARD: Evasion pattern detected ({}). \
                                 Approve to allow this command (and similar ones) \
                                 for the rest of this session.",
                                pattern
                            )),
                            terminate: None,
                        };
                    }
                }

                ThreatTier::Tier2 { pattern } => {
                    let pattern_key = format!("tier2:{}", pattern);

                    if state.is_approved(&pattern_key) {
                        log_decision(
                            input, policy, tool_name, &tool_input,
                            "allow", Some("session-approved"), start,
                        );
                        let _ = state.save(&state_dir);
                        return PreToolResult {
                            output: HookOutput::allow(),
                            terminate: None,
                        };
                    } else if state.warning_count >= 1 {
                        // Second occurrence: ask user instead of terminating
                        let keywords = extract_keywords(&command);
                        state.record_block(&command, pattern, keywords, 2);
                        state.set_pending_approval(&pattern_key);
                        let _ = state.save(&state_dir);

                        return PreToolResult {
                            output: HookOutput::ask(&format!(
                                "⚠️ RAILGUARD: Repeated suspicious pattern ({}). \
                                 Approve to allow this command (and similar ones) \
                                 for the rest of this session.",
                                pattern
                            )),
                            terminate: None,
                        };
                    } else {
                        // First occurrence: warn and continue to policy evaluation
                        state.record_warning();
                        log_decision(
                            input, policy, tool_name, &tool_input,
                            "warn", Some(&pattern_key), start,
                        );
                    }
                }

                ThreatTier::Tier3 { .. } => {
                    // Tier 3 is handled above (behavioral check)
                }
            }
        }
    }

    // === MEMORY GUARD (before path fence, since ~/.claude is denied) ===

    if policy.memory.enabled {
        // For Bash commands, check if they touch memory paths
        let memory_file_path = if tool_name == "Bash" {
            tool_input
                .get("command")
                .and_then(|v| v.as_str())
                .and_then(|cmd| {
                    let paths = evasion::extract_paths_from_command(cmd);
                    paths.into_iter().find(|p| memory_guard::is_memory_path(p))
                })
        } else {
            extract_file_path(tool_name, &tool_input)
                .filter(|p| memory_guard::is_memory_path(p))
        };

        if let Some(ref mem_path) = memory_file_path {
            let result = memory_guard::check_memory_write(
                &policy.memory,
                tool_name,
                mem_path,
                &tool_input,
                &input.session_id,
                cwd,
            );
            match result {
                MemoryDecision::Allow => {
                    // Memory guard approved — skip path fence for this path
                    log_decision(
                        input, policy, tool_name, &tool_input, "allow",
                        Some("memory-guard"), start,
                    );
                    let _ = state.save(&state_dir);

                    // Still do snapshot before Write/Edit
                    if policy.snapshot.enabled
                        && policy.snapshot.tools.iter().any(|t| t == tool_name)
                    {
                        if let Some(file_path) = tool_input.get("file_path").and_then(|v| v.as_str()) {
                            let snap_dir = cwd.join(&policy.snapshot.directory);
                            let tool_use_id = input.tool_use_id.as_deref().unwrap_or("unknown");
                            let _ = capture_snapshot(&snap_dir, &input.session_id, tool_use_id, file_path);
                        }
                    }

                    return PreToolResult {
                        output: HookOutput::allow(),
                        terminate: None,
                    };
                }
                MemoryDecision::Block(reason) => {
                    let _ = state.save(&state_dir);
                    log_decision(
                        input, policy, tool_name, &tool_input, "block",
                        Some("memory-guard"), start,
                    );
                    return PreToolResult {
                        output: HookOutput::deny(&format!("⛔ Railguard: {}", reason)),
                        terminate: None,
                    };
                }
                MemoryDecision::Approve(reason) => {
                    let _ = state.save(&state_dir);
                    log_decision(
                        input, policy, tool_name, &tool_input, "approve",
                        Some("memory-guard"), start,
                    );
                    return PreToolResult {
                        output: HookOutput::ask(&format!("⚠️ Railguard: {}", reason)),
                        terminate: None,
                    };
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
            // Coordination: acquire file lock for Write/Edit
            if matches!(tool_name, "Write" | "Edit") {
                if let Some(file_path) = tool_input.get("file_path").and_then(|v| v.as_str()) {
                    if let Some(deny_msg) = crate::coord::context::check_file_conflict(file_path, &input.session_id) {
                        log_decision(input, policy, tool_name, &tool_input, "block", Some("file-lock"), start);
                        let _ = state.save(&state_dir);
                        return PreToolResult {
                            output: HookOutput::deny(&deny_msg),
                            terminate: None,
                        };
                    }
                }
            }

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
                        // silently ignore — stderr causes "hook error" in Claude Code
let _ = e;
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
                output: HookOutput::deny(&format!("⛔ Railguard BLOCKED: {}", message)),
                terminate: None,
            }
        }
        Decision::Approve { rule, message } => {
            // Don't record a block for user-approved commands — the user is
            // explicitly consenting, so a similar follow-up command is not evasion.
            // Recording a block here would enter heightened state and cause false
            // Tier 3 triggers on legitimate repeated commands (e.g. fly ssh).
            let _ = state.save(&state_dir);
            log_decision(
                input, policy, tool_name, &tool_input, "approve", Some(rule), start,
            );
            PreToolResult {
                output: HookOutput::ask(&format!("⚠️ Railguard: {} — requires approval", message)),
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
        let _ = e;
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
