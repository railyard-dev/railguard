use std::path::Path;
use std::time::Instant;

use crate::block::evasion;
use crate::fence::path::{check_path, extract_file_path};
use crate::policy::engine::evaluate;
use crate::snapshot::capture::capture_snapshot;
use crate::trace::logger::log_trace;
use crate::types::{Decision, HookInput, HookOutput, Policy, TraceEntry};

/// Handle a PreToolUse event.
/// This is the critical path — every tool call passes through here.
pub fn handle(input: &HookInput, policy: &Policy) -> HookOutput {
    let start = Instant::now();
    let tool_name = input.tool_name.as_deref().unwrap_or("unknown");
    let tool_input = input.tool_input.clone().unwrap_or_default();

    // 1. Path Fence — check all file paths the command might touch
    if tool_name == "Bash" {
        // For Bash: extract paths with variable expansion to catch indirection
        if let Some(cmd) = tool_input.get("command").and_then(|v| v.as_str()) {
            let paths = evasion::extract_paths_from_command(cmd);
            for path in &paths {
                if let Err(reason) = check_path(&policy.fence, path, &input.cwd) {
                    log_decision(input, policy, tool_name, &tool_input, "block", Some("path-fence"), start);
                    return HookOutput::deny(&reason);
                }
            }
        }
    } else if let Some(file_path) = extract_file_path(tool_name, &tool_input) {
        // For Write/Edit/Read: check the explicit file_path
        if let Err(reason) = check_path(&policy.fence, &file_path, &input.cwd) {
            log_decision(input, policy, tool_name, &tool_input, "block", Some("path-fence"), start);
            return HookOutput::deny(&reason);
        }
    }

    // 2. Policy evaluation (allowlist → blocklist → approve)
    let decision = evaluate(policy, tool_name, &tool_input);

    match &decision {
        Decision::Allow => {
            // 3. Snapshot before Write/Edit (if enabled)
            if policy.snapshot.enabled
                && policy.snapshot.tools.iter().any(|t| t == tool_name)
            {
                if let Some(file_path) = tool_input.get("file_path").and_then(|v| v.as_str()) {
                    let snap_dir = Path::new(&input.cwd).join(&policy.snapshot.directory);
                    let tool_use_id = input.tool_use_id.as_deref().unwrap_or("unknown");
                    if let Err(e) = capture_snapshot(&snap_dir, &input.session_id, tool_use_id, file_path) {
                        eprintln!("railyard: snapshot warning: {}", e);
                    }
                }
            }

            log_decision(input, policy, tool_name, &tool_input, "allow", None, start);
            HookOutput::allow()
        }
        Decision::Block { rule, message } => {
            log_decision(input, policy, tool_name, &tool_input, "block", Some(rule), start);
            HookOutput::deny(&format!("⛔ Railyard BLOCKED: {}", message))
        }
        Decision::Approve { rule, message } => {
            log_decision(input, policy, tool_name, &tool_input, "approve", Some(rule), start);
            HookOutput::ask(&format!("⚠️ Railyard: {} — requires approval", message))
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

    let trace_dir = Path::new(&input.cwd).join(&policy.trace.directory);
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
