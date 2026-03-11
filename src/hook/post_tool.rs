use std::time::Instant;

use crate::trace::logger::log_trace;
use crate::types::{HookInput, Policy, TraceEntry};

/// Handle a PostToolUse event.
/// Logs the completed tool call for tracing.
pub fn handle(input: &HookInput, policy: &Policy) {
    if !policy.trace.enabled {
        return;
    }

    let start = Instant::now();
    let tool_name = input.tool_name.as_deref().unwrap_or("unknown");
    let tool_input = input.tool_input.clone().unwrap_or_default();

    let input_summary = match tool_name {
        "Bash" => tool_input
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown)")
            .chars()
            .take(200)
            .collect(),
        "Write" | "Edit" | "Read" => tool_input
            .get("file_path")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown)")
            .to_string(),
        _ => serde_json::to_string(&tool_input)
            .unwrap_or_default()
            .chars()
            .take(200)
            .collect(),
    };

    let trace_dir = crate::trace::logger::global_trace_dir();

    let entry = TraceEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        session_id: input.session_id.clone(),
        event: "PostToolUse".to_string(),
        tool: tool_name.to_string(),
        input_summary,
        decision: "completed".to_string(),
        rule: None,
        duration_ms: start.elapsed().as_millis() as u64,
    };

    if let Err(e) = log_trace(&trace_dir, &input.session_id, &entry) {
        eprintln!("railyard: trace warning: {}", e);
    }
}
