use std::path::Path;

use crate::threat::killer::format_restart_warning;
use crate::threat::state::SessionState;
use crate::trace::logger::log_trace;
use crate::types::{HookInput, HookOutput, Policy, TraceEntry};
use crate::update;

/// Handle a SessionStart event.
/// Logs the session initialization and warns about previous terminations.
/// Returns a HookOutput with optional update notification.
pub fn handle(input: &HookInput, policy: &Policy) -> HookOutput {
    let cwd = Path::new(&input.cwd);

    // Check for updates (at most once per week)
    let update_message = update::check_for_update(cwd);

    // Check for recently terminated sessions and warn
    let state_dir = cwd.join(".railyard/state");
    let terminated = SessionState::find_recent_terminations(&state_dir);
    if !terminated.is_empty() {
        for state in &terminated {
            let warning = format_restart_warning(state);
            eprintln!("{}", warning);
            eprintln!();
        }
    }

    // Clean up old state files (>24h)
    SessionState::cleanup_old_states(&state_dir);

    if policy.trace.enabled {
        let trace_dir = crate::trace::logger::global_trace_dir();

        let entry = TraceEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            session_id: input.session_id.clone(),
            event: "SessionStart".to_string(),
            tool: "-".to_string(),
            input_summary: format!("Session started in {}", input.cwd),
            decision: "allow".to_string(),
            rule: None,
            duration_ms: 0,
        };

        if let Err(e) = log_trace(&trace_dir, &input.session_id, &entry) {
            eprintln!("railyard: trace warning: {}", e);
        }
    }

    match update_message {
        Some(msg) => HookOutput::session_message(&msg),
        None => HookOutput::noop(),
    }
}
