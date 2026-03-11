use std::io::{Read, Write};
use std::path::Path;

use crate::hook::{post_tool, pre_tool, session};
use crate::policy::loader::load_policy_or_defaults;
use crate::threat::killer::terminate_session;
use crate::types::{HookInput, HookOutput};

/// Main hook entry point. Reads JSON from stdin, dispatches to the right handler.
pub fn run(event: &str) -> i32 {
    // Read stdin
    let mut input_str = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input_str) {
        eprintln!("railyard: failed to read stdin: {}", e);
        return 0; // Don't block on read errors
    }

    // Parse input
    let input: HookInput = match serde_json::from_str(&input_str) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("railyard: failed to parse hook input: {}", e);
            return 0; // Don't block on parse errors
        }
    };

    // Load policy
    let cwd = Path::new(&input.cwd);
    let policy = load_policy_or_defaults(cwd);

    // Dispatch
    match event {
        "PreToolUse" => {
            // Self-integrity check: verify hooks haven't been tampered with
            if let Some(output) = check_hook_integrity() {
                if let Ok(json) = serde_json::to_string(&output) {
                    let _ = std::io::stdout().write_all(json.as_bytes());
                    let _ = std::io::stdout().write_all(b"\n");
                    let _ = std::io::stdout().flush();
                }
                eprintln!(
                    "\n\x1b[1;31m⚠️  RAILYARD INTEGRITY VIOLATION\x1b[0m\n\
                     \x1b[31m   Railyard hooks have been removed or modified in ~/.claude/settings.json.\n\
                     \x1b[31m   This may indicate the agent tampered with its own guardrails.\n\
                     \x1b[31m   All tool calls are blocked until hooks are restored.\n\
                     \x1b[31m   Run: railyard install\x1b[0m\n"
                );
                return 0;
            }

            let result = pre_tool::handle(&input, &policy);

            // Write output to stdout
            if let Ok(json) = serde_json::to_string(&result.output) {
                let _ = std::io::stdout().write_all(json.as_bytes());
                let _ = std::io::stdout().write_all(b"\n");
                let _ = std::io::stdout().flush();
            }

            // If termination requested, flush output first then kill
            if let Some(req) = result.terminate {
                let state_dir = cwd.join(".railyard/state");
                let trace_dir = crate::trace::logger::global_trace_dir();
                let mut state = req.state;
                terminate_session(&mut state, &req.tier, &req.command, &state_dir, &trace_dir);
                // terminate_session sends SIGTERM to parent — exit cleanly
                std::process::exit(0);
            }

            0
        }
        "PostToolUse" => {
            post_tool::handle(&input, &policy);
            0
        }
        "SessionStart" => {
            let output = session::handle(&input, &policy);
            if let Ok(json) = serde_json::to_string(&output) {
                let _ = std::io::stdout().write_all(json.as_bytes());
                let _ = std::io::stdout().write_all(b"\n");
                let _ = std::io::stdout().flush();
            }
            0
        }
        _ => {
            eprintln!("railyard: unknown event: {}", event);
            0
        }
    }
}

/// Verify that Railyard's hooks are still present in ~/.claude/settings.json.
/// Returns Some(deny output) if hooks have been tampered with, None if OK.
///
/// Logic: If settings.json has hook entries for OTHER events but NOT PreToolUse
/// with railyard, that indicates tampering (someone selectively removed railyard).
/// If hooks is empty or missing entirely, we assume railyard isn't installed yet
/// (the fact we're running means Claude Code is calling us — don't block).
fn check_hook_integrity() -> Option<HookOutput> {
    let home = dirs::home_dir()?;
    let settings_path = home.join(".claude").join("settings.json");

    let content = std::fs::read_to_string(&settings_path).ok()?;
    let settings: serde_json::Value = serde_json::from_str(&content).ok()?;

    let hooks = match settings.get("hooks").and_then(|h| h.as_object()) {
        Some(h) => h,
        None => return None, // No hooks section — not installed, not tampered
    };

    // If hooks is empty, not installed yet — not tampered
    if hooks.is_empty() {
        return None;
    }

    // Hooks exist but check if railyard is still among them
    let has_railyard = hooks.values().any(|entries| {
        let json_str = serde_json::to_string(entries).unwrap_or_default();
        json_str.contains("railyard")
    });

    if !has_railyard {
        // Hooks exist for other things but railyard was removed — tampering
        return Some(HookOutput::deny(
            "⛔ RAILYARD INTEGRITY VIOLATION: Hooks removed from ~/.claude/settings.json. \
             All tool calls blocked. The agent may have tampered with its own guardrails. \
             Run 'railyard install' to restore protection.",
        ));
    }

    // Railyard hooks present — check PreToolUse specifically
    let has_pre_tool = hooks
        .get("PreToolUse")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter().any(|entry| {
                let json_str = serde_json::to_string(entry).unwrap_or_default();
                json_str.contains("railyard")
            })
        })
        .unwrap_or(false);

    if !has_pre_tool {
        return Some(HookOutput::deny(
            "⛔ RAILYARD INTEGRITY VIOLATION: PreToolUse hook removed from settings.json. \
             All tool calls blocked. Run 'railyard install' to restore protection.",
        ));
    }

    None
}
