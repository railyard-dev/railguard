use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::types::TraceEntry;

/// Return the global trace directory: ~/.railyard/traces
pub fn global_trace_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".railyard")
        .join("traces")
}

/// Append a trace entry to the session log file.
pub fn log_trace(trace_dir: &Path, session_id: &str, entry: &TraceEntry) -> Result<(), String> {
    fs::create_dir_all(trace_dir).map_err(|e| format!("Failed to create trace dir: {}", e))?;

    let log_path = trace_dir.join(format!("{}.jsonl", session_id));
    let line =
        serde_json::to_string(entry).map_err(|e| format!("Failed to serialize trace: {}", e))?;

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|e| format!("Failed to open trace file: {}", e))?;

    writeln!(file, "{}", line).map_err(|e| format!("Failed to write trace: {}", e))?;

    Ok(())
}

/// Read all trace entries for a session.
pub fn read_traces(trace_dir: &Path, session_id: &str) -> Result<Vec<TraceEntry>, String> {
    let log_path = trace_dir.join(format!("{}.jsonl", session_id));
    if !log_path.exists() {
        return Ok(vec![]);
    }

    let contents =
        fs::read_to_string(&log_path).map_err(|e| format!("Failed to read traces: {}", e))?;

    let entries: Vec<TraceEntry> = contents
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();

    Ok(entries)
}

/// List all session IDs with traces.
pub fn list_sessions(trace_dir: &Path) -> Result<Vec<String>, String> {
    if !trace_dir.exists() {
        return Ok(vec![]);
    }

    let mut sessions = vec![];
    let entries =
        fs::read_dir(trace_dir).map_err(|e| format!("Failed to read trace dir: {}", e))?;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "jsonl") {
            if let Some(stem) = path.file_stem() {
                sessions.push(stem.to_string_lossy().to_string());
            }
        }
    }

    sessions.sort();
    Ok(sessions)
}

/// Get a human-readable summary of a trace entry.
pub fn format_trace_entry(entry: &TraceEntry) -> String {
    let icon = match entry.decision.as_str() {
        "block" => "BLOCKED",
        "approve" => "APPROVE",
        "allow" => "  OK   ",
        _ => "  ??   ",
    };

    let rule_str = entry
        .rule
        .as_deref()
        .map(|r| format!(" ({})", r))
        .unwrap_or_default();

    format!(
        "[{}] {} {:>8} | {}: {}{}",
        entry.timestamp, icon, entry.tool, entry.event, entry.input_summary, rule_str
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(decision: &str) -> TraceEntry {
        TraceEntry {
            timestamp: "2026-03-09T12:00:00Z".to_string(),
            session_id: "test-session".to_string(),
            event: "PreToolUse".to_string(),
            tool: "Bash".to_string(),
            input_summary: "terraform destroy".to_string(),
            decision: decision.to_string(),
            rule: Some("no-destroy".to_string()),
            duration_ms: 1,
        }
    }

    #[test]
    fn test_write_and_read_traces() {
        let dir = tempfile::tempdir().unwrap();
        let entry = make_entry("block");

        log_trace(dir.path(), "test-session", &entry).unwrap();
        log_trace(dir.path(), "test-session", &entry).unwrap();

        let traces = read_traces(dir.path(), "test-session").unwrap();
        assert_eq!(traces.len(), 2);
        assert_eq!(traces[0].decision, "block");
    }

    #[test]
    fn test_list_sessions() {
        let dir = tempfile::tempdir().unwrap();
        let entry = make_entry("allow");

        log_trace(dir.path(), "session-a", &entry).unwrap();
        log_trace(dir.path(), "session-b", &entry).unwrap();

        let sessions = list_sessions(dir.path()).unwrap();
        assert_eq!(sessions.len(), 2);
    }

    #[test]
    fn test_format_trace_entry() {
        let entry = make_entry("block");
        let formatted = format_trace_entry(&entry);
        assert!(formatted.contains("BLOCKED"));
        assert!(formatted.contains("terraform destroy"));
    }
}
