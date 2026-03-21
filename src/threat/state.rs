use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Persistent session state for threat detection.
/// Stored at `.railguard/state/{session_id}.json`.
/// Each hook invocation loads, modifies, and saves this state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    pub session_id: String,
    pub tool_call_count: u64,
    pub suspicion_level: u32, // 0=normal, 1=warned, 2=heightened
    pub warning_count: u32,
    pub block_history: Vec<BlockEvent>,
    /// Tool call count at which heightened mode expires
    pub heightened_until_call: Option<u64>,
    /// Keywords to watch for during heightened state
    pub heightened_keywords: Vec<String>,
    /// Threat patterns the user has approved for this session.
    /// Once approved, the same pattern won't prompt again.
    #[serde(default)]
    pub session_approvals: Vec<String>,
    /// Pattern currently awaiting user approval via "ask".
    /// If the next tool call arrives (meaning user approved), we move this to session_approvals.
    #[serde(default)]
    pub pending_approval: Option<String>,
    pub terminated: bool,
    pub termination_reason: Option<String>,
    pub termination_timestamp: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockEvent {
    pub timestamp: String,
    pub tool_call_count: u64,
    pub command: String,
    pub rule: String,
    pub keywords: Vec<String>,
    pub tier: u8,
}

impl SessionState {
    pub fn new(session_id: &str) -> Self {
        SessionState {
            session_id: session_id.to_string(),
            tool_call_count: 0,
            suspicion_level: 0,
            warning_count: 0,
            block_history: Vec::new(),
            heightened_until_call: None,
            heightened_keywords: Vec::new(),
            session_approvals: Vec::new(),
            pending_approval: None,
            terminated: false,
            termination_reason: None,
            termination_timestamp: None,
        }
    }

    fn state_path(state_dir: &Path, session_id: &str) -> PathBuf {
        state_dir.join(format!("{}.json", session_id))
    }

    pub fn load(state_dir: &Path, session_id: &str) -> Self {
        let path = Self::state_path(state_dir, session_id);
        if path.exists() {
            if let Ok(data) = fs::read_to_string(&path) {
                if let Ok(state) = serde_json::from_str::<SessionState>(&data) {
                    return state;
                }
            }
        }
        Self::new(session_id)
    }

    /// Atomic save: write to .tmp then rename.
    pub fn save(&self, state_dir: &Path) -> Result<(), String> {
        fs::create_dir_all(state_dir).map_err(|e| format!("create state dir: {}", e))?;

        let path = Self::state_path(state_dir, &self.session_id);
        let tmp_path = path.with_extension("json.tmp");

        let data = serde_json::to_string_pretty(self)
            .map_err(|e| format!("serialize state: {}", e))?;

        fs::write(&tmp_path, data).map_err(|e| format!("write state: {}", e))?;
        fs::rename(&tmp_path, &path).map_err(|e| format!("rename state: {}", e))?;

        Ok(())
    }

    pub fn increment_tool_call(&mut self) {
        self.tool_call_count += 1;
    }

    pub fn record_block(&mut self, command: &str, rule: &str, keywords: Vec<String>, tier: u8) {
        self.block_history.push(BlockEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            tool_call_count: self.tool_call_count,
            command: command.chars().take(500).collect(),
            rule: rule.to_string(),
            keywords: keywords.clone(),
            tier,
        });

        // Enter heightened state: watch for keywords in next 3 tool calls
        self.heightened_until_call = Some(self.tool_call_count + 3);
        self.heightened_keywords = keywords;
    }

    pub fn record_warning(&mut self) {
        self.warning_count += 1;
        if self.suspicion_level < 1 {
            self.suspicion_level = 1;
        }
    }

    pub fn is_in_heightened_state(&self) -> bool {
        if let Some(until) = self.heightened_until_call {
            self.tool_call_count <= until
        } else {
            false
        }
    }

    /// Resolve any pending approval. Called at the start of each tool call.
    /// If we asked the user last time and a new tool call arrived, the user approved.
    pub fn resolve_pending_approval(&mut self) {
        if let Some(pattern) = self.pending_approval.take() {
            if !self.session_approvals.contains(&pattern) {
                self.session_approvals.push(pattern);
            }
        }
    }

    /// Check if a threat pattern has been approved by the user this session.
    pub fn is_approved(&self, pattern: &str) -> bool {
        self.session_approvals.iter().any(|p| p == pattern)
    }

    /// Set a pattern as pending user approval.
    pub fn set_pending_approval(&mut self, pattern: &str) {
        self.pending_approval = Some(pattern.to_string());
    }

    pub fn mark_terminated(&mut self, reason: &str) {
        self.terminated = true;
        self.termination_reason = Some(reason.to_string());
        self.termination_timestamp = Some(chrono::Utc::now().to_rfc3339());
    }

    /// Check all state files for recently terminated sessions.
    pub fn find_recent_terminations(state_dir: &Path) -> Vec<SessionState> {
        let mut terminated = Vec::new();

        if let Ok(entries) = fs::read_dir(state_dir) {
            for entry in entries.flatten() {
                if let Ok(data) = fs::read_to_string(entry.path()) {
                    if let Ok(state) = serde_json::from_str::<SessionState>(&data) {
                        if state.terminated {
                            terminated.push(state);
                        }
                    }
                }
            }
        }

        terminated
    }

    /// Clean up state files older than 24 hours.
    pub fn cleanup_old_states(state_dir: &Path) {
        if let Ok(entries) = fs::read_dir(state_dir) {
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata() {
                    if let Ok(modified) = meta.modified() {
                        if let Ok(age) = modified.elapsed() {
                            if age.as_secs() > 86400 {
                                let _ = fs::remove_file(entry.path());
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_state() {
        let state = SessionState::new("test-123");
        assert_eq!(state.session_id, "test-123");
        assert_eq!(state.tool_call_count, 0);
        assert!(!state.terminated);
    }

    #[test]
    fn test_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = SessionState::new("save-test");
        state.tool_call_count = 5;
        state.warning_count = 2;
        state.save(dir.path()).unwrap();

        let loaded = SessionState::load(dir.path(), "save-test");
        assert_eq!(loaded.tool_call_count, 5);
        assert_eq!(loaded.warning_count, 2);
    }

    #[test]
    fn test_heightened_state() {
        let mut state = SessionState::new("heightened");
        state.tool_call_count = 10;
        assert!(!state.is_in_heightened_state());

        state.record_block("terraform destroy", "terraform-destroy", vec!["terraform".into(), "destroy".into()], 1);
        assert!(state.is_in_heightened_state());

        // Still heightened at call 12 (10 + 3 = 13)
        state.tool_call_count = 12;
        assert!(state.is_in_heightened_state());

        // No longer heightened at call 14
        state.tool_call_count = 14;
        assert!(!state.is_in_heightened_state());
    }

    #[test]
    fn test_terminated_state() {
        let mut state = SessionState::new("terminated");
        state.mark_terminated("evasion detected: rev | sh");
        assert!(state.terminated);
        assert!(state.termination_reason.as_deref().unwrap().contains("rev | sh"));
    }
}
