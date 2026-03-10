use serde::{Deserialize, Serialize};

// ── Hook Input (what Claude Code sends on stdin) ──

#[derive(Debug, Clone, Deserialize)]
pub struct HookInput {
    pub session_id: String,
    pub cwd: String,
    pub hook_event_name: String,
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub tool_input: Option<serde_json::Value>,
    #[serde(default)]
    pub tool_use_id: Option<String>,
    #[serde(default)]
    pub tool_response: Option<serde_json::Value>,
    #[serde(default)]
    pub timestamp: Option<String>,
}

// ── Hook Output (what we write to stdout) ──

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HookOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hook_specific_output: Option<HookSpecificOutput>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HookSpecificOutput {
    pub hook_event_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_decision_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

impl HookOutput {
    pub fn allow() -> Self {
        HookOutput {
            hook_specific_output: None,
        }
    }

    pub fn deny(reason: &str) -> Self {
        HookOutput {
            hook_specific_output: Some(HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: Some("deny".to_string()),
                permission_decision_reason: Some(reason.to_string()),
                additional_context: None,
            }),
        }
    }

    pub fn ask(context: &str) -> Self {
        HookOutput {
            hook_specific_output: Some(HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: Some("ask".to_string()),
                permission_decision_reason: None,
                additional_context: Some(context.to_string()),
            }),
        }
    }
}

// ── Policy Types ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Policy {
    #[serde(default = "default_version")]
    pub version: u32,
    /// "chill" (default) or "hardcore"
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default)]
    pub blocklist: Vec<Rule>,
    #[serde(default)]
    pub approve: Vec<Rule>,
    #[serde(default)]
    pub allowlist: Vec<Rule>,
    #[serde(default)]
    pub fence: FenceConfig,
    #[serde(default)]
    pub trace: TraceConfig,
    #[serde(default)]
    pub snapshot: SnapshotConfig,
}

fn default_mode() -> String {
    "chill".to_string()
}

fn default_version() -> u32 {
    1
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rule {
    pub name: String,
    #[serde(default = "default_tool")]
    pub tool: String,
    pub pattern: String,
    #[serde(default = "default_action")]
    pub action: String,
    #[serde(default)]
    pub message: Option<String>,
}

fn default_tool() -> String {
    "Bash".to_string()
}

fn default_action() -> String {
    "block".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FenceConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub allowed_paths: Vec<String>,
    #[serde(default)]
    pub denied_paths: Vec<String>,
}

impl Default for FenceConfig {
    fn default() -> Self {
        FenceConfig {
            enabled: true,
            allowed_paths: vec![],
            denied_paths: vec![
                "~/.ssh".to_string(),
                "~/.aws".to_string(),
                "~/.gnupg".to_string(),
                "~/.config/gcloud".to_string(),
                "~/.claude".to_string(),
                "/etc".to_string(),
                "/usr".to_string(),
                "/System".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TraceConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_trace_dir")]
    pub directory: String,
}

impl Default for TraceConfig {
    fn default() -> Self {
        TraceConfig {
            enabled: true,
            directory: default_trace_dir(),
        }
    }
}

fn default_trace_dir() -> String {
    ".railyard/traces".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SnapshotConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_snapshot_tools")]
    pub tools: Vec<String>,
    #[serde(default = "default_snapshot_dir")]
    pub directory: String,
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        SnapshotConfig {
            enabled: true,
            tools: default_snapshot_tools(),
            directory: default_snapshot_dir(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_snapshot_tools() -> Vec<String> {
    vec!["Write".to_string(), "Edit".to_string()]
}

fn default_snapshot_dir() -> String {
    ".railyard/snapshots".to_string()
}

// ── Trace Entry ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEntry {
    pub timestamp: String,
    pub session_id: String,
    pub event: String,
    pub tool: String,
    pub input_summary: String,
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    pub duration_ms: u64,
}

// ── Snapshot Manifest Entry ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotEntry {
    pub id: String,
    pub timestamp: String,
    pub session_id: String,
    pub tool_use_id: String,
    pub file_path: String,
    pub hash: String,
    pub existed: bool,
}

// ── Decision (internal) ──

#[derive(Debug, Clone)]
pub enum Decision {
    Allow,
    Block { rule: String, message: String },
    Approve { rule: String, message: String },
}
