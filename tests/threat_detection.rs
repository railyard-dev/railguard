/// Threat Detection Integration Tests
///
/// Tests the "Ask the Human" system:
/// - Tier 1: Ask user on unambiguous evasion, allow if approved
/// - Tier 2: Warning on first occurrence, ask on second
/// - Tier 3: Behavioral retry detection — ask, then allow if approved
/// - Session approvals persist within a session
/// - Session state persistence

use std::io::Write;
use std::process::Command;
use tempfile::TempDir;

fn railguard_binary() -> String {
    let mut path = std::env::current_dir().unwrap();
    path.push("target/debug/railguard");
    path.to_str().unwrap().to_string()
}

fn create_test_dir() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    let yaml = "version: 1\nblocklist: []\ntrace:\n  enabled: true\n  directory: .railguard/traces";
    let policy_path = dir.path().join("railguard.yaml");
    std::fs::write(&policy_path, yaml).unwrap();
    dir
}

fn simulate_hook(binary: &str, event: &str, input_json: &str) -> (i32, String, String) {
    let output = Command::new(binary)
        .arg("hook")
        .arg("--event")
        .arg(event)
        .env("RAILGUARD_NO_KILL", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            if let Some(ref mut stdin) = child.stdin {
                stdin.write_all(input_json.as_bytes()).ok();
            }
            child.wait_with_output()
        })
        .unwrap();

    let code = output.status.code().unwrap_or(0);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (code, stdout, stderr)
}

fn make_bash_input(session_id: &str, cwd: &str, command: &str) -> String {
    serde_json::json!({
        "session_id": session_id,
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
        "tool_use_id": "test-001"
    })
    .to_string()
}

fn output_contains_deny(stdout: &str) -> bool {
    stdout.contains("\"deny\"")
}

fn output_contains_ask(stdout: &str) -> bool {
    stdout.contains("\"ask\"")
}

fn output_is_not_allowed(stdout: &str) -> bool {
    stdout.contains("\"deny\"") || stdout.contains("\"ask\"")
}

// ═══════════════════════════════════════════════════════════════════
// TIER 1: Evasion detected — asks user for approval
// ═══════════════════════════════════════════════════════════════════

#[test]
fn tier1_rev_pipe_sh_asks_user() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();

    let input = make_bash_input("tier1-rev", cwd, "rev <<< 'yortsed mrofarret' | sh");
    let (_, stdout, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input);

    assert!(output_contains_ask(&stdout), "should ask user for approval: {}", stdout);
    assert!(stdout.contains("RAILGUARD"), "should mention RAILGUARD: {}", stdout);

    // State file should have a pending approval
    let state_path = dir.path().join(".railguard/state/tier1-rev.json");
    assert!(state_path.exists(), "state file should be created");
    let state: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&state_path).unwrap()
    ).unwrap();
    assert!(!state["terminated"].as_bool().unwrap_or(false), "should NOT terminate");
    assert!(state["pending_approval"].is_string(), "should have pending approval");
}

#[test]
fn tier1_double_base64_asks_user() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();

    let input = make_bash_input(
        "tier1-b64",
        cwd,
        "echo abc123 | base64 -d | base64 -d | sh",
    );
    let (_, stdout, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input);
    assert!(output_contains_ask(&stdout), "should ask user: {}", stdout);
}

#[test]
fn tier1_python_chr_asks_user() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();

    let input = make_bash_input(
        "tier1-chr",
        cwd,
        r#"python3 -c "import os; os.system(chr(114)+chr(109))""#,
    );
    let (_, stdout, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input);
    assert!(output_contains_ask(&stdout), "should ask user: {}", stdout);
}

#[test]
fn tier1_printf_hex_asks_user() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();

    let input = make_bash_input(
        "tier1-hex",
        cwd,
        r"$(printf '\x72\x6d') -rf /tmp/something",
    );
    let (_, stdout, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input);
    assert!(output_contains_ask(&stdout), "should ask user: {}", stdout);
}

// ═══════════════════════════════════════════════════════════════════
// TIER 1: Approval persists within session
// ═══════════════════════════════════════════════════════════════════

#[test]
fn tier1_approval_allows_subsequent_same_pattern() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();

    // First call: should ask
    let input1 = make_bash_input("tier1-approve", cwd, "rev <<< 'test' | sh");
    let (_, stdout1, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input1);
    assert!(output_contains_ask(&stdout1), "first should ask: {}", stdout1);

    // Simulate user approval by making a subsequent call
    // (resolve_pending_approval runs at start of next call)
    // The next call with a similar Tier 1 pattern should be allowed
    let input2 = make_bash_input("tier1-approve", cwd, "rev <<< 'another' | sh");
    let (_, stdout2, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input2);
    assert!(!output_contains_deny(&stdout2), "second should be allowed after approval: {}", stdout2);
    assert!(!output_contains_ask(&stdout2), "should not ask again: {}", stdout2);
}

// ═══════════════════════════════════════════════════════════════════
// TIER 2: Escalating — warn first, ask on second
// ═══════════════════════════════════════════════════════════════════

#[test]
fn tier2_first_occurrence_warns() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();

    // First: variable-then-execution — should warn but NOT ask/terminate
    let input = make_bash_input("tier2-warn", cwd, r#"CMD="ls -la"; $CMD"#);
    let (_, stdout, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input);

    assert!(
        !output_contains_ask(&stdout),
        "first Tier 2 should not ask: {}",
        stdout
    );
    assert!(
        !output_contains_deny(&stdout),
        "first Tier 2 should not deny: {}",
        stdout
    );
}

#[test]
fn tier2_second_occurrence_asks_user() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();

    // First occurrence — warning
    let input1 = make_bash_input("tier2-ask", cwd, r#"CMD="ls -la"; $CMD"#);
    let (_, stdout1, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input1);
    assert!(
        !output_contains_ask(&stdout1),
        "first should not ask"
    );

    // Second occurrence — should ask user
    let input2 = make_bash_input("tier2-ask", cwd, r#"X="echo hello"; $X"#);
    let (_, stdout2, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input2);
    assert!(
        output_contains_ask(&stdout2),
        "second Tier 2 should ask user: {}",
        stdout2
    );
}

// ═══════════════════════════════════════════════════════════════════
// TIER 3: Behavioral retry detection
// ═══════════════════════════════════════════════════════════════════

#[test]
fn tier3_retry_after_block_asks_user() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();

    // Step 1: Run terraform destroy — gets blocked by policy
    let input1 = make_bash_input("tier3-retry", cwd, "terraform destroy");
    let (_, stdout1, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input1);
    assert!(output_contains_deny(&stdout1), "terraform destroy should be blocked");

    // Step 2: Try again with same keywords — behavioral evasion detected, asks user
    let input2 = make_bash_input("tier3-retry", cwd, "terraform apply -destroy");
    let (_, stdout2, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input2);
    assert!(output_is_not_allowed(&stdout2), "retry should be caught: {}", stdout2);
}

// ═══════════════════════════════════════════════════════════════════
// SESSION STATE PERSISTENCE
// ═══════════════════════════════════════════════════════════════════

#[test]
fn state_persists_across_invocations() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();

    // First call
    let input1 = make_bash_input("persist-test", cwd, "echo hello");
    simulate_hook(&railguard_binary(), "PreToolUse", &input1);

    // State file should exist
    let state_path = dir.path().join(".railguard/state/persist-test.json");
    assert!(state_path.exists(), "state file should be created");

    let state1: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    assert_eq!(state1["tool_call_count"], 1);

    // Second call
    let input2 = make_bash_input("persist-test", cwd, "echo world");
    simulate_hook(&railguard_binary(), "PreToolUse", &input2);

    let state2: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    assert_eq!(state2["tool_call_count"], 2);
}

#[test]
fn session_approvals_persist_in_state() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();

    // Trigger a Tier 1 ask
    let input1 = make_bash_input("approval-persist", cwd, "rev <<< 'test' | sh");
    let (_, stdout1, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input1);
    assert!(output_contains_ask(&stdout1));

    // State should have pending_approval
    let state_path = dir.path().join(".railguard/state/approval-persist.json");
    let state1: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    assert!(state1["pending_approval"].is_string());

    // Next call resolves the pending approval
    let input2 = make_bash_input("approval-persist", cwd, "echo safe");
    simulate_hook(&railguard_binary(), "PreToolUse", &input2);

    let state2: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    assert!(state2["pending_approval"].is_null(), "pending should be resolved");
    assert!(
        state2["session_approvals"].as_array().unwrap().len() > 0,
        "should have session approvals"
    );
}

// ═══════════════════════════════════════════════════════════════════
// SAFE COMMANDS NOT AFFECTED
// ═══════════════════════════════════════════════════════════════════

#[test]
fn normal_commands_unaffected_by_threat_system() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();

    let safe_commands = [
        "npm test",
        "cargo build --release",
        "git status",
        "ls -la",
        "python3 -c \"print('hello')\"",
        "echo hello | grep hello",
    ];

    for cmd in &safe_commands {
        let input = make_bash_input("safe-test", cwd, cmd);
        let (_, stdout, _) = simulate_hook(&railguard_binary(), "PreToolUse", &input);
        assert!(
            !output_is_not_allowed(&stdout),
            "'{}' should not trigger threat detection: {}",
            cmd,
            stdout
        );
    }
}
