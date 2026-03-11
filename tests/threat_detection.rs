/// Threat Detection Integration Tests
///
/// Tests the "Interrupt the Human" system:
/// - Tier 1: Immediate session termination on unambiguous evasion
/// - Tier 2: Warning on first occurrence, termination on second
/// - Tier 3: Behavioral retry detection
/// - Forensic breadcrumbs
/// - Session state persistence

use std::io::Write;
use std::process::Command;
use tempfile::TempDir;

fn railyard_binary() -> String {
    let mut path = std::env::current_dir().unwrap();
    path.push("target/debug/railyard");
    path.to_str().unwrap().to_string()
}

fn create_test_dir() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    let yaml = "version: 1\nblocklist: []\ntrace:\n  enabled: true\n  directory: .railyard/traces";
    let policy_path = dir.path().join("railyard.yaml");
    std::fs::write(&policy_path, yaml).unwrap();
    dir
}

fn simulate_hook(binary: &str, event: &str, input_json: &str) -> (i32, String, String) {
    let output = Command::new(binary)
        .arg("hook")
        .arg("--event")
        .arg(event)
        .env("RAILYARD_NO_KILL", "1")
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
    stdout.contains("\"deny\"") || stdout.contains("permissionDecision")
}

fn output_contains_critical(stdout: &str) -> bool {
    stdout.contains("CRITICAL") || stdout.contains("terminated")
}

// ═══════════════════════════════════════════════════════════════════
// TIER 1: Immediate session termination
// ═══════════════════════════════════════════════════════════════════

#[test]
fn tier1_rev_pipe_sh_terminates() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();

    let input = make_bash_input("tier1-rev", cwd, "rev <<< 'yortsed mrofarret' | sh");
    let (_, stdout, stderr) = simulate_hook(&railyard_binary(), "PreToolUse", &input);

    assert!(output_contains_deny(&stdout), "should deny");
    assert!(output_contains_critical(&stdout), "should indicate CRITICAL");
    assert!(stderr.contains("TERMINATED") || stderr.contains("terminated") || stderr.contains("SESSION"),
        "stderr should mention termination: {}", stderr);

    // State file should exist and be marked terminated
    let state_path = dir.path().join(".railyard/state/tier1-rev.json");
    assert!(state_path.exists(), "state file should be created");
    let state: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&state_path).unwrap()
    ).unwrap();
    assert_eq!(state["terminated"], true, "state should be terminated");
}

#[test]
fn tier1_double_base64_terminates() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();

    let input = make_bash_input(
        "tier1-b64",
        cwd,
        "echo abc123 | base64 -d | base64 -d | sh",
    );
    let (_, stdout, _) = simulate_hook(&railyard_binary(), "PreToolUse", &input);
    assert!(output_contains_deny(&stdout));
    assert!(output_contains_critical(&stdout));
}

#[test]
fn tier1_python_chr_terminates() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();

    let input = make_bash_input(
        "tier1-chr",
        cwd,
        r#"python3 -c "import os; os.system(chr(114)+chr(109))""#,
    );
    let (_, stdout, _) = simulate_hook(&railyard_binary(), "PreToolUse", &input);
    assert!(output_contains_deny(&stdout));
    assert!(output_contains_critical(&stdout));
}

#[test]
fn tier1_printf_hex_terminates() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();

    let input = make_bash_input(
        "tier1-hex",
        cwd,
        r"$(printf '\x72\x6d') -rf /tmp/something",
    );
    let (_, stdout, _) = simulate_hook(&railyard_binary(), "PreToolUse", &input);
    assert!(output_contains_deny(&stdout));
    assert!(output_contains_critical(&stdout));
}

// ═══════════════════════════════════════════════════════════════════
// TIER 2: Escalating — warn first, kill on second
// ═══════════════════════════════════════════════════════════════════

#[test]
fn tier2_first_occurrence_warns() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();

    // First: variable-then-execution — should warn but NOT terminate
    let input = make_bash_input("tier2-warn", cwd, r#"CMD="ls -la"; $CMD"#);
    let (_, stdout, _) = simulate_hook(&railyard_binary(), "PreToolUse", &input);

    // Should NOT contain CRITICAL (first occurrence = warning only)
    assert!(
        !output_contains_critical(&stdout),
        "first Tier 2 should not terminate: {}",
        stdout
    );
}

#[test]
fn tier2_second_occurrence_terminates() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();

    // First occurrence — warning
    let input1 = make_bash_input("tier2-kill", cwd, r#"CMD="ls -la"; $CMD"#);
    let (_, stdout1, _) = simulate_hook(&railyard_binary(), "PreToolUse", &input1);
    assert!(
        !output_contains_critical(&stdout1),
        "first should not terminate"
    );

    // Second occurrence — should terminate
    let input2 = make_bash_input("tier2-kill", cwd, r#"X="echo hello"; $X"#);
    let (_, stdout2, _) = simulate_hook(&railyard_binary(), "PreToolUse", &input2);
    assert!(
        output_contains_critical(&stdout2),
        "second Tier 2 should terminate: {}",
        stdout2
    );
}

// ═══════════════════════════════════════════════════════════════════
// TIER 3: Behavioral retry detection
// ═══════════════════════════════════════════════════════════════════

#[test]
fn tier3_retry_after_block_terminates() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();

    // Step 1: Run terraform destroy — gets blocked by policy
    let input1 = make_bash_input("tier3-retry", cwd, "terraform destroy");
    let (_, stdout1, _) = simulate_hook(&railyard_binary(), "PreToolUse", &input1);
    assert!(output_contains_deny(&stdout1), "terraform destroy should be blocked");

    // Step 2: Try again with same keywords — behavioral evasion detected
    let input2 = make_bash_input("tier3-retry", cwd, "terraform apply -destroy");
    let (_, stdout2, _) = simulate_hook(&railyard_binary(), "PreToolUse", &input2);
    // Should be blocked (either by policy or behavioral detection)
    assert!(output_contains_deny(&stdout2), "retry should be caught: {}", stdout2);
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
    simulate_hook(&railyard_binary(), "PreToolUse", &input1);

    // State file should exist
    let state_path = dir.path().join(".railyard/state/persist-test.json");
    assert!(state_path.exists(), "state file should be created");

    let state1: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    assert_eq!(state1["tool_call_count"], 1);

    // Second call
    let input2 = make_bash_input("persist-test", cwd, "echo world");
    simulate_hook(&railyard_binary(), "PreToolUse", &input2);

    let state2: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    assert_eq!(state2["tool_call_count"], 2);
}

#[test]
fn terminated_session_blocks_all_subsequent() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();

    // Trigger Tier 1 termination
    let input1 = make_bash_input("dead-session", cwd, "rev <<< 'test' | sh");
    let (_, stdout1, _) = simulate_hook(&railyard_binary(), "PreToolUse", &input1);
    assert!(output_contains_critical(&stdout1));

    // Subsequent safe command should still be blocked
    let input2 = make_bash_input("dead-session", cwd, "echo hello");
    let (_, stdout2, _) = simulate_hook(&railyard_binary(), "PreToolUse", &input2);
    assert!(
        output_contains_deny(&stdout2),
        "terminated session should block all commands: {}",
        stdout2
    );
}

// ═══════════════════════════════════════════════════════════════════
// FORENSIC BREADCRUMBS
// ═══════════════════════════════════════════════════════════════════

#[test]
fn termination_creates_trace_entry() {
    let dir = create_test_dir();
    let cwd = dir.path().to_str().unwrap();
    let session_id = format!("forensic-test-{}", std::process::id());

    let input = make_bash_input(&session_id, cwd, "rev <<< 'test' | sh");
    simulate_hook(&railyard_binary(), "PreToolUse", &input);

    let global_trace_dir = std::path::PathBuf::from(std::env::var("HOME").unwrap()).join(".railyard/traces");
    let trace_path = global_trace_dir.join(format!("{}.jsonl", session_id));
    assert!(trace_path.exists(), "trace file should exist");

    let content = std::fs::read_to_string(&trace_path).unwrap();
    assert!(
        content.contains("SessionTerminated"),
        "trace should contain SessionTerminated event: {}",
        content
    );

    // Clean up
    let _ = std::fs::remove_file(&trace_path);
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
        let (_, stdout, _) = simulate_hook(&railyard_binary(), "PreToolUse", &input);
        assert!(
            !output_contains_critical(&stdout),
            "'{}' should not trigger threat detection: {}",
            cmd,
            stdout
        );
    }
}
