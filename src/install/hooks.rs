use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

/// Get the path to Claude Code's user settings file.
pub fn claude_settings_path() -> PathBuf {
    let home = dirs::home_dir().expect("Could not determine home directory");
    home.join(".claude").join("settings.json")
}

/// Get the path to the railyard binary.
fn railyard_binary_path() -> String {
    std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "railyard".to_string())
}

/// Get the path to the railyard-shell binary (sibling of the railyard binary).
fn railyard_shell_path() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|dir| dir.join("railyard-shell")))
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "railyard-shell".to_string())
}

/// The CLAUDE.md content that teaches Claude about Railyard.
const CLAUDE_MD_CONTENT: &str = include_str!("../../defaults/CLAUDE.md");

/// Marker used to identify Railyard's section in CLAUDE.md.
const CLAUDE_MD_MARKER_START: &str = "<!-- railyard:start -->";
const CLAUDE_MD_MARKER_END: &str = "<!-- railyard:end -->";

/// Enable "dangerously skip permissions" (bypass mode) in Claude Code settings.
/// Railyard replaces the built-in permission system, so bypass mode is safe.
pub fn enable_bypass_permissions() -> Result<String, String> {
    let settings_path = claude_settings_path();
    let mut settings = read_settings(&settings_path)?;

    let root = settings
        .as_object_mut()
        .ok_or("Settings is not a JSON object")?;

    let permissions = root
        .entry("permissions")
        .or_insert_with(|| json!({}));

    let perms_obj = permissions
        .as_object_mut()
        .ok_or("permissions is not a JSON object")?;

    perms_obj.insert(
        "defaultMode".to_string(),
        json!("bypassPermissions"),
    );

    write_settings(&settings_path, &settings)?;

    Ok("Enabled bypass permissions mode in Claude Code".to_string())
}

/// Disable bypass permissions mode when Railyard is uninstalled.
/// Without Railyard, the user should go back to Claude Code's built-in permissions.
pub fn disable_bypass_permissions() -> Result<String, String> {
    let settings_path = claude_settings_path();
    if !settings_path.exists() {
        return Ok("No settings to restore".to_string());
    }

    let mut settings = read_settings(&settings_path)?;

    if let Some(perms) = settings
        .get_mut("permissions")
        .and_then(|p| p.as_object_mut())
    {
        // Only remove if it's set to bypassPermissions (don't touch other modes)
        if perms.get("defaultMode").and_then(|v| v.as_str()) == Some("bypassPermissions") {
            perms.remove("defaultMode");
        }
        if perms.is_empty() {
            settings.as_object_mut().unwrap().remove("permissions");
        }
    }

    write_settings(&settings_path, &settings)?;

    Ok("Disabled bypass permissions mode".to_string())
}

/// Install railyard hooks into Claude Code settings.
pub fn install_hooks() -> Result<String, String> {
    let settings_path = claude_settings_path();
    let mut settings = read_settings(&settings_path)?;
    let binary = railyard_binary_path();

    let hooks = settings
        .as_object_mut()
        .ok_or("Settings is not a JSON object")?
        .entry("hooks")
        .or_insert_with(|| json!({}));

    let hooks_obj = hooks
        .as_object_mut()
        .ok_or("hooks is not a JSON object")?;

    // PreToolUse hook — blocks/approves/traces before execution
    let pre_hook = json!([{
        "matcher": "",
        "hooks": [{
            "type": "command",
            "command": format!("{} hook --event PreToolUse", binary),
            "timeout": 5
        }]
    }]);

    // PostToolUse hook — traces results, captures snapshots
    let post_hook = json!([{
        "matcher": "",
        "hooks": [{
            "type": "command",
            "command": format!("{} hook --event PostToolUse", binary),
            "timeout": 5
        }]
    }]);

    // SessionStart hook — initializes session logging
    let session_hook = json!([{
        "matcher": "",
        "hooks": [{
            "type": "command",
            "command": format!("{} hook --event SessionStart", binary),
            "timeout": 5
        }]
    }]);

    hooks_obj.insert("PreToolUse".to_string(), pre_hook);
    hooks_obj.insert("PostToolUse".to_string(), post_hook);
    hooks_obj.insert("SessionStart".to_string(), session_hook);

    // Set CLAUDE_CODE_SHELL to railyard-shell for OS-level sandboxing.
    // This makes every Bash tool call run through our sandboxed shell.
    let shell_binary = railyard_shell_path();
    if std::path::Path::new(&shell_binary).exists() {
        let env_obj = settings
            .as_object_mut()
            .unwrap()
            .entry("env")
            .or_insert_with(|| json!({}));

        if let Some(env_map) = env_obj.as_object_mut() {
            env_map.insert(
                "CLAUDE_CODE_SHELL".to_string(),
                json!(shell_binary),
            );
        }
    }

    write_settings(&settings_path, &settings)?;

    // Inject CLAUDE.md so Claude knows about Railyard
    let claude_md_msg = inject_claude_md()?;

    let sandbox_msg = if std::path::Path::new(&shell_binary).exists() {
        format!("\n  ✓ OS sandbox shell: {}", shell_binary)
    } else {
        "\n  ● OS sandbox: railyard-shell not found (run cargo install to build)".to_string()
    };

    Ok(format!(
        "Installed railyard hooks in {}\n  {} {}{}",
        settings_path.display(),
        "✓",
        claude_md_msg,
        sandbox_msg
    ))
}

/// Inject Railyard instructions into the user's CLAUDE.md file.
/// This teaches Claude Code about rollback, context, and what's blocked.
fn inject_claude_md() -> Result<String, String> {
    let home = dirs::home_dir().ok_or("Could not determine home directory")?;
    let claude_md_path = home.join(".claude").join("CLAUDE.md");

    let marked_content = format!(
        "{}\n{}\n{}",
        CLAUDE_MD_MARKER_START, CLAUDE_MD_CONTENT, CLAUDE_MD_MARKER_END
    );

    if claude_md_path.exists() {
        let existing = fs::read_to_string(&claude_md_path)
            .map_err(|e| format!("Failed to read CLAUDE.md: {}", e))?;

        if existing.contains(CLAUDE_MD_MARKER_START) {
            // Replace existing railyard section
            let before = existing
                .split(CLAUDE_MD_MARKER_START)
                .next()
                .unwrap_or("");
            let after = existing
                .split(CLAUDE_MD_MARKER_END)
                .nth(1)
                .unwrap_or("");

            let updated = format!("{}{}{}", before.trim_end(), marked_content, after);
            fs::write(&claude_md_path, updated.trim().to_string() + "\n")
                .map_err(|e| format!("Failed to update CLAUDE.md: {}", e))?;

            return Ok("Updated Railyard instructions in ~/.claude/CLAUDE.md".to_string());
        }

        // Append to existing file
        let updated = format!("{}\n\n{}\n", existing.trim_end(), marked_content);
        fs::write(&claude_md_path, updated)
            .map_err(|e| format!("Failed to update CLAUDE.md: {}", e))?;

        Ok("Added Railyard instructions to ~/.claude/CLAUDE.md".to_string())
    } else {
        // Create new file
        if let Some(parent) = claude_md_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create ~/.claude dir: {}", e))?;
        }
        fs::write(&claude_md_path, format!("{}\n", marked_content))
            .map_err(|e| format!("Failed to create CLAUDE.md: {}", e))?;

        Ok("Created ~/.claude/CLAUDE.md with Railyard instructions".to_string())
    }
}

/// Remove railyard hooks from Claude Code settings.
/// Requires explicit human confirmation via a native OS dialog.
pub fn uninstall_hooks() -> Result<String, String> {
    // Check if running interactively (a TTY is attached)
    // Agents pipe stdin, so this catches most automated attempts
    if !is_interactive_terminal() {
        return Err("Railyard can only be uninstalled from an interactive terminal.\n  \
                    This prevents AI agents from removing their own guardrails."
            .to_string());
    }

    // Show native OS confirmation dialog — requires a real human to click through
    if !show_uninstall_confirmation()? {
        return Err("Uninstall cancelled by user".to_string());
    }

    let settings_path = claude_settings_path();

    if !settings_path.exists() {
        return Ok("No Claude Code settings found, nothing to uninstall".to_string());
    }

    let mut settings = read_settings(&settings_path)?;

    if let Some(hooks) = settings.get_mut("hooks").and_then(|h| h.as_object_mut()) {
        // Remove only hooks that reference railyard
        for event in &["PreToolUse", "PostToolUse", "SessionStart"] {
            if let Some(event_hooks) = hooks.get_mut(*event) {
                if let Some(arr) = event_hooks.as_array_mut() {
                    arr.retain(|entry| {
                        let is_railyard = entry
                            .pointer("/hooks/0/command")
                            .and_then(|c| c.as_str())
                            .is_some_and(|c| c.contains("railyard"));
                        !is_railyard
                    });
                    if arr.is_empty() {
                        hooks.remove(*event);
                    }
                }
            }
        }
    }

    // Remove CLAUDE_CODE_SHELL from env section
    if let Some(env_obj) = settings.get_mut("env").and_then(|e| e.as_object_mut()) {
        env_obj.remove("CLAUDE_CODE_SHELL");
        if env_obj.is_empty() {
            settings.as_object_mut().unwrap().remove("env");
        }
    }

    write_settings(&settings_path, &settings)?;

    // Disable bypass permissions — without Railyard, use built-in permissions
    let _ = disable_bypass_permissions();

    // Clean up CLAUDE.md
    remove_claude_md_section();

    Ok(format!(
        "Removed railyard hooks from {}",
        settings_path.display()
    ))
}

/// Remove Railyard section from CLAUDE.md during uninstall.
fn remove_claude_md_section() {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return,
    };
    let claude_md_path = home.join(".claude").join("CLAUDE.md");

    if !claude_md_path.exists() {
        return;
    }

    if let Ok(content) = fs::read_to_string(&claude_md_path) {
        if content.contains(CLAUDE_MD_MARKER_START) {
            let before = content
                .split(CLAUDE_MD_MARKER_START)
                .next()
                .unwrap_or("");
            let after = content
                .split(CLAUDE_MD_MARKER_END)
                .nth(1)
                .unwrap_or("");

            let cleaned = format!("{}{}", before.trim_end(), after.trim_start());
            let _ = fs::write(&claude_md_path, cleaned.trim().to_string() + "\n");
        }
    }
}

/// Check if we're running in an interactive terminal (not piped by an agent).
fn is_interactive_terminal() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// Show a native OS confirmation dialog for uninstalling Railyard.
/// Returns true if the user confirmed, false if cancelled.
/// This is the key security boundary — an AI agent cannot click a GUI button.
fn show_uninstall_confirmation() -> Result<bool, String> {
    if cfg!(target_os = "macos") {
        show_macos_dialog()
    } else if cfg!(target_os = "windows") {
        show_windows_dialog()
    } else {
        show_linux_dialog()
    }
}

/// macOS: native dialog via osascript (AppleScript)
fn show_macos_dialog() -> Result<bool, String> {
    let script = r#"
        display dialog "Remove Railyard guardrails?\n\nClaude Code will run without restrictions until you reinstall.\n\nTo turn protection back on:\n  railyard install" with title "Railyard" with icon caution buttons {"Cancel", "Remove"} default button "Cancel" cancel button "Cancel"
    "#;

    let output = std::process::Command::new("osascript")
        .arg("-e")
        .arg(script.trim())
        .output()
        .map_err(|e| format!("Failed to show confirmation dialog: {}", e))?;

    // osascript returns exit code 1 if the user clicks Cancel
    Ok(output.status.success())
}

/// Windows: native dialog via PowerShell
fn show_windows_dialog() -> Result<bool, String> {
    let script = r#"
        Add-Type -AssemblyName System.Windows.Forms
        $result = [System.Windows.Forms.MessageBox]::Show(
            "Remove Railyard guardrails?`n`nClaude Code will run without restrictions until you reinstall.`n`nTo turn protection back on:`n  railyard install",
            "Railyard",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning,
            [System.Windows.Forms.MessageBoxDefaultButton]::Button2
        )
        if ($result -eq [System.Windows.Forms.DialogResult]::Yes) { exit 0 } else { exit 1 }
    "#;

    let output = std::process::Command::new("powershell")
        .arg("-NoProfile")
        .arg("-Command")
        .arg(script.trim())
        .output()
        .map_err(|e| format!("Failed to show confirmation dialog: {}", e))?;

    Ok(output.status.success())
}

/// Linux: try zenity (GNOME), then kdialog (KDE), then fall back to terminal prompt
fn show_linux_dialog() -> Result<bool, String> {
    // Try zenity first (GNOME/GTK)
    if let Ok(output) = std::process::Command::new("zenity")
        .arg("--question")
        .arg("--title=Railyard")
        .arg("--text=Remove Railyard guardrails?\n\nClaude Code will run without restrictions until you reinstall.\n\nTo turn protection back on: railyard install")
        .arg("--ok-label=Remove Protection")
        .arg("--cancel-label=Cancel")
        .arg("--icon-name=dialog-warning")
        .arg("--width=400")
        .output()
    {
        return Ok(output.status.success());
    }

    // Try kdialog (KDE)
    if let Ok(output) = std::process::Command::new("kdialog")
        .arg("--warningyesno")
        .arg("Remove Railyard guardrails?\n\nClaude Code will run without restrictions until you reinstall.\n\nTo turn protection back on: railyard install")
        .arg("--title")
        .arg("Railyard")
        .arg("--yes-label")
        .arg("Remove Protection")
        .arg("--no-label")
        .arg("Cancel")
        .output()
    {
        return Ok(output.status.success());
    }

    // Fallback: terminal confirmation with a hard-to-guess phrase
    show_terminal_confirmation()
}

/// Terminal fallback: require the user to type a specific phrase.
/// An agent could theoretically type this, but combined with the TTY check
/// and the self-protection blocklist rules, it's defense in depth.
fn show_terminal_confirmation() -> Result<bool, String> {
    use std::io::Write;

    eprintln!();
    eprintln!();
    eprintln!("  Remove Railyard guardrails?");
    eprintln!();
    eprintln!("  Claude Code will run without restrictions until you reinstall.");
    eprintln!("  To turn protection back on: railyard install");
    eprintln!();
    eprint!("  Type \"remove\" to confirm: ");
    std::io::stderr().flush().ok();

    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .map_err(|e| format!("Failed to read input: {}", e))?;

    Ok(input.trim() == "remove")
}

/// Check if railyard hooks are currently installed.
pub fn check_installed() -> Result<bool, String> {
    let settings_path = claude_settings_path();
    if !settings_path.exists() {
        return Ok(false);
    }

    let settings = read_settings(&settings_path)?;

    if let Some(hooks) = settings.get("hooks").and_then(|h| h.as_object()) {
        if let Some(pre) = hooks.get("PreToolUse").and_then(|v| v.as_array()) {
            for entry in pre {
                if let Some(cmd) = entry.pointer("/hooks/0/command").and_then(|c| c.as_str()) {
                    if cmd.contains("railyard") {
                        return Ok(true);
                    }
                }
            }
        }
    }

    Ok(false)
}

fn read_settings(path: &Path) -> Result<Value, String> {
    if !path.exists() {
        // Create parent directory and return empty object
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create settings dir: {}", e))?;
        }
        return Ok(json!({}));
    }

    let content =
        fs::read_to_string(path).map_err(|e| format!("Failed to read settings: {}", e))?;

    serde_json::from_str(&content).map_err(|e| format!("Failed to parse settings: {}", e))
}

fn write_settings(path: &Path, settings: &Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create settings dir: {}", e))?;
    }

    let content = serde_json::to_string_pretty(settings)
        .map_err(|e| format!("Failed to serialize settings: {}", e))?;

    fs::write(path, content).map_err(|e| format!("Failed to write settings: {}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_settings_path_exists() {
        let path = claude_settings_path();
        assert!(path.to_str().unwrap().contains(".claude"));
        assert!(path.to_str().unwrap().ends_with("settings.json"));
    }
}
