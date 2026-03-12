use std::path::Path;

use crate::types::FenceConfig;

/// Result of a path fence check.
#[derive(Debug, PartialEq)]
pub enum PathCheck {
    /// Path is allowed — no fence issue.
    Allow,
    /// Path is in an explicitly denied location (e.g. ~/.ssh, /etc) — hard block.
    Denied(String),
    /// Path is outside the project directory but not explicitly denied — ask the user.
    OutsideProject(String),
}

/// Check if a file path is allowed by the fence configuration.
///
/// All paths are canonicalized before checking — this resolves:
/// - Relative traversal (../)
/// - Symlinks pointing to denied locations
/// - Home directory expansions (~, $HOME)
pub fn check_path(config: &FenceConfig, file_path: &str, cwd: &str) -> PathCheck {
    if !config.enabled {
        return PathCheck::Allow;
    }

    // Always allow /dev/* paths — they're not real files
    if is_dev_path(file_path) {
        return PathCheck::Allow;
    }

    let expanded = expand_path(file_path);
    let canonical = canonicalize_best_effort(&expanded);
    let cwd_canonical = canonicalize_best_effort(cwd);

    // Check explicit denied paths first (canonicalize each)
    for denied in &config.denied_paths {
        let denied_canonical = canonicalize_best_effort(&expand_path(denied));
        if path_starts_with(&canonical, &denied_canonical) {
            return PathCheck::Denied(format!(
                "Path Fence: '{}' is in denied path '{}'",
                file_path, denied
            ));
        }
    }

    // If allowed_paths is non-empty, the path must be in the project directory or one of the allowed paths
    if !config.allowed_paths.is_empty() {
        // Project directory is always implicitly allowed
        if path_starts_with(&canonical, &cwd_canonical) {
            return PathCheck::Allow;
        }
        for allowed in &config.allowed_paths {
            let allowed_canonical = canonicalize_best_effort(&expand_path(allowed));
            if path_starts_with(&canonical, &allowed_canonical) {
                return PathCheck::Allow;
            }
        }
        return PathCheck::OutsideProject(format!(
            "Path Fence: '{}' is not in any allowed path",
            file_path
        ));
    }

    // Default behavior: path outside the project directory needs approval
    if !path_starts_with(&canonical, &cwd_canonical) {
        return PathCheck::OutsideProject(format!(
            "Path Fence: '{}' is outside project directory '{}'",
            file_path, cwd
        ));
    }

    PathCheck::Allow
}

/// Canonicalize a path, resolving symlinks and ../
/// If the file doesn't exist yet, canonicalize the deepest existing ancestor
/// and append the remaining components.
fn canonicalize_best_effort(path: &str) -> String {
    let p = Path::new(path);

    // Try full canonicalization first (resolves symlinks + ../)
    if let Ok(canonical) = p.canonicalize() {
        return canonical.display().to_string();
    }

    // File doesn't exist — walk up until we find an existing ancestor
    let mut components: Vec<String> = Vec::new();
    let mut current = p.to_path_buf();
    loop {
        if current.exists() {
            if let Ok(canonical) = current.canonicalize() {
                let mut result = canonical;
                for component in components.iter().rev() {
                    result = result.join(component);
                }
                return result.display().to_string();
            }
            break;
        }
        if let Some(file_name) = current.file_name() {
            components.push(file_name.to_string_lossy().to_string());
        }
        if !current.pop() {
            break;
        }
    }

    // Fallback: return the original path
    path.to_string()
}

/// Check if a path is a /dev/* device path (always allowed).
fn is_dev_path(path: &str) -> bool {
    let p = path.trim();
    p == "/dev/null"
        || p == "/dev/stdin"
        || p == "/dev/stdout"
        || p == "/dev/stderr"
        || p == "/dev/tty"
        || p.starts_with("/dev/fd/")
}

/// Expand ~ to home directory and resolve relative paths.
fn expand_path(path: &str) -> String {
    if path.starts_with("~/") || path == "~" {
        if let Some(home) = dirs::home_dir() {
            return format!("{}{}", home.display(), &path[1..]);
        }
    }
    if path.starts_with("$HOME") {
        if let Some(home) = dirs::home_dir() {
            return path.replace("$HOME", &home.display().to_string());
        }
    }
    path.to_string()
}

/// Check if a path starts with a prefix (directory containment).
fn path_starts_with(path: &str, prefix: &str) -> bool {
    let path = Path::new(path);
    let prefix = Path::new(prefix);
    path.starts_with(prefix)
}

/// Extract the file path from a tool input, regardless of tool type.
pub fn extract_file_path(tool_name: &str, tool_input: &serde_json::Value) -> Option<String> {
    match tool_name {
        "Write" | "Edit" | "Read" => tool_input
            .get("file_path")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        "Bash" => {
            // Try to extract paths from common file-touching commands
            let cmd = tool_input.get("command").and_then(|v| v.as_str())?;
            extract_path_from_command(cmd)
        }
        _ => None,
    }
}

/// Best-effort extraction of file paths from shell commands.
fn extract_path_from_command(cmd: &str) -> Option<String> {
    // Patterns like: cat /etc/passwd, vim ~/.bashrc, > /sensitive/file
    let patterns = [
        r"(?:cat|less|more|head|tail|vim|nano|vi)\s+(?:-\S+\s+)*(?:\d+\s+)?([/~]\S+)",
        r">\s*([/~]\S+)",
        r"(?:cp|mv|scp)\s+([/~]\S+)",
        r"(?:tee|dd\s+of=)([/~]\S+)",
    ];

    for pattern in &patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if let Some(caps) = re.captures(cmd) {
                if let Some(path) = caps.get(1) {
                    return Some(path.as_str().to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::FenceConfig;

    fn default_fence(_cwd: &str) -> FenceConfig {
        FenceConfig {
            enabled: true,
            allowed_paths: vec![],
            denied_paths: vec![
                "~/.ssh".to_string(),
                "~/.aws".to_string(),
                "/etc".to_string(),
            ],
        }
    }

    #[test]
    fn test_denied_path_blocked() {
        let config = default_fence("/project");
        let home = dirs::home_dir().unwrap();
        let ssh_path = format!("{}/.ssh/authorized_keys", home.display());
        assert!(matches!(check_path(&config, &ssh_path, "/project"), PathCheck::Denied(_)));
    }

    #[test]
    fn test_etc_blocked() {
        let config = default_fence("/project");
        assert!(matches!(check_path(&config, "/etc/passwd", "/project"), PathCheck::Denied(_)));
    }

    #[test]
    fn test_project_path_allowed() {
        let config = default_fence("/project");
        assert_eq!(check_path(&config, "/project/src/main.rs", "/project"), PathCheck::Allow);
    }

    #[test]
    fn test_fence_disabled() {
        let config = FenceConfig {
            enabled: false,
            allowed_paths: vec![],
            denied_paths: vec!["/etc".to_string()],
        };
        assert_eq!(check_path(&config, "/etc/passwd", "/project"), PathCheck::Allow);
    }

    #[test]
    fn test_outside_project_is_approve() {
        let config = FenceConfig {
            enabled: true,
            allowed_paths: vec![],
            denied_paths: vec![],
        };
        assert!(matches!(check_path(&config, "/other/file.txt", "/project"), PathCheck::OutsideProject(_)));
    }

    #[test]
    fn test_allowed_paths_whitelist() {
        let config = FenceConfig {
            enabled: true,
            allowed_paths: vec!["/project".to_string(), "/tmp".to_string()],
            denied_paths: vec![],
        };
        assert_eq!(check_path(&config, "/project/src/main.rs", "/project"), PathCheck::Allow);
        assert_eq!(check_path(&config, "/tmp/test.txt", "/project"), PathCheck::Allow);
        assert!(matches!(check_path(&config, "/other/file.txt", "/project"), PathCheck::OutsideProject(_)));
    }

    #[test]
    fn test_allowed_paths_implicitly_includes_cwd() {
        // When allowed_paths is set but doesn't include cwd, cwd should still be allowed
        let config = FenceConfig {
            enabled: true,
            allowed_paths: vec!["/tmp".to_string()],
            denied_paths: vec![],
        };
        assert_eq!(check_path(&config, "/project/src/main.rs", "/project"), PathCheck::Allow);
        assert_eq!(check_path(&config, "/tmp/test.txt", "/project"), PathCheck::Allow);
        assert!(matches!(check_path(&config, "/other/file.txt", "/project"), PathCheck::OutsideProject(_)));
    }

    #[test]
    fn test_extract_path_from_bash() {
        assert_eq!(
            extract_path_from_command("cat /etc/passwd"),
            Some("/etc/passwd".to_string())
        );
        assert_eq!(
            extract_path_from_command("head -n 10 ~/.bashrc"),
            Some("~/.bashrc".to_string())
        );
        assert_eq!(
            extract_path_from_command("> /sensitive/output.txt"),
            Some("/sensitive/output.txt".to_string())
        );
    }

    #[test]
    fn test_extract_file_path_from_tool_input() {
        let input = serde_json::json!({"file_path": "/etc/passwd"});
        assert_eq!(
            extract_file_path("Read", &input),
            Some("/etc/passwd".to_string())
        );
    }
}
