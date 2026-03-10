/// Evasion detection and command normalization.
///
/// AI agents have been documented bypassing text-based safety rules by:
/// - Base64 encoding commands
/// - Using variable substitution ($CMD)
/// - Hex encoding
/// - String concatenation tricks
/// - Using eval/xargs/sh -c indirection
/// - Backtick/subshell command substitution
///
/// This module normalizes commands before pattern matching to catch these.

use base64::Engine;

/// Normalize a command string for pattern matching.
/// Returns a vec of strings to match against (original + decoded variants).
pub fn normalize_command(cmd: &str) -> Vec<String> {
    let mut variants = vec![cmd.to_string()];

    // Collapse whitespace
    let collapsed = collapse_whitespace(cmd);
    if collapsed != cmd {
        variants.push(collapsed);
    }

    // Detect and decode base64 pipes: echo "dGVycm..." | base64 -d | sh
    if let Some(decoded) = detect_base64_pipe(cmd) {
        variants.push(decoded.clone());
        variants.extend(normalize_command(&decoded));
    }

    // Detect eval with string concat: eval "ter""raform destroy"
    if let Some(evaled) = detect_eval_concat(cmd) {
        variants.push(evaled.clone());
        variants.extend(normalize_command(&evaled));
    }

    // Detect variable expansion patterns: CMD="terraform destroy"; $CMD
    if let Some(expanded) = detect_variable_expansion(cmd) {
        variants.push(expanded.clone());
        variants.extend(normalize_command(&expanded));
    }

    // Detect sh -c / bash -c wrapping
    if let Some(inner) = detect_shell_wrapper(cmd) {
        variants.push(inner.clone());
        variants.extend(normalize_command(&inner));
    }

    // Detect xargs indirection: echo "terraform destroy" | xargs -I{} sh -c "{}"
    if let Some(inner) = detect_xargs(cmd) {
        variants.push(inner.clone());
    }

    // Detect hex escape sequences: $'\x74\x65\x72\x72\x61\x66\x6f\x72\x6d'
    if let Some(decoded) = detect_hex_escapes(cmd) {
        variants.push(decoded.clone());
    }

    // Detect backtick substitution
    if let Some(inner) = detect_backtick_subshell(cmd) {
        variants.push(inner.clone());
    }

    variants.sort();
    variants.dedup();
    variants
}

fn collapse_whitespace(cmd: &str) -> String {
    cmd.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Detect: echo "BASE64" | base64 --decode | sh
fn detect_base64_pipe(cmd: &str) -> Option<String> {
    let patterns = [
        r#"echo\s+["']?([A-Za-z0-9+/=]+)["']?\s*\|\s*base64\s+(-d|--decode)"#,
        r#"printf\s+["']?([A-Za-z0-9+/=]+)["']?\s*\|\s*base64\s+(-d|--decode)"#,
    ];

    for pattern in &patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if let Some(caps) = re.captures(cmd) {
                if let Some(b64) = caps.get(1) {
                    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64.as_str()) {
                        if let Ok(decoded) = String::from_utf8(bytes) {
                            return Some(decoded);
                        }
                    }
                }
            }
        }
    }
    None
}

/// Detect: eval "ter""raform"" destroy" or eval $'terraform\x20destroy'
fn detect_eval_concat(cmd: &str) -> Option<String> {
    let trimmed = cmd.trim();
    if !trimmed.starts_with("eval ") {
        return None;
    }

    let rest = &trimmed[5..].trim();

    // Remove quotes and concatenate: "ter""raform" → terraform
    let unquoted = rest
        .replace("\"\"", "")
        .replace("''", "")
        .replace('"', "")
        .replace('\'', "");

    if unquoted != *rest {
        Some(unquoted)
    } else {
        Some(rest.to_string())
    }
}

/// Detect: CMD="terraform destroy"; $CMD  or  export X=terraform; $X destroy
fn detect_variable_expansion(cmd: &str) -> Option<String> {
    let re = regex::Regex::new(r#"(\w+)=["']?([^"';]+)["']?\s*[;&]\s*\$\1\b(.*)"#).ok()?;
    if let Some(caps) = re.captures(cmd) {
        let value = caps.get(2)?.as_str();
        let rest = caps.get(3).map(|m| m.as_str()).unwrap_or("");
        Some(format!("{}{}", value, rest))
    } else {
        None
    }
}

/// Detect: sh -c "dangerous command" or bash -c "..."
fn detect_shell_wrapper(cmd: &str) -> Option<String> {
    let re = regex::Regex::new(r#"(?:sh|bash|zsh)\s+-c\s+["'](.+?)["']"#).ok()?;
    re.captures(cmd).and_then(|caps| {
        caps.get(1).map(|m| m.as_str().to_string())
    })
}

/// Detect: echo "cmd" | xargs ...
fn detect_xargs(cmd: &str) -> Option<String> {
    let re = regex::Regex::new(r#"echo\s+["'](.+?)["']\s*\|\s*xargs"#).ok()?;
    re.captures(cmd).and_then(|caps| {
        caps.get(1).map(|m| m.as_str().to_string())
    })
}

/// Detect: $'\x74\x65\x72\x72...' hex escape sequences
fn detect_hex_escapes(cmd: &str) -> Option<String> {
    if !cmd.contains("\\x") {
        return None;
    }

    let re = regex::Regex::new(r"\\x([0-9a-fA-F]{2})").ok()?;
    let decoded = re.replace_all(cmd, |caps: &regex::Captures| {
        let hex_str = caps.get(1).unwrap().as_str();
        if let Ok(byte) = u8::from_str_radix(hex_str, 16) {
            String::from(byte as char)
        } else {
            caps[0].to_string()
        }
    });

    if decoded != cmd {
        Some(decoded.replace("$'", "").replace('\'', ""))
    } else {
        None
    }
}

/// Detect backtick command substitution: `echo terraform` destroy
fn detect_backtick_subshell(cmd: &str) -> Option<String> {
    if !cmd.contains('`') {
        return None;
    }

    let re = regex::Regex::new(r"`echo\s+([^`]+)`").ok()?;
    let expanded = re.replace_all(cmd, |caps: &regex::Captures| {
        caps.get(1).unwrap().as_str().to_string()
    });

    if expanded != cmd {
        Some(expanded.to_string())
    } else {
        None
    }
}

/// Extract all file paths from a command, resolving variable assignments.
/// This catches variable indirection like: d="$HOME/.ssh"; cat "$d/id_ed25519"
pub fn extract_paths_from_command(cmd: &str) -> Vec<String> {
    let mut paths = Vec::new();

    // Step 1: Parse variable assignments (VAR="value" or VAR='value' or VAR=value)
    let mut vars = std::collections::HashMap::new();
    let assign_re = regex::Regex::new(r#"(\w+)=["']?([^"';\s&|]+)["']?"#).unwrap();
    for caps in assign_re.captures_iter(cmd) {
        if let (Some(name), Some(value)) = (caps.get(1), caps.get(2)) {
            vars.insert(name.as_str().to_string(), value.as_str().to_string());
        }
    }

    // Step 2: Expand $HOME from environment
    if let Some(home) = dirs::home_dir() {
        vars.insert("HOME".to_string(), home.display().to_string());
    }

    // Step 3: Expand variables in the command
    let mut expanded_cmd = cmd.to_string();
    // Expand ${VAR} and $VAR patterns
    for (name, value) in &vars {
        expanded_cmd = expanded_cmd.replace(&format!("${{{}}}", name), value);
        expanded_cmd = expanded_cmd.replace(&format!("${}", name), value);
    }

    // Step 4: Extract all path-like tokens from the expanded command
    let path_re = regex::Regex::new(r#"(?:^|\s|["'=])((?:/|~/|\.\./)[\w./_-]+)"#).unwrap();
    for caps in path_re.captures_iter(&expanded_cmd) {
        if let Some(path_match) = caps.get(1) {
            let p = path_match.as_str().to_string();
            if !is_benign_path(&p) {
                paths.push(p);
            }
        }
    }

    // Also extract from the original command (unexpanded)
    for caps in path_re.captures_iter(cmd) {
        if let Some(path_match) = caps.get(1) {
            let p = path_match.as_str().to_string();
            if !is_benign_path(&p) && !paths.contains(&p) {
                paths.push(p);
            }
        }
    }

    paths
}

/// Paths that should never trigger fence violations
fn is_benign_path(path: &str) -> bool {
    path == "/dev/null"
        || path == "/dev/stdin"
        || path == "/dev/stdout"
        || path == "/dev/stderr"
        || path == "/dev/tty"
        || path.starts_with("/dev/fd/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_decode() {
        // "terraform destroy" in base64
        let cmd = "echo dGVycmFmb3JtIGRlc3Ryb3k= | base64 --decode | sh";
        let variants = normalize_command(cmd);
        assert!(variants.iter().any(|v| v.contains("terraform destroy")));
    }

    #[test]
    fn test_eval_concat() {
        let cmd = r#"eval "ter""raform destroy""#;
        let variants = normalize_command(cmd);
        assert!(variants.iter().any(|v| v.contains("terraform destroy")));
    }

    #[test]
    fn test_variable_expansion() {
        let cmd = r#"CMD="terraform destroy"; $CMD"#;
        let variants = normalize_command(cmd);
        assert!(variants.iter().any(|v| v.contains("terraform destroy")));
    }

    #[test]
    fn test_shell_wrapper() {
        let cmd = r#"sh -c "terraform destroy""#;
        let variants = normalize_command(cmd);
        assert!(variants.iter().any(|v| v == "terraform destroy"));
    }

    #[test]
    fn test_xargs() {
        let cmd = r#"echo "rm -rf /" | xargs sh -c"#;
        let variants = normalize_command(cmd);
        assert!(variants.iter().any(|v| v.contains("rm -rf /")));
    }

    #[test]
    fn test_hex_escapes() {
        // "rm" in hex
        let cmd = r"$'\x72\x6d' -rf /";
        let variants = normalize_command(cmd);
        assert!(variants.iter().any(|v| v.contains("rm -rf /")));
    }

    #[test]
    fn test_backtick_subshell() {
        let cmd = "`echo terraform` destroy";
        let variants = normalize_command(cmd);
        assert!(variants.iter().any(|v| v.contains("terraform destroy")));
    }

    #[test]
    fn test_passthrough_normal_command() {
        let cmd = "npm test";
        let variants = normalize_command(cmd);
        assert!(variants.contains(&"npm test".to_string()));
    }

    #[test]
    fn test_whitespace_collapse() {
        let cmd = "terraform    destroy   --auto-approve";
        let variants = normalize_command(cmd);
        assert!(variants.iter().any(|v| v == "terraform destroy --auto-approve"));
    }
}
