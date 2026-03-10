use std::path::{Path, PathBuf};

use crate::types::Policy;

/// Find railyard.yaml by walking up from the given directory.
pub fn find_policy_file(start_dir: &Path) -> Option<PathBuf> {
    let mut current = start_dir.to_path_buf();
    loop {
        let candidate = current.join("railyard.yaml");
        if candidate.exists() {
            return Some(candidate);
        }
        let candidate = current.join("railyard.yml");
        if candidate.exists() {
            return Some(candidate);
        }
        let candidate = current.join(".railyard.yaml");
        if candidate.exists() {
            return Some(candidate);
        }
        if !current.pop() {
            break;
        }
    }
    None
}

/// Load and parse policy from a YAML file.
pub fn load_policy(path: &Path) -> Result<Policy, String> {
    let contents =
        std::fs::read_to_string(path).map_err(|e| format!("Failed to read policy: {}", e))?;
    let policy: Policy =
        serde_yaml::from_str(&contents).map_err(|e| format!("Failed to parse policy: {}", e))?;
    validate_policy(&policy)?;
    Ok(policy)
}

/// Load policy from directory, or return defaults if no file found.
/// Always merges built-in defaults — user rules are additive.
pub fn load_policy_or_defaults(cwd: &Path) -> Policy {
    match find_policy_file(cwd) {
        Some(path) => match load_policy(&path) {
            Ok(policy) => merge_with_defaults(policy),
            Err(e) => {
                eprintln!("railyard: warning: {}", e);
                default_policy()
            }
        },
        None => default_policy(),
    }
}

/// Merge user policy with built-in defaults based on mode.
/// Built-in blocklist rules are always prepended — users can override with allowlist.
fn merge_with_defaults(mut policy: Policy) -> Policy {
    let defaults = crate::policy::defaults::default_blocklist_for_mode(&policy.mode);
    let user_rule_names: std::collections::HashSet<String> =
        policy.blocklist.iter().map(|r| r.name.clone()).collect();

    // Prepend default rules that aren't overridden by user
    let mut merged = defaults
        .into_iter()
        .filter(|r| !user_rule_names.contains(&r.name))
        .collect::<Vec<_>>();
    merged.append(&mut policy.blocklist);
    policy.blocklist = merged;

    // In chill mode, disable fence by default (unless user explicitly enabled it)
    if policy.mode == "chill" && policy.fence.denied_paths.is_empty() && policy.fence.allowed_paths.is_empty() {
        policy.fence.enabled = false;
    }

    policy
}

/// Default policy with built-in blocklist (chill mode).
pub fn default_policy() -> Policy {
    Policy {
        version: 1,
        mode: "chill".to_string(),
        blocklist: crate::policy::defaults::default_blocklist(),
        approve: vec![],
        allowlist: vec![],
        fence: crate::types::FenceConfig {
            enabled: false,
            ..Default::default()
        },
        trace: Default::default(),
        snapshot: Default::default(),
    }
}

/// Validate that all regex patterns in the policy compile.
fn validate_policy(policy: &Policy) -> Result<(), String> {
    let all_rules = policy
        .blocklist
        .iter()
        .chain(policy.approve.iter())
        .chain(policy.allowlist.iter());

    for rule in all_rules {
        regex::Regex::new(&rule.pattern)
            .map_err(|e| format!("Invalid regex in rule '{}': {}", rule.name, e))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_load_default_policy() {
        let policy = default_policy();
        assert!(!policy.blocklist.is_empty());
        assert_eq!(policy.mode, "chill");
        // Chill mode: fence is off by default
        assert!(!policy.fence.enabled);
        assert!(policy.trace.enabled);
        assert!(policy.snapshot.enabled);
    }

    #[test]
    fn test_load_yaml_policy() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
version: 1
blocklist:
  - name: test-rule
    tool: Bash
    pattern: "dangerous_command"
    action: block
    message: "Blocked for testing"
fence:
  enabled: true
  denied_paths:
    - "~/.ssh"
"#;
        let path = dir.path().join("railyard.yaml");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(yaml.as_bytes()).unwrap();

        let policy = load_policy(&path).unwrap();
        assert_eq!(policy.blocklist.len(), 1);
        assert_eq!(policy.blocklist[0].name, "test-rule");
    }

    #[test]
    fn test_find_policy_file_walks_up() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("a/b/c");
        std::fs::create_dir_all(&sub).unwrap();

        let yaml_path = dir.path().join("railyard.yaml");
        std::fs::write(&yaml_path, "version: 1\n").unwrap();

        let found = find_policy_file(&sub);
        assert_eq!(found, Some(yaml_path));
    }

    #[test]
    fn test_invalid_regex_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
version: 1
blocklist:
  - name: bad-regex
    tool: Bash
    pattern: "[invalid"
    action: block
"#;
        let path = dir.path().join("railyard.yaml");
        std::fs::write(&path, yaml).unwrap();

        let result = load_policy(&path);
        assert!(result.is_err());
    }
}
