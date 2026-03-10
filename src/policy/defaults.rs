use crate::types::Rule;

/// Rules shared by both modes — self-protection + destructive command blocking.
/// These are the "just don't blow stuff up" rules.
fn core_blocklist() -> Vec<Rule> {
    vec![
        // ── Destructive commands from real incidents ──
        Rule {
            name: "terraform-destroy".to_string(),
            tool: "Bash".to_string(),
            pattern: r"terraform\s+(destroy|apply\s+.*-auto-approve)".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: terraform destroy is a destructive infrastructure command".to_string()),
        },
        Rule {
            name: "rm-rf-critical".to_string(),
            tool: "Bash".to_string(),
            pattern: r"rm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+|--force\s+).*(/\s*$|/\*|~/|\$HOME|/home)".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: recursive force delete of critical path".to_string()),
        },
        Rule {
            name: "sql-drop".to_string(),
            tool: "Bash".to_string(),
            pattern: r"(?i)(DROP\s+(TABLE|DATABASE|SCHEMA)|TRUNCATE\s+TABLE)".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: destructive SQL operation".to_string()),
        },
        Rule {
            name: "git-force-push".to_string(),
            tool: "Bash".to_string(),
            pattern: r"git\s+push\s+.*--force".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: force push can overwrite remote history".to_string()),
        },
        Rule {
            name: "git-reset-hard".to_string(),
            tool: "Bash".to_string(),
            pattern: r"git\s+reset\s+--hard".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: hard reset discards uncommitted work".to_string()),
        },
        Rule {
            name: "git-clean-force".to_string(),
            tool: "Bash".to_string(),
            pattern: r"git\s+clean\s+(-[a-zA-Z]*f|--force)".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: git clean -f removes untracked files permanently".to_string()),
        },
        Rule {
            name: "drizzle-force".to_string(),
            tool: "Bash".to_string(),
            pattern: r"drizzle-kit\s+push\s+--force".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: drizzle-kit push --force can destroy database schema".to_string()),
        },
        Rule {
            name: "disk-format".to_string(),
            tool: "Bash".to_string(),
            pattern: r"(mkfs\.|dd\s+.*of=/dev/|>.*(/dev/sda|/dev/disk|/dev/nvme))".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: disk format/overwrite operation".to_string()),
        },
        Rule {
            name: "k8s-delete-namespace".to_string(),
            tool: "Bash".to_string(),
            pattern: r"kubectl\s+delete\s+(namespace|ns)\s".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: deleting a Kubernetes namespace".to_string()),
        },
        Rule {
            name: "aws-s3-rm-recursive".to_string(),
            tool: "Bash".to_string(),
            pattern: r"aws\s+s3\s+(rm|rb)\s+.*--recursive".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: recursive S3 deletion".to_string()),
        },
        Rule {
            name: "docker-system-prune".to_string(),
            tool: "Bash".to_string(),
            pattern: r"docker\s+system\s+prune\s+(-a|--all)".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: docker system prune -a removes all images".to_string()),
        },
        Rule {
            name: "chmod-777-recursive".to_string(),
            tool: "Bash".to_string(),
            pattern: r"chmod\s+(-R|--recursive)\s+777\s+/".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: recursive chmod 777 on root path".to_string()),
        },
        Rule {
            name: "npm-publish".to_string(),
            tool: "Bash".to_string(),
            pattern: r"npm\s+publish".to_string(),
            action: "approve".to_string(),
            message: Some("npm publish requires approval".to_string()),
        },
        // ── Self-protection (always active in both modes) ──
        Rule {
            name: "railyard-uninstall".to_string(),
            tool: "Bash".to_string(),
            pattern: r"railyard\s+uninstall".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: agents cannot uninstall Railyard hooks".to_string()),
        },
        Rule {
            name: "railyard-tamper-settings".to_string(),
            tool: "Bash".to_string(),
            pattern: r"\.claude/settings\.json".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: agents cannot modify Claude Code hook settings".to_string()),
        },
        Rule {
            name: "railyard-remove-binary".to_string(),
            tool: "Bash".to_string(),
            pattern: r"(rm|unlink|mv)\s+.*\.cargo/bin/railyard".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: agents cannot remove the Railyard binary".to_string()),
        },
    ]
}

/// Extra rules only active in hardcore mode — network, credentials, evasion, symlinks.
fn hardcore_rules() -> Vec<Rule> {
    vec![
        // ── Network exfiltration ──
        Rule {
            name: "network-curl-pipe-sh".to_string(),
            tool: "Bash".to_string(),
            pattern: r"curl\s+.*\|\s*(sh|bash|zsh|eval|source)".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: piping curl output to shell execution".to_string()),
        },
        Rule {
            name: "network-nc".to_string(),
            tool: "Bash".to_string(),
            pattern: r"(nc|ncat|netcat)\s+".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: raw socket connections".to_string()),
        },
        Rule {
            name: "network-curl-post".to_string(),
            tool: "Bash".to_string(),
            pattern: r"curl\s+.*(-X\s*POST|-d\s|--data)".to_string(),
            action: "approve".to_string(),
            message: Some("curl POST may exfiltrate data".to_string()),
        },
        Rule {
            name: "network-wget".to_string(),
            tool: "Bash".to_string(),
            pattern: r"wget\s+".to_string(),
            action: "approve".to_string(),
            message: Some("wget download requires approval".to_string()),
        },
        Rule {
            name: "network-ssh-scp".to_string(),
            tool: "Bash".to_string(),
            pattern: r"(ssh|scp|rsync\s+.*:)\s+".to_string(),
            action: "approve".to_string(),
            message: Some("Remote access requires approval".to_string()),
        },
        // ── Credential leakage ──
        Rule {
            name: "env-dump".to_string(),
            tool: "Bash".to_string(),
            pattern: r"^\s*(env|printenv|export\s+-p)\s*$".to_string(),
            action: "approve".to_string(),
            message: Some("Environment dump may expose secrets".to_string()),
        },
        Rule {
            name: "git-config-global-write".to_string(),
            tool: "Bash".to_string(),
            pattern: r"git\s+config\s+--(global|system)\s+\S+\s+".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: agents cannot modify global git configuration".to_string()),
        },
        // ── Dynamic command construction ──
        Rule {
            name: "base64-to-shell".to_string(),
            tool: "Bash".to_string(),
            pattern: r"base64\s+(-d|--decode).*\|\s*(sh|bash|zsh|eval|source)".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: decoded base64 piped to shell".to_string()),
        },
        Rule {
            name: "eval-dynamic".to_string(),
            tool: "Bash".to_string(),
            pattern: r"eval\s+.*\$".to_string(),
            action: "approve".to_string(),
            message: Some("eval with variable expansion requires approval".to_string()),
        },
        Rule {
            name: "printf-hex-exec".to_string(),
            tool: "Bash".to_string(),
            pattern: r"\$\(\s*printf\s+.*\\x".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: printf hex substitution in command position".to_string()),
        },
        // ── Symlink escape ──
        Rule {
            name: "symlink-to-outside".to_string(),
            tool: "Bash".to_string(),
            pattern: r"ln\s+(-[a-zA-Z]*s[a-zA-Z]*\s+|--symbolic\s+)(/|~|\$HOME)".to_string(),
            action: "approve".to_string(),
            message: Some("Symlink to absolute path requires approval".to_string()),
        },
    ]
}

/// Get the default blocklist for "chill" mode.
/// Just don't blow stuff up + self-protection. No restrictions on file access or network.
pub fn chill_blocklist() -> Vec<Rule> {
    core_blocklist()
}

/// Get the default blocklist for "hardcore" mode.
/// Full lockdown: destructive commands + network + credentials + evasion + symlinks.
pub fn hardcore_blocklist() -> Vec<Rule> {
    let mut rules = core_blocklist();
    rules.extend(hardcore_rules());
    rules
}

/// Get the default blocklist based on mode string.
/// Falls back to "chill" for unknown modes.
pub fn default_blocklist_for_mode(mode: &str) -> Vec<Rule> {
    match mode {
        "hardcore" => hardcore_blocklist(),
        _ => chill_blocklist(),
    }
}

/// Legacy: default blocklist (chill mode for backward compatibility).
pub fn default_blocklist() -> Vec<Rule> {
    chill_blocklist()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults_not_empty() {
        assert!(!chill_blocklist().is_empty());
        assert!(!hardcore_blocklist().is_empty());
    }

    #[test]
    fn test_hardcore_has_more_rules() {
        assert!(hardcore_blocklist().len() > chill_blocklist().len());
    }

    #[test]
    fn test_all_rules_have_valid_patterns() {
        for rule in &hardcore_blocklist() {
            assert!(
                regex::Regex::new(&rule.pattern).is_ok(),
                "Invalid pattern in rule '{}': {}",
                rule.name,
                rule.pattern
            );
        }
    }

    #[test]
    fn test_all_rules_have_messages() {
        for rule in &hardcore_blocklist() {
            assert!(rule.message.is_some(), "Rule '{}' missing message", rule.name);
        }
    }

    #[test]
    fn test_chill_has_self_protection() {
        let rules = chill_blocklist();
        assert!(rules.iter().any(|r| r.name == "railyard-uninstall"));
    }

    #[test]
    fn test_hardcore_has_network_rules() {
        let rules = hardcore_blocklist();
        assert!(rules.iter().any(|r| r.name == "network-curl-pipe-sh"));
        assert!(rules.iter().any(|r| r.name == "network-nc"));
    }
}
