use crate::types::Rule;

/// Default blocklist rules. One set for everyone, fully customizable via railyard.yaml.
///
/// Philosophy:
/// - Destructive commands → block (agent finds another way, you stay hands-off)
/// - Sensitive operations → approve (agent pauses, you say yes or no)
/// - Evasion attempts → block (never legitimate)
/// - Self-protection → block (agent can't disable its own guardrails)
pub fn default_blocklist() -> Vec<Rule> {
    vec![
        // ── Destructive commands — block (agent gets denied, finds safer approach) ──
        Rule {
            name: "terraform-destroy".to_string(),
            tool: "Bash".to_string(),
            pattern: r"terraform\s+(destroy|apply\s+.*-auto-approve)".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: destructive infrastructure command".to_string()),
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
        // ── Database migration resets — block (agents reach for these on migration errors) ──
        Rule {
            name: "prisma-reset".to_string(),
            tool: "Bash".to_string(),
            pattern: r"prisma\s+(migrate\s+reset|db\s+push\s+--force-reset)".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: prisma migrate reset drops and recreates the entire database".to_string()),
        },
        Rule {
            name: "flyway-clean".to_string(),
            tool: "Bash".to_string(),
            pattern: r"flyway\s+clean".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: flyway clean drops every object in the schema".to_string()),
        },
        Rule {
            name: "liquibase-drop-all".to_string(),
            tool: "Bash".to_string(),
            pattern: r"(?i)liquibase\s+(dropAll|drop-all)".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: liquibase dropAll drops every object in the database".to_string()),
        },
        // ── NoSQL/cache wipes ──
        Rule {
            name: "redis-flush".to_string(),
            tool: "Bash".to_string(),
            pattern: r"(?i)(FLUSHALL|FLUSHDB)".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: FLUSHALL/FLUSHDB wipes entire Redis database".to_string()),
        },
        Rule {
            name: "mongo-drop-database".to_string(),
            tool: "Bash".to_string(),
            pattern: r"(?i)(db\.dropDatabase\s*\(\)|dropDatabase)".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: dropDatabase destroys entire MongoDB database".to_string()),
        },
        // ── IaC destroy (same class as terraform destroy) ──
        Rule {
            name: "cdk-destroy".to_string(),
            tool: "Bash".to_string(),
            pattern: r"cdk\s+destroy".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: cdk destroy tears down infrastructure stacks".to_string()),
        },
        Rule {
            name: "pulumi-destroy".to_string(),
            tool: "Bash".to_string(),
            pattern: r"pulumi\s+destroy".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: pulumi destroy tears down infrastructure stacks".to_string()),
        },
        Rule {
            name: "cloudformation-delete".to_string(),
            tool: "Bash".to_string(),
            pattern: r"aws\s+cloudformation\s+delete-stack".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: deleting a CloudFormation stack destroys all its resources".to_string()),
        },
        // ── Cloud CLI destructive operations ──
        Rule {
            name: "aws-ec2-terminate".to_string(),
            tool: "Bash".to_string(),
            pattern: r"aws\s+ec2\s+terminate-instances".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: terminating EC2 instances".to_string()),
        },
        Rule {
            name: "aws-rds-delete".to_string(),
            tool: "Bash".to_string(),
            pattern: r"aws\s+rds\s+delete-db-(instance|cluster)".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: deleting RDS database".to_string()),
        },
        Rule {
            name: "gcloud-delete".to_string(),
            tool: "Bash".to_string(),
            pattern: r"gcloud\s+(compute\s+instances\s+delete|sql\s+instances\s+delete|projects\s+delete|container\s+clusters\s+delete)".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: deleting GCP resources".to_string()),
        },
        Rule {
            name: "az-delete".to_string(),
            tool: "Bash".to_string(),
            pattern: r"az\s+(vm\s+delete|group\s+delete|storage\s+account\s+delete|sql\s+db\s+delete|aks\s+delete)".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: deleting Azure resources".to_string()),
        },
        Rule {
            name: "gsutil-rm-recursive".to_string(),
            tool: "Bash".to_string(),
            pattern: r"gsutil\s+(-m\s+)?rm\s+-r".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: recursive GCS deletion".to_string()),
        },
        // ── Sensitive operations — approve (human decides) ──
        Rule {
            name: "npm-publish".to_string(),
            tool: "Bash".to_string(),
            pattern: r"npm\s+publish".to_string(),
            action: "approve".to_string(),
            message: Some("npm publish requires approval".to_string()),
        },
        // ── Network policy — approve or block ──
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
            message: Some("curl POST may exfiltrate data — requires approval".to_string()),
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
        // ── Credential protection ──
        Rule {
            name: "env-dump".to_string(),
            tool: "Bash".to_string(),
            pattern: r"^\s*(env|printenv|export\s+-p)\s*$".to_string(),
            action: "approve".to_string(),
            message: Some("Environment dump may expose secrets — requires approval".to_string()),
        },
        Rule {
            name: "git-config-global-write".to_string(),
            tool: "Bash".to_string(),
            pattern: r"git\s+config\s+--(global|system)\s+\S+\s+".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: agents cannot modify global git configuration".to_string()),
        },
        // ── Evasion detection — always block (never legitimate) ──
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
        Rule {
            name: "symlink-to-outside".to_string(),
            tool: "Bash".to_string(),
            pattern: r"ln\s+(-[a-zA-Z]*s[a-zA-Z]*\s+|--symbolic\s+)(/|~|\$HOME)".to_string(),
            action: "approve".to_string(),
            message: Some("Symlink to absolute path requires approval".to_string()),
        },
        Rule {
            name: "transform-pipe-to-shell".to_string(),
            tool: "Bash".to_string(),
            pattern: r"(?:rev|tr\s+|sed\s+|awk\s+).*\|\s*(?:sh|bash|zsh|eval|source)\b".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: text transform piped to shell can construct any command".to_string()),
        },
        Rule {
            name: "interpreter-obfuscation".to_string(),
            tool: "Bash".to_string(),
            pattern: r#"(?:python3?|ruby|perl|node)\s+-[ec]\s+.*(?:b64decode|b64encode|base64\..*decode|chr\s*\(|\\x[0-9a-fA-F]{2}|eval\s*\(|exec\s*\(|system\s*\(|os\.system|os\.popen|subprocess|Popen\s*\(|fromCharCode|['"]/'*\s*\.\s*join\s*\(|open\s*\(.*\.join\s*\(|open\s*\(.*chr\s*\()"#.to_string(),
            action: "block".to_string(),
            message: Some("Blocked: interpreter with string obfuscation can bypass command detection".to_string()),
        },
        // ── Self-protection — always block (agent can't disable guardrails) ──
        Rule {
            name: "railyard-uninstall".to_string(),
            tool: "Bash".to_string(),
            pattern: r"railyard\s+uninstall".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: agents cannot uninstall Railyard".to_string()),
        },
        Rule {
            name: "railyard-install".to_string(),
            tool: "Bash".to_string(),
            pattern: r"railyard\s+install".to_string(),
            action: "approve".to_string(),
            message: Some("Reinstalling Railyard requires human approval".to_string()),
        },
        Rule {
            name: "railyard-config-edit".to_string(),
            tool: "Write".to_string(),
            pattern: r"railyard\.yaml".to_string(),
            action: "approve".to_string(),
            message: Some("Writing Railyard policy requires human approval".to_string()),
        },
        Rule {
            name: "railyard-config-edit-2".to_string(),
            tool: "Edit".to_string(),
            pattern: r"railyard\.yaml".to_string(),
            action: "approve".to_string(),
            message: Some("Editing Railyard policy requires human approval".to_string()),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults_not_empty() {
        assert!(!default_blocklist().is_empty());
    }

    #[test]
    fn test_all_rules_have_valid_patterns() {
        for rule in &default_blocklist() {
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
        for rule in &default_blocklist() {
            assert!(rule.message.is_some(), "Rule '{}' missing message", rule.name);
        }
    }

    #[test]
    fn test_has_self_protection() {
        let rules = default_blocklist();
        assert!(rules.iter().any(|r| r.name == "railyard-uninstall"));
    }

    #[test]
    fn test_has_network_rules() {
        let rules = default_blocklist();
        assert!(rules.iter().any(|r| r.name == "network-curl-pipe-sh"));
        assert!(rules.iter().any(|r| r.name == "network-nc"));
    }

    #[test]
    fn test_destructive_commands_are_block() {
        let rules = default_blocklist();
        let block_rules = ["terraform-destroy", "rm-rf-critical", "sql-drop", "git-force-push", "git-reset-hard"];
        for name in &block_rules {
            let rule = rules.iter().find(|r| r.name == *name).unwrap();
            assert_eq!(rule.action, "block", "Rule '{}' should be block", name);
        }
    }

    #[test]
    fn test_evasion_rules_are_block() {
        let rules = default_blocklist();
        let block_rules = ["base64-to-shell", "transform-pipe-to-shell", "interpreter-obfuscation", "printf-hex-exec"];
        for name in &block_rules {
            let rule = rules.iter().find(|r| r.name == *name).unwrap();
            assert_eq!(rule.action, "block", "Rule '{}' should be block", name);
        }
    }
}
