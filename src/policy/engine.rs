use crate::block::matcher::evaluate_tool;
use crate::types::{Decision, Policy};

/// Evaluate a tool call against the full policy.
/// Order: allowlist → blocklist → approve → default allow.
pub fn evaluate(
    policy: &Policy,
    tool_name: &str,
    tool_input: &serde_json::Value,
) -> Decision {
    // 1. Check allowlist first — if explicitly allowed, skip everything
    if !policy.allowlist.is_empty() {
        let applicable: Vec<_> = policy
            .allowlist
            .iter()
            .filter(|r| r.tool == tool_name || r.tool == "*")
            .cloned()
            .collect();

        if !applicable.is_empty() {
            if let Decision::Block { .. } | Decision::Approve { .. } =
                evaluate_tool(tool_name, tool_input, &applicable)
            {
                // "block" in allowlist context means "matched the allowlist" → allow
                return Decision::Allow;
            }
        }
    }

    // 2. Check blocklist
    if !policy.blocklist.is_empty() {
        let decision = evaluate_tool(tool_name, tool_input, &policy.blocklist);
        if let Decision::Block { .. } = &decision {
            return decision;
        }
    }

    // 3. Check approve list
    if !policy.approve.is_empty() {
        let decision = evaluate_tool(tool_name, tool_input, &policy.approve);
        if let Decision::Approve { .. } = &decision {
            return decision;
        }
    }

    // 4. Default: allow
    Decision::Allow
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Rule, Policy};
    use serde_json::json;

    fn test_policy() -> Policy {
        Policy {
            version: 1,
            mode: "chill".to_string(),
            blocklist: vec![Rule {
                name: "no-destroy".to_string(),
                tool: "Bash".to_string(),
                pattern: r"terraform\s+destroy".to_string(),
                action: "block".to_string(),
                message: Some("Blocked".to_string()),
            }],
            approve: vec![Rule {
                name: "prod-db".to_string(),
                tool: "Bash".to_string(),
                pattern: r"psql.*prod".to_string(),
                action: "approve".to_string(),
                message: Some("Needs approval".to_string()),
            }],
            allowlist: vec![Rule {
                name: "safe".to_string(),
                tool: "Bash".to_string(),
                pattern: r"^(npm test|echo )".to_string(),
                action: "block".to_string(), // "block" in allowlist = matched = allow
                message: None,
            }],
            fence: Default::default(),
            trace: Default::default(),
            snapshot: Default::default(),
        }
    }

    #[test]
    fn test_blocklist_blocks() {
        let policy = test_policy();
        let input = json!({"command": "terraform destroy"});
        let decision = evaluate(&policy, "Bash", &input);
        assert!(matches!(decision, Decision::Block { .. }));
    }

    #[test]
    fn test_allowlist_bypasses_blocklist() {
        let mut policy = test_policy();
        // Add terraform to allowlist
        policy.allowlist.push(Rule {
            name: "allow-terraform".to_string(),
            tool: "Bash".to_string(),
            pattern: r"terraform".to_string(),
            action: "block".to_string(),
            message: None,
        });
        let input = json!({"command": "terraform destroy"});
        let decision = evaluate(&policy, "Bash", &input);
        assert!(matches!(decision, Decision::Allow));
    }

    #[test]
    fn test_approve_flags() {
        let policy = test_policy();
        let input = json!({"command": "psql -h prod-db.example.com"});
        let decision = evaluate(&policy, "Bash", &input);
        assert!(matches!(decision, Decision::Approve { .. }));
    }

    #[test]
    fn test_safe_command_allowed() {
        let policy = test_policy();
        let input = json!({"command": "npm test"});
        let decision = evaluate(&policy, "Bash", &input);
        assert!(matches!(decision, Decision::Allow));
    }

    #[test]
    fn test_unknown_command_allowed() {
        let policy = test_policy();
        let input = json!({"command": "cargo build"});
        let decision = evaluate(&policy, "Bash", &input);
        assert!(matches!(decision, Decision::Allow));
    }
}
