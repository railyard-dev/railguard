# Changelog

All notable changes to this project will be documented in this file.

## [0.2.1] - 2026-03-11

### Added

- **Live TUI dashboard** — `railyard dashboard` launches a full terminal UI showing all tool calls and decisions in real time. Search (`/`), filter (`f`), expand details (`Enter`), vim-style navigation.
- **Global trace directory** — all traces now write to `~/.railyard/traces/` instead of per-project `.railyard/traces/`. Dashboard and `railyard log` work from any directory and see all sessions across all projects.
- **Streaming mode** — `railyard dashboard --stream` for plain text output (old default behavior).

### Fixed

- **Dashboard shows no output** — traces were written relative to the project where Claude Code was running, but the dashboard read relative to where it was launched. Global traces fix this.
- **Config-edit rule too broad** — `railyard-config-edit` used `tool: *` which triggered approval on any tool call mentioning `railyard.yaml` (including `find` and `grep`). Now scoped to `Write` and `Edit` tools only.
- **TUI crash leaves terminal broken** — added panic hook to restore terminal state on crash.
- **Text invisible on light terminals** — replaced hardcoded `Color::White` with `Color::Reset` (terminal default foreground).

### Changed

- **Dashboard TUI is now the default** — `railyard dashboard` launches TUI. Use `--stream` for the old streaming behavior.
- **142 tests** (was 141)

## [0.2.0] - 2026-03-10

### Changed

- **Removed wrapper/launch CLI** — shell shim (`railyard-shell`) is now the only sandboxing approach. `railyard launch` and `railyard sandbox` commands removed.
- **Path fence: outside-project paths now prompt for approval** — explicitly denied paths (~/.ssh, ~/.aws, /etc) are still hard-blocked, but paths outside the project directory ask you instead of blocking outright.
- **Removed chill/hardcore modes** — single configurable ruleset. All features (threat detection, path fencing, evasion detection) always active.
- **Destructive commands block instead of approve** — terraform destroy, rm -rf, DROP TABLE etc. are denied automatically so the agent finds a safer approach. No babysitting.

### Added

- **13 new default rules** (26 total) — database migration resets, cloud CLI deletions (AWS, GCP, Azure), IaC destroy (CDK, Pulumi, CloudFormation), Redis/MongoDB wipes, gsutil recursive delete
- **Weekly update check** — on SessionStart, checks for new versions via Claude Code's hook system. Non-spammy: once per week.
- **Emergency security patches** — checks a `security` tag every session (<100ms). Maintainers push `git tag -f security` and every user's next session sees it immediately.
- **Customizable policy messaging** — if defaults are too strict, override once in `railyard.yaml` and it persists across sessions.

## [0.1.0] - 2026-03-09

Initial release.

### Features

- **Smart defaults:** destructive commands are blocked, sensitive operations require approval, everything else flows through instantly
- **13 default rules** covering terraform destroy, rm -rf, DROP TABLE, git force-push, drizzle-kit push --force, and more
- **Evasion detection:** base64 decoding, variable expansion, shell unwrapping, hex decoding, eval concatenation, multi-variable concat, rev|sh shape detection, Python/Ruby interpreter obfuscation
- **Threat escalation:** 3-tier system — pattern detection (Tier 1, instant kill), behavioral analysis (Tier 2, warn then kill), retry detection (Tier 3)
- **Path fencing:** restrict agent to project directory, deny ~/.ssh, ~/.aws, ~/.gnupg, /etc
- **OS-level sandboxing:** `railyard-shell` binary transparently wraps every Bash command in `sandbox-exec` (macOS) or `bwrap` (Linux)
- **Snapshots & rollback:** per-edit file backups with undo by steps, file, snapshot ID, or entire session
- **Trace logging:** structured audit log of every tool call and decision
- **Self-protection:** agent cannot uninstall hooks, edit settings.json, remove binary, or edit policy without human approval
- **Uninstall safety:** requires interactive terminal + native OS dialog (AppleScript/zenity/kdialog)
- **AI-assisted configuration:** Claude Code can propose policy changes, user approves via standard permission prompt
- **Claude Code integration:** hooks (PreToolUse, PostToolUse, SessionStart), CLAUDE.md injection, CLAUDE_CODE_SHELL env var
- **Per-project policy:** `railyard.yaml` with directory walk-up (like .gitignore)
- **Interactive setup:** `railyard configure` TUI and `railyard chat` policy assistant
- **141 tests:** 78 unit + 36 attack simulation + 15 rollback + 12 threat detection
