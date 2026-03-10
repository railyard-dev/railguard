# Railyard — Active Guardrails

Railyard is monitoring this session. Every tool call (Bash, Write, Edit, Read) passes through Railyard before execution.

## What you need to know

- **Some commands will be blocked.** If you see a "denied" response from a hook, it means Railyard blocked the command. Do NOT retry the same command — find a safer alternative.
- **Some commands require human approval.** If you see an "ask" response, the human will be prompted to approve or deny.
- **File writes are snapshotted.** Every Write/Edit you make is backed up before execution. The human can rollback any change.
- **Everything is logged.** All tool calls and decisions are recorded in `.railyard/traces/`.

## If something goes wrong

If the human asks you to undo changes, fix a mistake, or rollback:

1. **Get context first.** Run: `railyard context --session $SESSION_ID --verbose`
   This shows you exactly what changed, diffs, blocked commands, and available rollback commands.

2. **Check what changed.** Run: `railyard diff --session $SESSION_ID`
   Or for a specific file: `railyard diff --session $SESSION_ID --file <path>`

3. **Rollback options:**
   - Undo the last edit: `railyard rollback --session $SESSION_ID --steps 1`
   - Undo the last N edits: `railyard rollback --session $SESSION_ID --steps N`
   - Restore a specific file: `railyard rollback --session $SESSION_ID --file <path>`
   - Restore everything: `railyard rollback --session $SESSION_ID`
   - Restore a specific snapshot: `railyard rollback --session $SESSION_ID --id <snapshot-id>`

4. **Find your session ID.** Run: `railyard log`
   This lists all sessions. Pick the most recent one.

## Do NOT attempt to

- Run `railyard uninstall` — it will be blocked.
- Modify `~/.claude/settings.json` — it will be blocked.
- Remove the railyard binary — it will be blocked.
- Access `~/.ssh`, `~/.aws`, `~/.gnupg`, `/etc`, or other fenced paths (if path fencing is enabled).
