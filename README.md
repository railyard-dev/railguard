<div align="center">
<pre>
╦═╗ ╔═╗ ╦ ╦   ╔═╗ ╦ ╦ ╔═╗ ╦═╗ ╔╦╗
╠╦╝ ╠═╣ ║ ║   ║ ╦ ║ ║ ╠═╣ ╠╦╝  ║║
╩╚═ ╩ ╩ ╩ ╩═╝ ╚═╝ ╚═╝ ╩ ╩ ╩╚═ ═╩╝
</pre>
</div>

<p align="center">
  <strong>Safety runtime for Claude Code, built to be yours.</strong><br><br>
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

--dangerously-skip-permissions is all-or-nothing. Either you approve every tool call by hand, or the agent runs with zero restrictions. There's no middle ground.

Railguard is the middle ground.

```
cargo install railguard
railguard install
```

That's it. You keep using claude exactly as before.

---

## What it does

Railguard intercepts every tool call and decides in under 2ms: allow, block, or ask.

| | |
|---|---|
| npm install && npm run build | ✅ allowed |
| git commit -m "feat: add auth" | ✅ allowed |
| terraform destroy --auto-approve | ⛔ blocked |
| rm -rf ~/ | ⛔ blocked |
| echo payload \| base64 -d \| sh | ⛔ blocked |
| cat ~/.ssh/id_ed25519 | ⛔ blocked |
| curl -X POST api.com -d @secrets | ⚠️ asks you |
| git push --force origin main | ⚠️ asks you |

The same command can get different decisions depending on context:

| | | |
|---|---|---|
| rm dist/bundle.js | inside project | ✅ allowed |
| rm ~/.bashrc | outside project | ⛔ blocked |

99% of commands flow through instantly. You only see Railguard when it matters.

---

## What it guards

Every tool call passes through Railguard, not just Bash.

- **Bash** · command classification, pipe analysis, evasion detection
- **Read** · sensitive path detection (~/.ssh, ~/.aws, .env, ...)
- **Write** · path fencing + content inspection for secrets and dangerous payloads
- **Edit** · path fencing + content inspection on replacements
- **Memory** · classification of agent memory writes for secrets, behavioral injection, tampering

---

## Beyond pattern matching

Pattern matching alone is bypassable. Agents can write helper scripts, encode commands in base64, or chain pipes to evade rules. Railguard uses sandbox-exec (macOS) and bwrap (Linux) to resolve what actually executes at the kernel level, regardless of how the command was constructed.

Two layers: semantic rules catch the obvious stuff instantly. The OS-level sandbox catches everything else.

---

## Memory safety

Claude Code has persistent memory that carries context across sessions. This is a real attack surface. A misbehaving agent can exfiltrate secrets into memory, inject behavioral instructions for future sessions, or silently tamper with existing memories.

Railguard classifies every memory write:

- **Secrets** (API keys, JWTs, private keys, AWS credentials) → **blocked**
- **Behavioral instructions** ("skip safety checks", "override policy") → **asks you**
- **Factual content** (project info, tech stack, user preferences) → **allowed**
- **Overwrites of existing memories** → **asks you**
- **Deletions** → **blocked**

Every memory write is signed with a content hash. Tampering between sessions is detected automatically.

---

## Configure

Ask Claude, or edit railguard.yaml directly. Changes take effect immediately.

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

---

## Also included

- **Path fencing** · ~/.ssh, ~/.aws, ~/.gnupg, /etc fenced by default
- **Multi-agent coordination** · file locking per session, self-healing locks
- **Dashboard & replay** · real-time monitoring, session replay
- **Recovery** · file snapshots, per-edit or full-session rollback

---

## Contributing

[Join the Discord](https://discord.gg/MyaUZSus)

MIT License.
