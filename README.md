<p align="center">
  <h1 align="center">Railroad</h1>
  <p align="center"><strong>Run Claude Code autonomously and safely.</strong></p>
</p>

<p align="center">
  <a href="https://crates.io/crates/railroad-ai"><img src="https://img.shields.io/crates/v/railroad-ai.svg" alt="crates.io"></a>
  <a href="https://crates.io/crates/railroad-ai"><img src="https://img.shields.io/crates/d/railroad-ai.svg" alt="Downloads"></a>
  <a href="https://github.com/railroad-dev/railroad/stargazers"><img src="https://img.shields.io/github/stars/railroad-dev/railroad?style=flat" alt="GitHub stars"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/tests-151%20passed-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/built%20with-Rust-orange.svg" alt="Built with Rust">
  <a href="https://discord.gg/MyaUZSus"><img src="https://img.shields.io/badge/discord-join-7289da.svg" alt="Discord"></a>
</p>

---

## Install

```bash
cargo install railroad-ai
railroad install
```

Railroad makes `--dangerously-skip-permissions` safe.

---

## How is this different from Claude Code's sandbox?

Claude Code's sandbox and auto mode handle system-level sandboxing — filesystem access, network restrictions, OS-level permissions. Railroad is a different thing entirely.

Railroad is a hardening layer for autonomous Claude Code. It evaluates every command the agent runs and enforces practical restrictions — the same ones any experienced engineer would put in place before letting code run unattended in a real codebase.

`npm install` is fine. `terraform destroy --auto-approve` is not. `git commit` is fine. `git push --force origin main` is not. You already know this. Railroad knows it too.

---

## In practice

```
  Agent runs: npm install && npm run build          ✅ instant
  Agent runs: git commit -m "feat: add auth"        ✅ instant
  Agent runs: terraform destroy --auto-approve      ⛔ BLOCKED
  Agent runs: rm -rf ~/                             ⛔ BLOCKED
  Agent runs: echo payload | base64 -d | sh         ⛔ BLOCKED
  Agent runs: curl -X POST api.com -d @secrets      ⚠️  asks you
  Agent runs: cat ~/.ssh/id_ed25519                 ⛔ BLOCKED
```

99% of commands flow through in <2ms. You only see Railroad when it matters.

---

## How it works

`railroad install` does three things:

1. **Hooks** — registers with Claude Code so every tool call passes through Railroad
2. **Sandbox** — agents can obfuscate commands to bypass rules (`base64 -d | sh`, chained pipes). The sandbox resolves what a command actually does at the OS level so Railroad can evaluate the real intent
3. **CLAUDE.md** — teaches Claude about Railroad so it knows how to work with it

You keep using `claude` exactly as before. Nothing changes.

---

## Customize

Ask Claude to do it:

```
You: "Set up railroad so terraform plan is allowed but terraform apply needs my approval."
```

Or edit `railroad.yaml` directly:

```bash
railroad init    # creates railroad.yaml in your project
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

**Multi-agent coordination** — Run multiple Claude Code sessions in the same repo. Railroad locks files per session so agents don't clobber each other. Locks self-heal if a session dies.

```bash
railroad locks     # see all active locks
```

**Dashboard & replay** — Watch every tool call across all sessions in real time, or browse what any session did after the fact.

```bash
railroad dashboard
railroad replay --session <id>
```

**Recovery** — Every file write is snapshotted. Undo anything.

```bash
railroad rollback --session <id> --steps 1     # undo last edit
railroad rollback --session <id>               # undo entire session
```

---

## Contributing

Railroad is early. [Join the Discord](https://discord.gg/MyaUZSus) — we'd love your help.

```bash
git clone https://github.com/railroad-dev/railroad.git
cd railroad && cargo test
```

---

MIT License. Copyright 2026 Ari Choudhury <ari@railroad.tech>.
