<p align="center">
  <h1 align="center">railyard</h1>
  <p align="center"><strong>A secure runtime for AI coding agents.</strong></p>
  <p align="center">Run <code>claude --dangerously-skip-permissions</code> without the danger.<br>Normal commands flow through instantly. Destructive ones get blocked. You stop babysitting.</p>
</p>

<p align="center">
  <a href="https://github.com/railyarddev/railyard/stargazers"><img src="https://img.shields.io/github/stars/railyarddev/railyard?style=flat" alt="GitHub stars"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/tests-141%20passed-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/built%20with-Rust-orange.svg" alt="Built with Rust">
  <a href="https://discord.gg/MyaUZSus"><img src="https://img.shields.io/badge/discord-join-7289da.svg" alt="Discord"></a>
</p>

---

## Install

```bash
cargo install --git https://github.com/railyarddev/railyard.git
railyard install
```

That's it. Now use `claude --dangerously-skip-permissions`.

---

## What happens

```
  Agent runs: npm install && npm run build          ✅ instant
  Agent runs: git commit -m "feat: add auth"        ✅ instant
  Agent runs: terraform destroy --auto-approve      ⛔ BLOCKED
  Agent runs: rm -rf ~/                             ⛔ BLOCKED
  Agent runs: echo payload | base64 -d | sh         ⛔ BLOCKED
  Agent runs: curl -X POST api.com -d @secrets      ⚠️  asks you
  Agent runs: cat ~/.ssh/id_ed25519                 ⛔ BLOCKED
```

99% of commands flow through in <2ms. You only see Railyard when it matters.

---

## Why

You want Claude Code to be fully autonomous. But:

- An agent ran `terraform destroy` on production — **1.9M rows gone**
- An agent ran `drizzle-kit push --force` — **60 tables wiped**
- Agents have run `rm -rf ~/`, `git reset --hard`, `DROP DATABASE` on live systems

So you're stuck clicking "Allow" on every command like a cookie banner.

Railyard fixes this. Think of the [Shinkansen](https://en.wikipedia.org/wiki/Shinkansen) — Japanese high-speed rail goes 320 km/h not because it has fewer safety systems, but because it has *more*. The rails let it go faster. Same idea here.

---

## How it works

`railyard install` does three things:

1. **Hooks** — registers with Claude Code so every tool call passes through Railyard
2. **Sandbox shell** — sets every Bash command to run inside `sandbox-exec` (macOS) or `bwrap` (Linux) at the kernel level
3. **CLAUDE.md** — teaches Claude about Railyard so it knows how to work with it

You keep using `claude` exactly as before. Nothing changes.

### Three possible outcomes per command

- **Allow** — command runs, you don't even know Railyard is there (99% of commands)
- **Block** — agent gets denied, finds another way (destructive stuff, evasion attempts)
- **Approve** — you get a y/n prompt (sensitive operations like `npm publish`, `curl POST`)

---

## Customize

The defaults catch things no sane developer would do by accident. Beyond that, you configure.

**Ask Claude to do it:**

```
You: "Set up railyard so terraform plan is allowed but terraform apply needs my approval."
```

Claude proposes changes to `railyard.yaml` — you approve or reject each one.

**Or edit directly:**

```bash
railyard init    # creates railyard.yaml in your project
```

```yaml
blocklist:
  - name: terraform-destroy
    pattern: "terraform\\s+destroy"
    action: block

approve:
  - name: terraform-apply
    pattern: "terraform\\s+apply"
    action: approve

allowlist:
  - name: terraform-plan
    pattern: "terraform\\s+plan"
    action: allow
```

Changes take effect immediately. No restart. Policy files walk up directories like `.gitignore`.

---

## Recovery

Every file write is snapshotted. Undo anything:

```bash
railyard rollback --session <id> --steps 1     # undo last edit
railyard rollback --session <id>               # undo entire session
```

Or just ask Claude: *"Something went wrong, roll back the last 3 changes."*

---

## Self-protection

The agent can't turn Railyard off:

- `railyard uninstall` → blocked
- Editing settings.json → blocked
- Editing `railyard.yaml` → requires your approval
- Actually uninstalling → requires a native OS dialog click (AI can't click GUI buttons)

---

## Docs

- **[Rules & Configuration](docs/RULES.md)** — all default rules and how to customize
- **[Architecture](docs/ARCHITECTURE.md)** — technical deep dive
- **[Security](SECURITY.md)** — threat model, what it does and doesn't protect against
- **[Pentest Report](PENTEST-REPORT.md)** — 3 rounds of red teaming, 28 attack vectors

---

## Can you break it?

Railyard gets stronger with every bypass found. New evasion patterns, new destructive commands, new attack vectors — they all become new rules. Think you can find one we missed? Open an issue or PR and we'll ship a fix.

---

## Contributing

Railyard is early. [Join the Discord](https://discord.gg/MyaUZSus) — we'd love your help.

```bash
git clone https://github.com/railyarddev/railyard.git
cd railyard && cargo test    # 141 tests
```

---

MIT License. Copyright 2026 Ari Choudhury <ari@railyard.tech>.
