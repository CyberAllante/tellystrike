# Skills / agent-file audit

A skill file, agent definition or tool description ships **with** a repo and is read by an
AI agent as instructions. A poisoned one is a prompt injection that lands before the app ever
runs — the same class as MCP tool poisoning, but in the files instead of the live tools.

`scan.py` walks a repo for the agent-instruction surface — `SKILL.md`, `AGENTS.md`,
`CLAUDE.md`, `.claude/agents/*`, `.cursor/rules/*`, `tools.json`, and friends — and flags:

- **hidden-unicode** — zero-width, bidi-override or tag characters invisible to a human reviewer
- **instruction-override** — "ignore previous instructions", "do not tell the user", "you are now…"
- **secret-exfil** — a secret/credential reference and a network egress call in the same file
- **embedded-base64** — long base64 blobs buried in an instruction file
- **exec-request** — the file telling the agent to run a command / eval code

```bash
python3 scan.py /path/to/repo           # deterministic, no key
python3 scan.py /path/to/repo --llm      # + an intent read using your OPENROUTER_API_KEY
```

The pipeline runs this as **phase 4b** automatically — no flag, no account. The `--llm` pass is
added only when `OPENROUTER_API_KEY` is set in `.env`. It stays narrow on purpose: a normal docs
folder won't light up, only the files an agent actually treats as instructions.

Every hit is a **lead**, not a verdict — read the file and confirm intent before calling it malicious.
