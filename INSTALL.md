# Install the tools

This repo is the orchestrator. Each phase calls a tool you install yourself — install only the ones
whose phases you want. All are free/open-source; each keeps its own license.

## Deterministic phases (no account, no key)

**OSV-Scanner** (Google) — dependency CVEs, phase 2. Queries osv.dev. No login, no key.
```bash
brew install osv-scanner
# or:  go install github.com/google/osv-scanner/cmd/osv-scanner@latest
```

**Semgrep** (OSS) — SAST / code data-flow bugs, phase 3. Community rules, no account.
```bash
pipx install semgrep                # or: brew install semgrep
# the pipeline runs: semgrep scan --config auto   (no login; pin --config p/default for offline)
```

**mcp-scanner** (Cisco AI Defense) — phase 4, only if the target is an MCP server
```bash
uv tool install --python 3.13 cisco-ai-mcp-scanner
```

**Skills audit** — phase 4b. Built in: `skills/scan.py` ships with this repo and needs only
`python3` (no install, no account). It reads the target repo's agent instruction files
(`SKILL.md`, `.claude/agents/*`, `CLAUDE.md`, tool descriptions) for poisoning. The optional
intent read turns on by itself when `OPENROUTER_API_KEY` is in `.env`.

**nuclei** — the attack-phase default, phase 6b. Single Go binary, no server, no account. Runs a
templated vuln scan straight at the live URL.
```bash
brew install nuclei          # or: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

**OWASP ZAP** (optional, deeper) — the headless, free, no-license-restriction alternative to Burp for
a fuller passive + spider baseline. The pipeline calls `zap-baseline.py` if it is on PATH (it ships
with the ZAP install / the zaproxy docker image).
```bash
brew install --cask zap      # zap-baseline.py comes with it
```

Phase 6b runs whatever of these is installed (nuclei first, then ZAP, then a local HexStrike :8888 if
one happens to be up), so the no-server default is just nuclei.

> We deliberately do **not** use Burp Suite here: its license forbids hosting/reselling it as a
> service, and it needs a GUI. nuclei + ZAP cover the same ground headless, no account.

## AI phases (your OpenRouter key)

**AgentGG** — agentic SAST, phase 5 (`--agentgg`)
```bash
npm i -g agentgg
# set OPENROUTER_API_KEY in .env and configure agentgg for the OpenRouter provider.
# Drive it via OpenRouter, NOT the Anthropic path (that path hits an autocompact-loop bug).
```

**PyRIT** — AI red-team, phase 6c (`--pyrit <endpoint>`)
```bash
./pyrit/setup.sh        # isolated venv in ./pyrit/.venv — nothing on system Python
```
The PyRIT marker test runs even without this (builtin fallback engine); setup.sh adds PyRIT's
converters/scorers.

**garak** (NVIDIA) — AI red-team, phase 6d (`--garak <endpoint>`). The heavy probe library.
```bash
pipx install garak      # or: pip install garak
```
Targets your app's AI route via garak's REST generator; it assumes an OpenAI-shaped API and tells
you which two fields to edit if yours differs. See `garak/README.md` for that and for scanning a
model straight through OpenRouter. The phase skips clean if garak isn't installed.

## Quick check

```bash
for t in osv-scanner semgrep mcp-scanner agentgg python3; do command -v $t >/dev/null && echo "ok  $t" || echo "--  $t (phase will skip)"; done
```
Every phase skips cleanly if its tool is missing — install incrementally. The two core scanners
(osv-scanner, semgrep) need no account; only the optional AI phases use your OpenRouter key.
