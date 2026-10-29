# Install the tools

This repo is the orchestrator. Each phase calls a tool you install yourself — install only the ones
whose phases you want. All are free/open-source; each keeps its own license.

## Deterministic phases (no AI key)

**Snyk** — deps (SCA) + code (SAST), phases 2 & 3
```bash
npm i -g snyk && snyk auth          # free account; enable "Snyk Code" in your org for SAST
```

**mcp-scanner** (Cisco AI Defense) — phase 4, only if the target is an MCP server
```bash
uv tool install --python 3.13 cisco-ai-mcp-scanner
```

**OWASP ZAP** — the headless, free, no-license-restriction alternative to Burp Suite for the attack
phase. Runs as an API/daemon you can script; redistributable, hostable.
```bash
# macOS
brew install --cask zap
# then run headless:  zap.sh -daemon -port 8090 -config api.disablekey=true
```
Or **HexStrike** (what phase 6b posts to by default) if you prefer its :8888 command API.

> We deliberately do **not** use Burp Suite here: its license forbids hosting/reselling it as a
> service, and it needs a GUI. ZAP + nuclei cover the same ground headless.

## AI phases (BYOK — OpenRouter)

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

## Quick check

```bash
for t in snyk mcp-scanner agentgg python3; do command -v $t >/dev/null && echo "ok  $t" || echo "--  $t (phase will skip)"; done
```
Every phase skips cleanly if its tool is missing — install incrementally.
