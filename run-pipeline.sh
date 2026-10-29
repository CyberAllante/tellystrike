#!/bin/zsh
# run-pipeline.sh — one-command agentic security pipeline. Runs a chain of best-in-class
# tools, in order, against a target you own, and writes one report.
#
#   AUTHORIZED / OWN TARGETS ONLY. See README. This is not for systems you don't control.
#
#   ./run-pipeline.sh <repo_path> [live_url] [--agentgg] [--exploit <script>] [--attack] [--pyrit <ai-endpoint>]
#
# Bring-your-own-key: drop OPENROUTER_API_KEY (and optional SNYK token) in ./.env — see .env.example.
# The deterministic phases run without any key; the AI phases (AgentGG, PyRIT smart layer,
# mcp-scanner LLM analyzer) use your key.
#
# Phases (each skips cleanly if its tool/input is missing):
#   1 Recon      — what is this? (langs, deps, MCP server?, live target?)
#   2 Deps (SCA) — snyk test            : known CVEs in dependencies            [free; snyk account]
#   3 SAST       — snyk code test        : data-flow bugs (SSRF, injection)      [free; snyk account]
#   4 MCP audit  — mcp-scanner           : tool poisoning / prompt injection     [free; LLM analyzer = key]
#   5 Agentic    — agentgg scan          : confirms bugs incl. authz/IDOR        [--agentgg; OpenRouter key]
#   6 Live PoC   — your exploit script    : prove impact on the running box       [--exploit]
#   6b Attack    — HexStrike or ZAP       : autonomous nmap/nuclei/nikto sweep     [--attack; local service]
#   6c AI red-team — PyRIT probe          : fire injection seeds at an AI endpoint  [--pyrit <url>]
#   7 Report     — REPORT.md             : one summary of everything above
set -uo pipefail
ROOT=${0:A:h}
[ -f "$ROOT/.env" ] && source "$ROOT/.env"   # BYOK: OPENROUTER_API_KEY etc.

REPO="${1:?usage: run-pipeline.sh <repo_path> [live_url] [--agentgg] [--exploit <script>] [--attack] [--pyrit <ai-endpoint>]}"
shift
LIVE=""; RUN_AGENTGG=0; RUN_ATTACK=0; EXPLOIT=""; PYRIT=""
while [ $# -gt 0 ]; do case "$1" in
  --agentgg) RUN_AGENTGG=1;;
  --attack)  RUN_ATTACK=1;;
  --exploit) EXPLOIT="$2"; shift;;
  --pyrit)   PYRIT="$2"; shift;;
  http*://*) LIVE="$1";;
  *) [ -z "$LIVE" ] && LIVE="$1";;
esac; shift; done

REPO=${REPO:A}; NAME=${REPO:t}
TS=$(date +%Y%m%d-%H%M%S)
OUT="$ROOT/runs/$NAME-$TS"; mkdir -p "$OUT"
say(){ print -P "%F{cyan}== $* %f"; }
have(){ command -v "$1" >/dev/null 2>&1; }

say "PIPELINE: $NAME  ($REPO)  live=${LIVE:-none}  -> $OUT"

# ── 1. Recon ────────────────────────────────────────────────────────────────
say "1. Recon"
{ echo "repo: $REPO"; echo "live: ${LIVE:-none}"; echo "date: $(date -u +%FT%TZ)"
  echo "manifests:"; ls "$REPO"/package.json "$REPO"/composer.json "$REPO"/requirements.txt "$REPO"/go.mod 2>/dev/null
  echo "looks like an MCP server: $([ -n "$(grep -rl "tools/list\|registerTool\|@modelcontextprotocol" "$REPO" --include=*.ts --include=*.js --include=*.py --include=*.php 2>/dev/null | head -1)" ] && echo yes || echo no)"
} | tee "$OUT/01-recon.txt"

# ── 2. Dependencies (SCA) ───────────────────────────────────────────────────
say "2. Deps (Snyk SCA)"
if have snyk && ls "$REPO"/package*.json "$REPO"/composer.lock "$REPO"/requirements.txt >/dev/null 2>&1; then
  ( cd "$REPO" && snyk test --severity-threshold=high ) > "$OUT/02-deps.txt" 2>&1
  grep -E "Total|issues|CRITICAL|HIGH" "$OUT/02-deps.txt" | tail -3
else echo "skip (no snyk or no manifest — install: npm i -g snyk && snyk auth)" | tee "$OUT/02-deps.txt"; fi

# ── 3. SAST ─────────────────────────────────────────────────────────────────
say "3. SAST (Snyk Code)"
if have snyk; then
  ( cd "$REPO" && snyk code test --severity-threshold=high ) > "$OUT/03-sast.txt" 2>&1
  grep -E "✗|Total issues|HIGH" "$OUT/03-sast.txt" | head -20
else echo "skip (no snyk — enable Snyk Code in your org settings for SAST)" | tee "$OUT/03-sast.txt"; fi

# ── 4. MCP audit ────────────────────────────────────────────────────────────
say "4. MCP audit (mcp-scanner)"
if have mcp-scanner && grep -q yes <(grep "MCP server: yes" "$OUT/01-recon.txt" 2>/dev/null) ; then
  echo "MCP server detected — extract a tools.json and run: mcp-scanner --analyzers yara static --tools tools.json" | tee "$OUT/04-mcp.txt"
  echo "(LLM + behavioral analyzers need MCP_SCANNER_LLM_API_KEY = your OpenRouter/other key)" | tee -a "$OUT/04-mcp.txt"
else echo "skip (not an MCP server, or no mcp-scanner — install: uv tool install cisco-ai-mcp-scanner)" | tee "$OUT/04-mcp.txt"; fi

# ── 5. Agentic SAST (opt-in; brings your OpenRouter key) ─────────────────────
say "5. Agentic SAST (AgentGG)"
if [ "$RUN_AGENTGG" = 1 ] && have agentgg; then
  : "${OPENROUTER_API_KEY:?AgentGG phase needs OPENROUTER_API_KEY — set it in ./.env (see .env.example). Drive AgentGG via OpenRouter, not the Anthropic path.}"
  agentgg scan "$REPO" -o "$OUT/agentgg" > "$OUT/05-agentgg.txt" 2>&1
  tail -15 "$OUT/05-agentgg.txt"
else echo "skip (pass --agentgg; needs: npm i -g agentgg + OPENROUTER_API_KEY in .env)" | tee "$OUT/05-agentgg.txt"; fi

# ── 6. Live exploit / validation ────────────────────────────────────────────
say "6. Live PoC"
if [ -n "$EXPLOIT" ] && [ -x "$EXPLOIT" ]; then
  "$EXPLOIT" > "$OUT/06-exploit.txt" 2>&1
  tail -20 "$OUT/06-exploit.txt"
else echo "skip (pass --exploit <script> to run a weaponized PoC against $LIVE)" | tee "$OUT/06-exploit.txt"; fi

# ── 6b. Autonomous attack (HexStrike, local) ─────────────────────────────────
say "6b. Autonomous attack (HexStrike)"
HXOUT="$OUT/06b-attack.txt"
if [ "$RUN_ATTACK" = 1 ] && [ -n "$LIVE" ] && curl -s -o /dev/null http://127.0.0.1:8888/health; then
  HOST=$(echo "$LIVE" | sed -E 's#https?://##; s#[:/].*##')
  PORT=$(echo "$LIVE" | sed -E 's#.*:([0-9]+).*#\1#'); [ "$PORT" = "$LIVE" ] && PORT=80
  hx(){ curl -s -X POST http://127.0.0.1:8888/api/command -H 'content-type: application/json' \
          --data "$(python3 -c 'import json,sys;print(json.dumps({"command":sys.argv[1]}))' "$1")" \
        | python3 -c 'import sys,json;print(json.load(sys.stdin).get("stdout","")[:4000])' 2>/dev/null; }
  {
    echo "### HexStrike attack on $LIVE  (host $HOST port $PORT)"
    echo "## nmap service scan";   hx "nmap -sV -Pn -T4 $HOST -p $PORT"
    echo "## nuclei high/critical"; hx "nuclei -u $LIVE -severity high,critical -silent -nc -timeout 8"
    echo "## nikto (120s cap)";     hx "nikto -h $LIVE -maxtime 120s -ask no 2>&1 | tail -25"
  } | tee "$HXOUT"
else
  echo "skip (pass --attack + a live URL; needs a local HexStrike :8888, or swap in OWASP ZAP headless — see INSTALL.md)" | tee "$HXOUT"
fi

# ── 6c. AI red-team (PyRIT) ──────────────────────────────────────────────────
say "6c. AI red-team (PyRIT)"
PYOUT="$OUT/06c-pyrit.txt"
PYDIR="$ROOT/pyrit"
if [ -n "$PYRIT" ]; then
  if [ -x "$PYDIR/.venv/bin/python" ]; then PY="$PYDIR/.venv/bin/python"; else PY="python3"; fi
  "$PY" "$PYDIR/probe.py" "$PYRIT" --out "$PYOUT" 2>&1 | tee "$PYOUT.live"
  [ -f "$PYOUT.live" ] && { cat "$PYOUT.live" >> "$PYOUT" 2>/dev/null; rm -f "$PYOUT.live"; }
  tail -12 "$PYOUT"
else
  echo "skip (pass --pyrit <ai-endpoint-url>; run pyrit/setup.sh once for the full PyRIT engine)" | tee "$PYOUT"
fi

# ── 7. Report ───────────────────────────────────────────────────────────────
say "7. Report"
{
  echo "# Pipeline report — $NAME — $TS"
  echo; echo "Target: $REPO  |  live: ${LIVE:-none}"; echo
  for p in 01-recon 02-deps 03-sast 04-mcp 05-agentgg 06-exploit 06b-attack 06c-pyrit; do
    echo "## ${p#*-}"; echo '```'; tail -20 "$OUT/$p.txt" 2>/dev/null; echo '```'; echo
  done
} > "$OUT/REPORT.md"
print -P "%F{green}done -> $OUT/REPORT.md%f"
