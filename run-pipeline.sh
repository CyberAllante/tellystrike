#!/bin/zsh
# run-pipeline.sh — one-command agentic security pipeline. Runs a chain of best-in-class
# tools, in order, against a target you own, and writes one report.
#
#   AUTHORIZED / OWN TARGETS ONLY. See README. This is not for systems you don't control.
#
#   ./run-pipeline.sh <repo_path> [live_url] [--agentgg] [--exploit <script>] [--attack] [--pyrit <url>] [--garak <url>] [--only m,m] [--skip m,m]
#   ./run-pipeline.sh --help        # options + module list
#   ./run-pipeline.sh --check       # which tools are installed
#
# No accounts for the core phases. Optional: drop your own OPENROUTER_API_KEY in ./.env for the AI
# phases — see .env.example.
# The deterministic phases run without any key; the AI phases (AgentGG, PyRIT smart layer,
# mcp-scanner LLM analyzer) use your key.
#
# Phases (each skips cleanly if its tool/input is missing):
#   1 Recon      — what is this? (langs, deps, MCP server?, live target?)
#   2 Deps (SCA) — osv-scanner          : known CVEs in dependencies            [free; NO account]
#   3 SAST       — semgrep              : data-flow bugs (SSRF, injection)      [free; NO account]
#   4 MCP audit  — mcp-scanner           : tool poisoning / prompt injection     [free; LLM analyzer = key]
#   4b Skills     — skills/scan.py        : poisoned SKILL.md / agent files        [free; NO account]
#   5 Agentic    — agentgg scan          : confirms bugs incl. authz/IDOR        [--agentgg; OpenRouter key]
#   6 Live PoC   — your exploit script    : prove impact on the running box       [--exploit]
#   6b Attack    — nuclei / OWASP ZAP     : live scan (nuclei needs no server)      [--attack; local]
#   6c AI red-team — PyRIT probe          : fire injection seeds at an AI endpoint  [--pyrit <url>]
#   6d AI red-team — garak (NVIDIA)        : big probe library at an AI endpoint     [--garak <url>]
#   7 Report     — REPORT.md             : one summary of everything above
set -uo pipefail
ROOT=${0:A:h}
[ -f "$ROOT/.env" ] && source "$ROOT/.env"   # your OpenRouter key etc.
# One key covers everything: let mcp-scanner reuse your OpenRouter key if you didn't set its own.
: "${MCP_SCANNER_LLM_API_KEY:=${OPENROUTER_API_KEY:-}}"; export MCP_SCANNER_LLM_API_KEY

have(){ command -v "$1" >/dev/null 2>&1; }

usage(){ cat <<'H'
tellystrike — one security pipeline for an app you own.

  ./run-pipeline.sh <repo_path> [live_url] [options]

Options:
  --agentgg                 agentic SAST (needs agentgg + your OpenRouter key)
  --exploit <script>        run your own PoC against the live box
  --attack                  live attack scan (nuclei / ZAP) of the live_url
  --pyrit  <ai-endpoint>    AI red-team: PyRIT injection seeds
  --garak  <ai-endpoint>    AI red-team: NVIDIA garak probe library
  --only  <m,m,...>         run ONLY these modules
  --skip  <m,m,...>         run everything EXCEPT these modules
  --check                   show which tools are installed, then exit
  --help                    show this, then exit

Modules:  deps  sast  mcp  skills  agentgg  exploit  attack  pyrit  garak
          (recon + report always run)

One key unlocks every AI feature: put OPENROUTER_API_KEY in ./.env (see .env.example).
The core modules (deps, sast, mcp, skills) need no key and no account.
H
}

doctor(){
  print -P "%F{cyan}== tool check — which modules can run ==%f"
  for row in \
    "osv-scanner:deps — dependency CVEs" \
    "semgrep:sast — code data-flow bugs" \
    "mcp-scanner:mcp — MCP server audit" \
    "python3:skills + pyrit — agent files / AI red-team" \
    "agentgg:agentgg — agentic SAST" \
    "nuclei:attack — live scan, no server" \
    "zap-baseline.py:attack — deeper live baseline" \
    "garak:garak — NVIDIA AI red-team"; do
    t=${row%%:*}; d=${row#*:}
    if have "$t"; then print -P "  %F{green}ok%f  $t — $d"
    else print -P "  %F{yellow}--%f  $t — $d (phase skips)"; fi
  done
  if [ -n "${OPENROUTER_API_KEY:-}" ]; then print -P "  %F{green}ok%f  OPENROUTER_API_KEY set — AI features on"
  else print -P "  %F{yellow}--%f  OPENROUTER_API_KEY unset — AI features off (free phases still run)"; fi
}

case "${1:-}" in
  -h|--help|--list|"") usage; exit 0;;
  --check|--doctor)    doctor; exit 0;;
esac

REPO="$1"; shift
LIVE=""; RUN_AGENTGG=0; RUN_ATTACK=0; EXPLOIT=""; PYRIT=""; GARAK=""; ONLY=""; SKIP=""
while [ $# -gt 0 ]; do case "$1" in
  --agentgg) RUN_AGENTGG=1;;
  --attack)  RUN_ATTACK=1;;
  --exploit) EXPLOIT="$2"; shift;;
  --pyrit)   PYRIT="$2"; shift;;
  --garak)   GARAK="$2"; shift;;
  --only)    ONLY="$2"; shift;;
  --skip)    SKIP="$2"; shift;;
  http*://*) LIVE="$1";;
  *) [ -z "$LIVE" ] && LIVE="$1";;
esac; shift; done

# module gate: --only wins; else --skip; else everything runs.
want(){ local m="$1"
  if [ -n "$ONLY" ]; then [[ ",$ONLY," == *",$m,"* ]]; return $?; fi
  if [ -n "$SKIP" ]; then [[ ",$SKIP," != *",$m,"* ]]; return $?; fi
  return 0
}

REPO=${REPO:A}; NAME=${REPO:t}
TS=$(date +%Y%m%d-%H%M%S)
OUT="$ROOT/runs/$NAME-$TS"; mkdir -p "$OUT"
say(){ print -P "%F{cyan}== $* %f"; }

say "PIPELINE: $NAME  ($REPO)  live=${LIVE:-none}  -> $OUT"

# ── 1. Recon ────────────────────────────────────────────────────────────────
say "1. Recon"
{ echo "repo: $REPO"; echo "live: ${LIVE:-none}"; echo "date: $(date -u +%FT%TZ)"
  echo "manifests:"; ls "$REPO"/package.json "$REPO"/composer.json "$REPO"/requirements.txt "$REPO"/go.mod 2>/dev/null
  echo "looks like an MCP server: $([ -n "$(grep -rl "tools/list\|registerTool\|@modelcontextprotocol" "$REPO" --include=*.ts --include=*.js --include=*.py --include=*.php 2>/dev/null | head -1)" ] && echo yes || echo no)"
} | tee "$OUT/01-recon.txt"

# ── 2. Dependencies (SCA) — OSV-Scanner, no account ─────────────────────────
say "2. Deps (OSV-Scanner)"
if ! want deps; then echo "skip (deselected)" | tee "$OUT/02-deps.txt"
elif have osv-scanner; then
  # v1 syntax is `-r`; v2 is `scan -r`. Try both so either install works.
  ( osv-scanner --recursive "$REPO" || osv-scanner scan --recursive "$REPO" ) > "$OUT/02-deps.txt" 2>&1
  grep -iE "total|vulnerab|CVE|GHSA" "$OUT/02-deps.txt" | tail -5
else echo "skip (no osv-scanner — install: brew install osv-scanner — no account, no key)" | tee "$OUT/02-deps.txt"; fi

# ── 3. SAST — Semgrep OSS, no account ───────────────────────────────────────
say "3. SAST (Semgrep)"
if ! want sast; then echo "skip (deselected)" | tee "$OUT/03-sast.txt"
elif have semgrep; then
  # --config auto pulls community rules (no login). Pin p/default for fully offline runs.
  ( cd "$REPO" && semgrep scan --config auto --quiet "$REPO" ) > "$OUT/03-sast.txt" 2>&1
  grep -iE "finding|error|Blocking|rules ran" "$OUT/03-sast.txt" | tail -10
else echo "skip (no semgrep — install: pipx install semgrep — no account, no key)" | tee "$OUT/03-sast.txt"; fi

# ── 4. MCP audit ────────────────────────────────────────────────────────────
say "4. MCP audit (mcp-scanner)"
if ! want mcp; then echo "skip (deselected)" | tee "$OUT/04-mcp.txt"
elif have mcp-scanner && grep -q yes <(grep "MCP server: yes" "$OUT/01-recon.txt" 2>/dev/null) ; then
  echo "MCP server detected — extract a tools.json and run: mcp-scanner --analyzers yara static --tools tools.json" | tee "$OUT/04-mcp.txt"
  echo "(LLM + behavioral analyzers need MCP_SCANNER_LLM_API_KEY = your OpenRouter/other key)" | tee -a "$OUT/04-mcp.txt"
else echo "skip (not an MCP server, or no mcp-scanner — install: uv tool install cisco-ai-mcp-scanner)" | tee "$OUT/04-mcp.txt"; fi

# ── 4b. Skills / agent-file audit — poisoned instruction files, no account ───
say "4b. Skills audit (agent instruction files)"
SKOUT="$OUT/04b-skills.txt"
SKDIR="$ROOT/skills"
if ! want skills; then echo "skip (deselected)" | tee "$SKOUT"
elif [ -f "$SKDIR/scan.py" ]; then
  # --llm adds the intent read only when a key is present; deterministic otherwise.
  if [ -n "${OPENROUTER_API_KEY:-}" ]; then
    python3 "$SKDIR/scan.py" "$REPO" --llm > "$SKOUT" 2>&1
  else
    python3 "$SKDIR/scan.py" "$REPO" > "$SKOUT" 2>&1
  fi
  grep -iE "FINDING|clean|files scanned|high|medium" "$SKOUT" | tail -12
else echo "skip (no skills/scan.py in repo)" | tee "$SKOUT"; fi

# ── 5. Agentic SAST (opt-in; brings your OpenRouter key) ─────────────────────
say "5. Agentic SAST (AgentGG)"
if ! want agentgg; then echo "skip (deselected)" | tee "$OUT/05-agentgg.txt"
elif [ "$RUN_AGENTGG" = 1 ] && have agentgg; then
  : "${OPENROUTER_API_KEY:?AgentGG phase needs OPENROUTER_API_KEY — set it in ./.env (see .env.example). Drive AgentGG via OpenRouter, not the Anthropic path.}"
  agentgg scan "$REPO" -o "$OUT/agentgg" > "$OUT/05-agentgg.txt" 2>&1
  tail -15 "$OUT/05-agentgg.txt"
else echo "skip (pass --agentgg; needs: npm i -g agentgg + OPENROUTER_API_KEY in .env)" | tee "$OUT/05-agentgg.txt"; fi

# ── 6. Live exploit / validation ────────────────────────────────────────────
say "6. Live PoC"
if ! want exploit; then echo "skip (deselected)" | tee "$OUT/06-exploit.txt"
elif [ -n "$EXPLOIT" ] && [ -x "$EXPLOIT" ]; then
  "$EXPLOIT" > "$OUT/06-exploit.txt" 2>&1
  tail -20 "$OUT/06-exploit.txt"
else echo "skip (pass --exploit <script> to run a weaponized PoC against $LIVE)" | tee "$OUT/06-exploit.txt"; fi

# ── 6b. Live attack scan — runs whatever is installed; no server by default ──
say "6b. Live attack scan"
HXOUT="$OUT/06b-attack.txt"
if ! want attack; then echo "skip (deselected)" | tee "$HXOUT"
elif [ "$RUN_ATTACK" = 1 ] && [ -n "$LIVE" ]; then
  : > "$HXOUT"; ran=0
  # nuclei: single Go binary, no server, no account. The no-install-server default.
  if have nuclei; then
    echo "### nuclei (direct) on $LIVE" | tee -a "$HXOUT"
    nuclei -u "$LIVE" -severity low,medium,high,critical -silent -nc -timeout 8 2>&1 | tee -a "$HXOUT"
    ran=1
  fi
  # OWASP ZAP baseline: fuller passive + spider scan. Ships with the ZAP install; no account.
  if have zap-baseline.py; then
    echo "### OWASP ZAP baseline on $LIVE" | tee -a "$HXOUT"
    zap-baseline.py -t "$LIVE" -I 2>&1 | tail -40 | tee -a "$HXOUT"
    ran=1
  fi
  # HexStrike: optional heavy agentic sweep, only if its server is already up.
  if curl -s -o /dev/null http://127.0.0.1:8888/health 2>/dev/null; then
    HOST=$(echo "$LIVE" | sed -E 's#https?://##; s#[:/].*##')
    PORT=$(echo "$LIVE" | sed -E 's#.*:([0-9]+).*#\1#'); [ "$PORT" = "$LIVE" ] && PORT=80
    hx(){ curl -s -X POST http://127.0.0.1:8888/api/command -H 'content-type: application/json' \
            --data "$(python3 -c 'import json,sys;print(json.dumps({"command":sys.argv[1]}))' "$1")" \
          | python3 -c 'import sys,json;print(json.load(sys.stdin).get("stdout","")[:4000])' 2>/dev/null; }
    { echo "### HexStrike nmap + nikto on $HOST"
      hx "nmap -sV -Pn -T4 $HOST -p $PORT"
      hx "nikto -h $LIVE -maxtime 120s -ask no 2>&1 | tail -25"; } | tee -a "$HXOUT"
    ran=1
  fi
  [ "$ran" = 0 ] && echo "skip (no attack tool found — install nuclei for the no-server default: brew install nuclei; or OWASP ZAP for a deeper baseline — see INSTALL.md)" | tee "$HXOUT"
else
  echo "skip (pass --attack + a live URL you are authorized to test)" | tee "$HXOUT"
fi

# ── 6c. AI red-team (PyRIT) ──────────────────────────────────────────────────
say "6c. AI red-team (PyRIT)"
PYOUT="$OUT/06c-pyrit.txt"
PYDIR="$ROOT/pyrit"
if ! want pyrit; then echo "skip (deselected)" | tee "$PYOUT"
elif [ -n "$PYRIT" ]; then
  if [ -x "$PYDIR/.venv/bin/python" ]; then PY="$PYDIR/.venv/bin/python"; else PY="python3"; fi
  "$PY" "$PYDIR/probe.py" "$PYRIT" --out "$PYOUT" 2>&1 | tee "$PYOUT.live"
  [ -f "$PYOUT.live" ] && { cat "$PYOUT.live" >> "$PYOUT" 2>/dev/null; rm -f "$PYOUT.live"; }
  tail -12 "$PYOUT"
else
  echo "skip (pass --pyrit <ai-endpoint-url>; run pyrit/setup.sh once for the full PyRIT engine)" | tee "$PYOUT"
fi

# ── 6d. AI red-team (garak / NVIDIA) ─────────────────────────────────────────
say "6d. AI red-team (garak)"
GKOUT="$OUT/06d-garak.txt"
GKDIR="$ROOT/garak"
if ! want garak; then echo "skip (deselected)" | tee "$GKOUT"
elif [ -n "$GARAK" ]; then
  if [ -x "$GKDIR/run.sh" ]; then
    "$GKDIR/run.sh" "$GARAK" > "$GKOUT" 2>&1
  else
    zsh "$GKDIR/run.sh" "$GARAK" > "$GKOUT" 2>&1
  fi
  grep -iE "garak|probe|fail|pass|skip|report" "$GKOUT" | tail -15
else
  echo "skip (pass --garak <ai-endpoint-url>; install: pipx install garak — see garak/README.md)" | tee "$GKOUT"
fi

# ── 7. Report ───────────────────────────────────────────────────────────────
say "7. Report"
{
  echo "# Pipeline report — $NAME — $TS"
  echo; echo "Target: $REPO  |  live: ${LIVE:-none}"; echo
  for p in 01-recon 02-deps 03-sast 04-mcp 04b-skills 05-agentgg 06-exploit 06b-attack 06c-pyrit 06d-garak; do
    echo "## ${p#*-}"; echo '```'; tail -20 "$OUT/$p.txt" 2>/dev/null; echo '```'; echo
  done
} > "$OUT/REPORT.md"

# ── summary: what ran vs what skipped (deselected or tool/input missing) ──────
rn=(); sk=()
for pm in 02-deps:deps 03-sast:sast 04-mcp:mcp 04b-skills:skills 05-agentgg:agentgg \
          06-exploit:exploit 06b-attack:attack 06c-pyrit:pyrit 06d-garak:garak; do
  f=${pm%%:*}; m=${pm##*:}
  if head -1 "$OUT/$f.txt" 2>/dev/null | grep -qi '^skip'; then sk+=("$m"); else rn+=("$m"); fi
done
say "SUMMARY  ran: ${rn[*]:-none}   |   skipped: ${sk[*]:-none}"
print -P "%F{green}done -> $OUT/REPORT.md%f"
