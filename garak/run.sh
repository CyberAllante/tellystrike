#!/bin/zsh
# run.sh — NVIDIA garak (LLM vulnerability scanner) against an AI endpoint you own.
#
#   ./run.sh <ai-endpoint-url>
#
# garak is the live AI red-team sibling to the PyRIT phase: it fires a large library of
# jailbreak / prompt-injection / leakage probes at a running model. Here it targets YOUR
# app's AI route through garak's REST generator, so you test the app's guardrails, not a
# raw model. See README.md for OpenRouter-direct mode (scan a model straight through).
#
# AUTHORIZED / OWN TARGETS ONLY.
set -uo pipefail
HERE=${0:A:h}
EP="${1:?usage: run.sh <ai-endpoint-url>}"
have(){ command -v "$1" >/dev/null 2>&1; }

if have garak; then GARAK=(garak)
elif python3 -c "import garak" 2>/dev/null; then GARAK=(python3 -m garak)
else
  echo "skip (garak not installed — pipx install garak  OR  pip install garak; see garak/README.md)"
  exit 0
fi

# Use a config you filled in if present; otherwise generate an OpenAI-shaped one from the URL.
CFG="$HERE/rest-config.json"
if [ ! -f "$CFG" ]; then
  CFG="$HERE/rest-config.generated.json"
  sed "s#__URI__#$EP#g" "$HERE/rest-config.json.example" > "$CFG"
  echo "note: no rest-config.json — generated an OpenAI-shaped config from the URL. If your API's"
  echo "      request/response shape differs, copy rest-config.json.example to rest-config.json and"
  echo "      fix req_template_json_object / response_json_field, then re-run."
fi

# If your endpoint needs a key, garak reads it from REST_API_KEY (the $KEY placeholder).
export REST_API_KEY="${OPENROUTER_API_KEY:-}"

# A focused probe set keeps a run to minutes. Widen with --probes all yourself.
PROBES="promptinject,latentinjection,dan,encoding"
echo "### garak REST on $EP  (probes: $PROBES)"

# garak v0.16 renamed --model_type to --target_type; try the new flag, fall back to the old.
"${GARAK[@]}" --target_type rest -G "$CFG" --probes "$PROBES" --generations 3 2>&1 \
  || "${GARAK[@]}" --model_type rest -G "$CFG" --probes "$PROBES" --generations 3 2>&1
