#!/bin/zsh
# setup.sh — install the no-account core tools in one go, then show what's ready.
# The AI phases (agentgg, garak, PyRIT) are optional and installed separately — see INSTALL.md.
set -uo pipefail
HERE=${0:A:h}
have(){ command -v "$1" >/dev/null 2>&1; }

echo "installing tellystrike core tools (no accounts, no keys)…"
echo

if have brew; then
  brew install osv-scanner nuclei || true
else
  echo "!! no Homebrew. Install osv-scanner + nuclei manually (see INSTALL.md), or install brew first."
fi

if have pipx; then
  pipx install semgrep || true
elif have pip3; then
  pip3 install --user semgrep || true
else
  echo "!! no pipx/pip3 — install semgrep manually (see INSTALL.md)."
fi

echo
echo "optional AI phases (one OpenRouter key powers all of them):"
echo "  cp .env.example .env    # then paste your OPENROUTER_API_KEY"
echo
echo "what's ready now:"
"$HERE/run-pipeline.sh" --check
