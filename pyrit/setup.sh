#!/bin/zsh
# setup.sh — one-time, ISOLATED PyRIT install. Nothing touches the system Python.
# Everything lives in this folder's own venv; delete the folder to uninstall.
#
#   ~/AJLabs/security-lab/pyrit/setup.sh
#
# After this, the pipeline's --pyrit phase (and probe.py directly) will work.
set -euo pipefail
HERE=${0:A:h}
VENV="$HERE/.venv"

if [ ! -d "$VENV" ]; then
  echo "== making isolated venv at $VENV"
  python3 -m venv "$VENV"
fi
source "$VENV/bin/activate"
python -m pip install --quiet --upgrade pip
echo "== installing pyrit (isolated — only this folder)"
python -m pip install --quiet "pyrit" || python -m pip install --quiet "pyrit-ai"
python - <<'PY'
import importlib, sys
for name in ("pyrit", "pyrit.orchestrator"):
    try:
        importlib.import_module(name)
    except Exception as e:
        print(f"!! import check failed for {name}: {e}", file=sys.stderr)
        sys.exit(1)
print("== pyrit import OK:", importlib.import_module("pyrit").__version__ if hasattr(importlib.import_module("pyrit"), "__version__") else "(version attr absent)")
PY
echo "== done. Now run:  ~/AJLabs/security-lab/pyrit/probe.py <ai-endpoint-url>"
echo "   (or let the pipeline do it:  run-pipeline.sh <repo> <url> --pyrit <ai-endpoint-url>)"
