# PyRIT — AI red-team phase (pipeline phase 6c)

Microsoft PyRIT, wired into the security pipeline as the layer the code/network scanners can't do:
**does the app's AI obey a planted instruction?** Fires injection seeds at an AI endpoint N times
each and scores whether the harmless marker leaked into the reply (= injection beat the system prompt).
This is the Recoup "plant instructions in customerName" test from the harness workshop, automated.

## One-time setup (isolated — nothing on system Python)
```bash
~/AJLabs/security-lab/pyrit/setup.sh     # makes ./.venv, pip installs pyrit there only
```
Delete this folder's `.venv` to uninstall. The probe still runs without it (builtin fallback engine),
it just won't have PyRIT's converters/orchestrators.

## Run it
```bash
# direct:
~/AJLabs/security-lab/pyrit/probe.py http://127.0.0.1:3001/api/ai \
   --body '{"imageUrl":"x","prompt":"{{PAYLOAD}}"}' --response-key reply --n 5

# via the pipeline:
~/AJLabs/security-lab/run-pipeline.sh ~/AJLabs/products/tellysend http://127.0.0.1:3001 \
   --pyrit http://127.0.0.1:3001/api/ai
```

## Knobs
- `--body` — request JSON; `{{PAYLOAD}}` is where the seed goes (match the endpoint's real shape).
- `--response-key` — dotted path to the model's text in the JSON reply (omit to scan the whole body).
- `--header 'authorization: Bearer ...'` — auth if the route needs it.
- `--n` — runs per seed (default 5; injection is probabilistic, so never trust one run).
- `payloads.json` — the seeds + the marker. Add app-specific seeds as you learn each endpoint.

## Reading the output
- `🚩 OBEYED` — the marker came back = confirmed injection. **Still verify with a hand repro** before
  it's a finding (agent output is a lead, not a finding).
- `⚠️ sysprompt-lead` — reply looked like it might be leaking the system prompt; manual review only.
- `held` — no seed beat the system prompt on that endpoint.
- Exit code: 2 injectable / 1 lead-only / 0 held.

## Rules (from the workshop)
- Authorized / own + local endpoints only.
- Harmless marker (CAPTAIN-BANANA), never real scam/abuse text — keeps the classifier out of it and
  keeps the test about *control*, not content.
- Point `--pyrit` at the AI route, not the app root.
