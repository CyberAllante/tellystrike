# garak — live AI red-team (NVIDIA)

[garak](https://github.com/NVIDIA/garak) is NVIDIA's LLM vulnerability scanner. It's the heavy
sibling to the PyRIT phase: PyRIT fires a lean set of injection seeds; garak carries a large
library of probes — prompt injection, jailbreaks (DAN family), latent/indirect injection,
encoding attacks, data leakage, toxicity. Run both and you cover far more of the attack surface.

Install (optional — the phase skips clean without it):
```bash
pipx install garak        # or: pip install garak
```

## Mode 1 — scan your app's AI route (what the pipeline runs)

The pipeline calls this when you pass `--garak <ai-endpoint>`. It points garak's REST generator
at your endpoint so you test the app's guardrails, not a raw model:

```bash
./run.sh https://127.0.0.1:3000/api/ai
```

It assumes an OpenAI-shaped request/response. If your API differs, copy the template and fix two
fields, then re-run:

```bash
cp rest-config.json.example rest-config.json
# edit req_template_json_object  (how your endpoint takes the prompt)
# edit response_json_field       (JSONPath to the model's reply text)
```

`$INPUT` is where garak injects each probe; `$KEY` is filled from `REST_API_KEY` (the runner sets
it to your `OPENROUTER_API_KEY`). If your endpoint needs no auth, delete the `Authorization` header.

## Mode 2 — scan a model straight through OpenRouter

To red-team a model directly (no app in the middle), point garak's OpenAI-compatible generator at
OpenRouter with your key. Garak's env var name varies by version (`OPENAI_BASE_URL` /
`OPENAI_API_BASE_URL`); check `garak --help`:

```bash
export OPENAI_API_KEY="$OPENROUTER_API_KEY"
export OPENAI_BASE_URL="https://openrouter.ai/api/v1"
garak --target_type openai --target_name anthropic/claude-sonnet-4.5 --probes promptinject
```

Every hit is a **lead**, not a verdict — garak logs a `.report.jsonl` and an HTML report; read the
failing prompt/response pairs and confirm before calling anything real.
