# agentic-pentest

> Working name — rename before publishing.

One command runs a chain of best-in-class security tools against a codebase and its running
instance, then writes a single report. Static analysis, dependency CVEs, MCP tool audit, agentic
SAST, a live autonomous attack sweep, and an **AI red-team** phase that fires prompt-injection
payloads at the app's AI endpoint and scores whether the model obeyed.

**No signups.** Every core phase runs with no account and no login — clone it and go. The optional
AI phases use *your own* OpenRouter key; nothing routes through anyone else's account, and you are
never forced to create one to use the tool.

```bash
cp .env.example .env            # add OPENROUTER_API_KEY
./run-pipeline.sh ./my-app                                   # fast: recon + deps + SAST + MCP check
./run-pipeline.sh ./my-app http://127.0.0.1:3000 --agentgg   # + agentic SAST (authz/IDOR)
./run-pipeline.sh ./my-app http://127.0.0.1:3000 --pyrit http://127.0.0.1:3000/api/ai   # + AI red-team
```

Report lands in `runs/<name>-<timestamp>/REPORT.md`.

## Why this exists

I ran this on my own live apps. On one of them it found a **cross-tenant IDOR** — any logged-in user
could read, edit, and **delete** another tenant's data by guessing an ID — that **three automated
scanners missed.** Pattern-matching SAST is blind to authorization; only the agentic pass and the
live exploit caught it. That gap is the whole point: this pipeline chains the layers so the bug class
each tool misses gets caught by the next one.

The newest phase, **AI red-team (PyRIT)**, is the layer none of the code/network scanners can do:
it tests whether your app's *AI* obeys a planted instruction. It fires injection seeds at your AI
endpoint N times each and scores whether a harmless marker leaked into the reply (= the injection
beat your system prompt).

## The phases

| # | Phase | Tool | Finds | Key? |
|---|-------|------|-------|------|
| 1 | Recon | built-in | langs, deps, is-it-an-MCP-server, live target | — |
| 2 | Deps (SCA) | OSV-Scanner | known CVEs in dependencies | **no account** |
| 3 | SAST | Semgrep (OSS) | data-flow bugs: SSRF, injection | **no account** |
| 4 | MCP audit | mcp-scanner | tool poisoning / prompt injection (MCP servers) | LLM analyzer = key |
| 5 | Agentic SAST | AgentGG | confirms bugs incl. **authz / IDOR** that SAST misses | **OpenRouter** |
| 6 | Live PoC | your exploit script | proves real impact on the running box | — |
| 6b | Attack | HexStrike / OWASP ZAP | autonomous nmap/nuclei/nikto sweep of the live box | — (local) |
| 6c | AI red-team | PyRIT | injection seeds at an AI endpoint, scored over N runs | optional (smart layer) |
| 7 | Report | built-in | one REPORT.md of everything | — |

Install the third-party tools per [INSTALL.md](INSTALL.md). This repo is the **orchestrator + the
PyRIT driver** — it calls tools you install yourself, so each keeps its own license.

## The key model (BYOK)

The core phases need **no account and no key**: OSV-Scanner (deps) and Semgrep (SAST) are
account-free by design, and so are the ZAP/nuclei attack and the PyRIT marker test.

The only keys are optional and yours — one `OPENROUTER_API_KEY` in `.env` unlocks the AI phases:
- **AgentGG** — drive it via OpenRouter (not the Anthropic path).
- **PyRIT** — the marker-leak scoring is keyless; a key only powers PyRIT's LLM converters/scorers.
- **mcp-scanner** — yara/static analyzers are keyless; the LLM analyzer uses the key.

## Rules of the road

**Authorized / own targets only.** Point the code phases at code you control and the live/attack
phases at a box you own or have written authorization to test. The AI red-team uses a harmless marker
(not real abuse text) so the test is about *control*, not content. Running the attack phase against
something you don't own is illegal and not supported.

## License

MIT — the engine is free and open. (A hosted dashboard / team platform, if one ships, is a separate
product.) See [LICENSE](LICENSE).
