---
name: tellystrike
description: Run an end-to-end security pass on an app the user owns. Dependency CVEs, SAST, MCP audit, a live attack scan, and an AI red-team of the app's AI endpoint, with no accounts for the core phases. Use when the user asks to scan, pentest, security-check, harden, or audit their own app, repo, or live site.
---

# tellystrike

End-to-end security pass for an app the user owns or is authorized to test. One pipeline runs every
layer and writes one report. No signups for the core phases; the optional AI phases use the user's
own OpenRouter key.

## Before you run anything

Confirm the target is the user's own app, or one they have written authorization to test. The code
phases read a repo the user points you at. The live attack phase and the AI red-team send traffic to
a running app, so they only run against a box the user controls. If scope is unclear, ask first.
Never point the attack phase at a third party.

## How to run it

The orchestrator is `run-pipeline.sh` in this repo:

    ./run-pipeline.sh <repo_path> [live_url] [--attack] [--agentgg] [--pyrit <ai-endpoint>]

Pick the flags from what the user wants and what they have installed:

- **Always free, no account:** recon + OSV-Scanner (dep CVEs) + Semgrep (SAST) + MCP audit. Just pass
  the repo path.
- **`--attack` + a live URL:** a live scan with nuclei (no server needed), plus OWASP ZAP or a local
  HexStrike if either is present. Authorized targets only.
- **`--pyrit <ai-endpoint>`:** fire prompt-injection seeds at the app's AI route N times and score
  whether the model obeyed a planted instruction. Point it at the AI route, not the app root.
- **`--agentgg`:** agentic SAST that confirms authz/IDOR bugs the pattern scanners miss. Needs the
  user's `OPENROUTER_API_KEY` in `.env`.

A full run takes a few minutes. Start it in the background and report when it finishes.

## Reading the report

Results land in `runs/<name>-<timestamp>/REPORT.md`. Summarize per phase: the highest-severity
finding in each, which phases ran vs skipped, and the full report path.

Treat every automated finding as a lead, not a confirmed bug. The whole point of the pipeline is that
the layers catch what the others miss: pattern SAST is blind to authorization, so the agentic pass
(phase 5) and the live exploit (phase 6) are what catch the cross-tenant IDOR class, and the AI
red-team (phase 6c) is the only layer that tests whether the app's AI obeys a planted instruction.
Confirm anything serious with a hand repro before calling it real.

## Setup the user may need (all no-account except the last)

- `brew install osv-scanner` (deps), `pipx install semgrep` (SAST), `brew install nuclei` (attack).
- `./pyrit/setup.sh` once for the full PyRIT engine. The marker test runs without it.
- Optional AI phases only: copy `.env.example` to `.env` and add the user's own OpenRouter key.

See `INSTALL.md` for the full list. Every phase skips cleanly if its tool is missing, so the user can
install only the layers they want and run the rest today.
