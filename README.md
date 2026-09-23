# Aegis — AI Pentesting Agent

Aegis is an autonomous AI pentesting agent: it maps out an app you own,
forms a hypothesis about what could be broken, safely confirms it on a
sandboxed copy, explains it in plain language, and generates a fix --
then re-tests to prove the fix actually holds. Runs on a free local model
(Ollama), so your code never leaves the machine.

Track: ASYNC 2026 — Cybersecurity & Defense.

## Pipeline

```
OBSERVE  ->  DETECT  ->  EXPLAIN  ->  RESPOND
```

## Status: Phase 1 (in progress)

- [x] Secrets detection (Gitleaks) + plain-language explanation
- [ ] Explain -> fix -> re-scan loop
- [ ] Dependency scan (OSV-Scanner)
- [ ] Missing-auth check (safe active probe, sandboxed)
- [ ] Frontend dashboard

## Setup

### 1. Local LLM (Ollama)

```bash
ollama pull qwen2.5-coder:7b
```

### 2. Secrets scanner (Gitleaks)

Install from https://github.com/gitleaks/gitleaks/releases or:

```bash
winget install gitleaks
```

### 3. Reference tool (PentestGPT)

We reuse PentestGPT-legacy's multi-provider LLM connector as a library
(not its CLI). Clone it as a sibling folder:

```bash
git clone https://github.com/GreyDGL/PentestGPT.git
```

It is excluded from this repo's git history (see `.gitignore`) since it's
an external MIT-licensed reference dependency, not our code.

### 4. Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### 5. Try it

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"repo_path": "../demo-app"}'
```

## Project structure

```
backend/       FastAPI backend -- detectors, LLM connector, API
demo-app/      Deliberately vulnerable sample app, used only for testing/demo
frontend/      Next.js dashboard (not yet built)
PentestGPT/    External reference clone (not committed -- see .gitignore)
```

## Scope and safety

Aegis only ever scans repos the user owns and points to directly -- there
is no scanning of arbitrary or third-party targets. Detection is either
deterministic (secrets, dependency versions) or, for active checks,
confirmed with a single fixed, non-destructive probe against a sandboxed
copy of the user's own code. No exploit payloads or attack tooling are
generated or stored.
