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

## Status: Phases 1-3 complete (detect -> explain -> fix -> re-verify)

- [x] Secrets detection (Gitleaks), git-ignore aware
- [x] Dependency scan: known vulns (OSV API) + hallucinated-package check (npm registry)
- [x] Cloud config scan (Firebase/Firestore open rules)
- [x] Plain-language explanations (local Qwen via Ollama)
- [x] Fix generation + re-verification loop (fix on a temp copy, re-scan, confirm gone)
- [x] Security score + `/scan` and `/fix` API endpoints
- [ ] Phase 4-5: AI reasoning agent + safe active probe (missing-auth)
- [ ] Frontend dashboard (Next.js)

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

### 4. GitHub OAuth App (for "Connect with GitHub")

Aegis proves you own a repo before scanning or probing it by having you
sign in on GitHub's own login page -- no token is ever typed into Aegis's
UI. To enable this locally:

1. Go to GitHub -> Settings -> Developer settings -> OAuth Apps -> New OAuth App
2. Application name: `Aegis (Dev)`
3. Homepage URL: `http://localhost:3000`
4. Authorization callback URL: `http://localhost:8000/github/oauth/callback`
5. Create it, generate a Client Secret, and put both in `backend/.env`
   (already git-ignored -- never commit this file):

```
GITHUB_CLIENT_ID=your_client_id
GITHUB_CLIENT_SECRET=your_client_secret
```

The access token this produces lives only in the backend's in-memory
session store (keyed by an httpOnly cookie) -- it's never sent to the
frontend, logged, or written to disk. See `backend/app/github_oauth.py`
and `backend/app/github_auth.py` for the exact handling.

### 5. Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### 6. Try it

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
