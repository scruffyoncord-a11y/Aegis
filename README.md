# Aegis — AI Pentesting Agent

Aegis is an autonomous AI pentesting agent: it maps out an app you own,
forms a hypothesis about what could be broken, safely confirms it on a
sandboxed copy of the app, explains it in plain language, and generates a
fix -- then re-tests to prove the fix actually holds. Reasoning and
explanations run on free local models via Ollama, so your code never
leaves the machine (dependency lookups do query public registries -- see
[Scope and safety](#scope-and-safety)).

Track: ASYNC 2026 — Cybersecurity & Defense.

## Pipeline

```
OBSERVE  ->  DETECT  ->  EXPLAIN  ->  RESPOND
```

Static findings (Phases 1-3) and the active probe (Phases 4-6) both follow
this flow: nothing is reported as a finding until it's independently
confirmed, and no fix is reported "resolved" until a fresh re-check
verifies it.

## Status

### Phases 1-3: static detection -- complete
- [x] Secrets (Gitleaks), git-ignore aware, searches the whole repo
- [x] Dependencies: known vulns (OSV API) + hallucinated/non-existent
      packages (npm registry), every `package.json` in the repo
- [x] Cloud config: Firebase/Firestore open rules, **and** Supabase Row
      Level Security (disabled, open policies, never-enabled tables)
- [x] Fix + re-verification loop for every finding type above

### Phases 4-6: the active probe -- complete
- [x] **Agent + tool registry** (`app/probes/agent.py`, `tool.py`): traces
      the target once, lets each registered `Tool` reason independently,
      then confirms every tool's candidates inside one shared, disposable
      Docker sandbox -- the same "reason, pick, run, record" shape AIDA
      uses, scoped down hard: a small fixed tool set, never an open-ended
      command executor
- [x] **Missing-auth tool**: traces routes for ones that look sensitive but
      have no auth attached, confirms with one unauthenticated request
- [x] **IDOR tool**: traces id-scoped routes for a missing ownership check
      *in the actual handler code*, confirms by requesting the same route
      with two different ids under one fixed test identity
- [x] **Framework-aware**: Express (JS), FastAPI and Flask (Python) --
      auto-detected from the repo's own code, not assumed
- [x] Fix + re-verification for both active-probe finding types (reuses
      whatever auth/ownership pattern the app already uses elsewhere,
      never invents one)

### Everything around it -- complete
- [x] Two local models, split by job: **Qwen2.5-Coder** for code reasoning
      (route tracing, vulnerability hypothesis), **Gemma 3** for
      plain-language explanations -- verified ~6x faster per call than
      using Qwen for both
- [x] Deterministic risk scoring (`app/risk.py`): score, area, likelihood,
      impact, and the risk-matrix placement all come from fixed rules,
      **never** the LLM -- the model only explains a finding after its
      severity is already decided
- [x] Real-time NDJSON progress streaming (`/scan/stream`, `/probe/stream`)
      -- the frontend's progress overlay follows genuine backend stages,
      never a simulated timer
- [x] GitHub OAuth ("Connect with GitHub") + repo picker -- no token is
      ever typed into Aegis's UI or sent to the frontend
- [x] Full dashboard (Next.js + Tailwind): animated score gauge, verdict,
      risk-by-area bars, risk matrix, evidence donut, per-finding Fix
      button with live diff, PDF export

## Setup

### 1. Docker Desktop

Required for the active probe (Phases 4-6) -- it builds and runs the
target repo's own Dockerfile in a disposable sandbox. Static detection
(Phases 1-3) works without it.

### 2. Local LLMs (Ollama)

```bash
ollama pull qwen2.5-coder:7b
ollama pull gemma3:4b
```

### 3. Secrets scanner (Gitleaks)

Install from https://github.com/gitleaks/gitleaks/releases or:

```bash
winget install gitleaks
```

### 4. Reference tool (PentestGPT)

We reuse PentestGPT-legacy's multi-provider LLM connector as a library
(not its CLI). Clone it as a sibling folder:

```bash
git clone https://github.com/GreyDGL/PentestGPT.git
```

It is excluded from this repo's git history (see `.gitignore`) since it's
an external MIT-licensed reference dependency, not our code.

### 5. GitHub OAuth App (for "Connect with GitHub")

Aegis proves you own a repo before scanning or probing it by having you
sign in on GitHub's own login page -- no token is ever typed into Aegis's
UI. To enable this locally:

1. Go to GitHub -> Settings -> Developer settings -> OAuth Apps -> New OAuth App
2. Application name: `Aegis (Dev)`
3. Homepage URL: `http://localhost:3000`
4. Authorization callback URL: `http://localhost:8000/github/oauth/callback`
5. Create it, generate a Client Secret, and put both in `backend/.env`
   (copy `backend/.env.example`; the real file is already git-ignored --
   never commit it):

```
GITHUB_CLIENT_ID=your_client_id
GITHUB_CLIENT_SECRET=your_client_secret
```

The access token this produces lives only in the backend's in-memory
session store (keyed by an httpOnly cookie) -- it's never sent to the
frontend, logged, or written to disk. See `backend/app/github_oauth.py`
and `backend/app/github_auth.py` for the exact handling.

### 6. Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### 7. Frontend

```bash
cd frontend
npm install
npm run dev
```

Opens at `http://localhost:3000`. CORS and the OAuth redirect are already
configured for this port.

### 8. Try it (API directly, no frontend needed)

```bash
# Static detection
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"repo_path": "../demo-app"}'

# Active probe (needs Docker running)
curl -X POST http://localhost:8000/probe \
  -H "Content-Type: application/json" \
  -d '{"repo_path": "../demo-app"}'
```

## API endpoints

| Endpoint | What it does |
|---|---|
| `POST /scan` / `/scan/stream` | Phases 1-3: secrets, dependencies, cloud config. Streaming variant emits real progress. |
| `POST /probe` / `/probe/stream` | Phases 4-6: the active probe (missing-auth, IDOR). Skips honestly if Docker/a Dockerfile/a supported entry point isn't available. |
| `POST /fix` | Generate + re-verify a fix for one finding (never touches the working tree until applied). |
| `GET /github/oauth/login`, `GET /github/oauth/callback` | The OAuth flow -- redirects to GitHub, then back with a session cookie. |
| `GET /github/session`, `GET /github/repos`, `POST /github/logout` | Session status, the connected account's repos, disconnect. |
| `POST /github/verify-and-clone` | Verifies push/admin access, then shallow-clones the repo. |

## Project structure

```
backend/
  app/
    detectors/       secrets, dependencies, cloud_config, supabase, routes
    probes/          agent.py (orchestrator), tool.py (interface),
                      missing_auth.py, idor.py -- the active-probe tools
    fixers.py         fix + re-verify, one function per finding type
    risk.py           deterministic scoring/area/matrix -- no LLM involved
    llm.py            local model connector (Qwen for reasoning, Gemma for explain)
    sandbox.py        builds/runs/tears down the target's own Dockerfile
    github_oauth.py, github_auth.py   OAuth flow, permission check, clone
    main.py           FastAPI app, all endpoints
frontend/
  app/                Next.js dashboard (risk-dashboard, sandbox-badge,
                       analysis-overlay, GitHub connect + repo picker)
  components/ui/       shared UI primitives (loader)
demo-app/             Deliberately vulnerable Express + Firebase + Supabase target
demo-app-py/          Deliberately vulnerable FastAPI target
PentestGPT/           External reference clone (not committed -- see .gitignore)
```

## Scope and safety

Aegis only ever scans/probes repos the user has verified ownership of
(via GitHub OAuth, or a local path they provide directly) -- there is no
scanning of arbitrary or third-party targets.

- **Static detection** is fully deterministic: regex/AST-level parsing,
  known-vulnerability database lookups. No LLM involvement in the
  detection itself.
- **The active probe** builds the target's own Dockerfile into a
  disposable, resource-limited container Aegis fully controls, then runs
  exactly one fixed, safe, non-destructive request per hypothesis (no
  exploit payloads, no data exfiltration, no writes). The "tools" the
  agent can run are a small, fixed set (`app/probes/tool.py`) -- there is
  no path for the model to invent or request a new one.
- **Scoring is rule-based, not LLM-based.** `app/risk.py`'s score, area,
  likelihood, and impact all come from fixed lookup tables, computed
  *before* the local model ever sees a finding -- it can only explain,
  never raise or lower anything.
- **Dependency lookups** (OSV, npm registry) send only public package
  names and versions -- the same identifiers `npm audit`/`pip-audit` use.
  Your source code itself never leaves the machine; only the local LLM
  ever reads it.
- **GitHub credentials** are never typed into Aegis's UI. OAuth tokens
  live only in an in-memory, httpOnly-cookie-keyed backend session --
  never sent to the frontend, logged, or written to disk.
