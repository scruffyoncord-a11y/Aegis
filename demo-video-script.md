# Aegis — 4-Minute Demo Video Script

**Team Barbie** | ASYNC 2026 Hackathon — Cybersecurity & Defense Track

---

## 0:00–0:35 — Hook & Problem (35s)

**VISUAL:** Fast montage — a solo dev shipping a SaaS idea overnight with an AI coding assistant, deploying it, sharing the link. Then cut to a dark terminal with a scrolling stream of exposed `.env` secrets / open admin routes found in the wild.

**VO:**
"Right now, more people than ever are building and shipping real web apps solo — vibe coders, indie hackers, people going from idea to a live product in a weekend, powered by AI pair-programmers. That's incredible. But almost none of them are doing a security review before they ship.

Not because they don't care — because a real pentest needs a specialist, costs real money, and takes days they don't have. So most solo-shipped apps go live with exactly the kind of holes that show up in breach reports six months later: hardcoded secrets, an admin route with no auth check, one user able to read another user's data just by changing an ID in the URL.

We built Aegis so that gap doesn't have to exist."

---

## 0:35–1:10 — Why Not Just Use Burp Suite? (35s)

**VISUAL:** Split screen — Burp Suite's dense proxy/intruder UI on one side, Aegis's clean dashboard on the other.

**VO:**
"'Why not just use Burp Suite?' Fair question — and Burp is a phenomenal tool, if you already know how to use it. It's built for security professionals who understand HTTP proxying, manual request tampering, intruder payloads. Hand it to a solo developer who just wants to know 'is my app safe to launch,' and it's the wrong tool for the job — too much power, too little guidance, and it doesn't read your code or reason about your architecture at all.

Aegis isn't trying to replace Burp for professionals. It's for the other 95% — the person who needs an honest answer in minutes, not a new skillset."

---

## 1:10–1:55 — How We Built It: Two Local Models, One Sandbox (45s)

**VISUAL:** Terminal split into two panes — `ollama run qwen2.5-coder` and `ollama run gemma3` both idle/ready. Then a quick cut to Docker Desktop showing a fresh `aegis-sandbox-*` container spinning up.

**VO:**
"'Isn't that just one AI doing everything?' No — and that's on purpose.

Aegis runs two separate local models through Ollama, and they never do each other's job. Qwen2.5-Coder is our reasoning model — it's the one that actually thinks like a pentester: it reads your routes and your code structure and proposes what's worth checking, like 'this admin route has no auth middleware, test it.' Gemma3 never touches that decision at all — its only job is taking a finding that's already been confirmed and rules-scored, and explaining it in plain language a non-security person can actually understand.

Neither model decides your score — that's pure deterministic rules, every time, for every repo. And when Aegis actually needs to test something live, it builds your app inside a real, disposable Docker container — no network access beyond what your app itself needs, memory and process limited, torn down the second the check ends. Everything — both models, the sandbox — runs entirely on your own machine. Nothing about your code ever leaves it."

---

## 1:55–2:55 — Core Feature Walkthrough (60s)

**VISUAL:** Full screen recording, real flow:
1. Connect GitHub (OAuth) → pick a repo
2. Static scan runs (secrets/deps/config)
3. Active probe: "Opening a private container…" sandbox animation → Docker build → live HTTP probe against the real running app
4. Dashboard: security score, risk-by-area gradient bars, risk matrix, findings list sorted by severity
5. Click a finding → AI-fix suggestion + verified diff

**VO:**
"Here's the real flow. You sign in directly with GitHub — your token never touches our frontend, it stays server-side. Pick a repo, and Aegis does two things: a static scan for leaked secrets, vulnerable dependencies, and misconfigurations — and an active probe, where it actually builds your app inside a disposable, network-isolated Docker sandbox and sends real HTTP requests against the live running instance. Not just reading your source — actually testing it, the way a real attacker would hit a running server.

You get a single security score, a risk breakdown by area, and every finding sorted worst-first, with a plain-language explanation of why it matters and exactly which file and line it's in. For a lot of findings, Aegis can generate a fix and verify it actually closes the hole before it shows you the diff."

---

## 2:55–3:25 — Supporting Feature: Test a Hunch (30s)

**VISUAL:** Click "Test a Hunch," type a suspicion, show the three possible outcomes — confirmed / not found / not testable with an honest explanation.

**VO:**
"Sometimes you already have a suspicion — 'I think this admin panel doesn't check auth.' 'Test a Hunch' lets you type that in plain English, and Aegis biases its investigation toward it and gives you a straight answer: confirmed, not found, or — just as important — 'that's not something these checks can test,' with the reason why. No fake confidence, ever."

---

## 3:25–3:50 — Technical & Scalability Overview (25s)

**VISUAL:** Quick architecture callouts — FastAPI backend, Next.js frontend, two local Ollama models labeled, Docker sandbox with resource limits, deterministic risk engine.

**VO:**
"Under the hood: a FastAPI backend, a Next.js frontend, and two local models running through Ollama — one for reasoning, one for explanation — so nothing about your code ever leaves your machine. Every sandbox is disposable, memory- and process-limited, and torn down the moment the check ends. Because detection is rule-based and the sandbox is just a Dockerfile your app already needs for deployment, this scales to any repo that already ships with — or can infer — a standard container, not just our demo app."

---

## 3:50–4:00 — Summary & Call to Action (10s)

**VISUAL:** Aegis logo/wordmark, GitHub repo link, "Team Barbie — ASYNC 2026."

**VO:**
"Aegis gives every solo developer shipping a real product the honest, automated security check they'd otherwise skip. Check out the repo, connect your own app, and see what it finds."

---

## Production Notes

- Keep all on-screen findings from the **demo mode** (`/demo` route) or a known-safe fixture repo — never show a real production secret, even blurred.
- The "Opening a private container…" sandbox animation should get a clean few seconds on screen — it's a strong visual beat and directly supports the "not just reading your source" claim.
- If recording live (not demo mode), have the backend already warmed up before hitting record — Ollama's first model load can be slow and will kill pacing.
- Consider a lower-third citation ("PentestGPT, USENIX Security 2024") during the 1:10–1:55 segment for credibility with judges who know the space.
