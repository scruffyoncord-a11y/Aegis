"use client";

// A fully mocked walk-through of Aegis's whole pipeline -- connect, browse,
// choose scope, scan, probe, findings, fix -- with NO real backend calls at
// all (no GitHub OAuth, no clone, no Docker, no Ollama). Exists so the UI
// can be restyled and rearranged freely without waiting on any of that, or
// accidentally firing a real pentest while iterating.
//
// It deliberately reuses the REAL rendering components (Card, RiskDashboard,
// AnalysisOverlay, SandboxBadge, FindingCard, RepoTree, DownloadReport) from
// the real page instead of rebuilding look-alikes -- a style/copy change
// made to one of those shows up identically here and in production, so this
// page can't quietly drift out of sync with the real thing.

import { useState } from "react";
import { AnalysisOverlay } from "../analysis-overlay";
import { Card } from "../components";
import { DownloadReport } from "../download-report";
import { classify, summarise } from "./mock-risk";
import {
  FindingCard,
  HunchModal,
  PROBE_STEPS,
  RepoTree,
  SCAN_STEPS,
  mergeRisk,
  type Repo,
  type TreeNode,
} from "../page";
import { RiskDashboard } from "../risk-dashboard";
import { SandboxBadge, type SandboxState } from "../sandbox-badge";
import type { Finding, FixResult, HunchResult, ProbeResponse, ScanResponse } from "../types";

const DEMO_REPO_PATH = "acme/webapp (demo)";

const MOCK_REPOS: Repo[] = [
  { full_name: "acme/webapp", private: false, permission: "admin", updated_at: null },
  { full_name: "acme/payments-api", private: true, permission: "write", updated_at: null },
  { full_name: "your-org/side-project", private: false, permission: "admin", updated_at: null },
];

const MOCK_TREE: TreeNode = {
  name: "webapp", path: ".", type: "dir",
  children: [
    {
      name: "src", path: "src", type: "dir",
      children: [
        {
          name: "routes", path: "src/routes", type: "dir",
          children: [
            { name: "admin.js", path: "src/routes/admin.js", type: "file" },
            { name: "orders.js", path: "src/routes/orders.js", type: "file" },
            { name: "profile.js", path: "src/routes/profile.js", type: "file" },
          ],
        },
        { name: "server.js", path: "src/server.js", type: "file" },
      ],
    },
    { name: "package.json", path: "package.json", type: "file" },
    { name: "Dockerfile", path: "Dockerfile", type: "file" },
    { name: "README.md", path: "README.md", type: "file" },
  ],
};

const MOCK_SUBPROJECTS = [".", "frontend", "backend"];

// Mirrors the real findings vulnscan-demo-bad (see /demo-repos) actually
// produces, so this demo shows the same story the live pipeline does.
const MOCK_SCAN_FINDINGS: Finding[] = [
  {
    type: "secret", file: "src/server.js", line: 12, rule: "aws-access-token",
    match: "AKIAQGXHZ3AB6PMKLNOP", severity: "critical",
    explanation: "This looks like a real AWS access key committed directly in source. Anyone who can read this file -- or its git history -- can use it.",
  },
  {
    type: "dependency-vuln", file: "package.json", line: null, rule: null,
    match: "express@4.16.0", severity: "high",
    explanation: "This version of express has a known, published vulnerability. Upgrading to a patched version removes it.",
  },
  {
    type: "dependency-vuln", file: "package.json", line: null, rule: null,
    match: "lodash@4.17.4", severity: "high",
    explanation: "This version of lodash has a known prototype-pollution vulnerability (CVE-2019-10744).",
  },
  {
    type: "dependency-missing", file: "package.json", line: null, rule: null,
    match: "totally-real-http-utils-2024@1.0.0", severity: "medium",
    explanation: "This package does not exist on the npm registry. If an attacker registers it first, `npm install` would silently pull in whatever they publish.",
  },
];

const MOCK_PROBE_FINDINGS: Finding[] = [
  {
    type: "missing-auth", file: "src/routes/admin.js", line: 14, rule: "unauthenticated-sensitive-route",
    match: "GET /api/admin/users", severity: "critical",
    explanation: "This route is reachable with no login required. Anyone who finds the URL can read or modify sensitive user data directly from the server.",
    evidence: {
      request: "GET /api/admin/users  (no Authorization header sent)",
      response_status: 200,
      response_body: '{"users":[{"id":1,"name":"Alice","email":"alice@example.com"}]}',
    },
  },
  {
    type: "idor", file: "src/routes/orders.js", line: 22, rule: "insecure-direct-object-reference",
    match: "GET /api/orders/:id", severity: "critical",
    explanation: "Essentially, this means someone could access orders that don't belong to them by changing the id in the URL (e.g. /api/orders/123), tricking the system into showing another user's order details.",
    evidence: {
      request: "GET /api/orders/1 and /api/orders/2, same identity, both requests",
      response_status: 200,
      response_body: 'id=1: {"order":{"id":1,"item":"Widget A"}}\nid=2: {"order":{"id":2,"item":"Widget B"}}',
    },
  },
];

function delay(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function buildScanResult(): ScanResponse {
  const findings = MOCK_SCAN_FINDINGS.map((f) => classify({ ...f }));
  const risk = summarise(findings, ["Secrets", "Dependencies", "Cloud Config"]);
  return { findings, score: risk.security_score, risk };
}

// A stand-in for the real screenshot the live pipeline captures of the
// actual sandboxed container -- an inline SVG mockup, so this page still
// needs no real image asset or backend call.
const MOCK_SCREENSHOT =
  "data:image/svg+xml," +
  encodeURIComponent(`<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="500">
    <rect width="1280" height="500" fill="#0f0f11"/>
    <rect width="1280" height="36" fill="#1f1f23"/>
    <circle cx="20" cy="18" r="6" fill="#ef4444"/>
    <circle cx="42" cy="18" r="6" fill="#eab308"/>
    <circle cx="64" cy="18" r="6" fill="#22c55e"/>
    <rect x="100" y="8" width="360" height="20" rx="10" fill="#2a2a2f"/>
    <text x="112" y="22" font-family="monospace" font-size="12" fill="#9ca3af">127.0.0.1:41883 (sandbox)</text>
    <text x="48" y="200" font-family="sans-serif" font-size="28" fill="#e5e7eb">acme/webapp is running.</text>
    <text x="48" y="240" font-family="monospace" font-size="16" fill="#6b7280">GET /api/admin/users -&gt; 200</text>
  </svg>`);

function buildProbeResult(): ProbeResponse {
  const findings = MOCK_PROBE_FINDINGS.map((f) => classify({ ...f }));
  const risk = summarise(findings, ["Access Control"]);
  return { findings, skipped: false, score: risk.security_score, risk, screenshot: MOCK_SCREENSHOT };
}

async function mockFix(finding: Finding): Promise<FixResult> {
  await delay(900); // a real fix generates + re-verifies against a throwaway copy; this just feels like it does
  if (finding.type === "secret") {
    return {
      finding_match: finding.match,
      finding_type: finding.type,
      verified: true,
      note: "Moved the secret out of code into an environment variable (AWS_ACCESS_KEY_ID), stored the real value in .env (now git-ignored), and added a .env.example placeholder.",
      diffs: {
        "src/server.js": `--- a/src/server.js\n+++ b/src/server.js\n@@ -10,7 +10,7 @@\n \n-const AWS_ACCESS_KEY_ID = "AKIAQGXHZ3AB6PMKLNOP";\n+const AWS_ACCESS_KEY_ID = process.env.AWS_ACCESS_KEY_ID;\n`,
      },
    };
  }
  if (finding.type === "dependency-vuln") {
    const [name] = (finding.match ?? "").split("@");
    return {
      finding_match: finding.match,
      finding_type: finding.type,
      verified: true,
      note: `Bumped ${name} to the first version without this vulnerability. Run \`npm install\` to apply.`,
      diffs: { "package.json": `--- a/package.json\n+++ b/package.json\n@@ -6,7 +6,7 @@\n-    "${name}": "${(finding.match ?? "").split("@")[1]}",\n+    "${name}": "latest-safe",\n` },
    };
  }
  if (finding.type === "missing-auth") {
    return {
      finding_match: finding.match,
      finding_type: finding.type,
      verified: true,
      note: "Added the existing `requireAuth` middleware to this route -- the same check other protected routes use.",
      diffs: { "src/routes/admin.js": `--- a/src/routes/admin.js\n+++ b/src/routes/admin.js\n@@ -12,7 +12,7 @@\n-app.get("/api/admin/users", (req, res) => {\n+app.get("/api/admin/users", requireAuth, (req, res) => {\n` },
    };
  }
  return {
    finding_match: finding.match,
    finding_type: finding.type,
    verified: true,
    note: "Added the ownership check another route in this app already uses on the same resource.",
    diffs: { "src/routes/orders.js": `--- a/src/routes/orders.js\n+++ b/src/routes/orders.js\n@@ -20,6 +20,9 @@\n   if (!order) return res.status(404).json({ error: "Not found" });\n+  if (order.ownerId !== CALLER_USER_ID) {\n+    return res.status(403).json({ error: "Forbidden" });\n+  }\n` },
  };
}

type FlowStep = "connect" | "verifying" | "browsing" | "idle" | "done";

export default function DemoPage() {
  const [flow, setFlow] = useState<FlowStep>("connect");
  const [pickedRepo, setPickedRepo] = useState<string | null>(null);
  const [connected, setConnected] = useState(false);

  const [scanOverlayOpen, setScanOverlayOpen] = useState(false);
  const [scanStage, setScanStage] = useState(0);
  const [scanFinished, setScanFinished] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResponse | null>(null);

  const [probeOverlayOpen, setProbeOverlayOpen] = useState(false);
  const [probeStage, setProbeStage] = useState(0);
  const [probeFinished, setProbeFinished] = useState(false);
  const [probeResult, setProbeResult] = useState<ProbeResponse | null>(null);

  const [hunchModalOpen, setHunchModalOpen] = useState(false);
  const [hunchAsked, setHunchAsked] = useState<string | null>(null);
  const [hunchResult, setHunchResult] = useState<HunchResult | null>(null);
  const [hunchEvaluating, setHunchEvaluating] = useState(false);

  const [testCredential, setTestCredential] = useState("");
  const [credentialFieldOpen, setCredentialFieldOpen] = useState(false);

  async function playStages(
    steps: { key: string }[],
    setStage: (i: number) => void,
    msPerStage: number,
  ) {
    for (let i = 0; i < steps.length; i++) {
      setStage(i);
      await delay(msPerStage);
    }
  }

  async function runScan() {
    setScanOverlayOpen(true);
    setScanStage(0);
    setScanFinished(false);
    await playStages(SCAN_STEPS, setScanStage, 550);
    setScanResult(buildScanResult());
    setScanFinished(true);
  }

  async function runProbe(): Promise<ProbeResponse> {
    setProbeOverlayOpen(true);
    setProbeStage(0);
    setProbeFinished(false);
    await playStages(PROBE_STEPS, setProbeStage, 600);
    const result = buildProbeResult();
    setProbeResult(result);
    setProbeFinished(true);
    return result;
  }

  // A stand-in for the real /hunch endpoint's LLM judgment: keyword-matches
  // the hint against categories this demo's canned findings actually cover,
  // so "Test a Hunch" still demonstrates all three real outcomes (confirmed
  // / not found / not testable) without a backend call.
  const _NOT_TESTABLE_HINTS = ["xss", "injection", "sql", "csrf", "rate limit", "business logic", "price", "discount"];
  const _CATEGORY_KEYWORDS: { words: string[]; type: string }[] = [
    { words: ["admin", "auth", "login", "permission"], type: "missing-auth" },
    { words: ["order", "idor", "another user", "other user", "someone else"], type: "idor" },
    { words: ["secret", "key", "credential", "token", "aws"], type: "secret" },
    { words: ["depend", "package", "express", "lodash", "vulnerable"], type: "dependency-vuln" },
  ];

  async function evaluateHunchMock(hintText: string, findings: Finding[]): Promise<HunchResult> {
    await delay(900); // feels like a real model call
    const lower = hintText.toLowerCase();
    if (_NOT_TESTABLE_HINTS.some((w) => lower.includes(w))) {
      return {
        testable: false,
        confirmed: null,
        explanation: "This is outside what Aegis's current checks can verify -- it doesn't test business logic, injection, or client-side issues like this.",
      };
    }
    const category = _CATEGORY_KEYWORDS.find((c) => c.words.some((w) => lower.includes(w)));
    if (!category) {
      return {
        testable: false,
        confirmed: null,
        explanation: "Not sure this maps to any check Aegis currently runs -- try phrasing it around auth, access control, secrets, or dependencies.",
      };
    }
    const match = findings.find((f) => f.type === category.type);
    if (match) {
      return {
        testable: true,
        confirmed: true,
        explanation: `Confirmed -- ${match.type}: ${match.match} (${match.file ?? "no specific file"}). This matches what you suspected.`,
      };
    }
    return {
      testable: true,
      confirmed: false,
      explanation: "This is something Aegis can test for, but nothing in this run's confirmed findings matches it -- that area looks clean.",
    };
  }

  async function submitHunch(hintText: string) {
    setHunchModalOpen(false);
    setHunchAsked(hintText);
    setHunchResult(null);
    const freshProbe = await runProbe();
    const combined = [...(scanResult?.findings ?? []), ...(freshProbe.findings ?? [])];
    setHunchEvaluating(true);
    try {
      setHunchResult(await evaluateHunchMock(hintText, combined));
    } finally {
      setHunchEvaluating(false);
    }
  }

  async function pickRepo(name: string) {
    setPickedRepo(name);
    setFlow("verifying");
    await delay(1100);
    setFlow("browsing");
  }

  async function confirmScope() {
    setConnected(true);
    setFlow("idle");
    await runScan();
    await runProbe();
    setFlow("done");
  }

  function reset() {
    setFlow("connect");
    setPickedRepo(null);
    setConnected(false);
    setScanOverlayOpen(false);
    setScanFinished(false);
    setScanResult(null);
    setProbeOverlayOpen(false);
    setProbeFinished(false);
    setProbeResult(null);
    setHunchModalOpen(false);
    setHunchAsked(null);
    setHunchResult(null);
  }

  const combinedRisk = mergeRisk(scanResult?.risk ?? null, probeResult?.risk ?? null);
  const allFindings: Finding[] = [...(scanResult?.findings ?? []), ...(probeResult?.findings ?? [])];
  const sandboxState: SandboxState = probeOverlayOpen ? "opening" : probeResult ? "active" : "standby";

  return (
    <main className="w-full px-10 py-10">
      <div className="no-print mb-4 flex items-center justify-between rounded-lg border border-amber-400 bg-amber-50 px-4 py-2 text-sm text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-200">
        <span>
          <strong>Demo mode</strong> -- every screen below is mocked. No GitHub, no clone, no Docker, no Ollama call happens on this page.
        </span>
        <button type="button" onClick={reset} className="shrink-0 font-semibold underline">
          Restart demo
        </button>
      </div>

      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold">Aegis</h1>
          <p className="mt-1 text-zinc-600 dark:text-zinc-300">
            AI pentesting agent -- Observe &rarr; Detect &rarr; Explain &rarr; Respond
          </p>
        </div>
        <div className="flex items-center gap-3">
          {connected && (
            <div className="flex gap-2">
              <button
                type="button"
                onClick={runScan}
                disabled={scanOverlayOpen}
                className="rounded-lg border border-zinc-300 px-4 py-1.5 text-sm font-semibold text-zinc-700 transition hover:bg-zinc-100 disabled:opacity-50 dark:border-zinc-700 dark:text-zinc-200 dark:hover:bg-zinc-800"
              >
                {scanOverlayOpen ? "Scanning…" : "Re-scan"}
              </button>
              <button
                type="button"
                onClick={() => setHunchModalOpen(true)}
                disabled={probeOverlayOpen}
                className="rounded-lg bg-zinc-900 px-4 py-1.5 text-sm font-semibold text-white transition hover:bg-zinc-700 disabled:opacity-50 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-white"
              >
                {probeOverlayOpen ? "Pentesting…" : "Test a Hunch"}
              </button>
              <button
                type="button"
                onClick={() => setCredentialFieldOpen((o) => !o)}
                title="Optional: a real test-account token/cookie from YOUR OWN app, used for the IDOR check instead of Aegis's demo convention."
                className="rounded-lg px-2 py-1.5 text-xs text-zinc-500 underline hover:text-zinc-700 dark:hover:text-zinc-300"
              >
                {testCredential ? "Test credential set" : "Set test credential"}
              </button>
            </div>
          )}
          <SandboxBadge state={sandboxState} />
        </div>
      </header>

      {connected && credentialFieldOpen && (
        <div className="mt-2 flex items-center gap-2">
          <input
            value={testCredential}
            onChange={(e) => setTestCredential(e.target.value)}
            placeholder='Bearer eyJhbGci... or Cookie: session=... (optional, for a real IDOR check)'
            className="flex-1 rounded-lg border border-zinc-300 bg-transparent p-2 text-sm dark:border-zinc-700"
          />
          <p className="text-xs text-zinc-500">
            A real logged-in token/cookie from a test account on <em>this app</em> -- lets the IDOR check use your
            own auth instead of Aegis's demo convention. Never sent anywhere but this app's own sandbox.
          </p>
        </div>
      )}

      {hunchModalOpen && <HunchModal onCancel={() => setHunchModalOpen(false)} onSubmit={submitHunch} />}

      <div className="mt-6">
        {connected ? (
          <div className="tg-card flex items-center justify-between gap-3 p-4 text-sm">
            <span className="text-emerald-600 dark:text-emerald-400">
              Connected -- {pickedRepo} (admin access)
            </span>
            <button type="button" onClick={reset} className="shrink-0 text-zinc-500 underline">
              Change repo
            </button>
          </div>
        ) : flow === "verifying" ? (
          <Card title="Connect a GitHub repo">
            <div className="flex flex-col items-center gap-3 py-10 text-center">
              <div className="h-8 w-8 animate-spin rounded-full border-2 border-zinc-300 border-t-emerald-500 dark:border-zinc-700" />
              <p className="text-sm font-medium">Verifying repository ownership&hellip;</p>
              <p className="text-xs text-zinc-500">Checking push/admin access, then cloning into a disposable sandbox copy.</p>
            </div>
          </Card>
        ) : flow === "browsing" ? (
          <Card title="Your codebase">
            <p className="text-sm text-zinc-600 dark:text-zinc-300">
              {pickedRepo} &mdash; admin access. Verified and cloned into a sandbox copy.
            </p>
            <div className="tg-card mt-3 max-h-64 overflow-y-auto !rounded-lg p-3 font-mono text-xs">
              <RepoTree node={MOCK_TREE} depth={0} />
            </div>
            <p className="mt-4 text-sm font-semibold uppercase tracking-wide text-zinc-500">What do you want to pentest?</p>
            <ul className="mt-2 space-y-1">
              {MOCK_SUBPROJECTS.map((sub) => (
                <li key={sub}>
                  <button
                    type="button"
                    onClick={confirmScope}
                    className="tg-card flex w-full items-center justify-between gap-2 !rounded-lg px-3 py-2 text-left text-sm"
                  >
                    <span>{sub === "." ? "Whole app (everything Aegis can reach)" : `${sub}/`}</span>
                  </button>
                </li>
              ))}
            </ul>
            <button type="button" onClick={reset} className="mt-3 text-xs text-zinc-500 underline">
              Change repo
            </button>
          </Card>
        ) : (
          <Card title="Connect a GitHub repo">
            <p className="text-sm text-zinc-600 dark:text-zinc-300">
              Aegis only scans repos you can prove you control. You sign in directly on GitHub -- your access token stays on
              the Aegis backend and is never sent to or stored by this page.
            </p>
            <p className="mt-3 text-sm text-emerald-600 dark:text-emerald-400">Signed in as demo-user</p>
            <ul className="mt-2 space-y-1">
              {MOCK_REPOS.map((r) => (
                <li key={r.full_name}>
                  <button
                    type="button"
                    onClick={() => pickRepo(r.full_name)}
                    className="tg-card flex w-full items-center justify-between gap-2 !rounded-lg px-3 py-2 text-left text-sm"
                  >
                    <span className="truncate">{r.full_name}</span>
                    <span className="shrink-0 text-xs text-zinc-500">{r.private ? "private" : "public"}</span>
                  </button>
                </li>
              ))}
            </ul>
          </Card>
        )}
      </div>


      {scanOverlayOpen && (
        <AnalysisOverlay
          steps={SCAN_STEPS.map(({ label, detail }) => ({ label, detail }))}
          stage={scanStage}
          finished={scanFinished}
          onClosed={() => setScanOverlayOpen(false)}
        />
      )}
      {probeOverlayOpen && (
        <AnalysisOverlay
          steps={PROBE_STEPS.map(({ label, detail }) => ({ label, detail }))}
          stage={probeStage}
          finished={probeFinished}
          onClosed={() => setProbeOverlayOpen(false)}
          onTerminate={() => setProbeOverlayOpen(false)}
        />
      )}

      {combinedRisk && (
        <div className="mt-6 space-y-6">
          <RiskDashboard risk={combinedRisk} />

          {hunchAsked && (
            <Card title="Your Hunch">
              <p className="text-sm text-zinc-500">You asked Aegis to specifically check:</p>
              <p className="mt-1 text-sm font-medium text-zinc-800 dark:text-zinc-100">&ldquo;{hunchAsked}&rdquo;</p>
              {hunchEvaluating ? (
                <p className="mt-3 text-sm text-zinc-500">Checking your hunch against what this run actually found&hellip;</p>
              ) : hunchResult ? (
                <div className="mt-3">
                  <span
                    className={`inline-block rounded px-2.5 py-0.5 text-xs font-bold text-white ${
                      hunchResult.testable === null
                        ? "bg-zinc-500"
                        : !hunchResult.testable
                          ? "bg-amber-500"
                          : hunchResult.confirmed
                            ? "bg-red-600"
                            : "bg-emerald-600"
                    }`}
                  >
                    {hunchResult.testable === null
                      ? "COULD NOT EVALUATE"
                      : !hunchResult.testable
                        ? "NOT TESTABLE HERE"
                        : hunchResult.confirmed
                          ? "CONFIRMED"
                          : "NOT FOUND"}
                  </span>
                  <p className="mt-2 text-sm text-zinc-700 dark:text-zinc-300">{hunchResult.explanation}</p>
                </div>
              ) : null}
            </Card>
          )}

          {probeResult?.screenshot && (
            <Card title="What we actually tested">
              <p className="text-sm text-zinc-600 dark:text-zinc-300">
                Captured the moment the sandboxed container came up -- proof this ran against a real, live instance, not just its source.
              </p>
              <img
                src={probeResult.screenshot}
                alt="Screenshot of the sandboxed app at the moment it was probed"
                className="mt-3 w-full rounded-lg border border-zinc-300 dark:border-zinc-700"
              />
            </Card>
          )}

          {allFindings.length > 0 && (
            <div className="space-y-3">
              <h2 className="text-sm font-semibold uppercase tracking-wide text-zinc-600 dark:text-zinc-300">
                {allFindings.length} finding{allFindings.length === 1 ? "" : "s"}
              </h2>
              {allFindings.map((f, i) => (
                <FindingCard key={`${f.type}-${i}`} finding={f} repoPath={DEMO_REPO_PATH} fixOverride={mockFix} />
              ))}
            </div>
          )}

          <DownloadReport />
        </div>
      )}
    </main>
  );
}
