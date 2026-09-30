"use client";

import { useEffect, useState } from "react";
import { AnalysisOverlay } from "./analysis-overlay";
import type { Step } from "@/components/ui/onboard-card";
import { Card } from "./components";
import { DownloadReport } from "./download-report";
import { API, readStream } from "./lib";
import { RiskDashboard } from "./risk-dashboard";
import { SandboxBadge, type SandboxState } from "./sandbox-badge";
import type { Finding, FixResult, HunchResult, ProbeResponse, RiskSummary, ScanResponse } from "./types";

// Each entry's key must match a real "stage" event name the backend actually
// emits (see backend/app/main.py::_run_scan / _run_probe) -- the overlay
// follows real progress, it never fakes a step that isn't really happening.
export const SCAN_STEPS: (Step & { key: string })[] = [
  { key: "started", label: "Request received", detail: "Reading the repo" },
  { key: "detecting", label: "Detecting issues", detail: "Gitleaks, dependency, and config checks" },
  { key: "explaining", label: "Explaining findings", detail: "A local model writes each explanation" },
];

export const PROBE_STEPS: (Step & { key: string })[] = [
  { key: "started", label: "Request received", detail: "Preparing the active probe" },
  { key: "tracing", label: "Tracing routes", detail: "Mapping the app's routes and middleware" },
  { key: "reasoning", label: "Reasoning about auth", detail: "A local model hypothesizes what's unprotected" },
  { key: "sandbox", label: "Building sandbox", detail: "Building and starting the app's own Dockerfile" },
  { key: "probing", label: "Probing live", detail: "Sending one safe request, no credentials" },
  { key: "explaining", label: "Explaining findings", detail: "A local model writes each explanation" },
];

export const SEVERITY_STYLE: Record<string, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-amber-400 text-zinc-900",
  low: "bg-zinc-500 text-white",
};

/** Combines /scan and /probe's independent RiskSummary responses into one
 * dashboard view, the same way Epiderm combines a message + its attachment:
 * each stage becomes a `part`, and the worse verdict of the two governs the
 * overall picture shown at the top. */
export function mergeRisk(scanRisk: RiskSummary | null, probeRisk: RiskSummary | null): RiskSummary | null {
  if (!scanRisk && !probeRisk) return null;
  const parts = [];
  if (scanRisk) parts.push({ name: "Static scan (secrets, deps, config)", risk_score: scanRisk.risk_score, verdict: scanRisk.verdict });
  if (probeRisk) parts.push({ name: "Active AI pentest probe", risk_score: probeRisk.risk_score, verdict: probeRisk.verdict });

  const base = scanRisk && probeRisk
    ? (scanRisk.security_score <= probeRisk.security_score ? scanRisk : probeRisk) // worse (lower) score wins
    : (scanRisk ?? probeRisk)!;

  const areas = [...(scanRisk?.areas ?? []), ...(probeRisk?.areas ?? [])];
  const matrix = [...(scanRisk?.matrix ?? []), ...(probeRisk?.matrix ?? [])].sort((a, b) => b.weight - a.weight);
  const suspicious = (scanRisk?.suspicious ?? 0) + (probeRisk?.suspicious ?? 0);
  const reassuring = (scanRisk?.reassuring ?? 0) + (probeRisk?.reassuring ?? 0);

  return { ...base, areas, matrix, suspicious, reassuring, parts };
}

export function FindingCard({
  finding,
  repoPath,
  fixOverride,
}: {
  finding: Finding;
  repoPath: string;
  /** When given, used INSTEAD of the real /fix call -- this is what lets
   * the demo page reuse this exact component with no real backend at all. */
  fixOverride?: (finding: Finding) => Promise<FixResult>;
}) {
  const [fixing, setFixing] = useState(false);
  const [fix, setFix] = useState<FixResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleFix() {
    setFixing(true);
    setError(null);
    try {
      if (fixOverride) {
        setFix(await fixOverride(finding));
        return;
      }
      const res = await fetch(`${API}/fix`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo_path: repoPath, finding }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setFix(await res.json());
    } catch (e) {
      setError(String(e));
    } finally {
      setFixing(false);
    }
  }

  return (
    <Card
      title={finding.type}
      aside={
        <span className={`rounded px-2 py-0.5 text-xs font-bold uppercase ${SEVERITY_STYLE[finding.severity] ?? "bg-zinc-500 text-white"}`}>
          {finding.severity}
        </span>
      }
    >
      <p className="text-sm font-medium text-zinc-800 dark:text-zinc-100">{finding.match}</p>
      <p className="mt-2 text-sm text-zinc-700 dark:text-zinc-300">{finding.explanation}</p>

      {finding.evidence && (
        <div className="mt-3 rounded-lg border border-zinc-300 bg-zinc-100 p-3 font-mono text-xs dark:border-zinc-700 dark:bg-zinc-900">
          <div className="text-zinc-600 dark:text-zinc-400">{finding.evidence.request}</div>
          <div className="mt-1 font-semibold text-orange-600 dark:text-orange-400">
            → {finding.evidence.response_status} response, real data returned
          </div>
          <div className="mt-1 text-zinc-500 dark:text-zinc-500">{finding.evidence.response_body}</div>
        </div>
      )}

      {!fix && (
        <button
          type="button"
          onClick={handleFix}
          disabled={fixing}
          className="mt-3 rounded-lg bg-fuchsia-600 px-4 py-1.5 text-sm font-semibold text-white transition hover:bg-fuchsia-500 disabled:opacity-50"
        >
          {fixing ? "Fixing…" : "Fix"}
        </button>
      )}
      {error && <p className="mt-2 text-sm text-red-500">Error: {error}</p>}

      {fix && (
        <div className="mt-3">
          <span
            className={`inline-block rounded px-2.5 py-0.5 text-xs font-bold text-white ${fix.verified ? "bg-emerald-600" : "bg-red-600"}`}
          >
            {fix.verified ? "VERIFIED FIXED" : "NOT VERIFIED"}
          </span>
          <p className="mt-2 text-sm text-zinc-700 dark:text-zinc-300">{fix.note}</p>
          {Object.entries(fix.diffs).map(([path, diff]) => (
            <div key={path} className="mt-2">
              <div className="text-xs text-zinc-500">{path}</div>
              <pre className="mt-1 overflow-x-auto rounded-lg border border-zinc-300 bg-zinc-100 p-3 text-xs dark:border-zinc-700 dark:bg-zinc-900">
                {diff}
              </pre>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}

export type Repo = { full_name: string; private: boolean; permission: string; updated_at: string | null };
export type TreeNode = { name: string; path: string; type: "dir" | "file" | "more"; children?: TreeNode[] };

/** A read-only, GitHub-style mini file tree -- <details>/<summary> gives
 * collapsible folders for free, no extra expand/collapse state to manage. */
export function RepoTree({ node, depth }: { node: TreeNode; depth: number }) {
  if (node.type === "more") {
    return <p className="pl-4 text-zinc-500">&hellip; more</p>;
  }
  if (node.type === "file") {
    return <p style={{ paddingLeft: `${depth * 16}px` }}>{node.name}</p>;
  }
  return (
    <details open={depth < 1} style={{ paddingLeft: depth === 0 ? 0 : 16 }}>
      <summary className="cursor-pointer select-none text-zinc-700 dark:text-zinc-300">{node.name}/</summary>
      {(node.children ?? []).map((child) => (
        <RepoTree key={child.path || child.name} node={child} depth={depth + 1} />
      ))}
    </details>
  );
}

/** "Test a Hunch": a small modal card, not the full AnalysisOverlay
 * treatment -- this is a quick text prompt, not a multi-step process. States
 * the check's real scope up front (what it CAN and CAN'T test) so a hunch
 * about something outside that scope isn't a surprise later in the report. */
export function HunchModal({
  onCancel,
  onSubmit,
}: {
  onCancel: () => void;
  onSubmit: (hint: string) => void;
}) {
  const [text, setText] = useState("");
  return (
    <div className="no-print fixed inset-0 z-50 flex items-center justify-center bg-background/55 px-4 backdrop-blur-md" onClick={onCancel}>
      <div className="tg-card w-full max-w-lg p-6" onClick={(e) => e.stopPropagation()}>
        <h2 className="text-lg font-semibold">Test a Hunch</h2>
        <p className="mt-1 text-sm text-zinc-600 dark:text-zinc-300">
          Tell Aegis what you suspect might be wrong. It'll pay extra attention to that area during the pentest, then
          tell you plainly whether it found something, or if it's not something these checks can test.
        </p>

        <div className="mt-4 grid grid-cols-2 gap-3 text-xs">
          <div className="tg-card !rounded-lg p-3">
            <p className="font-semibold text-emerald-600 dark:text-emerald-400">Works best for</p>
            <ul className="mt-1 list-disc space-y-0.5 pl-4 text-zinc-600 dark:text-zinc-300">
              <li>Missing authentication on a route</li>
              <li>Broken access control / IDOR</li>
              <li>Leaked secrets or API keys</li>
              <li>Vulnerable or fake dependencies</li>
              <li>Open Firebase/Supabase rules</li>
            </ul>
          </div>
          <div className="tg-card !rounded-lg p-3">
            <p className="font-semibold text-amber-600 dark:text-amber-400">Not testable here</p>
            <ul className="mt-1 list-disc space-y-0.5 pl-4 text-zinc-600 dark:text-zinc-300">
              <li>Business logic bugs</li>
              <li>XSS / SQL injection</li>
              <li>Rate limiting, CSRF</li>
            </ul>
          </div>
        </div>

        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder={'e.g. "I think the orders endpoint might let one user see another user\'s order"'}
          rows={3}
          className="mt-4 w-full rounded-lg border border-zinc-300 bg-transparent p-2 text-sm dark:border-zinc-700"
        />

        <div className="mt-4 flex justify-end gap-2">
          <button type="button" onClick={onCancel} className="rounded-lg px-4 py-1.5 text-sm font-semibold text-zinc-500 hover:underline">
            Cancel
          </button>
          <button
            type="button"
            onClick={() => text.trim() && onSubmit(text.trim())}
            disabled={!text.trim()}
            className="rounded-lg bg-zinc-900 px-4 py-1.5 text-sm font-semibold text-white transition hover:bg-zinc-700 disabled:opacity-50 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-white"
          >
            Run it
          </button>
        </div>
      </div>
    </div>
  );
}

function GitHubConnect({ onConnected }: { onConnected: (path: string) => void }) {
  const [status, setStatus] = useState<{ loading: boolean; connected: boolean; github_login?: string }>({ loading: true, connected: false });
  const [repos, setRepos] = useState<Repo[] | null>(null);
  const [reposError, setReposError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [cloningRepo, setCloningRepo] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [cloned, setCloned] = useState<{ owner: string; repo: string; permission: string; private: boolean; subpath: string } | null>(null);
  // Set right after clone succeeds -- holds everything needed to show the
  // "browse the codebase, then pick what to pentest" step before anything
  // actually runs. `tree` arrives a beat later (its own fetch), so the
  // structure step can render immediately with a loading placeholder rather
  // than blocking on it.
  const [browsing, setBrowsing] = useState<{
    repo_path: string; owner: string; repo: string; permission: string; private: boolean;
    subprojects: string[]; tree: TreeNode | null; treeLoading: boolean;
  } | null>(null);

  async function refreshStatus() {
    try {
      const res = await fetch(`${API}/github/session`, { credentials: "include" });
      const data = await res.json();
      setStatus({ loading: false, ...data });
      if (data.connected) loadRepos();
    } catch {
      setStatus({ loading: false, connected: false });
    }
  }

  async function loadRepos() {
    setReposError(null);
    try {
      const res = await fetch(`${API}/github/repos`, { credentials: "include" });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
      setRepos(data.repos);
    } catch (e) {
      setReposError(String(e));
    }
  }

  useEffect(() => {
    refreshStatus();
  }, []);

  async function handleLogout() {
    await fetch(`${API}/github/logout`, { method: "POST", credentials: "include" });
    setCloned(null);
    setRepos(null);
    refreshStatus();
  }

  async function handlePick(repoUrl: string) {
    setCloningRepo(repoUrl);
    setError(null);
    try {
      const res = await fetch(`${API}/github/verify-and-clone`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo_url: repoUrl }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
      const subprojects: string[] = data.subprojects ?? ["."];
      // Always land on the "browse, then pick what to pentest" step now --
      // never auto-run. The tree fetch is separate and slower, so this
      // renders immediately with a loading placeholder rather than making
      // the whole step wait on it.
      setBrowsing({ ...data, subprojects, tree: null, treeLoading: true });
      fetchTree(data.repo_path);
    } catch (e) {
      setError(String(e));
    } finally {
      setCloningRepo(null);
    }
  }

  async function fetchTree(repoPath: string) {
    try {
      const res = await fetch(`${API}/repo/tree`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo_path: repoPath }),
      });
      const tree: TreeNode = await res.json();
      setBrowsing((prev) => (prev ? { ...prev, tree, treeLoading: false } : prev));
    } catch {
      setBrowsing((prev) => (prev ? { ...prev, treeLoading: false } : prev));
    }
  }

  function confirmScope(subpath: string) {
    if (!browsing) return;
    const fullPath = subpath === "." ? browsing.repo_path : `${browsing.repo_path}/${subpath}`;
    setCloned({ ...browsing, subpath });
    setBrowsing(null);
    onConnected(fullPath);
  }

  const filtered = (repos ?? []).filter((r) => r.full_name.toLowerCase().includes(query.toLowerCase()));

  // Once a repo is verified and cloned, collapse the whole connect/picker
  // UI down to one line -- the dashboard below is the point from here on.
  if (cloned) {
    return (
      <div className="tg-card flex items-center justify-between gap-3 p-4 text-sm">
        <span className="text-emerald-600 dark:text-emerald-400">
          Connected -- {cloned.owner}/{cloned.repo}
          {cloned.subpath !== "." && <> ({cloned.subpath}/)</>} ({cloned.permission} access{cloned.private ? ", private" : ""})
        </span>
        <button
          type="button"
          onClick={() => setCloned(null)}
          className="shrink-0 text-zinc-500 underline"
        >
          Change repo
        </button>
      </div>
    );
  }

  // Between clicking a repo and the clone finishing: a dedicated verifying
  // step, not just a busy button -- this can take a few seconds for a
  // larger repo, and a blank list with a disabled button reads as stuck.
  if (cloningRepo) {
    return (
      <Card title="Connect a GitHub repo">
        <div className="flex flex-col items-center gap-3 py-10 text-center">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-zinc-300 border-t-emerald-500 dark:border-zinc-700" />
          <p className="text-sm font-medium">Verifying repository ownership&hellip;</p>
          <p className="text-xs text-zinc-500">Checking push/admin access, then cloning into a disposable sandbox copy.</p>
        </div>
      </Card>
    );
  }

  if (browsing) {
    return (
      <Card title="Your codebase">
        <p className="text-sm text-zinc-600 dark:text-zinc-300">
          {browsing.owner}/{browsing.repo} &mdash; {browsing.permission} access{browsing.private ? ", private" : ""}.
          Verified and cloned into a sandbox copy.
        </p>

        <div className="tg-card mt-3 max-h-64 overflow-y-auto !rounded-lg p-3 font-mono text-xs">
          {browsing.treeLoading ? (
            <p className="text-zinc-500">Reading the file tree&hellip;</p>
          ) : browsing.tree ? (
            <RepoTree node={browsing.tree} depth={0} />
          ) : (
            <p className="text-zinc-500">Could not read the file tree (continuing anyway).</p>
          )}
        </div>

        <p className="mt-4 text-sm font-semibold uppercase tracking-wide text-zinc-500">What do you want to pentest?</p>
        <ul className="mt-2 space-y-1">
          {browsing.subprojects.map((sub) => (
            <li key={sub}>
              <button
                type="button"
                onClick={() => confirmScope(sub)}
                className="tg-card flex w-full items-center justify-between gap-2 !rounded-lg px-3 py-2 text-left text-sm"
              >
                <span>{sub === "." ? "Whole app (everything Aegis can reach)" : `${sub}/`}</span>
              </button>
            </li>
          ))}
        </ul>
        <button type="button" onClick={() => setBrowsing(null)} className="mt-3 text-xs text-zinc-500 underline">
          Change repo
        </button>
      </Card>
    );
  }

  return (
    <Card title="Connect a GitHub repo">
      <p className="text-sm text-zinc-600 dark:text-zinc-300">
        Aegis only scans repos you can prove you control. You sign in directly on GitHub -- your access token stays on
        the Aegis backend and is never sent to or stored by this page.
      </p>

      {status.loading ? null : !status.connected ? (
        <a
          href={`${API}/github/oauth/login`}
          className="mt-3 inline-block rounded-lg bg-zinc-900 px-4 py-2 text-sm font-semibold text-white hover:bg-zinc-700 dark:bg-zinc-100 dark:text-zinc-900"
        >
          Connect with GitHub
        </a>
      ) : (
        <>
          <p className="mt-3 text-sm text-emerald-600 dark:text-emerald-400">
            Signed in as {status.github_login}{" "}
            <button type="button" onClick={handleLogout} className="text-zinc-500 underline">
              disconnect
            </button>
          </p>

          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search repositories, or paste a URL…"
            className="mt-2 w-full rounded-lg border border-zinc-300 bg-transparent p-2 text-sm dark:border-zinc-700"
          />

          {reposError && (
            <p className="mt-2 text-sm text-red-500">
              Could not list repos: {reposError}{" "}
              <button type="button" onClick={loadRepos} className="underline">retry</button>
            </p>
          )}

          {repos === null && !reposError && (
            <p className="mt-2 text-sm text-zinc-500">Loading your repos…</p>
          )}

          {repos !== null && (
            <ul className="mt-2 max-h-72 space-y-1 overflow-y-auto">
              {filtered.length === 0 && (
                <li className="text-sm text-zinc-500">
                  {query ? "No matching repo. You can also paste a full owner/repo URL above." : "No repos with write access found."}
                </li>
              )}
              {filtered.map((r) => (
                <li key={r.full_name}>
                  <button
                    type="button"
                    onClick={() => handlePick(r.full_name)}
                    disabled={cloningRepo !== null}
                    className="tg-card flex w-full items-center justify-between gap-2 !rounded-lg px-3 py-2 text-left text-sm disabled:opacity-50"
                  >
                    <span className="truncate">{r.full_name}</span>
                    <span className="shrink-0 text-xs text-zinc-500">
                      {cloningRepo === r.full_name ? "Verifying…" : r.private ? "private" : "public"}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}

          {/* Paste-a-URL fallback: if what's typed looks like an owner/repo not in the list above. */}
          {query.includes("/") && filtered.length === 0 && (
            <button
              type="button"
              onClick={() => handlePick(query)}
              disabled={cloningRepo !== null}
              className="mt-2 rounded-lg bg-emerald-600 px-4 py-2 text-sm font-semibold text-white disabled:opacity-50"
            >
              {cloningRepo ? "Verifying…" : `Verify & Clone "${query}"`}
            </button>
          )}
        </>
      )}

      {error && <p className="mt-2 text-sm text-red-500">{error}</p>}
    </Card>
  );
}

export default function Home() {
  const [repoPath, setRepoPath] = useState("../demo-app");
  const [repoConnected, setRepoConnected] = useState(false);
  const [scanOverlayOpen, setScanOverlayOpen] = useState(false);
  const [scanStage, setScanStage] = useState(0);
  const [scanFinished, setScanFinished] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResponse | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  const [probeOverlayOpen, setProbeOverlayOpen] = useState(false);
  const [probeStage, setProbeStage] = useState(0);
  const [probeFinished, setProbeFinished] = useState(false);
  const [probeResult, setProbeResult] = useState<ProbeResponse | null>(null);
  const [probeError, setProbeError] = useState<string | null>(null);
  // Handed to us in /probe/stream's very first event -- the "Terminate
  // pentest" button needs it to tell the backend which run to actually stop.
  const [probeRunId, setProbeRunId] = useState<string | null>(null);

  // "Test a Hunch": the modal's open/closed state, the hunch actually
  // submitted (shown in the report section once set), and its verdict once
  // /hunch answers (null while that call is still in flight).
  const [hunchModalOpen, setHunchModalOpen] = useState(false);
  const [hunchAsked, setHunchAsked] = useState<string | null>(null);
  const [hunchResult, setHunchResult] = useState<HunchResult | null>(null);
  const [hunchEvaluating, setHunchEvaluating] = useState(false);

  // A real test credential from the user's OWN account on the target app --
  // used for the IDOR probe's two test requests instead of Aegis's demo
  // fixture convention (Bearer demo-valid-token), which only means
  // anything to Aegis's own test apps. Optional: every probe still runs
  // fine without one, just against the demo convention as before.
  const [testCredential, setTestCredential] = useState("");
  const [credentialFieldOpen, setCredentialFieldOpen] = useState(false);

  // Both take an optional explicit path so they can be called right after a
  // repo is connected, using the fresh value directly -- calling them via
  // the repoPath STATE at that point would still see the old value, since
  // setRepoPath's update hasn't landed yet on the same tick.
  async function handleScan(path?: string) {
    const target = path ?? repoPath;
    setScanOverlayOpen(true);
    setScanStage(0);
    setScanFinished(false);
    setScanError(null);
    try {
      const res = await fetch(`${API}/scan/stream`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo_path: target }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await readStream<ScanResponse>(res, (s) => {
        const i = SCAN_STEPS.findIndex((step) => step.key === s);
        if (i >= 0) setScanStage((cur) => Math.max(cur, i));
      });
      setScanResult(data);
    } catch (e) {
      setScanError(String(e));
    } finally {
      setScanFinished(true); // lets the overlay play its remaining steps, then it calls back to close itself
    }
  }

  // `hint` is "Test a Hunch"'s free-text lead (undefined for a normal
  // re-run). Returns the fresh result directly -- a caller that needs it
  // right after (submitHunch, below) can't rely on the probeResult STATE
  // being updated yet in the same tick, the same staleness issue explicit
  // path-passing already works around elsewhere in this file.
  async function handleProbe(path?: string, hint?: string): Promise<ProbeResponse | undefined> {
    const target = path ?? repoPath;
    setProbeOverlayOpen(true);
    setProbeStage(0);
    setProbeFinished(false);
    setProbeError(null);
    setProbeRunId(null);
    try {
      const res = await fetch(`${API}/probe/stream`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo_path: target, hint: hint ?? null, test_credential: testCredential.trim() || null }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await readStream<ProbeResponse>(
        res,
        (s) => {
          const i = PROBE_STEPS.findIndex((step) => step.key === s);
          if (i >= 0) setProbeStage((cur) => Math.max(cur, i));
        },
        (started) => {
          if (typeof started.run_id === "string") setProbeRunId(started.run_id);
        },
      );
      setProbeResult(data);
      return data;
    } catch (e) {
      setProbeError(String(e));
      return undefined;
    } finally {
      setProbeFinished(true);
    }
  }

  async function evaluateHunch(hintText: string, findings: Finding[]) {
    setHunchEvaluating(true);
    try {
      const res = await fetch(`${API}/hunch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hint: hintText, findings }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setHunchResult(await res.json());
    } catch (e) {
      setHunchResult({ testable: null, confirmed: null, explanation: `Could not evaluate this hunch right now: ${e}` });
    } finally {
      setHunchEvaluating(false);
    }
  }

  // Re-runs the probe biased toward the user's hunch (see
  // detectors/routes.py's hypothesize_* for how that biasing works), then
  // judges the hunch against the FULL picture -- the existing scan findings
  // plus this fresh probe's findings -- since a hunch about a leaked secret,
  // say, can only ever be confirmed by the scan side, not the probe alone.
  async function submitHunch(hintText: string) {
    setHunchModalOpen(false);
    setHunchAsked(hintText);
    setHunchResult(null);
    const freshProbe = await handleProbe(undefined, hintText);
    const combined = [...(scanResult?.findings ?? []), ...(freshProbe?.findings ?? [])];
    await evaluateHunch(hintText, combined);
  }

  // Closes the overlay immediately for instant feedback, and tells the
  // backend to actually stop -- fire-and-forget from the UI's side, since
  // handleProbe's own request is still in flight and will resolve on its
  // own once the backend honors the cancel (see app/cancellation.py).
  function handleTerminateProbe() {
    setProbeOverlayOpen(false);
    if (probeRunId) {
      fetch(`${API}/probe/cancel`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ run_id: probeRunId }),
      }).catch(() => {});
    }
  }

  // As soon as a repo is connected, start both checks immediately -- no
  // extra button click needed. They run one after another (not in
  // parallel): both use the one shared local model, and the probe also
  // needs Docker, so overlapping the two would just contend for the same
  // resources rather than actually go faster.
  async function handleConnected(path: string) {
    setRepoPath(path);
    setRepoConnected(true);
    await handleScan(path);
    await handleProbe(path);
  }

  const combinedRisk = mergeRisk(scanResult?.risk ?? null, probeResult?.risk ?? null);
  const allFindings: Finding[] = [...(scanResult?.findings ?? []), ...(probeResult?.findings ?? [])];

  const sandboxState: SandboxState = probeOverlayOpen
    ? "opening"
    : probeResult?.skipped
      ? "off"
      : probeResult && !probeResult.skipped
        ? "active"
        : "standby";

  return (
    <main className="w-full px-10 py-10">
      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold">Aegis</h1>
          <p className="mt-1 text-zinc-600 dark:text-zinc-300">
            AI pentesting agent -- Observe &rarr; Detect &rarr; Explain &rarr; Respond
          </p>
        </div>
        <div className="flex items-center gap-3">
          {repoConnected && (
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => handleScan()}
                disabled={scanOverlayOpen}
                className="rounded-lg border border-zinc-300 px-4 py-1.5 text-sm font-semibold text-zinc-700 transition hover:bg-zinc-100 disabled:opacity-50 dark:border-zinc-700 dark:text-zinc-200 dark:hover:bg-zinc-800"
              >
                {scanOverlayOpen ? "Scanning…" : "Re-scan"}
              </button>
              <button
                type="button"
                onClick={() => setHunchModalOpen(true)}
                disabled={probeOverlayOpen}
                title="Tell Aegis what you suspect, then watch it actually check -- confirmed, not found, or not something these checks can test."
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

      {repoConnected && credentialFieldOpen && (
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
        <GitHubConnect onConnected={handleConnected} />
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
          onTerminate={handleTerminateProbe}
          loaderThroughIndex={0}
        />
      )}

      {scanError && <p className="mt-2 text-sm text-red-500">Scan error: {scanError}</p>}
      {probeError && <p className="mt-2 text-sm text-red-500">Probe error: {probeError}</p>}
      {probeResult?.skipped && (
        <p className="mt-2 text-sm text-zinc-500">Active probe skipped: {probeResult.reason}</p>
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
              <div className="mt-3 flex w-full max-w-xl items-center justify-between rounded-t-lg border border-b-0 border-zinc-300 bg-zinc-100 px-3 py-1.5 dark:border-zinc-700 dark:bg-zinc-800">
                <div className="flex items-center gap-1.5">
                  <span className="h-2.5 w-2.5 rounded-full bg-red-400" />
                  <span className="h-2.5 w-2.5 rounded-full bg-amber-400" />
                  <span className="h-2.5 w-2.5 rounded-full bg-emerald-400" />
                </div>
              </div>
              <a
                href={probeResult.screenshot}
                target="_blank"
                rel="noreferrer"
                className="block h-72 w-full max-w-xl overflow-hidden rounded-b-lg border border-zinc-300 dark:border-zinc-700"
                title="Open full size"
              >
                <img
                  src={probeResult.screenshot}
                  alt="Screenshot of the sandboxed app at the moment it was probed"
                  className="h-full w-full object-cover object-top"
                />
              </a>
            </Card>
          )}

          {allFindings.length > 0 ? (
            <div className="space-y-3">
              <h2 className="text-sm font-semibold uppercase tracking-wide text-zinc-600 dark:text-zinc-300">
                {allFindings.length} finding{allFindings.length === 1 ? "" : "s"}
              </h2>
              {allFindings.map((f, i) => (
                <FindingCard key={i} finding={f} repoPath={repoPath} />
              ))}
            </div>
          ) : (
            <p className="text-emerald-600 dark:text-emerald-400">No findings. Clean scan.</p>
          )}

          <DownloadReport />
        </div>
      )}
    </main>
  );
}
