"use client";

import { useEffect, useState } from "react";
import { AnalysisOverlay } from "./analysis-overlay";
import type { Step } from "@/components/ui/onboard-card";
import { Card } from "./components";
import { DownloadReport } from "./download-report";
import { API, readStream } from "./lib";
import { RiskDashboard } from "./risk-dashboard";
import { SandboxBadge, type SandboxState } from "./sandbox-badge";
import type { Finding, FixResult, ProbeResponse, RiskSummary, ScanResponse } from "./types";

// Each entry's key must match a real "stage" event name the backend actually
// emits (see backend/app/main.py::_run_scan / _run_probe) -- the overlay
// follows real progress, it never fakes a step that isn't really happening.
const SCAN_STEPS: (Step & { key: string })[] = [
  { key: "started", label: "Request received", detail: "Reading the repo" },
  { key: "detecting", label: "Detecting issues", detail: "Gitleaks, dependency, and config checks" },
  { key: "explaining", label: "Explaining findings", detail: "A local model writes each explanation" },
];

const PROBE_STEPS: (Step & { key: string })[] = [
  { key: "started", label: "Request received", detail: "Preparing the active probe" },
  { key: "tracing", label: "Tracing routes", detail: "Mapping the app's routes and middleware" },
  { key: "reasoning", label: "Reasoning about auth", detail: "A local model hypothesizes what's unprotected" },
  { key: "sandbox", label: "Building sandbox", detail: "Building and starting the app's own Dockerfile" },
  { key: "probing", label: "Probing live", detail: "Sending one safe request, no credentials" },
  { key: "explaining", label: "Explaining findings", detail: "A local model writes each explanation" },
];

const SEVERITY_STYLE: Record<string, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-amber-400 text-zinc-900",
  low: "bg-zinc-500 text-white",
};

/** Combines /scan and /probe's independent RiskSummary responses into one
 * dashboard view, the same way Epiderm combines a message + its attachment:
 * each stage becomes a `part`, and the worse verdict of the two governs the
 * overall picture shown at the top. */
function mergeRisk(scanRisk: RiskSummary | null, probeRisk: RiskSummary | null): RiskSummary | null {
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

function FindingCard({ finding, repoPath }: { finding: Finding; repoPath: string }) {
  const [fixing, setFixing] = useState(false);
  const [fix, setFix] = useState<FixResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleFix() {
    setFixing(true);
    setError(null);
    try {
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

type Repo = { full_name: string; private: boolean; permission: string; updated_at: string | null };

function GitHubConnect({ onConnected }: { onConnected: (path: string) => void }) {
  const [status, setStatus] = useState<{ loading: boolean; connected: boolean; github_login?: string }>({ loading: true, connected: false });
  const [repos, setRepos] = useState<Repo[] | null>(null);
  const [reposError, setReposError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [cloningRepo, setCloningRepo] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [cloned, setCloned] = useState<{ owner: string; repo: string; permission: string; private: boolean } | null>(null);

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
      setCloned(data);
      onConnected(data.repo_path);
    } catch (e) {
      setError(String(e));
    } finally {
      setCloningRepo(null);
    }
  }

  const filtered = (repos ?? []).filter((r) => r.full_name.toLowerCase().includes(query.toLowerCase()));

  // Once a repo is verified and cloned, collapse the whole connect/picker
  // UI down to one line -- the dashboard below is the point from here on.
  if (cloned) {
    return (
      <div className="tg-card flex items-center justify-between gap-3 p-4 text-sm">
        <span className="text-emerald-600 dark:text-emerald-400">
          Connected -- {cloned.owner}/{cloned.repo} ({cloned.permission} access{cloned.private ? ", private" : ""})
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

  async function handleScan() {
    setScanOverlayOpen(true);
    setScanStage(0);
    setScanFinished(false);
    setScanError(null);
    try {
      const res = await fetch(`${API}/scan/stream`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo_path: repoPath }),
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

  async function handleProbe() {
    setProbeOverlayOpen(true);
    setProbeStage(0);
    setProbeFinished(false);
    setProbeError(null);
    try {
      const res = await fetch(`${API}/probe/stream`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo_path: repoPath }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await readStream<ProbeResponse>(res, (s) => {
        const i = PROBE_STEPS.findIndex((step) => step.key === s);
        if (i >= 0) setProbeStage((cur) => Math.max(cur, i));
      });
      setProbeResult(data);
    } catch (e) {
      setProbeError(String(e));
    } finally {
      setProbeFinished(true);
    }
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
    <main className="mx-auto max-w-5xl px-5 py-10">
      <SandboxBadge state={sandboxState} />

      <h1 className="text-3xl font-bold">Aegis</h1>
      <p className="mt-1 text-zinc-600 dark:text-zinc-300">
        AI pentesting agent -- Observe &rarr; Detect &rarr; Explain &rarr; Respond
      </p>

      <div className="mt-6">
        <GitHubConnect
          onConnected={(path) => {
            setRepoPath(path);
            setRepoConnected(true);
          }}
        />
      </div>

      {repoConnected && (
      <div className="mt-4 flex flex-wrap gap-2">
        <input
          value={repoPath}
          onChange={(e) => setRepoPath(e.target.value)}
          placeholder="Path to the repo you own"
          className="flex-1 rounded-lg border border-zinc-300 bg-transparent p-2 text-sm dark:border-zinc-700"
        />
        <button
          type="button"
          onClick={handleScan}
          disabled={scanOverlayOpen}
          className="rounded-lg bg-blue-600 px-5 py-2 text-sm font-semibold text-white transition hover:bg-blue-500 disabled:opacity-50"
        >
          {scanOverlayOpen ? "Scanning…" : "Scan"}
        </button>
        <button
          type="button"
          onClick={handleProbe}
          disabled={probeOverlayOpen}
          title="AI-hypothesized, sandbox-confirmed missing-auth check. Builds and runs the repo's own Dockerfile."
          className="rounded-lg bg-fuchsia-600 px-5 py-2 text-sm font-semibold text-white transition hover:bg-fuchsia-500 disabled:opacity-50"
        >
          {probeOverlayOpen ? "Pentesting…" : "Run AI Pentest"}
        </button>
      </div>
      )}

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
