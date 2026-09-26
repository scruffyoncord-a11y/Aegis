"use client";

import { useEffect, useState } from "react";
import { Card } from "./components";
import { DownloadReport } from "./download-report";
import { RiskDashboard } from "./risk-dashboard";
import { SandboxBadge, type SandboxState } from "./sandbox-badge";
import type { Finding, FixResult, ProbeResponse, RiskSummary, ScanResponse } from "./types";

const API = "http://localhost:8000";

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

function GitHubConnect({ onConnected }: { onConnected: (path: string) => void }) {
  const [status, setStatus] = useState<{ loading: boolean; connected: boolean; github_login?: string }>({ loading: true, connected: false });
  const [repoUrl, setRepoUrl] = useState("");
  const [cloning, setCloning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [cloned, setCloned] = useState<{ owner: string; repo: string; permission: string; private: boolean } | null>(null);

  async function refreshStatus() {
    try {
      const res = await fetch(`${API}/github/session`, { credentials: "include" });
      setStatus({ loading: false, ...(await res.json()) });
    } catch {
      setStatus({ loading: false, connected: false });
    }
  }

  useEffect(() => {
    refreshStatus();
  }, []);

  async function handleLogout() {
    await fetch(`${API}/github/logout`, { method: "POST", credentials: "include" });
    setCloned(null);
    refreshStatus();
  }

  async function handleClone() {
    setCloning(true);
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
      setCloning(false);
    }
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
          <div className="mt-2 flex gap-2">
            <input
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              placeholder="owner/repo or github.com/owner/repo"
              className="flex-1 rounded-lg border border-zinc-300 bg-transparent p-2 text-sm dark:border-zinc-700"
            />
            <button
              type="button"
              onClick={handleClone}
              disabled={cloning || !repoUrl}
              className="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-semibold text-white disabled:opacity-50"
            >
              {cloning ? "Verifying…" : "Verify & Clone"}
            </button>
          </div>
        </>
      )}

      {error && <p className="mt-2 text-sm text-red-500">{error}</p>}
      {cloned && (
        <p className="mt-2 text-sm text-emerald-600 dark:text-emerald-400">
          Verified -- {cloned.owner}/{cloned.repo} ({cloned.permission} access{cloned.private ? ", private" : ""})
        </p>
      )}
    </Card>
  );
}

export default function Home() {
  const [repoPath, setRepoPath] = useState("../demo-app");
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResponse | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  const [probing, setProbing] = useState(false);
  const [probeResult, setProbeResult] = useState<ProbeResponse | null>(null);
  const [probeError, setProbeError] = useState<string | null>(null);

  async function handleScan() {
    setScanning(true);
    setScanError(null);
    try {
      const res = await fetch(`${API}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo_path: repoPath }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
      setScanResult(data);
    } catch (e) {
      setScanError(String(e));
    } finally {
      setScanning(false);
    }
  }

  async function handleProbe() {
    setProbing(true);
    setProbeError(null);
    try {
      const res = await fetch(`${API}/probe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo_path: repoPath }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
      setProbeResult(data);
    } catch (e) {
      setProbeError(String(e));
    } finally {
      setProbing(false);
    }
  }

  const combinedRisk = mergeRisk(scanResult?.risk ?? null, probeResult?.risk ?? null);
  const allFindings: Finding[] = [...(scanResult?.findings ?? []), ...(probeResult?.findings ?? [])];

  const sandboxState: SandboxState = probing
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
        <GitHubConnect onConnected={setRepoPath} />
      </div>

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
          disabled={scanning}
          className="rounded-lg bg-blue-600 px-5 py-2 text-sm font-semibold text-white transition hover:bg-blue-500 disabled:opacity-50"
        >
          {scanning ? "Scanning…" : "Scan"}
        </button>
        <button
          type="button"
          onClick={handleProbe}
          disabled={probing}
          title="AI-hypothesized, sandbox-confirmed missing-auth check. Builds and runs the repo's own Dockerfile."
          className="rounded-lg bg-fuchsia-600 px-5 py-2 text-sm font-semibold text-white transition hover:bg-fuchsia-500 disabled:opacity-50"
        >
          {probing ? "Pentesting…" : "Run AI Pentest"}
        </button>
      </div>

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
