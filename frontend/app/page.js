"use client";

import { useEffect, useState } from "react";

const API = "http://localhost:8000";

const SEVERITY_COLOR = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#64748b",
};

function ScoreBadge({ score }) {
  const color = score >= 80 ? "#22c55e" : score >= 40 ? "#eab308" : "#ef4444";
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        gap: 4,
      }}
    >
      <div style={{ fontSize: 48, fontWeight: 700, color }}>{score}</div>
      <div style={{ fontSize: 12, color: "#94a3b8", letterSpacing: 1 }}>
        SECURITY SCORE
      </div>
    </div>
  );
}

function FindingCard({ finding, repoPath }) {
  const [fixing, setFixing] = useState(false);
  const [fix, setFix] = useState(null);
  const [error, setError] = useState(null);

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
      const data = await res.json();
      setFix(data);
    } catch (e) {
      setError(String(e));
    } finally {
      setFixing(false);
    }
  }

  const color = SEVERITY_COLOR[finding.severity] || "#64748b";

  return (
    <div
      style={{
        background: "#1e293b",
        border: "1px solid #334155",
        borderRadius: 8,
        padding: 16,
        marginBottom: 12,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <span
          style={{
            background: color,
            color: "#0b1120",
            fontSize: 11,
            fontWeight: 700,
            padding: "2px 8px",
            borderRadius: 4,
            textTransform: "uppercase",
          }}
        >
          {finding.severity}
        </span>
        <span style={{ fontWeight: 600 }}>{finding.type}</span>
        <span style={{ color: "#94a3b8", fontSize: 13 }}>
          {finding.match}
        </span>
      </div>

      <p style={{ color: "#cbd5e1", fontSize: 14, marginTop: 10 }}>
        {finding.explanation}
      </p>

      {finding.evidence && (
        <div
          style={{
            background: "#0b1120",
            border: "1px solid #334155",
            borderRadius: 6,
            padding: 10,
            marginBottom: 10,
            fontSize: 12,
            fontFamily: "monospace",
          }}
        >
          <div style={{ color: "#94a3b8" }}>{finding.evidence.request}</div>
          <div style={{ color: "#f97316" }}>
            → {finding.evidence.response_status} response, real data returned
          </div>
          <div style={{ color: "#64748b", marginTop: 4 }}>
            {finding.evidence.response_body}
          </div>
        </div>
      )}

      {!fix && (
        <button
          onClick={handleFix}
          disabled={fixing}
          style={{
            background: "#d946ef",
            color: "#fff",
            border: "none",
            borderRadius: 6,
            padding: "6px 14px",
            fontSize: 13,
            fontWeight: 600,
            cursor: fixing ? "default" : "pointer",
            opacity: fixing ? 0.6 : 1,
          }}
        >
          {fixing ? "Fixing..." : "Fix"}
        </button>
      )}

      {error && (
        <p style={{ color: "#ef4444", fontSize: 13 }}>Error: {error}</p>
      )}

      {fix && (
        <div style={{ marginTop: 12 }}>
          <div
            style={{
              display: "inline-block",
              background: fix.verified ? "#16a34a" : "#dc2626",
              color: "#fff",
              fontSize: 12,
              fontWeight: 700,
              padding: "2px 10px",
              borderRadius: 4,
              marginBottom: 8,
            }}
          >
            {fix.verified ? "VERIFIED FIXED" : "NOT VERIFIED"}
          </div>
          <p style={{ color: "#cbd5e1", fontSize: 13 }}>{fix.note}</p>
          {Object.entries(fix.diffs || {}).map(([path, diff]) => (
            <div key={path} style={{ marginTop: 8 }}>
              <div style={{ fontSize: 12, color: "#94a3b8" }}>{path}</div>
              <pre
                style={{
                  background: "#0b1120",
                  border: "1px solid #334155",
                  borderRadius: 6,
                  padding: 10,
                  fontSize: 12,
                  overflowX: "auto",
                  whiteSpace: "pre-wrap",
                }}
              >
                {diff}
              </pre>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function GitHubConnect({ onConnected }) {
  const [status, setStatus] = useState({ loading: true, connected: false });
  const [repoUrl, setRepoUrl] = useState("");
  const [cloning, setCloning] = useState(false);
  const [error, setError] = useState(null);
  const [cloned, setCloned] = useState(null);

  async function refreshStatus() {
    try {
      const res = await fetch(`${API}/github/session`, {
        credentials: "include",
      });
      const data = await res.json();
      setStatus({ loading: false, ...data });
    } catch {
      setStatus({ loading: false, connected: false });
    }
  }

  useEffect(() => {
    refreshStatus();
  }, []);

  async function handleLogout() {
    await fetch(`${API}/github/logout`, {
      method: "POST",
      credentials: "include",
    });
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
    <div
      style={{
        background: "#1e293b",
        border: "1px solid #334155",
        borderRadius: 8,
        padding: 16,
        marginBottom: 20,
      }}
    >
      <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8 }}>
        Connect a GitHub repo
      </div>
      <div style={{ fontSize: 12, color: "#94a3b8", marginBottom: 10 }}>
        Aegis only scans repos you can prove you control. You sign in
        directly on GitHub -- your access token stays on the Aegis backend
        and is never sent to or stored by this page.
      </div>

      {status.loading ? null : !status.connected ? (
        <a
          href={`${API}/github/oauth/login`}
          style={{
            display: "inline-block",
            background: "#24292f",
            color: "#fff",
            border: "1px solid #444c56",
            borderRadius: 6,
            padding: "8px 16px",
            fontSize: 13,
            fontWeight: 600,
            textDecoration: "none",
          }}
        >
          Connect with GitHub
        </a>
      ) : (
        <>
          <p style={{ color: "#22c55e", fontSize: 13, marginTop: 0 }}>
            Signed in as {status.github_login}{" "}
            <button
              onClick={handleLogout}
              style={{
                background: "none",
                border: "none",
                color: "#94a3b8",
                fontSize: 12,
                textDecoration: "underline",
                cursor: "pointer",
              }}
            >
              disconnect
            </button>
          </p>
          <div style={{ display: "flex", gap: 8 }}>
            <input
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              placeholder="owner/repo or github.com/owner/repo"
              style={{
                flex: 1,
                background: "#0b1120",
                border: "1px solid #334155",
                borderRadius: 6,
                padding: "8px 12px",
                color: "#e5e7eb",
                fontSize: 13,
              }}
            />
            <button
              onClick={handleClone}
              disabled={cloning || !repoUrl}
              style={{
                background: "#22c55e",
                color: "#0b1120",
                border: "none",
                borderRadius: 6,
                padding: "8px 16px",
                fontSize: 13,
                fontWeight: 700,
                cursor: cloning ? "default" : "pointer",
                opacity: cloning || !repoUrl ? 0.5 : 1,
              }}
            >
              {cloning ? "Verifying..." : "Verify & Clone"}
            </button>
          </div>
        </>
      )}

      {error && <p style={{ color: "#ef4444", fontSize: 13 }}>{error}</p>}
      {cloned && (
        <p style={{ color: "#22c55e", fontSize: 13, marginBottom: 0 }}>
          Verified -- {cloned.owner}/{cloned.repo} ({cloned.permission} access
          {cloned.private ? ", private" : ""})
        </p>
      )}
    </div>
  );
}

export default function Home() {
  const [repoPath, setRepoPath] = useState("../demo-app");
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const [probing, setProbing] = useState(false);
  const [probeResult, setProbeResult] = useState(null);
  const [probeError, setProbeError] = useState(null);

  async function handleScan() {
    setScanning(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch(`${API}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo_path: repoPath }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || `HTTP ${res.status}`);
      }
      const data = await res.json();
      setResult(data);
    } catch (e) {
      setError(String(e));
    } finally {
      setScanning(false);
    }
  }

  async function handleProbe() {
    setProbing(true);
    setProbeError(null);
    setProbeResult(null);
    try {
      const res = await fetch(`${API}/probe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo_path: repoPath }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || `HTTP ${res.status}`);
      }
      const data = await res.json();
      setProbeResult(data);
    } catch (e) {
      setProbeError(String(e));
    } finally {
      setProbing(false);
    }
  }

  return (
    <main style={{ maxWidth: 800, margin: "0 auto", padding: "40px 20px" }}>
      <h1 style={{ fontSize: 28, fontWeight: 700, marginBottom: 4 }}>
        Aegis
      </h1>
      <p style={{ color: "#94a3b8", marginTop: 0, marginBottom: 24 }}>
        AI pentesting agent -- Observe &rarr; Detect &rarr; Explain &rarr; Respond
      </p>

      <GitHubConnect onConnected={(path) => setRepoPath(path)} />

      <div style={{ display: "flex", gap: 8, marginBottom: 24 }}>
        <input
          value={repoPath}
          onChange={(e) => setRepoPath(e.target.value)}
          placeholder="Path to the repo you own"
          style={{
            flex: 1,
            background: "#1e293b",
            border: "1px solid #334155",
            borderRadius: 6,
            padding: "8px 12px",
            color: "#e5e7eb",
            fontSize: 14,
          }}
        />
        <button
          onClick={handleScan}
          disabled={scanning}
          style={{
            background: "#3b82f6",
            color: "#fff",
            border: "none",
            borderRadius: 6,
            padding: "8px 20px",
            fontSize: 14,
            fontWeight: 600,
            cursor: scanning ? "default" : "pointer",
            opacity: scanning ? 0.6 : 1,
          }}
        >
          {scanning ? "Scanning..." : "Scan"}
        </button>
        <button
          onClick={handleProbe}
          disabled={probing}
          title="AI-hypothesized, sandbox-confirmed missing-auth check. Builds and runs the repo's own Dockerfile -- slower than Scan."
          style={{
            background: "#d946ef",
            color: "#fff",
            border: "none",
            borderRadius: 6,
            padding: "8px 20px",
            fontSize: 14,
            fontWeight: 600,
            cursor: probing ? "default" : "pointer",
            opacity: probing ? 0.6 : 1,
          }}
        >
          {probing ? "Pentesting..." : "Run AI Pentest"}
        </button>
      </div>

      {error && (
        <p style={{ color: "#ef4444" }}>Error: {error}</p>
      )}
      {probeError && (
        <p style={{ color: "#ef4444" }}>Probe error: {probeError}</p>
      )}

      {probeResult && (
        <div style={{ marginBottom: 24 }}>
          {probeResult.skipped ? (
            <p style={{ color: "#94a3b8", fontSize: 14 }}>
              Active probe skipped: {probeResult.reason}
            </p>
          ) : probeResult.findings.length === 0 ? (
            <p style={{ color: "#22c55e" }}>
              No missing-auth issues confirmed by the sandbox probe.
            </p>
          ) : (
            <>
              <h2 style={{ fontSize: 16, color: "#94a3b8", marginBottom: 12 }}>
                {probeResult.findings.length} confirmed by active probe
              </h2>
              {probeResult.findings.map((f, i) => (
                <FindingCard key={i} finding={f} repoPath={repoPath} />
              ))}
            </>
          )}
        </div>
      )}

      {result && (
        <>
          <div style={{ marginBottom: 24 }}>
            <ScoreBadge score={result.score} />
          </div>
          <h2 style={{ fontSize: 16, color: "#94a3b8", marginBottom: 12 }}>
            {result.findings.length} finding
            {result.findings.length === 1 ? "" : "s"}
          </h2>
          {result.findings.map((f, i) => (
            <FindingCard key={i} finding={f} repoPath={repoPath} />
          ))}
          {result.findings.length === 0 && (
            <p style={{ color: "#22c55e" }}>No findings. Clean scan.</p>
          )}
        </>
      )}
    </main>
  );
}
