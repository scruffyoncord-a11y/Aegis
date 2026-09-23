"use client";

import { useState } from "react";

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

export default function Home() {
  const [repoPath, setRepoPath] = useState("../demo-app");
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

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

  return (
    <main style={{ maxWidth: 800, margin: "0 auto", padding: "40px 20px" }}>
      <h1 style={{ fontSize: 28, fontWeight: 700, marginBottom: 4 }}>
        Aegis
      </h1>
      <p style={{ color: "#94a3b8", marginTop: 0, marginBottom: 24 }}>
        AI pentesting agent -- Observe &rarr; Detect &rarr; Explain &rarr; Respond
      </p>

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
      </div>

      {error && (
        <p style={{ color: "#ef4444" }}>Error: {error}</p>
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
