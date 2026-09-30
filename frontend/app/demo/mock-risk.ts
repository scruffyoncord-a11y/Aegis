// A TypeScript mirror of backend/app/risk.py's rules -- NOT a reimplementation
// of the real scoring engine, just enough to make the demo page's canned
// findings produce internally-consistent numbers (score/areas/matrix that
// actually agree with each other), the same way the real backend's fixed
// rules do. Keep this in sync if risk.py's weights ever change.

import type { Finding, RiskSummary } from "../types";

const AREA_FOR_TYPE: Record<string, string> = {
  secret: "Secrets",
  "dependency-vuln": "Dependencies",
  "dependency-missing": "Dependencies",
  "cloud-misconfig": "Cloud Config",
  "missing-auth": "Access Control",
  idor: "Access Control",
};

const SOURCE_FOR_TYPE: Record<string, string> = {
  secret: "Gitleaks",
  "dependency-vuln": "OSV",
  "dependency-missing": "npm registry",
  "cloud-misconfig": "Config parser",
  "missing-auth": "Sandbox probe",
  idor: "Sandbox probe",
};

const LIKELIHOOD_FOR_TYPE: Record<string, number> = {
  secret: 5,
  "cloud-misconfig": 5,
  "missing-auth": 5,
  idor: 5,
  "dependency-vuln": 3,
  "dependency-missing": 2,
};

const IMPACT_FOR_SEVERITY: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2 };
const SCORE_WEIGHTS: Record<string, number> = { critical: 25, high: 15, medium: 8, low: 3 };

function score(findings: Finding[]): number {
  const penalty = findings.reduce((sum, f) => sum + (SCORE_WEIGHTS[f.severity] ?? 3), 0);
  return Math.max(0, 100 - penalty);
}

function verdict(secScore: number): { verdict: RiskSummary["verdict"]; label: string } {
  if (secScore >= 80) return { verdict: "secure", label: "SECURE" };
  if (secScore >= 40) return { verdict: "needs_attention", label: "NEEDS ATTENTION" };
  return { verdict: "vulnerable", label: "VULNERABLE" };
}

function level(secScore: number): RiskSummary["level"] {
  if (secScore >= 80) return "low";
  if (secScore >= 60) return "medium";
  if (secScore >= 30) return "high";
  return "critical";
}

function source(f: Finding): string {
  const rule = f.rule ?? "";
  if (rule.startsWith("supabase-")) return "Supabase RLS parser";
  if (rule === "firebase-open-rule") return "Firebase rules parser";
  return SOURCE_FOR_TYPE[f.type] ?? "Aegis";
}

function label(f: Finding): string {
  const detail = f.match ?? f.rule ?? "";
  return detail ? `${f.type}: ${detail}` : f.type;
}

/** Fills in area/likelihood/impact on a finding, mutating it -- mirrors
 * risk.classify(). Call once per mock finding before summarise(). */
export function classify(f: Finding): Finding {
  f.area = AREA_FOR_TYPE[f.type] ?? "Other";
  f.likelihood = LIKELIHOOD_FOR_TYPE[f.type] ?? 3;
  f.impact = IMPACT_FOR_SEVERITY[f.severity] ?? 2;
  return f;
}

export function summarise(findings: Finding[], checkedAreas: string[]): RiskSummary {
  const secScore = score(findings);
  const { verdict: v, label: verdictLabel } = verdict(secScore);

  const byArea = new Map<string, Finding[]>();
  for (const f of findings) {
    const area = f.area ?? "Other";
    byArea.set(area, [...(byArea.get(area) ?? []), f]);
  }

  const areaNames = Array.from(new Set([...byArea.keys(), ...checkedAreas])).sort();
  const areas = areaNames.map((name) => {
    const items = byArea.get(name) ?? [];
    return {
      name,
      risk: score(items),
      suspicious: items.length,
      reassuring: items.length === 0 && checkedAreas.includes(name) ? 1 : 0,
      unknown: 0,
    };
  });

  const matrix = findings
    .map((f, i) => {
      const li = Math.max(1, Math.min(5, f.likelihood ?? 3));
      const im = Math.max(1, Math.min(5, f.impact ?? 2));
      return {
        id: `${f.type}-${i}`,
        label: label(f),
        area: f.area ?? "Other",
        likelihood: li,
        impact: im,
        weight: Math.min(100, li * im * 4),
        source: source(f),
      };
    })
    .sort((a, b) => b.weight - a.weight);

  const checkedClean = areas.filter((a) => a.suspicious === 0 && a.reassuring).length;

  return {
    risk_score: 100 - secScore,
    security_score: secScore,
    verdict: v,
    verdict_label: verdictLabel,
    level: level(secScore),
    areas,
    matrix,
    suspicious: findings.length,
    reassuring: checkedClean,
    unknown: 0,
    parts: [],
    basis:
      "The score comes from fixed rules based on each finding's severity and area, the same way for every scan. The AI (Gemma) only explains a finding in plain language after its severity, area and likelihood are already decided here -- it never raises or lowers the score.",
  };
}
