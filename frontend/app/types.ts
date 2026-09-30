// Ported from Epiderm's types.ts. Same RiskSummary shape and the same
// discipline (verdict/score/matrix placement are rule-based, never
// LLM-derived -- see backend/app/risk.py), with wording adapted from
// "is this message legit" to "is this code secure".

export type Severity = "critical" | "high" | "medium" | "low";

export type Finding = {
  type: string;
  file: string | null;
  line: number | null;
  rule: string | null;
  match: string | null;
  severity: Severity;
  detail?: string;
  explanation?: string;
  area?: string;
  likelihood?: number;
  impact?: number;
  evidence?: { request: string; response_status: number; response_body: string };
  entry_file?: string;
};

export type FixResult = {
  finding_match: string | null;
  finding_type: string | null;
  diffs: Record<string, string>;
  note: string;
  verified: boolean;
};

export type RiskFactor = { id: string; label: string; area: string; likelihood: number; impact: number; weight: number; source: string };
export type RiskArea = { name: string; risk: number; suspicious: number; reassuring: number; unknown: number };
export type RiskPart = { name: string; risk_score: number; verdict: string };

export type RiskSummary = {
  risk_score: number;
  security_score: number;
  verdict: "secure" | "needs_attention" | "vulnerable";
  verdict_label: string;
  level: "low" | "medium" | "high" | "critical";
  areas: RiskArea[];
  matrix: RiskFactor[];
  suspicious: number;
  reassuring: number;
  unknown: number;
  parts: RiskPart[];
  basis: string;
};

export type ScanResponse = { findings: Finding[]; score: number; risk: RiskSummary };
export type ProbeResponse = {
  findings: Finding[];
  skipped: boolean;
  cancelled?: boolean;
  reason?: string;
  score?: number;
  risk?: RiskSummary;
  /** A data: URL screenshot of the actual sandboxed app, captured the
   * moment its container came up -- a live "this is what we tested"
   * preview, best-effort only (absent if capture failed or there was no
   * sandboxed container at all, e.g. the Supabase-probe fallback path). */
  screenshot?: string | null;
};

/** Result of POST /hunch -- "Test a Hunch"'s verdict on a user-supplied
 * lead. `testable`/`confirmed` are null only when the model couldn't be
 * reached at all; show that as "couldn't evaluate", never as "not found". */
export type HunchResult = {
  testable: boolean | null;
  confirmed: boolean | null;
  explanation: string;
};
