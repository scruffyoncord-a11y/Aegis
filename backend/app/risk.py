"""Deterministic risk classification and scoring.

Mirrors Epiderm's core discipline: the score, the risk area, and the
likelihood x impact matrix placement all come from FIXED RULES, never from
the LLM. Gemma (see app/llm.py) only writes the plain-language explanation
for a finding whose area/likelihood/impact/severity are already decided
here -- it cannot raise or lower anything, and it's never even shown this
module's output to reason about.
"""

from __future__ import annotations

from typing import Any

# Which dashboard "area" a finding type belongs to.
AREA_FOR_TYPE: dict[str, str] = {
    "secret": "Secrets",
    "dependency-vuln": "Dependencies",
    "dependency-missing": "Dependencies",
    "cloud-misconfig": "Cloud Config",
    "missing-auth": "Access Control",
}

# Which detector actually produced a finding of this type -- shown in the
# risk matrix so it's clear the placement traces back to a real tool, not
# an LLM guess.
SOURCE_FOR_TYPE: dict[str, str] = {
    "secret": "Gitleaks",
    "dependency-vuln": "OSV",
    "dependency-missing": "npm registry",
    "cloud-misconfig": "Config parser",
    "missing-auth": "Sandbox probe",
}

# 1-5: how immediately an attacker could act on this, given only the
# finding's TYPE -- a fixed lookup, never an LLM guess. Everything Aegis
# reports is already confirmed (deterministic detection, or an actively
# probe-confirmed hypothesis), so this axis reflects ease-of-exploitation,
# not confidence.
LIKELIHOOD_FOR_TYPE: dict[str, int] = {
    "secret": 5,  # usable immediately, as-is
    "cloud-misconfig": 5,  # trivially reachable by anyone
    "missing-auth": 5,  # confirmed live via a real sandboxed request
    "dependency-vuln": 3,  # needs a matching public exploit to exist
    "dependency-missing": 2,  # needs an attacker to register + get it installed
}

# 1-5: impact, taken straight from the finding's own severity.
IMPACT_FOR_SEVERITY: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
}

_SCORE_WEIGHTS = {"critical": 25, "high": 15, "medium": 8, "low": 3}

_BASIS = (
    "The score comes from fixed rules based on each finding's severity and "
    "area, the same way for every scan. The AI (Gemma) only explains a "
    "finding in plain language after its severity, area and likelihood are "
    "already decided here -- it never raises or lowers the score."
)


def classify(finding: dict[str, Any]) -> dict[str, Any]:
    """Attach area/likelihood/impact to one finding in place. Pure lookup."""
    ftype = finding.get("type", "")
    severity = finding.get("severity", "low")
    finding["area"] = AREA_FOR_TYPE.get(ftype, "Other")
    finding["likelihood"] = LIKELIHOOD_FOR_TYPE.get(ftype, 3)
    finding["impact"] = IMPACT_FOR_SEVERITY.get(severity, 2)
    return finding


def score(findings: list[dict[str, Any]]) -> int:
    """0-100 security score: 100 minus weighted severity penalties."""
    penalty = sum(_SCORE_WEIGHTS.get(f.get("severity", "low"), 3) for f in findings)
    return max(0, 100 - penalty)


def _verdict(sec_score: int) -> tuple[str, str]:
    if sec_score >= 80:
        return "secure", "SECURE"
    if sec_score >= 40:
        return "needs_attention", "NEEDS ATTENTION"
    return "vulnerable", "VULNERABLE"


def _level(sec_score: int) -> str:
    if sec_score >= 80:
        return "low"
    if sec_score >= 60:
        return "medium"
    if sec_score >= 30:
        return "high"
    return "critical"


def _label(finding: dict[str, Any]) -> str:
    ftype = finding.get("type", "finding")
    detail = finding.get("match") or finding.get("rule") or ""
    return f"{ftype}: {detail}" if detail else ftype


def summarise(
    findings: list[dict[str, Any]], checked_areas: list[str] | None = None
) -> dict[str, Any]:
    """Build the full RiskSummary the dashboard needs -- areas, the
    likelihood x impact matrix, the evidence mix, and the verdict. Assumes
    each finding was already run through classify().

    `checked_areas` is the universe of areas actually run this call (e.g.
    ["Secrets", "Dependencies", "Cloud Config"] for /scan) -- an area that
    was checked and produced zero findings counts as a "clean" (reassuring)
    result, not silence.
    """
    sec_score = score(findings)
    verdict, verdict_label = _verdict(sec_score)

    by_area: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        by_area.setdefault(f.get("area", "Other"), []).append(f)

    areas = []
    for area in sorted(set(list(by_area.keys()) + list(checked_areas or []))):
        items = by_area.get(area, [])
        areas.append(
            {
                "name": area,
                "risk": score(items),
                "suspicious": len(items),
                "reassuring": 1 if not items and area in (checked_areas or []) else 0,
                "unknown": 0,
            }
        )

    matrix = []
    for i, f in enumerate(findings):
        li = max(1, min(5, f.get("likelihood", 3)))
        im = max(1, min(5, f.get("impact", 2)))
        matrix.append(
            {
                "id": f"{f.get('type', 'finding')}-{i}",
                "label": _label(f),
                "area": f.get("area", "Other"),
                "likelihood": li,
                "impact": im,
                "weight": min(100, li * im * 4),
                "source": SOURCE_FOR_TYPE.get(f.get("type", ""), "Aegis"),
            }
        )
    matrix.sort(key=lambda m: m["weight"], reverse=True)

    checked_clean = sum(1 for a in areas if a["suspicious"] == 0 and a["reassuring"])

    return {
        "risk_score": 100 - sec_score,
        "security_score": sec_score,
        "verdict": verdict,
        "verdict_label": verdict_label,
        "level": _level(sec_score),
        "areas": areas,
        "matrix": matrix,
        "suspicious": len(findings),
        "reassuring": checked_clean,
        "unknown": 0,
        "parts": [],
        "basis": _BASIS,
    }
