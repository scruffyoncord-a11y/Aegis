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


def summarise(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Risk-by-area, the likelihood x impact matrix, and the evidence mix --
    everything the dashboard's risk views need, computed once. Assumes each
    finding was already run through classify().
    """
    areas: dict[str, dict[str, Any]] = {}
    matrix = [[0] * 5 for _ in range(5)]  # matrix[likelihood-1][impact-1]

    by_area: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        by_area.setdefault(f.get("area", "Other"), []).append(f)

        li = max(1, min(5, f.get("likelihood", 3)))
        im = max(1, min(5, f.get("impact", 2)))
        matrix[li - 1][im - 1] += 1

    for area, items in by_area.items():
        areas[area] = {"count": len(items), "score": score(items)}

    return {
        "score": score(findings),
        "areas": areas,
        "matrix": matrix,
        "evidence_mix": {
            "confirmed": len(findings),
            "possible": 0,
            "could_not_verify": 0,
        },
    }
