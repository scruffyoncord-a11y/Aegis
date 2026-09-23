"""Aegis backend -- Phases 1-3.

Pipeline: OBSERVE (ingest repo) -> DETECT (secrets, deps, cloud config)
-> EXPLAIN (local model) -> RESPOND (fix + re-verify).

Run with:
    uvicorn app.main:app --reload --port 8000
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.detectors import run_all_detectors
from app.detectors.secrets import GitleaksNotInstalled
from app.fixers import fix_and_verify
from app.llm import explain_finding

app = FastAPI(title="Aegis", version="0.3.0")

# Allow the local Next.js dashboard to call the API during the demo.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    repo_path: str


class ScanResponse(BaseModel):
    findings: list[dict[str, Any]]
    score: int


class FixRequest(BaseModel):
    repo_path: str
    finding: dict[str, Any]


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


def _score(findings: list[dict]) -> int:
    """Simple 0-100 security score: 100 minus weighted severity penalties."""
    weights = {"critical": 25, "high": 15, "medium": 8, "low": 3}
    penalty = sum(weights.get(f.get("severity", "low"), 3) for f in findings)
    return max(0, 100 - penalty)


@app.post("/scan", response_model=ScanResponse)
def scan(req: ScanRequest) -> ScanResponse:
    try:
        findings = run_all_detectors(req.repo_path)
    except GitleaksNotInstalled as e:
        raise HTTPException(status_code=500, detail=str(e)) from e

    for f in findings:
        try:
            f["explanation"] = explain_finding(f)
        except Exception as e:  # local model may be unavailable
            f["explanation"] = f"(explanation unavailable: {e})"

    return ScanResponse(findings=findings, score=_score(findings))


@app.post("/fix")
def fix(req: FixRequest) -> dict:
    """Generate a verified fix for one finding (does not touch the working tree)."""
    result = fix_and_verify(req.finding, req.repo_path)
    return result.to_dict()
