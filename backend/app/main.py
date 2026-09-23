"""Aegis backend -- Phase 1: secrets scan -> explain.

Run with:
    uvicorn app.main:app --reload --port 8000

Then:
    curl -X POST http://localhost:8000/scan -H "Content-Type: application/json" \
        -d '{"repo_path": "../demo-app"}'
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from app.detectors.secrets import GitleaksNotInstalled, scan_secrets
from app.llm import explain_finding

app = FastAPI(title="Aegis", version="0.1.0")


class ScanRequest(BaseModel):
    repo_path: str


class Finding(BaseModel):
    type: str
    file: str | None = None
    line: int | None = None
    rule: str | None = None
    match: str | None = None
    severity: str
    explanation: str | None = None


class ScanResponse(BaseModel):
    findings: list[Finding]


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResponse)
def scan(req: ScanRequest) -> ScanResponse:
    try:
        raw_findings = scan_secrets(req.repo_path)
    except GitleaksNotInstalled as e:
        raise HTTPException(status_code=500, detail=str(e)) from e

    findings: list[Finding] = []
    for f in raw_findings:
        try:
            explanation = explain_finding(f)
        except Exception as e:  # local model may not be running yet
            explanation = f"(explanation unavailable: {e})"
        findings.append(Finding(**f, explanation=explanation))

    return ScanResponse(findings=findings)
