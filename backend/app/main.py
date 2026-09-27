"""Aegis backend -- Phases 1-3.

Pipeline: OBSERVE (ingest repo) -> DETECT (secrets, deps, cloud config)
-> EXPLAIN (local model) -> RESPOND (fix + re-verify).

Run with:
    uvicorn app.main:app --reload --port 8000
"""

from __future__ import annotations

import json
import queue
import threading
from typing import Any, Callable

from fastapi import Cookie, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, StreamingResponse
from pydantic import BaseModel

from app.detectors import run_all_detectors
from app.detectors.secrets import GitleaksNotInstalled
from app.fixers import fix_and_verify
from app.github_auth import RepoRefError, clone_repo, list_user_repos, verify_repo_access
from app.github_oauth import (
    FRONTEND_URL,
    OAuthError,
    OAuthNotConfigured,
    build_authorize_url,
    clear_session,
    get_session,
    get_token,
    handle_callback,
)
from app import risk
from app.llm import explain_finding
from app.probes.agent import NoSupportedEntryPoint, run_active_probes
from app.probes.idor import IDOR_TOOL
from app.probes.missing_auth import MISSING_AUTH_TOOL
from app.sandbox import SandboxBuildError, SandboxUnavailable

SESSION_COOKIE = "aegis_session"

app = FastAPI(title="Aegis", version="0.3.0")

# Allow the local Next.js dashboard to call the API during the demo.
# allow_credentials is required so the httpOnly session cookie (set after
# GitHub OAuth) is actually sent back on later requests.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    repo_path: str


class ScanResponse(BaseModel):
    findings: list[dict[str, Any]]
    score: int
    risk: dict[str, Any]


class FixRequest(BaseModel):
    repo_path: str
    finding: dict[str, Any]


class CloneRequest(BaseModel):
    repo_url: str


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


def _ndjson_stream(fn: Callable[[Callable[[str], None]], dict]) -> StreamingResponse:
    """Runs fn(progress) in a background thread and reports it as
    newline-delimited JSON events, so the frontend can show real progress
    instead of a spinner with no information behind it.

    Events: {"stage": "started"}, then whatever real stage names fn's own
    progress() calls emit, then either {"stage": "done", "result": ...} or
    {"stage": "error", "detail": "..."}. Mirrors Epiderm's own
    backend/app/main.py::_ndjson_stream (same team, same pattern).
    """
    events: "queue.Queue[dict | None]" = queue.Queue()

    def work() -> None:
        try:
            events.put({"stage": "started"})
            result = fn(lambda stage: events.put({"stage": stage}))
            events.put({"stage": "done", "result": result})
        except Exception as e:
            events.put({"stage": "error", "detail": str(e)})
        finally:
            events.put(None)

    threading.Thread(target=work, daemon=True).start()

    def stream():
        while True:
            event = events.get()
            if event is None:
                break
            yield json.dumps(event) + "\n"

    return StreamingResponse(
        stream(),
        media_type="application/x-ndjson",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


def _run_scan(repo_path: str, progress: Callable[[str], None]) -> dict:
    progress("detecting")
    findings = run_all_detectors(repo_path)  # raises GitleaksNotInstalled -> surfaced as an "error" event

    for f in findings:
        risk.classify(f)  # area/likelihood/impact -- rules only, before the LLM sees it

    progress("explaining")
    for f in findings:
        try:
            f["explanation"] = explain_finding(f)
        except Exception as e:  # local model may be unavailable
            f["explanation"] = f"(explanation unavailable: {e})"

    checked_areas = ["Secrets", "Dependencies", "Cloud Config"]
    return {
        "findings": findings,
        "score": risk.score(findings),
        "risk": risk.summarise(findings, checked_areas),
    }


@app.post("/scan", response_model=ScanResponse)
def scan(req: ScanRequest) -> ScanResponse:
    try:
        return ScanResponse(**_run_scan(req.repo_path, lambda _stage: None))
    except GitleaksNotInstalled as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.post("/scan/stream")
def scan_stream(req: ScanRequest) -> StreamingResponse:
    """Same as /scan, reported stage-by-stage as newline-delimited JSON."""
    return _ndjson_stream(lambda progress: _run_scan(req.repo_path, progress))


@app.post("/fix")
def fix(req: FixRequest) -> dict:
    """Generate a verified fix for one finding (does not touch the working tree)."""
    result = fix_and_verify(req.finding, req.repo_path)
    return result.to_dict()


def _run_probe(repo_path: str, progress: Callable[[str], None]) -> dict:
    """Phase 4-5: AI-hypothesized, sandbox-confirmed active probe.

    Slower than /scan (builds and runs a Docker container). Skips cleanly
    (never raises past this point) if Docker, a Dockerfile, or a supported
    entry point isn't available -- the caller is told exactly why, not left
    guessing, and it is reported as "could not check", never as "clean".
    """
    try:
        findings = run_active_probes(repo_path, [MISSING_AUTH_TOOL, IDOR_TOOL], on_stage=progress)
    except (SandboxUnavailable, SandboxBuildError, NoSupportedEntryPoint) as e:
        return {"findings": [], "skipped": True, "reason": str(e)}

    progress("explaining")
    for f in findings:
        risk.classify(f)
        try:
            f["explanation"] = explain_finding(f)
        except Exception as e:
            f["explanation"] = f"(explanation unavailable: {e})"

    return {
        "findings": findings,
        "skipped": False,
        "score": risk.score(findings),
        "risk": risk.summarise(findings, ["Access Control"]),
    }


@app.post("/probe")
def probe(req: ScanRequest) -> dict:
    return _run_probe(req.repo_path, lambda _stage: None)


@app.post("/probe/stream")
def probe_stream(req: ScanRequest) -> StreamingResponse:
    """Same as /probe, reported stage-by-stage as newline-delimited JSON."""
    return _ndjson_stream(lambda progress: _run_probe(req.repo_path, progress))


@app.get("/github/oauth/login")
def github_oauth_login() -> RedirectResponse:
    """Send the browser to GitHub's own login/consent page. No token ever
    touches Aegis's frontend -- the user authenticates directly with GitHub.
    """
    try:
        url = build_authorize_url()
    except OAuthNotConfigured as e:
        raise HTTPException(status_code=500, detail=str(e)) from e
    return RedirectResponse(url)


@app.get("/github/oauth/callback")
def github_oauth_callback(code: str, state: str) -> RedirectResponse:
    """GitHub redirects here with a one-time code. Exchange it for an access
    token server-side, store it only in an in-memory session, and hand the
    browser back an httpOnly session cookie -- never the token itself.
    """
    try:
        session_id = handle_callback(code, state)
    except (OAuthError, OAuthNotConfigured) as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    response = RedirectResponse(f"{FRONTEND_URL}/?connected=1")
    response.set_cookie(
        SESSION_COOKIE,
        session_id,
        httponly=True,
        samesite="lax",
        max_age=3600,
    )
    return response


@app.get("/github/session")
def github_session_status(aegis_session: str | None = Cookie(default=None)) -> dict:
    """Is this browser currently connected? Returns the GitHub login only --
    never the token."""
    session = get_session(aegis_session)
    if not session:
        return {"connected": False}
    return {"connected": True, "github_login": session.get("github_login")}


@app.get("/github/repos")
def github_repos(aegis_session: str | None = Cookie(default=None)) -> dict:
    """List repos the connected account can push/admin to, for the repo
    picker. Uses the server-side session token -- never sent to the frontend.
    """
    token = get_token(aegis_session)
    if not token:
        raise HTTPException(status_code=401, detail="Not connected to GitHub. Connect first.")
    return {"repos": list_user_repos(token)}


@app.post("/github/logout")
def github_logout(aegis_session: str | None = Cookie(default=None)) -> dict:
    clear_session(aegis_session)
    return {"connected": False}


@app.post("/github/verify-and-clone")
def github_verify_and_clone(
    req: CloneRequest, aegis_session: str | None = Cookie(default=None)
) -> dict:
    """Verify the connected GitHub account has push/admin access to the repo,
    then shallow-clone it. Uses the server-side session token -- the frontend
    never sees or sends any token."""
    token = get_token(aegis_session)
    if not token:
        raise HTTPException(status_code=401, detail="Not connected to GitHub. Connect first.")

    try:
        result = verify_repo_access(req.repo_url, token)
    except RepoRefError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    if not result["verified"]:
        raise HTTPException(status_code=403, detail=result.get("error") or "Not verified.")

    try:
        local_path = clone_repo(req.repo_url, token, branch=result.get("default_branch"))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Clone failed: {e}") from e

    return {
        "verified": True,
        "owner": result["owner"],
        "repo": result["repo"],
        "permission": result["permission"],
        "private": result["private"],
        "repo_path": str(local_path),
    }
