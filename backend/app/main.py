"""Aegis backend -- Phases 1-3.

Pipeline: OBSERVE (ingest repo) -> DETECT (secrets, deps, cloud config)
-> EXPLAIN (local model) -> RESPOND (fix + re-verify).

Run with:
    uvicorn app.main:app --reload --port 8000
"""

from __future__ import annotations

import base64
import json
import queue
import threading
from typing import Any, Callable

from fastapi import Cookie, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, StreamingResponse
from pydantic import BaseModel

from app.cancellation import Cancelled, finish_run, new_run, request_cancel
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
    set_cloned_repo,
)
from app import risk
from app.hunch import evaluate_hunch
from app.llm import explain_finding
from app.probes.agent import NoSupportedEntryPoint, run_active_probes
from app.probes.idor import build_idor_tool
from app.probes.missing_auth import MISSING_AUTH_TOOL
from app.probes.supabase_probe import NoSupabaseProject, run_supabase_probe
from app.repo_tree import build_tree
from app.sandbox import SandboxBuildError, SandboxUnavailable
from app.screenshot import take_screenshot
from app.subprojects import find_subprojects

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


class CancelRequest(BaseModel):
    run_id: str


class ProbeRequest(BaseModel):
    repo_path: str
    # The free-text lead from "Test a Hunch" -- optional, absent for a
    # normal Re-run pentest.
    hint: str | None = None
    # A real test credential from the user's OWN account on the target app
    # (e.g. "Bearer eyJhbGci..." or "Cookie: session=..."), used for the
    # IDOR probe's two test requests instead of Aegis's demo-fixture
    # convention -- see app/probes/idor.py::build_idor_tool. Optional;
    # falls back to the demo convention when absent.
    test_credential: str | None = None


class HunchRequest(BaseModel):
    hint: str
    # Findings already gathered this session (scan + probe combined) --
    # sent by the frontend rather than re-fetched here, since the caller
    # already has them and this endpoint never re-runs anything itself.
    findings: list[dict[str, Any]]


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


def _ndjson_stream(
    fn: Callable[[Callable[[str], None]], dict],
    extra_started: dict[str, Any] | None = None,
) -> StreamingResponse:
    """Runs fn(progress) in a background thread and reports it as
    newline-delimited JSON events, so the frontend can show real progress
    instead of a spinner with no information behind it.

    Events: {"stage": "started", ...extra_started}, then whatever real stage
    names fn's own progress() calls emit, then either {"stage": "done",
    "result": ...} or {"stage": "error", "detail": "..."}. `extra_started`
    lets a caller (probe_stream) hand the frontend a run id in that first
    event, before any real work starts -- e.g. so a "Terminate" button has
    something to cancel from the very first moment it's shown. Mirrors
    Epiderm's own backend/app/main.py::_ndjson_stream (same team, same
    pattern).
    """
    events: "queue.Queue[dict | None]" = queue.Queue()

    def work() -> None:
        try:
            events.put({"stage": "started", **(extra_started or {})})
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


@app.post("/repo/tree")
def repo_tree(req: ScanRequest) -> dict:
    """A shallow, read-only file/folder tree for the "browse the codebase"
    step between connecting a repo and choosing what to pentest. Never reads
    file contents -- just names and structure, capped so a huge repo still
    returns fast (see app/repo_tree.py).
    """
    return build_tree(req.repo_path)


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


def _run_probe(
    repo_path: str,
    progress: Callable[[str], None],
    cancel_event: threading.Event | None = None,
    user_hint: str | None = None,
    test_credential: str | None = None,
) -> dict:
    """Phase 4-5: AI-hypothesized, sandbox-confirmed active probe.

    Slower than /scan (builds and runs a Docker container). Skips cleanly
    (never raises past this point) if Docker, a Dockerfile, or a supported
    entry point isn't available -- the caller is told exactly why, not left
    guessing, and it is reported as "could not check", never as "clean".
    A user-requested cancel (see app/cancellation.py) is reported the same
    honest way: "skipped", never as an error and never as "clean".

    `user_hint` is "Test a Hunch"'s free-text lead -- passed through to bias
    the hypothesis step (see run_active_probes), not evaluated here; the
    /hunch endpoint judges the hunch against the final findings afterward.

    `test_credential`, if given, is used for the IDOR probe's test requests
    instead of Aegis's demo-fixture convention -- see
    app/probes/idor.py::build_idor_tool.
    """
    # Filled in by on_sandbox_ready the moment the container is confirmed
    # live -- a plain dict so the closure below can write into it (Python
    # closures can't assign to an outer local directly). Stays empty for the
    # Supabase-probe fallback path, which has no sandboxed container at all.
    screenshot: dict[str, str] = {}

    def capture_screenshot(base_url: str) -> None:
        png = take_screenshot(base_url)
        if png:
            screenshot["data_url"] = "data:image/png;base64," + base64.b64encode(png).decode()

    try:
        findings = run_active_probes(
            repo_path,
            [MISSING_AUTH_TOOL, build_idor_tool(test_credential)],
            on_stage=progress,
            cancel_event=cancel_event,
            on_sandbox_ready=capture_screenshot,
            user_hint=user_hint,
        )
    except Cancelled as e:
        return {"findings": [], "skipped": True, "cancelled": True, "reason": str(e)}
    except NoSupportedEntryPoint:
        # No Express/FastAPI/Flask server to trace -- this is also exactly
        # what a Supabase-backed SPA with no server of its own looks like,
        # so try that specific, different-shaped check before giving up.
        try:
            progress("reasoning")
            findings = run_supabase_probe(repo_path)
            progress("probing")
        except NoSupabaseProject as e:
            return {"findings": [], "skipped": True, "reason": str(e)}
    except (SandboxUnavailable, SandboxBuildError) as e:
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
        "screenshot": screenshot.get("data_url"),
    }


@app.post("/probe")
def probe(req: ProbeRequest) -> dict:
    return _run_probe(req.repo_path, lambda _stage: None, user_hint=req.hint, test_credential=req.test_credential)


@app.post("/probe/stream")
def probe_stream(req: ProbeRequest) -> StreamingResponse:
    """Same as /probe, reported stage-by-stage as newline-delimited JSON.

    Mints a run id up front and sends it in the very first ("started")
    event, so the frontend's "Terminate pentest" button has something to
    call /probe/cancel with immediately -- not just once some later stage
    arrives.
    """
    run_id, cancel_event = new_run()

    def work(progress: Callable[[str], None]) -> dict:
        try:
            return _run_probe(
                req.repo_path,
                progress,
                cancel_event=cancel_event,
                user_hint=req.hint,
                test_credential=req.test_credential,
            )
        finally:
            finish_run(run_id)

    return _ndjson_stream(work, extra_started={"run_id": run_id})


@app.post("/hunch")
def hunch(req: HunchRequest) -> dict:
    """"Test a Hunch": judges the user's free-text lead against findings
    already gathered this session (scan + probe combined, sent by the
    caller) -- never re-runs anything itself, and says outright when the
    hunch isn't something Aegis's checks can test at all.
    """
    return evaluate_hunch(req.hint, req.findings)


@app.post("/probe/cancel")
def probe_cancel(req: CancelRequest) -> dict:
    """Signals a running probe to stop. Best-effort and honest about it:
    the build phase (see sandbox.py) can't be interrupted mid-flight, so a
    cancel during that window takes effect right after it finishes, not
    instantly -- everywhere else it stops within one poll interval.
    """
    return {"cancelled": request_cancel(req.run_id)}


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

    # Track this clone against the session so it gets deleted if the user
    # connects a different repo or disconnects -- previously nothing ever
    # cleaned these up, leaving a permanent leftover folder in Temp per clone.
    set_cloned_repo(aegis_session, str(local_path))

    return {
        "verified": True,
        "owner": result["owner"],
        "repo": result["repo"],
        "permission": result["permission"],
        "private": result["private"],
        "repo_path": str(local_path),
        # If this is a monorepo (e.g. separate frontend/ + backend/ services),
        # the frontend lets the user pick which one to point Aegis at --
        # asking the model to infer one Dockerfile for two unrelated apps at
        # once doesn't work, but each service alone is just a normal repo.
        "subprojects": find_subprojects(str(local_path)),
    }
