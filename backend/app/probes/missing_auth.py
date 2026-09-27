"""Phase 5: the safe active probe for missing-authentication candidates.

This is the piece that turns a static hypothesis into a CONFIRMED finding
with real evidence: Aegis builds the target repo's own Dockerfile into a
disposable container it controls, sends the route ONE plain request with no
credentials, and looks at the real response. Only a genuinely successful
response (real data, not a 401/403/404) counts as confirmed.

No exploit payloads, no data exfiltration, no destructive requests -- this
is a read-only, single GET/POST with an empty body, exactly what an
unauthenticated visitor's browser would send.
"""

from __future__ import annotations

from typing import Any, Callable

import httpx

from app.detectors.routes import (
    detect_and_find_entry,
    extract_routes,
    hypothesize_missing_auth,
)
from app.sandbox import SandboxBuildError, SandboxUnavailable, run_sandbox

_SUCCESS_STATUS = range(200, 300)

_NOOP_STAGE: Callable[[str], None] = lambda _stage: None  # noqa: E731

# The port each framework's app listens on INSIDE its container. Docker maps
# it to a random free host port; this just has to match what the app binds.
# Our demo Dockerfiles follow these conventions (Express 3001, uvicorn 8000,
# Flask 5000).
_PORT_FOR_FRAMEWORK = {"express": 3001, "fastapi": 8000, "flask": 5000}


class NoSupportedEntryPoint(RuntimeError):
    """Raised when the repo doesn't look like a web app we can trace at all --
    this means the active probe genuinely could not check anything, which is a
    different, more honest signal than "checked, found nothing"."""


def run_missing_auth_probe(
    repo_path: str,
    entry_file: str | None = None,
    framework: str | None = None,
    container_port: int | None = None,
    on_stage: Callable[[str], None] | None = None,
) -> list[dict[str, Any]]:
    """Full Phase 4-5 pipeline: trace routes -> hypothesize -> sandbox-probe.

    Framework-aware: works on Express (JS), FastAPI and Flask (Python).

    Returns a list of CONFIRMED findings only. Candidates the probe
    couldn't confirm (e.g. the route actually was protected, contrary to
    the hypothesis) are silently dropped -- Aegis never reports something
    it could not verify as if it were certain.

    Raises NoSupportedEntryPoint if the repo doesn't look like a supported
    web app -- callers must surface this as "could not check", not "clean".
    """
    stage = on_stage or _NOOP_STAGE

    stage("tracing")
    if entry_file is None or framework is None:
        found = detect_and_find_entry(repo_path)
        if found is None:
            raise NoSupportedEntryPoint(
                "No supported web-app entry point found anywhere in this repo. "
                "The active probe supports Express (app.js/server.js/index.js), "
                "FastAPI and Flask (main.py/app.py/server.py)."
            )
        entry_file, framework = found

    if container_port is None:
        container_port = _PORT_FOR_FRAMEWORK.get(framework, 3001)

    routes = extract_routes(repo_path, entry_file, framework)

    stage("reasoning")
    candidates = hypothesize_missing_auth(routes, framework)
    if not candidates:
        return []

    stage("sandbox")
    try:
        with run_sandbox(repo_path, container_port) as base_url:
            stage("probing")
            return [
                finding
                for c in candidates
                if (finding := _probe_one(base_url, c, entry_file, framework)) is not None
            ]
    except (SandboxUnavailable, SandboxBuildError):
        # No Docker / no Dockerfile / build failed -> the active-probe stage
        # is simply skipped. The caller (main.py) reports this honestly
        # rather than pretending the check ran.
        raise


def _probe_one(
    base_url: str, candidate: dict[str, Any], entry_file: str, framework: str
) -> dict[str, Any] | None:
    method = candidate["method"]
    path = candidate["path"]

    try:
        resp = httpx.request(method, f"{base_url}{path}", timeout=5.0)
    except Exception:
        return None  # couldn't even reach it -- not a confirmed finding

    if resp.status_code not in _SUCCESS_STATUS:
        return None  # the hypothesis was wrong -- it's actually protected

    body_snippet = resp.text[:300]
    return {
        "type": "missing-auth",
        "file": entry_file,
        "entry_file": entry_file,
        "framework": framework,
        "line": None,
        "rule": "unauthenticated-sensitive-route",
        "match": f"{method} {path}",
        "severity": "critical",
        "detail": candidate.get("reason", ""),
        "evidence": {
            "request": f"{method} {path}  (no Authorization header sent)",
            "response_status": resp.status_code,
            "response_body": body_snippet,
        },
    }
