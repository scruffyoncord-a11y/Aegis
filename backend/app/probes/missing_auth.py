"""Phase 5: the safe active probe for missing-authentication candidates.

This is the piece that turns a static hypothesis into a CONFIRMED finding
with real evidence: Aegis builds the target repo's own Dockerfile into a
disposable container it controls, sends the route ONE plain request with no
credentials, and looks at the real response. Only a genuinely successful
response (real data, not a 401/403/404) counts as confirmed.

No exploit payloads, no data exfiltration, no destructive requests -- this
is a read-only, single GET/POST with an empty body, exactly what an
unauthenticated visitor's browser would send.

This module defines MISSING_AUTH_TOOL, one Tool for app.probes.agent's
registry (see app/probes/tool.py). run_missing_auth_probe() is kept as a
thin, backward-compatible wrapper that runs the agent with just this tool.
"""

from __future__ import annotations

from typing import Any, Callable

import httpx

from app.detectors.routes import hypothesize_missing_auth
from app.probes.agent import NoSupportedEntryPoint, run_active_probes  # noqa: F401  (re-exported)
from app.probes.tool import Tool

_SUCCESS_STATUS = range(200, 300)


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


MISSING_AUTH_TOOL = Tool(
    name="missing-auth",
    description=(
        "Traces routes for ones that look sensitive but have no auth "
        "attached, then confirms with a single unauthenticated request."
    ),
    hypothesize=hypothesize_missing_auth,
    probe=_probe_one,
)


def run_missing_auth_probe(
    repo_path: str,
    entry_file: str | None = None,
    framework: str | None = None,
    container_port: int | None = None,
    on_stage: Callable[[str], None] | None = None,
) -> list[dict[str, Any]]:
    """Backward-compatible entry point: runs the agent with only the
    missing-auth tool registered. See app.probes.agent.run_active_probes
    for the general (multi-tool) form.
    """
    return run_active_probes(
        repo_path,
        [MISSING_AUTH_TOOL],
        entry_file=entry_file,
        framework=framework,
        container_port=container_port,
        on_stage=on_stage,
    )
