"""The probe agent: trace the target once, then let each registered Tool
reason about candidates and confirm them inside one shared sandbox.

Architecturally this is the same shape as AIDA's agent loop (reason about
the target, pick/run a tool, record why) -- but scoped down hard: the tools
are a small, fixed set Aegis ships with (see app/probes/tool.py), never an
open-ended command executor, and every tool's probe is a single safe,
read-only, no-credential request against a repo the caller already proved
they own. No exploit payloads, no destructive requests, no target chosen by
anything other than "the repo path Aegis was given".
"""

from __future__ import annotations

from typing import Any, Callable

from app.detectors.routes import detect_and_find_entry, extract_routes
from app.probes.tool import Tool
from app.sandbox import SandboxBuildError, SandboxUnavailable, run_sandbox_auto

_NOOP_STAGE: Callable[[str], None] = lambda _stage: None  # noqa: E731

# The port each framework's app listens on INSIDE its container. Docker maps
# it to a random free host port; this just has to match what the app binds.
_PORT_FOR_FRAMEWORK = {"express": 3001, "fastapi": 8000, "flask": 5000}


class NoSupportedEntryPoint(RuntimeError):
    """Raised when the repo doesn't look like a web app any registered tool
    can trace at all -- this means the agent genuinely could not check
    anything, which is a different, more honest signal than "checked, found
    nothing"."""


def run_active_probes(
    repo_path: str,
    tools: list[Tool],
    entry_file: str | None = None,
    framework: str | None = None,
    container_port: int | None = None,
    on_stage: Callable[[str], None] | None = None,
) -> list[dict[str, Any]]:
    """Trace once, hypothesize per tool, confirm every tool's candidates
    inside ONE shared sandbox (so a multi-tool run only pays the Docker
    build/start cost once), and return every confirmed finding across tools.
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

    # Reasoning: each tool independently hypothesizes over the same route
    # map -- this is the "agent picks what to try" step, kept per-tool so
    # each check's prompt stays narrow and auditable rather than one giant
    # do-everything prompt.
    stage("reasoning")
    tool_candidates: list[tuple[Tool, list[dict[str, Any]]]] = []
    for tool in tools:
        candidates = tool.hypothesize(routes, framework)
        if candidates:
            tool_candidates.append((tool, candidates))

    if not tool_candidates:
        return []

    stage("sandbox")
    findings: list[dict[str, Any]] = []
    try:
        with run_sandbox_auto(repo_path, container_port, entry_file=entry_file) as base_url:
            stage("probing")
            for tool, candidates in tool_candidates:
                for candidate in candidates:
                    finding = tool.probe(base_url, candidate, entry_file, framework)
                    if finding is not None:
                        findings.append(finding)
    except (SandboxUnavailable, SandboxBuildError):
        # No Docker / no Dockerfile / build failed -> the active-probe stage
        # is simply skipped. The caller reports this honestly rather than
        # pretending the check ran.
        raise

    return findings
