"""Phase 4: route extraction + AI hypothesis for missing authentication.

Two steps, deliberately kept separate:

1. Static extraction (`extract_routes`) -- deterministic regex parse of
   Express route definitions. No LLM, no guessing: just facts (method, path,
   the middleware/handler names in the call, the source line).

2. Hypothesis (`hypothesize_missing_auth`) -- the local LLM reads those facts
   plus the surrounding source and reasons like a pentester: "does this route
   look like it should require authentication, and does it actually have any
   auth-shaped middleware attached?" This produces CANDIDATES only -- nothing
   here is a confirmed finding yet. Confirmation happens by actually probing
   the route in a sandbox (see app/probes/missing_auth.py).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from app.llm import ask_json

# Matches the START of an Express route definition: app.<method>('/path',
# middleware1, middleware2, (req, res) => { ... -- deliberately stops at the
# handler's own opening paren/keyword rather than requiring the whole
# (usually multi-line) statement to close on the same line.
_ROUTE_RE = re.compile(
    r"""app\.(get|post|put|delete|patch)\s*\(\s*
        ['"`]([^'"`]+)['"`]\s*,\s*
        (?P<middleware>[\w\s,]*?)
        \s*,?\s*(?:\(|async\s*\(|function)""",
    re.VERBOSE,
)

# Heuristic names that suggest a handler argument is an auth check, not the
# route's actual business-logic handler. Used only to pre-filter obvious
# cases for the LLM -- the LLM makes the real call, this just gives it clean
# structured facts to reason over instead of raw regex noise.
_AUTH_LOOKING_NAMES = re.compile(
    r"auth|Auth|requireLogin|isLoggedIn|verifyToken|checkSession", re.IGNORECASE
)

_SKIP_DIRS = {"node_modules", ".git", ".next", "dist", "build", "__pycache__", "venv", ".venv"}
_ENTRY_CANDIDATES = ("app.js", "server.js", "index.js")


def find_entry_file(repo_path: str) -> str | None:
    """Look for a plausible Express entry point anywhere in the repo (a
    monorepo keeps its backend in a subfolder, e.g. backend/app.js), not
    just the root. Returns a path relative to repo_path, or None if this
    doesn't look like an Express app at all -- callers must treat that as
    "could not check", never as "checked and clean".
    """
    root = Path(repo_path)
    for name in _ENTRY_CANDIDATES:
        matches = [
            p
            for p in root.rglob(name)
            if not any(part in _SKIP_DIRS for part in p.relative_to(root).parts)
        ]
        if matches:
            # Prefer the shallowest match (closest to repo root).
            matches.sort(key=lambda p: len(p.relative_to(root).parts))
            return str(matches[0].relative_to(root))
    return None


def extract_routes(repo_path: str, entry_file: str = "app.js") -> list[dict[str, Any]]:
    """Deterministic regex extraction of Express route definitions."""
    path = Path(repo_path) / entry_file
    if not path.exists():
        return []

    routes: list[dict[str, Any]] = []
    lines = path.read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines, start=1):
        m = _ROUTE_RE.search(line.strip())
        if not m:
            continue
        method, route_path = m.group(1), m.group(2)
        middleware_blob = m.group("middleware").strip()
        middleware_args = (
            [a.strip() for a in middleware_blob.split(",") if a.strip()]
            if middleware_blob
            else []
        )
        has_auth_looking_middleware = any(
            _AUTH_LOOKING_NAMES.search(a) for a in middleware_args
        )
        routes.append(
            {
                "method": method.upper(),
                "path": route_path,
                "line": i,
                "middleware": middleware_args,
                "has_auth_looking_middleware": has_auth_looking_middleware,
                "source_line": line.strip(),
            }
        )
    return routes


_HYPOTHESIS_PROMPT = """You are a security reasoning assistant tracing routes \
in a small Express app to find candidates for a MISSING AUTHENTICATION check.

You will get a JSON list of routes, each with its method, path, the \
middleware/handler names in its definition, and whether any of those names \
already look auth-related.

Flag a route as a candidate ONLY if:
- Its path suggests it returns sensitive or privileged data (e.g. contains \
"admin", "user", "account", "profile", "order", "payment", "settings"), AND
- It has NO auth-looking middleware attached.

Do NOT flag a route just because it's a GET request, and do NOT flag a route \
that already has an auth-looking middleware -- that one is fine.

Respond with ONLY a JSON array (no prose), each item:
{{"path": "...", "method": "...", "reason": "one short sentence"}}
If no route qualifies, respond with an empty JSON array: []

Routes:
{routes_json}
"""


def hypothesize_missing_auth(routes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Ask the local LLM which routes look like missing-auth candidates.

    Returns a list of {path, method, reason} -- candidates only, not yet
    confirmed. Falls back to an empty list (never crashes the scan) if the
    model output can't be parsed.
    """
    if not routes:
        return []

    routes_json = json.dumps(
        [
            {
                "method": r["method"],
                "path": r["path"],
                "middleware": r["middleware"],
                "has_auth_looking_middleware": r["has_auth_looking_middleware"],
            }
            for r in routes
        ],
        indent=2,
    )
    prompt = _HYPOTHESIS_PROMPT.format(routes_json=routes_json)

    try:
        candidates = ask_json(prompt)
    except Exception:
        return []

    if not isinstance(candidates, list):
        return []

    # Only keep candidates that actually match a real extracted route --
    # never trust the model's path/method verbatim without cross-checking.
    known = {(r["method"], r["path"]) for r in routes}
    confirmed_candidates = []
    for c in candidates:
        if not isinstance(c, dict):
            continue
        key = (str(c.get("method", "")).upper(), c.get("path", ""))
        if key in known:
            confirmed_candidates.append(
                {"method": key[0], "path": key[1], "reason": c.get("reason", "")}
            )
    return confirmed_candidates
