"""Phase 4: route extraction + AI hypothesis for missing authentication.

Two steps, deliberately kept separate:

1. Static extraction (`extract_routes`) -- deterministic regex parse of route
   definitions. Framework-aware: Express (JS), FastAPI, and Flask (Python).
   No LLM, no guessing: just facts (method, path, whether any auth-shaped
   middleware / dependency / decorator is attached, the source line).

2. Hypothesis (`hypothesize_missing_auth`) -- the local LLM reads those facts
   and reasons like a pentester: "does this route look like it should require
   authentication, and does it actually have any auth attached?" This produces
   CANDIDATES only -- nothing here is confirmed yet. Confirmation happens by
   actually probing the route in a sandbox (see app/probes/missing_auth.py).

The extraction is framework-specific; everything downstream (hypothesis,
sandbox probe) works off the framework-neutral route list and real HTTP
responses, so it needed no per-framework changes.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from app.llm import ask_json

# --- Express (JS) --------------------------------------------------------- #

# app.<method>('/path', middleware1, middleware2, (req, res) => { ...
_EXPRESS_ROUTE_RE = re.compile(
    r"""(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*
        ['"`]([^'"`]+)['"`]\s*,\s*
        (?P<middleware>[\w\s,]*?)
        \s*,?\s*(?:\(|async\s*\(|function)""",
    re.VERBOSE,
)

# --- FastAPI (Python) ----------------------------------------------------- #

# @app.get("/path")  /  @router.post("/path", dependencies=[...])
_FASTAPI_DECORATOR_RE = re.compile(
    r"""@\s*(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*
        ['"]([^'"]+)['"]
        (?P<rest>[^\n]*)""",
    re.VERBOSE,
)

# --- Flask (Python) ------------------------------------------------------- #

# @app.route("/path", methods=["GET", "POST"])  /  @app.get("/path")
_FLASK_ROUTE_RE = re.compile(
    r"""@\s*(?:app|bp|blueprint)\.route\s*\(\s*['"]([^'"]+)['"]
        (?P<rest>[^\n]*)""",
    re.VERBOSE,
)
_FLASK_SHORTCUT_RE = re.compile(
    r"""@\s*(?:app|bp|blueprint)\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]""",
    re.VERBOSE,
)

# Names that look like an auth check, across all three frameworks: Express
# middleware, FastAPI Depends(...), Flask decorators (@login_required etc.).
_AUTH_LOOKING_NAMES = re.compile(
    r"auth|Auth|requireLogin|require_login|isLoggedIn|login_required|"
    r"verifyToken|verify_token|checkSession|check_session|jwt_required|"
    r"get_current_user|current_user|Security\(",
    re.IGNORECASE,
)

_SKIP_DIRS = {"node_modules", ".git", ".next", "dist", "build", "__pycache__", "venv", ".venv"}

# Entry-file candidates per framework, and how to recognise the framework
# from a file's own contents (so we don't mis-tag a Flask app as FastAPI).
_JS_ENTRIES = ("app.js", "server.js", "index.js")
_PY_ENTRIES = ("main.py", "app.py", "server.py", "api.py", "asgi.py", "wsgi.py")


def _framework_of(text: str) -> str | None:
    if "FastAPI(" in text or re.search(r"from\s+fastapi\b", text):
        return "fastapi"
    if "Flask(" in text or re.search(r"from\s+flask\b", text):
        return "flask"
    if re.search(r"require\(['\"]express['\"]\)", text) or re.search(r"from\s+['\"]express['\"]", text):
        return "express"
    return None


def detect_and_find_entry(repo_path: str) -> tuple[str, str] | None:
    """Find an entry file AND its framework anywhere in the repo (a monorepo
    keeps its backend in a subfolder). Returns (entry_file_rel, framework),
    or None if nothing recognisable is found -- callers must treat None as
    "could not check", never "checked and clean".
    """
    root = Path(repo_path)

    def _search(names: tuple[str, ...], js_default: str | None):
        for name in names:
            matches = sorted(
                (
                    p
                    for p in root.rglob(name)
                    if not any(part in _SKIP_DIRS for part in p.relative_to(root).parts)
                ),
                key=lambda p: len(p.relative_to(root).parts),  # shallowest first
            )
            for p in matches:
                try:
                    fw = _framework_of(p.read_text(encoding="utf-8", errors="ignore"))
                except OSError:
                    continue
                if fw:
                    return str(p.relative_to(root)), fw
                if js_default:  # a JS entry file we couldn't positively type -> assume express
                    return str(p.relative_to(root)), js_default
        return None

    return _search(_PY_ENTRIES, None) or _search(_JS_ENTRIES, "express")


# Backwards-compatible shim (older callers expected just the entry path).
def find_entry_file(repo_path: str) -> str | None:
    found = detect_and_find_entry(repo_path)
    return found[0] if found else None


def extract_routes(
    repo_path: str, entry_file: str = "app.js", framework: str = "express"
) -> list[dict[str, Any]]:
    """Deterministic route extraction, dispatched by framework."""
    path = Path(repo_path) / entry_file
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")

    if framework == "fastapi":
        return _extract_fastapi(text)
    if framework == "flask":
        return _extract_flask(text)
    return _extract_express(text)


def _route(method: str, path: str, line: int, has_auth: bool, source: str, middleware=None):
    return {
        "method": method.upper(),
        "path": path,
        "line": line,
        "middleware": middleware or [],
        "has_auth_looking_middleware": has_auth,
        "source_line": source,
    }


def _extract_express(text: str) -> list[dict[str, Any]]:
    routes = []
    for i, line in enumerate(text.splitlines(), start=1):
        m = _EXPRESS_ROUTE_RE.search(line.strip())
        if not m:
            continue
        method, route_path = m.group(1), m.group(2)
        middleware_blob = m.group("middleware").strip()
        middleware = [a.strip() for a in middleware_blob.split(",") if a.strip()]
        has_auth = any(_AUTH_LOOKING_NAMES.search(a) for a in middleware)
        routes.append(_route(method, route_path, i, has_auth, line.strip(), middleware))
    return routes


def _extract_fastapi(text: str) -> list[dict[str, Any]]:
    """FastAPI auth can live in the decorator (`dependencies=[Depends(...)]`)
    OR in the handler's own signature (`user = Depends(get_current_user)`),
    so for each route we inspect the decorator line plus the following few
    lines of the function signature.
    """
    lines = text.splitlines()
    routes = []
    for i, line in enumerate(lines, start=1):
        m = _FASTAPI_DECORATOR_RE.search(line.strip())
        if not m:
            continue
        method, route_path = m.group(1), m.group(2)
        # Window: the decorator's own tail + up to the next 6 lines (the def
        # and its parameter list), which is where Depends(...) auth appears.
        window = m.group("rest") + "\n" + "\n".join(lines[i : i + 6])
        has_auth = bool(_AUTH_LOOKING_NAMES.search(window))
        routes.append(_route(method, route_path, i, has_auth, line.strip()))
    return routes


def _extract_flask(text: str) -> list[dict[str, Any]]:
    """Flask auth is usually a separate decorator line (`@login_required`)
    stacked with the route decorator, so we scan a small window of lines
    around each route decorator for auth-looking decorators.
    """
    lines = text.splitlines()
    routes = []
    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        m = _FLASK_ROUTE_RE.search(stripped)
        if m:
            route_path, rest = m.group(1), m.group("rest")
            methods = re.findall(r"['\"](GET|POST|PUT|DELETE|PATCH)['\"]", rest, re.IGNORECASE)
            methods = [x.upper() for x in methods] or ["GET"]
        else:
            m = _FLASK_SHORTCUT_RE.search(stripped)
            if not m:
                continue
            methods, route_path = [m.group(1).upper()], m.group(2)

        # Auth decorators sit in the stacked decorator block: a few lines
        # above (other decorators) and just below (down to the def).
        window = "\n".join(lines[max(0, i - 4) : i + 3])
        has_auth = bool(_AUTH_LOOKING_NAMES.search(window))
        for method in methods:
            routes.append(_route(method, route_path, i, has_auth, stripped))
    return routes


_HYPOTHESIS_PROMPT = """You are a security reasoning assistant tracing routes \
in a small {framework} web app to find candidates for a MISSING \
AUTHENTICATION check.

You will get a JSON list of routes, each with its method, path, and whether \
any auth-related middleware / dependency / decorator is already attached.

Flag a route as a candidate ONLY if:
- Its path suggests it returns sensitive or privileged data (e.g. contains \
"admin", "user", "account", "profile", "order", "payment", "settings"), AND
- It has NO auth attached (has_auth_looking_middleware is false).

Do NOT flag a route just because it's a GET request, and do NOT flag a route \
that already has auth attached -- that one is fine.

Respond with ONLY a JSON array (no prose), each item:
{{"path": "...", "method": "...", "reason": "one short sentence"}}
If no route qualifies, respond with an empty JSON array: []

Routes:
{routes_json}
"""


def hypothesize_missing_auth(
    routes: list[dict[str, Any]], framework: str = "express"
) -> list[dict[str, Any]]:
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
                "has_auth_looking_middleware": r["has_auth_looking_middleware"],
            }
            for r in routes
        ],
        indent=2,
    )
    prompt = _HYPOTHESIS_PROMPT.format(framework=framework, routes_json=routes_json)

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
