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

    Candidates from BOTH languages are pooled and tried SHALLOWEST-first,
    never Python-before-JS regardless of depth -- a root-level app.js is far
    more likely to be the app someone would actually deploy than some
    unrelated server.py three folders deep that happens to share a common
    entry-point filename (a small nested utility script, a test fixture,
    etc.). Trying one language's names across the whole tree before ever
    looking at the other's used to mean a single stray server.py anywhere
    could permanently hide a repo's real, root-level Express app.
    """
    root = Path(repo_path)

    def _candidates(names: tuple[str, ...]) -> list[Path]:
        found = []
        for name in names:
            found.extend(
                p
                for p in root.rglob(name)
                if not any(part in _SKIP_DIRS for part in p.relative_to(root).parts)
            )
        return found

    candidates = _candidates(_PY_ENTRIES) + _candidates(_JS_ENTRIES)
    candidates.sort(key=lambda p: len(p.relative_to(root).parts))  # shallowest first

    for p in candidates:
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        fw = _framework_of(text)
        if fw:
            return str(p.relative_to(root)), fw
        if p.name in _JS_ENTRIES:  # a JS entry file we couldn't positively type -> assume express
            return str(p.relative_to(root)), "express"
    return None


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


# A path parameter that looks like a resource ID: Express :id, FastAPI/Flask
# {id}/{order_id}, Flask <id>/<int:id>. Used to find IDOR candidates -- a
# route with no id-like parameter can't have an ID-swap ownership problem.
# Public (no leading underscore): reused by app/probes/idor.py to substitute
# a concrete test id into the path template for the active probe.
ID_PARAM_RE = re.compile(r"(:\w*id\w*)|(\{\w*id\w*\})|(<(?:int:|string:)?\w*id\w*>)", re.IGNORECASE)

_HANDLER_SNIPPET_LINES = 15  # enough to see the resource lookup + any ownership check

# Any line that starts a NEW route definition, across all three frameworks --
# used to stop a handler snippet before it bleeds into the next route's code.
_ANY_ROUTE_START_RES = (_EXPRESS_ROUTE_RE, _FASTAPI_DECORATOR_RE, _FLASK_ROUTE_RE, _FLASK_SHORTCUT_RE)


def _route(
    method: str,
    path: str,
    line: int,
    has_auth: bool,
    source: str,
    middleware=None,
    handler_snippet: str = "",
):
    return {
        "method": method.upper(),
        "path": path,
        "line": line,
        "middleware": middleware or [],
        "has_auth_looking_middleware": has_auth,
        "has_id_param": bool(ID_PARAM_RE.search(path)),
        "handler_snippet": handler_snippet,
        "source_line": source,
    }


def _snippet(lines: list[str], start_idx: int) -> str:
    """The handler body following a route definition -- enough for the LLM
    to actually read the code, not just guess from the path name.

    Stops at the next route definition, OR at a comment line, OR at the
    window limit, whichever comes first. Both boundary conditions matter:
    without the route-start check, a short handler's snippet bleeds into
    the next route's code; without the comment check, it bleeds into a
    comment ABOUT the next route (e.g. "# Correctly protected contrast --
    checks the owner_id..."), which the model then misreads as evidence of
    a check that isn't actually in this route's own code. Both bugs were
    caught by actually reading what the LLM was doing, not assumed.
    """
    collected = [lines[start_idx]]
    for line in lines[start_idx + 1 : start_idx + _HANDLER_SNIPPET_LINES]:
        stripped = line.strip()
        if any(r.search(stripped) for r in _ANY_ROUTE_START_RES):
            break
        if stripped.startswith(("#", "//", "/*", "*")):
            break
        collected.append(line)
    return "\n".join(collected)


def _extract_express(text: str) -> list[dict[str, Any]]:
    lines = text.splitlines()
    routes = []
    for i, line in enumerate(lines, start=1):
        m = _EXPRESS_ROUTE_RE.search(line.strip())
        if not m:
            continue
        method, route_path = m.group(1), m.group(2)
        middleware_blob = m.group("middleware").strip()
        middleware = [a.strip() for a in middleware_blob.split(",") if a.strip()]
        has_auth = any(_AUTH_LOOKING_NAMES.search(a) for a in middleware)
        routes.append(
            _route(method, route_path, i, has_auth, line.strip(), middleware, _snippet(lines, i - 1))
        )
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
        # Window: the decorator's own tail + this route's own body (stops at
        # the next route/comment -- see _snippet's docstring for why that
        # boundary matters: an unbounded window here previously bled into
        # the NEXT route's `Depends(get_current_user)` and wrongly marked
        # THIS route as authenticated).
        window = m.group("rest") + "\n" + _snippet(lines, i - 1)
        has_auth = bool(_AUTH_LOOKING_NAMES.search(window))
        routes.append(
            _route(method, route_path, i, has_auth, line.strip(), handler_snippet=_snippet(lines, i - 1))
        )
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
        # above (other decorators) and just below (down to the def). Bounded
        # in both directions at the nearest route/blank-line/comment so this
        # can't bleed into a neighbouring route's own decorators or body --
        # the same class of bug fixed in _extract_fastapi above.
        back = []
        for line_back in reversed(lines[max(0, i - 5) : i - 1]):
            s = line_back.strip()
            if not s or any(r.search(s) for r in _ANY_ROUTE_START_RES):
                break
            back.insert(0, line_back)
        window = "\n".join(back) + "\n" + _snippet(lines, i - 1)
        has_auth = bool(_AUTH_LOOKING_NAMES.search(window))
        for method in methods:
            routes.append(
                _route(method, route_path, i, has_auth, stripped, handler_snippet=_snippet(lines, i - 1))
            )
    return routes


_HYPOTHESIS_PROMPT = """You are looking at ONE route from a small {framework} \
web app.

Route: {method} {path}
{hint_block}
Does this path suggest it returns sensitive or privileged data -- for \
example an admin panel, another user's data, an account, an order, a \
payment, or settings? Judge ONLY the path, not whether it has authentication.

Respond with ONLY a JSON object, no prose:
{{"looks_sensitive": true or false, "reason": "one short sentence"}}
"""

# Appended into a hypothesis prompt when the user supplied a hunch -- kept as
# EXTRA CONTEXT for a still-single factual question, never a second condition
# to AND/OR against (see both hypothesize_* docstrings: a compound question
# was unreliable on this model). The route is still judged on its own merits;
# the hunch just gives the model something to weigh it against.
_HINT_BLOCK = """
The developer connected this repo specifically suspecting: "{hint}"
If this route looks related to that, weigh it accordingly -- but still \
judge it honestly even if it doesn't relate at all.
"""


def hypothesize_missing_auth(
    routes: list[dict[str, Any]], framework: str = "express", user_hint: str | None = None
) -> list[dict[str, Any]]:
    """Ask the local LLM which routes look like missing-auth candidates.

    Deliberately asks the model ONE direct question per route ("does the
    path look sensitive?") rather than the compound "flag it if it looks
    sensitive AND has no auth" -- that compound/negation prompt was
    unreliable on this model (it flagged an already-protected route and
    missed the actually vulnerable one). Whether auth is attached is
    already known deterministically from static extraction
    (has_auth_looking_middleware), so it's applied here in plain Python,
    never asked of the model.

    `user_hint`, if given (the "Test a Hunch" feature), is folded in as
    extra context per route -- see _HINT_BLOCK for why it can't become a
    second condition in the question itself.

    Returns a list of {path, method, reason} -- candidates only, not yet
    confirmed. A route the model can't be parsed for is skipped, never
    crashes the scan.
    """
    hint_block = _HINT_BLOCK.format(hint=user_hint) if user_hint else ""
    candidates = []
    for r in routes:
        if r["has_auth_looking_middleware"]:
            continue  # already known to be fine -- don't even ask the model
        prompt = _HYPOTHESIS_PROMPT.format(
            framework=framework, method=r["method"], path=r["path"], hint_block=hint_block
        )
        try:
            result = ask_json(prompt)
        except Exception:
            continue
        if isinstance(result, dict) and result.get("looks_sensitive"):
            candidates.append(
                {"method": r["method"], "path": r["path"], "reason": result.get("reason", "")}
            )
    return candidates


_IDOR_HYPOTHESIS_PROMPT = """You are reading ONE route handler from a small \
{framework} web app.

Route: {method} {path}
{hint_block}
Handler source code:
```
{handler_snippet}
```

Look ONLY at the code above. Does it compare the looked-up record's owner to \
the logged-in caller before returning it? For example: checking `.ownerId`, \
`.owner_id`, `.userId`, or `user_id` against the current user's id.

Respond with ONLY a JSON object, no prose:
{{"has_ownership_check": true or false, "evidence": "quote the exact comparison line, or empty string if none"}}
"""


def hypothesize_idor(
    routes: list[dict[str, Any]], framework: str = "express", user_hint: str | None = None
) -> list[dict[str, Any]]:
    """Ask the local LLM which id-param routes look like IDOR candidates,
    based on actually reading the handler code for a missing ownership check.

    Deliberately asks the model ONE direct factual question per route
    ("does an ownership check exist?") rather than the compound "flag it if
    the check does NOT exist" -- that negation was unreliable on this model
    (it repeatedly flagged the route that DID have the check and missed the
    one that didn't). The candidate decision itself (missing_auth check ==
    False) is computed here in plain Python, not by the model.

    `user_hint`, if given (the "Test a Hunch" feature), is folded in as
    extra context per route -- see _HINT_BLOCK for why it can't become a
    second condition in the question itself.

    Returns a list of {path, method, reason} -- candidates only, not yet
    confirmed. A route the model can't be parsed for is skipped, never
    crashes the scan.
    """
    hint_block = _HINT_BLOCK.format(hint=user_hint) if user_hint else ""
    id_routes = [r for r in routes if r.get("has_id_param")]
    candidates = []
    for r in id_routes:
        prompt = _IDOR_HYPOTHESIS_PROMPT.format(
            framework=framework,
            method=r["method"],
            path=r["path"],
            handler_snippet=r["handler_snippet"],
            hint_block=hint_block,
        )
        try:
            result = ask_json(prompt)
        except Exception:
            continue
        if not isinstance(result, dict):
            continue
        if not result.get("has_ownership_check"):
            candidates.append(
                {
                    "method": r["method"],
                    "path": r["path"],
                    "reason": "No ownership check found on this id-looked-up record.",
                }
            )
    return candidates
