"""Active probe for Supabase-backed apps that have no server code of their
own to trace -- a Vite/Next.js SPA whose "backend" is Supabase's own hosted
REST API, secured (or not) by Postgres Row-Level Security, is a genuinely
different shape of app than the sandbox-based Tools in app/probes/tool.py
target.

This deliberately does NOT go through app/probes/agent.py's Tool interface:
there is nothing to build or containerize here -- Supabase is already a
live, hosted service the repo talks to directly, so run_active_probes'
requirement to first find a traceable server entry point (Express/FastAPI/
Flask) will always fail on this shape of app, correctly, since there is no
server in the repo to find. See main.py::_run_probe for how this is tried
as a fallback specifically when that happens.

The repo's own Supabase anon key is not a secret Aegis extracts -- it is the
public client key Supabase's own docs say is meant to ship inside every
build of the app, embedded in the JS bundle every visitor's browser already
downloads. The check here is whether Row Level Security actually blocks an
anonymous read AT RUNTIME, which is what matters, not just whether the
migration SQL looks right (that's the separate static check in
app/detectors/supabase.py::scan_supabase).

Safety: at most one GET per table this repo's own migrations define
(`select=*&limit=1`), with only the `apikey` header set -- no Authorization,
no session, exactly what a stranger's browser could send. Never a write,
never a request for anything the repo's own SQL didn't already name.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import httpx

from app.detectors.supabase import list_table_names

_SKIP_DIRS = {"node_modules", ".git", ".next", "dist", "build", "__pycache__", "venv", ".venv"}
_SCAN_EXTENSIONS = {".env", ".local", ".ts", ".tsx", ".js", ".jsx", ".mjs", ""}
_SCAN_NAMES = {".env", ".env.local", ".env.production", ".env.development"}

# Covers Vite's and Next.js's own naming conventions -- the two frameworks
# Supabase's quickstart docs cover, and the two conventions
# dockerfile_inference.py-adjacent detection already assumes elsewhere.
_URL_RE = re.compile(
    r"(?:NEXT_PUBLIC_SUPABASE_URL|VITE_SUPABASE_URL)\s*[:=]\s*['\"]?(https://[a-z0-9-]+\.supabase\.co)"
)
_ANON_KEY_RE = re.compile(
    # Matches both key formats Supabase has issued: the classic JWT
    # ("eyJ...") and the newer "sb_publishable_..." key.
    r"(?:NEXT_PUBLIC_SUPABASE_ANON_KEY|VITE_SUPABASE_ANON_KEY|NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY|VITE_SUPABASE_PUBLISHABLE_KEY)"
    r"\s*[:=]\s*['\"]?(eyJ[\w.-]+|sb_publishable_[\w-]+)"
)

_SUCCESS_STATUS = range(200, 300)


class NoSupabaseProject(RuntimeError):
    """Raised when the repo doesn't look like it uses Supabase at all -- the
    same "genuinely could not check" signal as NoSupportedEntryPoint, not a
    finding of any kind."""


def _find_credentials(repo_path: str) -> tuple[str, str] | None:
    """Reads the project URL + anon key the same way the app's own frontend
    bundle does: from its own env files or, just as often, hardcoded straight
    into the client-init source (a second common Supabase-quickstart pattern).
    """
    root = Path(repo_path)
    url: str | None = None
    key: str | None = None
    for p in root.rglob("*"):
        if not p.is_file() or any(part in _SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        if p.name not in _SCAN_NAMES and p.suffix not in _SCAN_EXTENSIONS:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if url is None and (m := _URL_RE.search(text)):
            url = m.group(1)
        if key is None and (m := _ANON_KEY_RE.search(text)):
            key = m.group(1)
        if url and key:
            return url, key
    return None


def run_supabase_probe(repo_path: str) -> list[dict[str, Any]]:
    """Anonymously request one row from every table this repo's own
    migrations define. A table that returns real data with no
    Authorization header at all means RLS is not actually enforced on it,
    regardless of what the migration SQL says it should do.
    """
    creds = _find_credentials(repo_path)
    if creds is None:
        raise NoSupabaseProject(
            "No Supabase project URL/anon key found anywhere in this repo -- "
            "the Supabase probe only applies to apps built against Supabase."
        )
    url, anon_key = creds

    tables = list_table_names(repo_path)
    if not tables:
        raise NoSupabaseProject(
            "Found a Supabase project URL and anon key, but no CREATE TABLE "
            "statements in this repo's own migrations to know what to check."
        )

    findings: list[dict[str, Any]] = []
    for table in tables:
        try:
            resp = httpx.get(
                f"{url}/rest/v1/{table}",
                params={"select": "*", "limit": "1"},
                headers={"apikey": anon_key},  # no Authorization -- anonymous request
                timeout=5.0,
            )
        except Exception:
            continue  # couldn't reach the live project -- not a confirmed finding

        if resp.status_code not in _SUCCESS_STATUS:
            continue  # RLS (or the table not existing) blocked it -- as it should

        try:
            rows = resp.json()
        except ValueError:
            continue
        if not isinstance(rows, list) or not rows:
            continue  # "succeeded" but returned nothing -- RLS is filtering rows out, working as intended

        findings.append(
            {
                "type": "supabase-rls-missing",
                "file": "supabase (live project)",
                "entry_file": None,
                "framework": "supabase",
                "line": None,
                "rule": "anonymous-read-succeeded",
                "match": f"GET {table}",
                "severity": "critical",
                "detail": (
                    f"The '{table}' table returned real data to a completely "
                    "anonymous request -- no login, no Authorization header "
                    "sent. Row Level Security is not actually blocking reads "
                    "on it at runtime, whatever the migration SQL intends."
                ),
                "evidence": {
                    "request": f"GET {url}/rest/v1/{table}?select=*&limit=1  (apikey only, no session)",
                    "response_status": resp.status_code,
                    "response_body": str(rows)[:300],
                },
            }
        )

    return findings
