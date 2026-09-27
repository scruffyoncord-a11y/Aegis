"""Phase 3 detector (Supabase): missing or disabled Row Level Security.

Deterministic parsing of Supabase's own SQL migration files -- no live
probing. Supabase tables are readable/writable by anyone with the public
anon key UNLESS Row Level Security (RLS) is turned on for that table, so
the two classic flaws here are:

1. RLS explicitly turned off (`ALTER TABLE ... DISABLE ROW LEVEL SECURITY`).
2. A policy that grants access to everyone (`USING (true)` / `WITH CHECK
   (true)`), the same shape of bug as Firebase's `allow ...: if true`.
3. A table that never had RLS enabled at all -- this is the most common
   real-world Supabase mistake, since RLS is OFF by default on a new table.
   Detecting it means tracking every `CREATE TABLE` against every
   `ENABLE ROW LEVEL SECURITY` across the whole migration set.

Looks under `supabase/migrations/*.sql` (Supabase CLI's own convention) plus
any `*.sql` file at the repo root, so it still finds a single hand-written
migration in a smaller project.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

_DISABLE_RLS = re.compile(
    r"ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?[\"']?(\w+)[\"']?\s+DISABLE\s+ROW\s+LEVEL\s+SECURITY",
    re.IGNORECASE,
)
_ENABLE_RLS = re.compile(
    r"ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?[\"']?(\w+)[\"']?\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY",
    re.IGNORECASE,
)
_CREATE_TABLE = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[\"']?(\w+)[\"']?",
    re.IGNORECASE,
)
_OPEN_POLICY = re.compile(
    r"CREATE\s+POLICY\s+[\"']?([\w\s]+?)[\"']?\s+ON\s+[\"']?(\w+)[\"']?.*?"
    r"(?:USING|WITH\s+CHECK)\s*\(\s*true\s*\)",
    re.IGNORECASE | re.DOTALL,
)


_SKIP_DIRS = {"node_modules", ".git", ".next", "dist", "build", "__pycache__", "venv", ".venv"}


def _sql_files(repo_path: str) -> list[Path]:
    """supabase/migrations/*.sql anywhere in the repo (a monorepo keeps its
    Supabase project inside a subfolder, not the repo root), plus any *.sql
    file sitting directly at the repo root for a smaller, single-project repo.
    """
    root = Path(repo_path)
    found = [
        p
        for p in root.rglob("supabase/migrations/*.sql")
        if not any(part in _SKIP_DIRS for part in p.relative_to(root).parts)
    ]
    found += list(root.glob("*.sql"))
    return found


def _strip_sql_comments(text: str) -> str:
    text = re.sub(r"--[^\n]*", "", text)  # line comments
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)  # block comments
    return text


def scan_supabase(repo_path: str) -> list[dict[str, Any]]:
    root = Path(repo_path)
    files = _sql_files(repo_path)
    if not files:
        return []

    findings: list[dict[str, Any]] = []
    created_tables: dict[str, tuple[str, int]] = {}  # table -> (file, line)
    rls_enabled_tables: set[str] = set()

    for path in files:
        rel = str(path.relative_to(root))
        raw = path.read_text(encoding="utf-8")

        for i, line in enumerate(raw.splitlines(), start=1):
            clean = _strip_sql_comments(line)

            m = _DISABLE_RLS.search(clean)
            if m:
                findings.append(
                    {
                        "type": "cloud-misconfig",
                        "file": rel,
                        "line": i,
                        "rule": "supabase-rls-disabled",
                        "match": line.strip(),
                        "severity": "critical",
                        "detail": (
                            f"Row Level Security was explicitly turned off for "
                            f"table '{m.group(1)}'. Anyone with the public anon "
                            f"key can read and write every row."
                        ),
                    }
                )

            m = _ENABLE_RLS.search(clean)
            if m:
                rls_enabled_tables.add(m.group(1).lower())

            m = _CREATE_TABLE.search(clean)
            if m:
                created_tables.setdefault(m.group(1).lower(), (rel, i))

        stripped_raw = _strip_sql_comments(raw)
        for m in _OPEN_POLICY.finditer(stripped_raw):
            policy_name, table = m.group(1).strip(), m.group(2)
            # Count newlines in the SAME stripped string the match came from --
            # counting in the original `raw` would be off whenever a comment
            # was removed before this point, since that shifts the offsets.
            line_no = stripped_raw[: m.start()].count("\n") + 1
            findings.append(
                {
                    "type": "cloud-misconfig",
                    "file": rel,
                    "line": line_no,
                    "rule": "supabase-open-policy",
                    "match": f"CREATE POLICY \"{policy_name}\" ON {table} ... USING/WITH CHECK (true)",
                    "severity": "critical",
                    "detail": (
                        f"Policy '{policy_name}' on table '{table}' grants access "
                        f"to everyone with no restriction -- the same bug as "
                        f"Firebase's 'allow: if true'."
                    ),
                }
            )

    # A table created but never covered by ENABLE ROW LEVEL SECURITY anywhere
    # in the migration set -- RLS is off by default, so this is silently open.
    for table, (rel, line_no) in created_tables.items():
        if table not in rls_enabled_tables:
            findings.append(
                {
                    "type": "cloud-misconfig",
                    "file": rel,
                    "line": line_no,
                    "rule": "supabase-rls-never-enabled",
                    "match": f"CREATE TABLE {table} (no ENABLE ROW LEVEL SECURITY found)",
                    "severity": "critical",
                    "detail": (
                        f"Table '{table}' has no Row Level Security policy "
                        f"anywhere in the migrations. RLS is OFF by default on "
                        f"a new Supabase table, so this table is fully open to "
                        f"anyone with the public anon key."
                    ),
                }
            )

    return findings


def list_table_names(repo_path: str) -> list[str]:
    """Every table name seen in a CREATE TABLE statement across the repo's
    Supabase migrations, lowercased and deduplicated. Shares the same file
    discovery and parsing as scan_supabase() so the live probe (see
    app/probes/supabase_probe.py) checks exactly the tables the static
    scanner already knows about, never a separately-guessed list.
    """
    tables: set[str] = set()
    for path in _sql_files(repo_path):
        raw = _strip_sql_comments(path.read_text(encoding="utf-8"))
        for line in raw.splitlines():
            m = _CREATE_TABLE.search(line)
            if m:
                tables.add(m.group(1).lower())
    return sorted(tables)
