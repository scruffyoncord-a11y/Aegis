"""Phase 3 detector: misconfigured cloud backend rules.

Deterministic file parsing -- no live probing. Looks for permissive
Firebase/Firestore security rules that expose the whole database.

The classic flaw is `allow read, write: if true;` (or `if 1 == 1`, etc.),
which lets anyone on the internet read and write all data with no auth.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

# `allow <perms> : if true` with flexible whitespace; also catches trivially
# true conditions like `if 1 == 1` or `if true == true`.
_ALLOW_TRUE = re.compile(
    r"allow\s+([a-z,\s]+?)\s*:\s*if\s+(true|1\s*==\s*1|true\s*==\s*true)\b",
    re.IGNORECASE,
)

_RULE_FILENAMES = ("firestore.rules", "firebase.rules", "storage.rules")

# Same reasoning as dependencies.py's _SKIP_DIRS: a monorepo's real rules
# file lives inside a subproject (frontend/, functions/, etc.), so this has
# to search the whole repo -- but never inside dependency/build trees.
_SKIP_DIRS = {"node_modules", ".git", ".next", "dist", "build", "__pycache__", "venv", ".venv"}


def _find_rule_files(root: Path) -> list[Path]:
    found = []
    for filename in _RULE_FILENAMES:
        for p in root.rglob(filename):
            if not any(part in _SKIP_DIRS for part in p.relative_to(root).parts):
                found.append(p)
    return found


def scan_cloud_config(repo_path: str) -> list[dict[str, Any]]:
    root = Path(repo_path)
    findings: list[dict[str, Any]] = []

    for path in _find_rule_files(root):
        rel = str(path.relative_to(root))
        lines = path.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines, start=1):
            stripped = line.lstrip()
            # Skip comment lines (// ... or * ... inside a /* */ block).
            if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
                continue
            m = _ALLOW_TRUE.search(line)
            if m:
                perms = m.group(1).strip()
                findings.append(
                    {
                        "type": "cloud-misconfig",
                        "file": rel,
                        "line": i,
                        "rule": "firebase-open-rule",
                        "match": line.strip(),
                        "severity": "critical",
                        "detail": (
                            f"Rule grants '{perms}' to everyone with no "
                            "authentication. Anyone on the internet can access "
                            "this data."
                        ),
                    }
                )
    return findings
