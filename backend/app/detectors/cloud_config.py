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


def scan_cloud_config(repo_path: str) -> list[dict[str, Any]]:
    root = Path(repo_path)
    findings: list[dict[str, Any]] = []

    for filename in _RULE_FILENAMES:
        path = root / filename
        if not path.exists():
            continue
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
                        "file": filename,
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
