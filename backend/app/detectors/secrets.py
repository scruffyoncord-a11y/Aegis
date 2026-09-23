"""Phase 1 detector: leaked secrets via Gitleaks.

Wraps the `gitleaks` CLI as a subprocess and turns its JSON report into
Aegis's plain finding format. No live probing needed here — a matched
secret pattern is already a certain finding.
"""

from __future__ import annotations

import fnmatch
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


class GitleaksNotInstalled(RuntimeError):
    pass


def _gitleaks_binary() -> str:
    binary = shutil.which("gitleaks")
    if not binary:
        raise GitleaksNotInstalled(
            "gitleaks is not installed or not on PATH. "
            "Install it from https://github.com/gitleaks/gitleaks/releases "
            "or `winget install gitleaks`."
        )
    return binary


def scan_secrets(repo_path: str) -> list[dict[str, Any]]:
    """Run gitleaks against repo_path and return a list of findings.

    Each finding: {file, line, rule, match, severity}
    """
    binary = _gitleaks_binary()

    with tempfile.NamedTemporaryFile(
        mode="r", suffix=".json", delete=False
    ) as report_file:
        report_path = Path(report_file.name)

    try:
        result = subprocess.run(
            [
                binary,
                "detect",
                "--source",
                repo_path,
                "--no-git",  # scan the working tree, not just git history
                "--report-format",
                "json",
                "--report-path",
                str(report_path),
                "--exit-code",
                "0",  # never fail the process on findings; we read the report
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        if result.returncode not in (0, 1):
            raise RuntimeError(
                f"gitleaks exited with code {result.returncode}: {result.stderr}"
            )

        raw = report_path.read_text(encoding="utf-8").strip()
        if not raw:
            return []

        entries = json.loads(raw)
        ignored = _gitignore_patterns(Path(repo_path))
        findings = []
        for entry in entries:
            file_path = entry.get("File", "")
            # A git-ignored file (e.g. .env) is the correct place for a secret,
            # so a secret there is not a leak -- don't flag it.
            if _is_ignored(file_path, ignored):
                continue
            findings.append(
                {
                    "type": "secret",
                    "file": file_path,
                    "line": entry.get("StartLine"),
                    "rule": entry.get("RuleID"),
                    "match": entry.get("Match"),
                    "severity": "high",
                }
            )
        return findings
    finally:
        report_path.unlink(missing_ok=True)


def _gitignore_patterns(repo_path: Path) -> list[str]:
    """Read .gitignore patterns from the repo, plus .env always."""
    patterns = [".env", "*.env"]
    gi = repo_path / ".gitignore"
    if gi.exists():
        for line in gi.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.append(line.rstrip("/"))
    return patterns


def _is_ignored(file_path: str, patterns: list[str]) -> bool:
    name = Path(file_path).name
    for pat in patterns:
        if fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(file_path, pat):
            return True
    return False
