"""Phase 1 detector: leaked secrets via Gitleaks.

Wraps the `gitleaks` CLI as a subprocess and turns its JSON report into
Aegis's plain finding format. No live probing needed here — a matched
secret pattern is already a certain finding.
"""

from __future__ import annotations

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
        findings = []
        for entry in entries:
            findings.append(
                {
                    "type": "secret",
                    "file": entry.get("File"),
                    "line": entry.get("StartLine"),
                    "rule": entry.get("RuleID"),
                    "match": entry.get("Match"),
                    "severity": "high",
                }
            )
        return findings
    finally:
        report_path.unlink(missing_ok=True)
