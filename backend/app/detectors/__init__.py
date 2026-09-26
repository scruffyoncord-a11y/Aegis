"""Detector registry -- runs every Phase 1-3 detector over a repo."""

from __future__ import annotations

from typing import Any

from app.detectors.cloud_config import scan_cloud_config
from app.detectors.dependencies import scan_dependencies
from app.detectors.secrets import scan_secrets
from app.detectors.supabase import scan_supabase


def run_all_detectors(repo_path: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    findings.extend(scan_secrets(repo_path))
    findings.extend(scan_dependencies(repo_path))
    findings.extend(scan_cloud_config(repo_path))
    findings.extend(scan_supabase(repo_path))
    return findings
