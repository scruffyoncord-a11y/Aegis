"""Phase 2 detector: vulnerable and hallucinated dependencies.

Two deterministic checks (no live probing, no source code leaves the machine):

1. Known-vulnerability check -- each package/version is looked up in the OSV
   database (api.osv.dev). Only the public package name + version is sent, the
   same public identifiers `npm audit` / `pip-audit` use. Your source stays local.

2. Existence check -- each package name is checked against the npm / PyPI
   registry. A name that does not exist is a supply-chain risk: AI code
   generators sometimes invent package names, and an attacker can register the
   invented name and ship malware ("slopsquatting").

Currently parses npm `package.json`. Python `requirements.txt` is a TODO.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import httpx

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
NPM_REGISTRY = "https://registry.npmjs.org"
_TIMEOUT = 15.0


def _osv_lookup(name: str, version: str, ecosystem: str) -> list[dict[str, Any]]:
    """Return OSV vulnerability records for a package@version, or []."""
    payload = {
        "version": version,
        "package": {"name": name, "ecosystem": ecosystem},
    }
    try:
        resp = httpx.post(OSV_QUERY_URL, json=payload, timeout=_TIMEOUT)
        resp.raise_for_status()
        return resp.json().get("vulns", []) or []
    except Exception:
        # Network/OSV failure should not crash the whole scan.
        return []


def _npm_package_exists(name: str) -> bool | None:
    """True/False if the package exists on npm, or None if the check failed."""
    try:
        resp = httpx.get(f"{NPM_REGISTRY}/{name}", timeout=_TIMEOUT)
        if resp.status_code == 404:
            return False
        if resp.status_code == 200:
            return True
        return None
    except Exception:
        return None


def _parse_npm(manifest: Path) -> dict[str, str]:
    data = json.loads(manifest.read_text(encoding="utf-8"))
    deps: dict[str, str] = {}
    for section in ("dependencies", "devDependencies"):
        for name, ver in (data.get(section) or {}).items():
            deps[name] = str(ver).lstrip("^~>=<= ")
    return deps


def scan_dependencies(repo_path: str) -> list[dict[str, Any]]:
    """Scan npm dependencies for known vulns and non-existent packages."""
    root = Path(repo_path)
    manifest = root / "package.json"
    if not manifest.exists():
        return []

    findings: list[dict[str, Any]] = []
    deps = _parse_npm(manifest)

    for name, version in deps.items():
        exists = _npm_package_exists(name)
        if exists is False:
            findings.append(
                {
                    "type": "dependency-missing",
                    "file": "package.json",
                    "line": None,
                    "rule": "hallucinated-package",
                    "match": f"{name}@{version}",
                    "severity": "high",
                    "detail": (
                        f"Package '{name}' does not exist on the npm registry. "
                        "An attacker could register this name and ship malware."
                    ),
                }
            )
            continue  # can't look up vulns for a package that doesn't exist

        vulns = _osv_lookup(name, version, "npm")
        if vulns:
            # Collapse every CVE for this package into ONE finding, bumped to the
            # highest fixed version so a single upgrade clears all known vulns.
            cve_ids: list[str] = []
            summaries: list[str] = []
            fixed_versions: list[str] = []
            for v in vulns:
                cve_ids.extend(v.get("aliases", []) or [v.get("id", "")])
                summary = v.get("summary") or v.get("details", "")[:120]
                if summary:
                    summaries.append(summary)
                fv = _first_fixed_version(v, name)
                if fv:
                    fixed_versions.append(fv)

            best_fixed = _max_version(fixed_versions) if fixed_versions else None
            cve_list = ", ".join(sorted({c for c in cve_ids if c}))
            findings.append(
                {
                    "type": "dependency-vuln",
                    "file": "package.json",
                    "line": None,
                    "rule": f"{len(vulns)} known vulnerabilities",
                    "match": f"{name}@{version}",
                    "severity": "high",
                    "detail": "; ".join(summaries[:3]),
                    "aliases": cve_list,
                    "fixed_version": best_fixed,
                }
            )

    return findings


def _max_version(versions: list[str]) -> str:
    """Return the highest semver-ish version from a list."""
    def key(v: str) -> tuple:
        parts = re.split(r"[.\-+]", v)
        return tuple(int(p) if p.isdigit() else 0 for p in parts)

    return max(versions, key=key)


def _first_fixed_version(vuln: dict[str, Any], name: str) -> str | None:
    """Best-effort extraction of the first 'fixed' version from an OSV record."""
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name") != name:
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return None
