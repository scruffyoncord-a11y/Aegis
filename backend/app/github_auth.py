"""GitHub-based repo ownership verification.

Aegis only scans/probes repos the user actually controls. We prove that by
asking for a GitHub Personal Access Token and checking the *authenticated
user's own permission level* on the target repo via GitHub's API (push or
admin access required) before anything is cloned or scanned.

Token handling rules (read before touching this file):
  - The token is used in-memory for exactly one request's duration. It is
    never written to disk, never logged, and never persisted in any session
    store.
  - When cloning, the token is passed to git via a one-shot GIT_CONFIG_*
    environment override (not embedded in the clone URL and not written into
    the cloned repo's `.git/config`), so it can't leak into the working copy
    or its history.
  - FastAPI/uvicorn's default access logs record the request path only, not
    the JSON body, so the token is not written to backend logs either.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import httpx

GITHUB_API = "https://api.github.com"
_TIMEOUT = 15.0

_REPO_URL_RE = re.compile(
    r"^(?:https?://github\.com/)?([\w.-]+)/([\w.-]+?)(?:\.git)?/?$"
)


class RepoRefError(ValueError):
    pass


def parse_repo_ref(repo_url: str) -> tuple[str, str]:
    """Accepts 'owner/repo', a github.com URL, or a .git URL. Returns (owner, repo)."""
    m = _REPO_URL_RE.match(repo_url.strip())
    if not m:
        raise RepoRefError(f"Could not parse a GitHub owner/repo from: {repo_url!r}")
    return m.group(1), m.group(2)


def verify_repo_access(repo_url: str, token: str) -> dict[str, Any]:
    """Check the token's own permission level on the target repo.

    Requires push or admin access -- a token that can only read the repo is
    not proof of ownership/control, so verification fails for read-only.
    """
    owner, repo = parse_repo_ref(repo_url)

    resp = httpx.get(
        f"{GITHUB_API}/repos/{owner}/{repo}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        },
        timeout=_TIMEOUT,
    )

    if resp.status_code == 404:
        return {
            "verified": False,
            "error": "Repo not found, or this token can't see it.",
        }
    if resp.status_code == 401:
        return {"verified": False, "error": "Invalid or expired token."}
    resp.raise_for_status()

    data = resp.json()
    perms = data.get("permissions", {}) or {}
    has_control = bool(perms.get("push") or perms.get("admin"))
    permission = (
        "admin" if perms.get("admin") else "write" if perms.get("push") else "read/none"
    )

    return {
        "verified": has_control,
        "owner": owner,
        "repo": repo,
        "permission": permission,
        "private": data.get("private", False),
        "default_branch": data.get("default_branch", "main"),
        "error": None if has_control else "Token does not have push/admin access to this repo.",
    }


def clone_repo(repo_url: str, token: str, branch: str | None = None) -> Path:
    """Shallow-clone the repo into a fresh temp dir using the token, then
    discard the token immediately -- it's passed via a process-scoped env
    override, never written to the clone's .git/config or to disk.
    """
    owner, repo = parse_repo_ref(repo_url)
    clone_url = f"https://github.com/{owner}/{repo}.git"

    dest_parent = Path(tempfile.mkdtemp(prefix="aegis-clone-"))
    dest = dest_parent / repo

    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_CONFIG_COUNT"] = "1"
    env["GIT_CONFIG_KEY_0"] = "http.extraheader"
    env["GIT_CONFIG_VALUE_0"] = f"AUTHORIZATION: bearer {token}"

    cmd = ["git", "clone", "--depth", "1"]
    if branch:
        cmd += ["--branch", branch]
    cmd += [clone_url, str(dest)]

    try:
        result = subprocess.run(
            cmd, env=env, capture_output=True, text=True, timeout=60
        )
    finally:
        # Belt-and-braces: drop our only reference to the token-bearing env.
        del env

    if result.returncode != 0:
        shutil.rmtree(dest_parent, ignore_errors=True)
        # git's stderr can echo the URL but never the header/token.
        raise RuntimeError(f"git clone failed: {result.stderr.strip()}")

    return dest
