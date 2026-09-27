"""Detect which directory (or directories) inside a cloned repo look like an
independently runnable service.

Why this exists: a monorepo like a separate frontend/ + backend/ pair has no
single Dockerfile and no single set of dependencies -- asking the local model
to infer ONE Dockerfile that starts two unrelated apps at once doesn't make
sense, and it correctly declines rather than guessing (see
dockerfile_inference.py). The real fix is letting the user point Aegis at
just one service directory, which on its own looks like any other
single-service repo Aegis already knows how to sandbox.
"""

from __future__ import annotations

from pathlib import Path

_SKIP_DIRS = {"node_modules", ".git", ".next", "dist", "build", "__pycache__", "venv", ".venv"}

# The same kind of build/dependency/entry-point files dockerfile_inference.py
# looks for -- if a directory has one of these, it looks like something that
# can run on its own.
_SERVICE_SIGNALS = (
    "Dockerfile",
    "package.json",
    "requirements.txt",
    "pyproject.toml",
    "manage.py",
)


def _has_signal(dir_path: Path) -> bool:
    return any((dir_path / name).is_file() for name in _SERVICE_SIGNALS)


def find_subprojects(repo_root: str) -> list[str]:
    """Candidate service directories, as paths relative to repo_root ("."
    for the repo root itself). Only looks one level deep -- this is meant to
    catch the common frontend/ + backend/ split, not act as a general
    workspace resolver for arbitrarily nested monorepos.
    """
    root = Path(repo_root)
    candidates: list[str] = []
    if _has_signal(root):
        candidates.append(".")
    for child in sorted(root.iterdir()):
        if not child.is_dir() or child.name in _SKIP_DIRS or child.name.startswith("."):
            continue
        if _has_signal(child):
            candidates.append(child.name)
    return candidates
