"""Builds a lightweight file/folder tree for the "browse the codebase" step
between connecting a repo and choosing what to pentest -- a read-only,
GitHub-style mini repository view, not a full source browser.

Deliberately shallow and size-capped: this is a UI preview, not a code
index, so it never reads file contents and never returns something large
enough to stall the frontend on a big repo.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

_SKIP_DIRS = {
    "node_modules", ".git", ".next", "dist", "build", "__pycache__",
    "venv", ".venv", ".turbo", "coverage",
}
_MAX_DEPTH = 4
_MAX_ENTRIES_PER_DIR = 200
_MAX_TOTAL_NODES = 2000


def build_tree(repo_path: str) -> dict[str, Any]:
    """Returns {"name", "path", "type": "dir", "children": [...]} for the
    repo root. Each child is the same shape ("type": "file" has no
    "children"). Stops early (adds a synthetic "...": true marker) past
    _MAX_DEPTH, _MAX_ENTRIES_PER_DIR, or _MAX_TOTAL_NODES so a huge repo
    still returns fast.
    """
    root = Path(repo_path)
    counter = {"n": 0}

    def _walk(dir_path: Path, depth: int) -> list[dict[str, Any]]:
        if counter["n"] >= _MAX_TOTAL_NODES:
            return []
        try:
            entries = sorted(
                dir_path.iterdir(), key=lambda p: (p.is_file(), p.name.lower())
            )
        except OSError:
            return []

        children: list[dict[str, Any]] = []
        for p in entries:
            if p.name in _SKIP_DIRS or p.name.startswith("."):
                continue
            if len(children) >= _MAX_ENTRIES_PER_DIR or counter["n"] >= _MAX_TOTAL_NODES:
                children.append({"name": "...", "path": "", "type": "more"})
                break
            counter["n"] += 1
            rel = str(p.relative_to(root))
            if p.is_dir():
                node: dict[str, Any] = {"name": p.name, "path": rel, "type": "dir"}
                if depth < _MAX_DEPTH:
                    node["children"] = _walk(p, depth + 1)
                children.append(node)
            else:
                children.append({"name": p.name, "path": rel, "type": "file"})
        return children

    return {"name": root.name, "path": ".", "type": "dir", "children": _walk(root, 1)}
