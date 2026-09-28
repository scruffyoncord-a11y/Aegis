"""Best-effort Dockerfile synthesis for repos that don't ship their own.

Tried ONLY as a fallback when the target repo has no Dockerfile at all --
a repo-provided Dockerfile always wins outright (see sandbox.py). Qwen
reads the repo's own build/dependency signals (package.json,
requirements.txt, a Django/Flask/FastAPI entry file) and proposes a
minimal Dockerfile plus the port the app will listen on inside it.

The guess is written into a temporary COPY of the repo (the original is
never touched) and built with the exact same sandbox machinery as a
repo-provided Dockerfile -- same resource limits, same teardown. A bad
guess simply fails the Docker build or the app never responds; both are
surfaced as SandboxBuildError/SandboxUnavailable, the same as any other
sandbox failure -- never as a silent "clean" result.
"""

from __future__ import annotations

from pathlib import Path

from app.detectors.routes import _JS_ENTRIES, _PY_ENTRIES
from app.llm import ask_json

_SKIP_DIRS = {"node_modules", ".git", ".next", "dist", "build", "__pycache__", "venv", ".venv"}

# The files a human would look at first to figure out how to run an
# unfamiliar repo -- not the whole codebase, just its own build/dependency
# manifests and common entry-point filenames.
_SIGNAL_FILES = (
    "package.json",
    "requirements.txt",
    "pyproject.toml",
    "manage.py",
    "main.py",
    "app.py",
    "server.py",
    "Procfile",
)

# The same "this directory looks like its own app root" vocabulary
# detect_and_find_entry() already uses to pick an entry point.
_APP_ENTRY_NAMES = set(_PY_ENTRIES) | set(_JS_ENTRIES) | {"Dockerfile"}


def _collect_signals(repo_path: str, entry_file: str | None = None) -> str:
    """Reads build/dependency signal files from the repo, EXCLUDING any
    directory that looks like its own independent app root (has its own
    app.js/main.py/etc.) other than the one the caller says it actually
    picked (`entry_file`'s own directory).

    Without this, a repo that's mainly one app but happens to also contain
    an unrelated nested script sharing a common entry-point filename (e.g. a
    small Flask tool tucked into an Express app's public/ folder) gets its
    signals mixed across both -- the model is then asked to write ONE
    Dockerfile for what are really two unrelated apps, and correctly
    declines, the same failure mode as a real frontend/+backend/ monorepo
    (see subprojects.py). Scoping to the entry point's own directory is what
    fixes that, the same way subdirectory targeting fixes the monorepo case.
    """
    root = Path(repo_path)
    entry_dir = (root / Path(entry_file).parent).resolve() if entry_file else root.resolve()

    def _is_other_app_dir(p: Path) -> bool:
        if p.resolve() == entry_dir:
            return False
        return any((p / name).is_file() for name in _APP_ENTRY_NAMES)

    parts = []
    for name in _SIGNAL_FILES:
        matches = sorted(
            (
                p
                for p in root.rglob(name)
                if not any(part in _SKIP_DIRS for part in p.relative_to(root).parts)
                and not _is_other_app_dir(p.parent)
            ),
            key=lambda p: len(p.relative_to(root).parts),  # shallowest first
        )
        if not matches:
            continue
        p = matches[0]
        try:
            content = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        parts.append(f"--- {p.relative_to(root)} ---\n{content[:2000]}")
    return "\n\n".join(parts)


_INFER_PROMPT = """You are looking at the build/dependency files of a small \
web app repo. Based ONLY on what's shown below, write a minimal Dockerfile \
that installs its dependencies and starts it, and say which port it \
listens on inside the container.

Repo files:
{signals}

Rules:
- Use a small, standard base image (python:3.12-slim, node:20-slim, etc.)
- Install dependencies, copy the app, then CMD to start it
- Bind to 0.0.0.0, not localhost/127.0.0.1, so it's reachable from outside the container
- If a COPY's source is a wildcard or matches more than one file (e.g. \
`package*.json`), its destination MUST be a directory ending in `/` -- \
write `COPY package*.json ./`, never `COPY package*.json .` (Docker \
rejects that build: "the destination must be a directory and end with \
a /"). A single, exact source file (e.g. `COPY requirements.txt .`) is \
fine either way.
- If you genuinely can't tell how to start this app from what's shown, say so \
instead of guessing wildly

Respond with ONLY a JSON object, no prose:
{{"can_infer": true or false, "dockerfile": "the full Dockerfile text, or empty string", "port": 8000, "reason": "one short sentence"}}
"""


def infer_dockerfile(repo_path: str, entry_file: str | None = None) -> tuple[str, int] | None:
    """Ask the local model to synthesize a Dockerfile from the repo's own
    build/dependency signals. Returns (dockerfile_text, port), or None if
    there was nothing to reason about or the model wouldn't/couldn't guess
    -- callers must treat None the same as "no Dockerfile available".

    `entry_file` (the same one route-tracing already picked, if any) scopes
    signal collection to that app's own directory -- see _collect_signals.
    """
    signals = _collect_signals(repo_path, entry_file)
    if not signals.strip():
        return None

    prompt = _INFER_PROMPT.format(signals=signals)
    try:
        result = ask_json(prompt)
    except Exception:
        return None

    if not isinstance(result, dict) or not result.get("can_infer"):
        return None

    dockerfile = result.get("dockerfile")
    port = result.get("port")
    if not isinstance(dockerfile, str) or not dockerfile.strip():
        return None
    if not isinstance(port, int):
        return None

    return dockerfile, port
