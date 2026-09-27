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


def _collect_signals(repo_path: str) -> str:
    root = Path(repo_path)
    parts = []
    for name in _SIGNAL_FILES:
        matches = sorted(
            (
                p
                for p in root.rglob(name)
                if not any(part in _SKIP_DIRS for part in p.relative_to(root).parts)
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
- If you genuinely can't tell how to start this app from what's shown, say so \
instead of guessing wildly

Respond with ONLY a JSON object, no prose:
{{"can_infer": true or false, "dockerfile": "the full Dockerfile text, or empty string", "port": 8000, "reason": "one short sentence"}}
"""


def infer_dockerfile(repo_path: str) -> tuple[str, int] | None:
    """Ask the local model to synthesize a Dockerfile from the repo's own
    build/dependency signals. Returns (dockerfile_text, port), or None if
    there was nothing to reason about or the model wouldn't/couldn't guess
    -- callers must treat None the same as "no Dockerfile available".
    """
    signals = _collect_signals(repo_path)
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
