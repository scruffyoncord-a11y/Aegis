"""Sandbox orchestration for the active probe (Phase 4-5).

Aegis's active checks never touch a live/production system. Instead, the
target repo is built into a Docker container **that Aegis itself starts and
tears down**, on a random free host port, with no other network access than
what the container image itself needs to boot -- and every probe in
`app/probes/` talks only to that one disposable container.

Convention: the target repo should provide its own `Dockerfile` (same
convention many CI systems use) -- if it has one, that always wins and is
used exactly as-is. If it doesn't, `run_sandbox_auto` falls back to asking
the local model to synthesize a minimal one from the repo's own
build/dependency files (see app/dockerfile_inference.py); that guess is
written into a disposable COPY of the repo, never the original, and built
with the exact same sandbox machinery. If neither a real nor an inferred
Dockerfile is available, the active-probe stage is simply skipped and
Aegis says so, rather than trying to run untrusted code some other way.
"""

from __future__ import annotations

import contextlib
import shutil
import tempfile
import time
import uuid
from pathlib import Path
from typing import Iterator

import docker
import httpx
from docker.errors import BuildError, DockerException

_READY_TIMEOUT_SECONDS = 20.0
_READY_POLL_INTERVAL = 0.5


class SandboxUnavailable(RuntimeError):
    pass


class SandboxBuildError(RuntimeError):
    pass


def has_dockerfile(repo_path: str) -> bool:
    return (Path(repo_path) / "Dockerfile").exists()


@contextlib.contextmanager
def run_sandbox(repo_path: str, container_port: int) -> Iterator[str]:
    """Build + run the target repo's own Dockerfile, yield its base URL.

    The container is always removed on exit, even on error. `container_port`
    is the port the app listens on *inside* the container (e.g. 3001) --
    Docker maps it to a random free port on the host, so parallel runs never
    collide.
    """
    if not has_dockerfile(repo_path):
        raise SandboxUnavailable(
            f"No Dockerfile in {repo_path!r} -- the active probe needs the "
            "target repo to provide one. Skipping the sandboxed check."
        )

    try:
        client = docker.from_env()
        client.ping()
    except DockerException as e:
        raise SandboxUnavailable(
            "Docker is not running or not reachable. Start Docker Desktop "
            "to enable the active-probe stage."
        ) from e

    tag = f"aegis-sandbox-{uuid.uuid4().hex[:10]}"
    container = None
    try:
        try:
            client.images.build(path=str(repo_path), tag=tag, rm=True)
        except BuildError as e:
            raise SandboxBuildError(f"Docker build failed: {e}") from e

        container = client.containers.run(
            tag,
            detach=True,
            ports={f"{container_port}/tcp": None},  # None = random free host port
            network_mode="bridge",
            mem_limit="256m",
            pids_limit=100,
            security_opt=["no-new-privileges"],
            remove=False,  # we remove explicitly in finally, after logs if needed
        )
        container.reload()
        host_port = container.ports[f"{container_port}/tcp"][0]["HostPort"]
        base_url = f"http://127.0.0.1:{host_port}"

        _wait_until_ready(base_url)
        yield base_url

    finally:
        if container is not None:
            try:
                container.remove(force=True)
            except DockerException:
                pass
        try:
            client.images.remove(tag, force=True)
        except Exception:
            pass


def run_sandbox_auto(repo_path: str, container_port: int, entry_file: str | None = None):
    """Like run_sandbox, but if the repo has no Dockerfile, tries a
    best-effort model-synthesized one first (see app/dockerfile_inference.py)
    before giving up. A repo-provided Dockerfile always wins outright --
    inference is a fallback, never a replacement for it.

    `entry_file` (the one route-tracing already picked) scopes the
    inference's signal collection to that app's own directory, so a repo
    that's mainly one app but happens to also contain an unrelated nested
    script doesn't get its signals mixed across both.

    Returns a context manager, same as run_sandbox -- use with `with ... as
    base_url:`.
    """
    if has_dockerfile(repo_path):
        return run_sandbox(repo_path, container_port)

    from app.dockerfile_inference import infer_dockerfile  # local import: keep the LLM dependency out of sandbox.py's module load unless actually needed

    inferred = infer_dockerfile(repo_path, entry_file)
    if inferred is None:
        raise SandboxUnavailable(
            f"No Dockerfile in {repo_path!r}, and the local model could not "
            "infer how to build and run this app from its own files either. "
            "Add a Dockerfile to enable the active-probe stage."
        )
    dockerfile_text, inferred_port = inferred
    return _run_sandbox_with_synthesized_dockerfile(repo_path, dockerfile_text, inferred_port)


@contextlib.contextmanager
def _run_sandbox_with_synthesized_dockerfile(
    repo_path: str, dockerfile_text: str, container_port: int
) -> Iterator[str]:
    """Copies the repo to a temp dir (the original is NEVER touched), writes
    the model-synthesized Dockerfile into that copy only, then reuses
    run_sandbox's exact build/run/teardown path unchanged -- same resource
    limits, same cleanup, same honest failure behavior on a bad guess.
    """
    tmp = Path(tempfile.mkdtemp(prefix="aegis-autodockerfile-"))
    work = tmp / Path(repo_path).resolve().name
    try:
        shutil.copytree(
            repo_path,
            work,
            ignore=shutil.ignore_patterns(
                "node_modules", ".git", ".next", "dist", "build",
                "__pycache__", "venv", ".venv",
            ),
        )
        (work / "Dockerfile").write_text(dockerfile_text, encoding="utf-8")
        with run_sandbox(str(work), container_port) as base_url:
            yield base_url
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _wait_until_ready(base_url: str) -> None:
    deadline = time.time() + _READY_TIMEOUT_SECONDS
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            httpx.get(base_url, timeout=2.0)
            return
        except Exception as e:
            last_error = e
            time.sleep(_READY_POLL_INTERVAL)
    raise SandboxUnavailable(f"Sandboxed app never became ready: {last_error}")
