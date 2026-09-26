"""Sandbox orchestration for the active probe (Phase 4-5).

Aegis's active checks never touch a live/production system. Instead, the
target repo is built into a Docker container **that Aegis itself starts and
tears down**, on a random free host port, with no other network access than
what the container image itself needs to boot -- and every probe in
`app/probes/` talks only to that one disposable container.

Convention: the target repo must provide its own `Dockerfile` (same
convention many CI systems use). Aegis does not guess how to run an
arbitrary app -- if there's no Dockerfile, the active-probe stage is simply
skipped and Aegis says so, rather than trying to run untrusted code some
other way.
"""

from __future__ import annotations

import contextlib
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
