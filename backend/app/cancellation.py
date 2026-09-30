"""Lets a running probe be told to stop -- the backing for the "Terminate
pentest" button.

Aegis is a single-user local tool: there is only ever one probe genuinely
running at a time, so a plain dict keyed by a random run id (handed to the
frontend the moment a probe starts) is enough. No need for anything heavier.
"""

from __future__ import annotations

import threading
import uuid

_events: dict[str, threading.Event] = {}


class Cancelled(RuntimeError):
    """Raised inside a probe run when the user terminated it. Callers treat
    this as "could not check", the same honest-skip family as
    NoSupportedEntryPoint/SandboxUnavailable -- never as a silent "clean"
    result, and never as an ordinary error."""


def new_run() -> tuple[str, threading.Event]:
    run_id = uuid.uuid4().hex
    event = threading.Event()
    _events[run_id] = event
    return run_id, event


def request_cancel(run_id: str) -> bool:
    """Returns True if a run with this id was actually found and signalled
    (False for an id that's unknown, or whose run already finished)."""
    event = _events.get(run_id)
    if event is None:
        return False
    event.set()
    return True


def finish_run(run_id: str) -> None:
    """Drop the run's entry once it's done, cancelled or not -- otherwise
    this dict grows forever across a long session."""
    _events.pop(run_id, None)
