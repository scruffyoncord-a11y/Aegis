"""The Tool interface for Aegis's probe agent.

A Tool is one self-contained, safe, non-destructive check the agent can run
against the sandboxed target. This is deliberately NOT an open-ended
"run any command" interface (the way AIDA's real tool-calling works against
nmap/sqlmap/ffuf/etc.) -- Aegis ships a small, fixed set of Tool instances,
and there is no path for the LLM to invent, request, or execute anything
outside that set. Every Tool's probe() is still a single, read-only,
no-credential HTTP request.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

# hypothesize(routes, framework) -> candidate dicts (must carry enough info
# for this Tool's own probe() to act on -- typically at least method/path).
Hypothesize = Callable[[list[dict[str, Any]], str], list[dict[str, Any]]]

# probe(base_url, candidate, entry_file, framework) -> a confirmed finding
# dict, or None if the candidate could not be confirmed (e.g. it turned out
# to actually be protected).
Probe = Callable[[str, dict[str, Any], str, str], "dict[str, Any] | None"]


@dataclass
class Tool:
    name: str  # e.g. "missing-auth" -- also used as the finding "type"
    description: str  # human-readable, for logs/pitch material
    hypothesize: Hypothesize
    probe: Probe
