"""Phase 6: the safe active probe for IDOR (Insecure Direct Object Reference).

Confirms a hypothesis the same way missing-auth does -- one real, read-only
request against the sandbox, not a guess. The check: authenticate as ONE
fixed test identity, then request the SAME id-scoped route with two
different small integer ids. If both come back successful with genuinely
different bodies, that one identity could read at least two different
records through an id-scoped route -- exactly what a properly scoped
endpoint (which only returns the caller's OWN record) would never allow.

The one fixed test identity is now configurable (build_idor_tool's
`auth_header_value`) instead of hardcoded, closing a real limitation: a
repo whose auth doesn't accept `Authorization: Bearer demo-valid-token`
(essentially every real-world repo -- that string only means something to
Aegis's own demo fixtures) could never actually be probed for IDOR before.
If the caller supplies a real token/cookie of their own -- from an actual
test account on THEIR OWN app, the same convention as the rest of this
project's "test your own stuff" boundary -- this checks their app for
real; supplying nothing at all still exercises the demo convention, so
existing fixtures and tests keep working unchanged.
"""

from __future__ import annotations

from typing import Any

import httpx

from app.detectors.routes import ID_PARAM_RE, hypothesize_idor
from app.probes.agent import run_active_probes
from app.probes.tool import Tool

_SUCCESS_STATUS = range(200, 300)
_DEFAULT_TEST_AUTH = "Bearer demo-valid-token"
_TEST_IDS = (1, 2)  # two different small integers -- one identity should own at most one of these


def _substitute_id(path_template: str, value: int) -> str:
    """Replace the first id-like path parameter (:id, {id}, {order_id},
    <id>, <int:id>, ...) with a concrete integer."""
    return ID_PARAM_RE.sub(str(value), path_template, count=1)


def build_idor_tool(auth_header_value: str | None = None) -> Tool:
    """Builds an IDOR Tool that authenticates its two test requests with
    `auth_header_value` as the Authorization header -- e.g. `"Bearer
    eyJhbGci..."` from a real test account on the target app, or a session
    cookie string if the caller passes `"Cookie: session=..."` verbatim
    (anything containing a colon is sent as a raw header line instead of
    wrapped as Authorization). Falls back to the demo convention
    (`Bearer demo-valid-token`) when None, so existing fixtures/tests that
    rely on IDOR_TOOL below keep working exactly as before.
    """
    if auth_header_value and ":" in auth_header_value:
        name, _, value = auth_header_value.partition(":")
        headers = {name.strip(): value.strip()}
    else:
        headers = {"Authorization": auth_header_value or _DEFAULT_TEST_AUTH}

    def _probe_one(
        base_url: str, candidate: dict[str, Any], entry_file: str, framework: str
    ) -> dict[str, Any] | None:
        method, path_template = candidate["method"], candidate["path"]

        responses: dict[int, httpx.Response] = {}
        for test_id in _TEST_IDS:
            concrete_path = _substitute_id(path_template, test_id)
            try:
                resp = httpx.request(
                    method, f"{base_url}{concrete_path}", headers=headers, timeout=5.0
                )
            except Exception:
                return None  # couldn't reach it -- not a confirmed finding
            if resp.status_code in _SUCCESS_STATUS:
                responses[test_id] = resp

        if len(responses) < 2:
            return None  # only got through on one id (or neither) -- looks scoped, or just not found

        body_a, body_b = responses[_TEST_IDS[0]].text.strip(), responses[_TEST_IDS[1]].text.strip()
        if body_a == body_b:
            return None  # identical response for two different ids -- not proof of anything

        return {
            "type": "idor",
            "file": entry_file,
            "entry_file": entry_file,
            "framework": framework,
            "line": None,
            "rule": "insecure-direct-object-reference",
            "match": f"{method} {path_template}",
            "severity": "critical",
            "detail": candidate.get("reason", ""),
            "evidence": {
                "request": (
                    f"{method} {_substitute_id(path_template, _TEST_IDS[0])} and "
                    f"{_substitute_id(path_template, _TEST_IDS[1])}, same identity, both requests"
                ),
                "response_status": responses[_TEST_IDS[0]].status_code,
                "response_body": f"id={_TEST_IDS[0]}: {body_a[:150]}\nid={_TEST_IDS[1]}: {body_b[:150]}",
            },
        }

    return Tool(
        name="idor",
        description=(
            "Traces id-scoped routes for a missing ownership check in the "
            "handler code, then confirms by requesting two different ids with "
            "one fixed test identity."
        ),
        hypothesize=hypothesize_idor,
        probe=_probe_one,
    )


# The demo-convention instance -- kept as a stable, importable default for
# anything that doesn't have (or need) a real user-supplied credential.
IDOR_TOOL = build_idor_tool()


def run_idor_probe(repo_path: str, auth_header_value: str | None = None, **kwargs) -> list[dict[str, Any]]:
    """Backward-compatible entry point (matches run_missing_auth_probe's
    shape): runs the agent with only the IDOR tool registered. Used by
    fixers.py to re-verify a fix by re-probing a fresh sandbox.
    """
    return run_active_probes(repo_path, [build_idor_tool(auth_header_value)], **kwargs)
