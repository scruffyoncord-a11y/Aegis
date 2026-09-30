""""Test a Hunch": evaluates a user-supplied lead ("I think X might be
broken") against a run's actual, already-confirmed findings -- and says
outright when the hunch isn't something Aegis's checks can test at all,
rather than forcing a match to something that was never actually verified.

This is a judgment/explanation task over facts that are already decided
(same discipline as app/risk.py and llm.py::explain_finding) -- it can
never invent a finding or change what was actually confirmed; it only
describes, in plain language, whether the confirmed findings support the
user's hunch.
"""

from __future__ import annotations

from typing import Any

from app.llm import EXPLAIN_MODEL, ask_json

# What Aegis can actually verify -- kept in sync with the real detectors/
# tools (app/detectors/*.py, app/probes/*.py). Told to the model explicitly
# so it can say "not testable here" instead of guessing at a match.
_TESTABLE = (
    "leaked secrets, vulnerable or hallucinated/non-existent dependencies, "
    "misconfigured cloud rules (Firebase rules or Supabase Row-Level "
    "Security), missing authentication on a route, and IDOR (one logged-in "
    "user reading another user's data by changing an id in the URL)"
)

# Two separate, single-fact questions -- NOT one compound "classify AND
# compare" prompt (same discipline as detectors/routes.py's hypothesis
# prompts). Even split out, a live test caught BOTH models answering
# testable=true for a SQL-injection hunch while their own stated reason
# said it was out of scope -- a plain instruction/exclusion-list wasn't
# enough. Fixed by adding worked examples covering exactly that failure
# case: this model follows a concrete example far more reliably than an
# abstract "these five things are out of scope" instruction.
_TESTABLE_PROMPT = """Aegis's automated checks can ONLY test for: {testable}.

Examples of judging a developer's hunch against that list:
Hunch: "I think the admin panel might not require login" -> {{"testable": true, "reason": "This is about missing authentication, which is on the list."}}
Hunch: "I think one user could see another user's order by changing the id" -> {{"testable": true, "reason": "This is IDOR, which is on the list."}}
Hunch: "I think there might be a SQL injection in the search box" -> {{"testable": false, "reason": "SQL injection is not on the list of things Aegis's checks cover."}}
Hunch: "I think the discount calculation has a logic bug" -> {{"testable": false, "reason": "Business logic bugs are not on the list."}}

Now judge this hunch the same way, checking it against the list above -- \
not against how serious or plausible it sounds:

"{hint}"

Respond with ONLY a JSON object, no prose:
{{"testable": true or false, "reason": "one short sentence"}}
"""

_CONFIRM_PROMPT = """A developer suspected: "{hint}"

Here is what this run actually confirmed (each one is real and already \
verified, not a guess):
{findings}

Does anything in the confirmed findings above match or directly relate to \
the hunch?

Respond with ONLY a JSON object, no prose:
{{"confirmed": true or false, "explanation": "two or three plain, direct sentences -- name the specific finding if one applies"}}
"""


def _format_findings(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "(nothing -- every check that ran came back clean)"
    lines = []
    for f in findings:
        match = f.get("match") or f.get("rule") or ""
        lines.append(f"- {f.get('type')}: {match} ({f.get('file') or 'no specific file'})")
    return "\n".join(lines)


def evaluate_hunch(hint: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Returns {testable, confirmed, explanation}. `testable`/`confirmed`
    are None (not True/False) only if the model couldn't be reached at
    all -- the caller should show that as "couldn't evaluate", never as a
    silent "not confirmed".
    """
    try:
        testable_result = ask_json(
            _TESTABLE_PROMPT.format(hint=hint, testable=_TESTABLE), model=EXPLAIN_MODEL
        )
    except Exception as e:
        return {"testable": None, "confirmed": None, "explanation": f"Could not evaluate this hunch right now: {e}"}

    if not isinstance(testable_result, dict):
        return {"testable": None, "confirmed": None, "explanation": "Could not evaluate this hunch right now."}

    if not testable_result.get("testable"):
        reason = testable_result.get("reason", "")
        explanation = (
            f"Not something Aegis's current checks can test. {reason}".strip()
            if reason
            else "Not something Aegis's current checks can test."
        )
        return {"testable": False, "confirmed": None, "explanation": explanation}

    try:
        confirm_result = ask_json(
            _CONFIRM_PROMPT.format(hint=hint, findings=_format_findings(findings)), model=EXPLAIN_MODEL
        )
    except Exception as e:
        return {"testable": True, "confirmed": None, "explanation": f"Could not evaluate this hunch right now: {e}"}

    if not isinstance(confirm_result, dict):
        return {"testable": True, "confirmed": None, "explanation": "Could not evaluate this hunch right now."}

    return {
        "testable": True,
        "confirmed": confirm_result.get("confirmed"),
        "explanation": confirm_result.get("explanation", ""),
    }
