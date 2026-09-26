"""Local LLM connector for Aegis.

Reuses PentestGPT-legacy's multi-provider LLM client (USENIX Security 2024)
purely as a connector library -- we import its `get_client` factory directly
and call it, we do NOT drive its interactive CLI/REPL. See
../../PentestGPT/pentestgpt_legacy/llm/ for the source.

PentestGPT is cloned as a sibling folder (../PentestGPT) and is NOT part of
this repo's own git history (see .gitignore) -- it's an external reference
dependency, MIT licensed.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

_PENTESTGPT_PATH = Path(__file__).resolve().parents[2] / "PentestGPT"
if str(_PENTESTGPT_PATH) not in sys.path:
    sys.path.insert(0, str(_PENTESTGPT_PATH))

from pentestgpt_legacy.llm.factory import get_client  # noqa: E402

# Two models, two different jobs -- same split Epiderm uses (a code/reasoning
# model vs. a lighter content-reading model), and the same discipline: the
# LLM never decides severity, likelihood, or the score. That's rule-based
# only (see app/risk.py). The LLM's job is strictly framing/explanation.
#
# Qwen2.5-Coder: code-tuned, used for anything that reasons about source
# (route tracing, vulnerability hypothesis -- Phase 4-5).
REASONING_MODEL = os.environ.get("AEGIS_REASONING_MODEL", "ollama:qwen2.5-coder:7b")
# Gemma 3 4B: smaller and faster, used only to turn an already-decided
# finding into a plain-language explanation. It cannot change what was
# found or how severe it is -- those are already fixed before this is called.
EXPLAIN_MODEL = os.environ.get("AEGIS_EXPLAIN_MODEL", "ollama:gemma3:4b")

# Kept for any old call sites; new code should use REASONING_MODEL/EXPLAIN_MODEL.
DEFAULT_MODEL = REASONING_MODEL


def explain_finding(finding: dict) -> str:
    """Ask the local model to explain a single finding in plain language.

    Uses the lighter EXPLAIN_MODEL (Gemma) -- explanation is a framing task,
    not a code-reasoning one, and Gemma is faster, which matters since /scan
    calls this once per finding.
    """
    client = get_client(EXPLAIN_MODEL)

    prompt = (
        "You are explaining a security finding to a beginner developer, in "
        "plain language, 2-3 sentences. Be concrete about the real-world risk. "
        "Do not include any exploit code or working payloads -- explanation only.\n\n"
        f"Finding type: {finding.get('type')}\n"
        f"File: {finding.get('file')}\n"
        f"Rule: {finding.get('rule')}\n"
        f"Matched text (redact if sensitive): {finding.get('match')}\n"
        f"Details: {finding.get('detail', '')}\n"
    )

    response, _conversation_id = client.send_new_message(prompt)
    return response


_JSON_BLOCK_RE = re.compile(r"\[.*\]|\{.*\}", re.DOTALL)


def ask_json(prompt: str, model: str = REASONING_MODEL) -> Any:
    """Send a prompt expecting a JSON response, and parse it robustly.

    Local models often wrap JSON in markdown fences or add a sentence before
    or after it -- we pull out the first bracket-balanced-looking block
    rather than requiring a perfectly clean response.
    """
    client = get_client(model)
    response, _conversation_id = client.send_new_message(prompt)

    text = response.strip()
    # Strip a ```json ... ``` or ``` ... ``` fence if present.
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text)

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    match = _JSON_BLOCK_RE.search(text)
    if match:
        return json.loads(match.group(0))

    raise ValueError(f"Could not parse JSON from model response: {text[:200]!r}")
