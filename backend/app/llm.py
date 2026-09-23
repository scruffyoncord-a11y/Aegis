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

import os
import sys
from pathlib import Path

_PENTESTGPT_PATH = Path(__file__).resolve().parents[2] / "PentestGPT"
if str(_PENTESTGPT_PATH) not in sys.path:
    sys.path.insert(0, str(_PENTESTGPT_PATH))

from pentestgpt_legacy.llm.factory import get_client  # noqa: E402

DEFAULT_MODEL = os.environ.get("AEGIS_LLM_MODEL", "ollama:qwen2.5-coder:7b")


def explain_finding(finding: dict) -> str:
    """Ask the local model to explain a single finding in plain language."""
    client = get_client(DEFAULT_MODEL)

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
