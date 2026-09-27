"""GitHub OAuth (Authorization Code flow) -- real "Connect with GitHub".

The user authenticates on GitHub's own login/consent page, never types a
token into Aegis's UI. The resulting access token lives ONLY server-side,
in an in-memory session keyed by a random, httpOnly session cookie -- it is
never sent to the frontend, never logged, and never written to disk.

Sessions are process-memory only (a plain dict). That's the right tradeoff
for a local, single-user hackathon tool: restarting the backend simply logs
everyone out, and there is no token-bearing file left behind anywhere.
"""

from __future__ import annotations

import os
import secrets
import shutil
import time
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv

load_dotenv()

GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", "")
OAUTH_REDIRECT_URI = os.environ.get(
    "GITHUB_OAUTH_REDIRECT_URI", "http://localhost:8000/github/oauth/callback"
)
FRONTEND_URL = os.environ.get("AEGIS_FRONTEND_URL", "http://localhost:3000")

AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
TOKEN_URL = "https://github.com/login/oauth/access_token"
_SCOPE = "repo"  # needed to check push/admin permission and clone private repos
_SESSION_TTL_SECONDS = 60 * 60  # 1 hour

# session_id -> {access_token, github_login, created_at}
_sessions: dict[str, dict[str, Any]] = {}
# oauth "state" -> created_at, for CSRF protection during the redirect round-trip
_pending_states: dict[str, float] = {}


class OAuthNotConfigured(RuntimeError):
    pass


class OAuthError(RuntimeError):
    pass


def _require_configured() -> None:
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        raise OAuthNotConfigured(
            "GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET are not set. Create a "
            "GitHub OAuth App and put the values in backend/.env (see README)."
        )


def build_authorize_url() -> str:
    _require_configured()
    state = secrets.token_urlsafe(24)
    _pending_states[state] = time.time()
    params = (
        f"client_id={GITHUB_CLIENT_ID}"
        f"&redirect_uri={OAUTH_REDIRECT_URI}"
        f"&scope={_SCOPE}"
        f"&state={state}"
        f"&allow_signup=false"
    )
    return f"{AUTHORIZE_URL}?{params}"


def handle_callback(code: str, state: str) -> str:
    """Exchange the code for a token, create a session, return the session id."""
    _require_configured()

    if state not in _pending_states:
        raise OAuthError("Invalid or expired OAuth state (possible CSRF, or a stale link).")
    del _pending_states[state]

    resp = httpx.post(
        TOKEN_URL,
        headers={"Accept": "application/json"},
        data={
            "client_id": GITHUB_CLIENT_ID,
            "client_secret": GITHUB_CLIENT_SECRET,
            "code": code,
            "redirect_uri": OAUTH_REDIRECT_URI,
        },
        timeout=15.0,
    )
    resp.raise_for_status()
    payload = resp.json()

    access_token = payload.get("access_token")
    if not access_token:
        raise OAuthError(payload.get("error_description") or "No access token returned.")

    # Look up who we're now acting as, for display only -- never the token itself.
    who = httpx.get(
        "https://api.github.com/user",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=15.0,
    )
    login = who.json().get("login") if who.status_code == 200 else None

    session_id = secrets.token_urlsafe(32)
    _sessions[session_id] = {
        "access_token": access_token,
        "github_login": login,
        "created_at": time.time(),
    }
    return session_id


def get_session(session_id: str | None) -> dict[str, Any] | None:
    if not session_id:
        return None
    session = _sessions.get(session_id)
    if session is None:
        return None
    if time.time() - session["created_at"] > _SESSION_TTL_SECONDS:
        _sessions.pop(session_id, None)
        return None
    return session


def get_token(session_id: str | None) -> str | None:
    session = get_session(session_id)
    return session["access_token"] if session else None


def set_cloned_repo(session_id: str, path: str) -> None:
    """Remember which local clone belongs to this session, and delete the
    PREVIOUS one first if the user connects a different repo -- otherwise
    every "Verify & Clone" leaves a permanent leftover directory in Temp,
    since nothing else ever cleaned these up."""
    session = _sessions.get(session_id)
    if session is None:
        return
    _delete_cloned_repo(session)
    session["cloned_repo_path"] = path


def _delete_cloned_repo(session: dict[str, Any]) -> None:
    old_path = session.get("cloned_repo_path")
    if not old_path:
        return
    # The clone lives at <tmp>/<repo-name>; remove the whole parent temp dir
    # (created by tempfile.mkdtemp in github_auth.clone_repo), not just the
    # inner folder.
    shutil.rmtree(Path(old_path).parent, ignore_errors=True)
    session["cloned_repo_path"] = None


def clear_session(session_id: str | None) -> None:
    if not session_id:
        return
    session = _sessions.get(session_id)
    if session is not None:
        _delete_cloned_repo(session)
    _sessions.pop(session_id, None)
