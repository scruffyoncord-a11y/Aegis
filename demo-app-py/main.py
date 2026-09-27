"""Aegis FastAPI demo target -- DELIBERATELY VULNERABLE.

Used only to test/demo Aegis's own active probe against a Python app, inside
the disposable Docker sandbox Aegis controls. Never deployed.

Flaw: /api/admin/users has no auth dependency, while /api/profile correctly
requires one -- so the reasoning step has to actually discriminate, not just
flag every route.
"""

from fastapi import Depends, FastAPI, Header, HTTPException

app = FastAPI()

# Fake "database" -- sensitive-looking data to make the flaw's impact real.
USERS = [
    {"id": 1, "name": "Alice", "email": "alice@example.com", "ssn": "123-45-6789"},
    {"id": 2, "name": "Bob", "email": "bob@example.com", "ssn": "987-65-4321"},
]


def get_current_user(authorization: str = Header(default="")):
    """Auth dependency, used correctly on /api/profile below."""
    if authorization == "Bearer demo-valid-token":
        return USERS[0]
    raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/")
def root():
    return {"message": "Aegis FastAPI demo target is running."}


# Correctly protected -- the reasoning step must NOT flag this one.
@app.get("/api/profile")
def profile(user=Depends(get_current_user)):
    return {"message": "Your profile", "user": user}


# --- PLANTED FLAW: no auth dependency on a sensitive admin route ---
@app.get("/api/admin/users")
def admin_users():
    return {"users": USERS}
