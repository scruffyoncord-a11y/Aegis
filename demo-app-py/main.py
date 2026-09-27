"""Aegis FastAPI demo target -- DELIBERATELY VULNERABLE.

Used only to test/demo Aegis's own active probe against a Python app, inside
the disposable Docker sandbox Aegis controls. Never deployed.

Flaws:
  - /api/admin/users has no auth dependency, while /api/profile correctly
    requires one -- so the reasoning step has to actually discriminate.
  - /api/orders/{id} (IDOR) requires auth but never checks that the order
    actually belongs to the caller.
"""

from fastapi import Depends, FastAPI, Header, HTTPException

app = FastAPI()

# Fake "database" -- sensitive-looking data to make the flaw's impact real.
USERS = [
    {"id": 1, "name": "Alice", "email": "alice@example.com", "ssn": "123-45-6789"},
    {"id": 2, "name": "Bob", "email": "bob@example.com", "ssn": "987-65-4321"},
]

# The fixed test identity ("demo-valid-token") represents user id 1, so it
# should only ever be able to read order 1, never order 2. (Small sequential
# ids on purpose: Aegis's IDOR probe tries ids 1 and 2 as a general
# heuristic against any repo.)
ORDERS = [
    {"id": 1, "owner_id": 1, "item": "Widget A", "total": 42.5},
    {"id": 2, "owner_id": 2, "item": "Widget B", "total": 17.0},
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


# --- PLANTED FLAW (IDOR): requires auth, but never checks that the order
# actually belongs to the caller -- any logged-in user can read anyone's
# order just by changing the id in the URL.
@app.get("/api/orders/{order_id}")
def get_order(order_id: int, user=Depends(get_current_user)):
    order = next((o for o in ORDERS if o["id"] == order_id), None)
    if order is None:
        raise HTTPException(status_code=404, detail="Not found")
    return {"order": order}


# Correctly protected contrast -- checks the order's owner_id against the
# caller before returning it, so the reasoning step has to discriminate.
@app.get("/api/my-order/{order_id}")
def get_my_order(order_id: int, user=Depends(get_current_user)):
    order = next((o for o in ORDERS if o["id"] == order_id), None)
    if order is None:
        raise HTTPException(status_code=404, detail="Not found")
    if order["owner_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    return {"order": order}
