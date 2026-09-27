/**
 * Aegis demo target — DELIBERATELY VULNERABLE.
 *
 * This is a tiny Express app used only to test and demo Aegis's own
 * detection pipeline. It is never deployed and never used for anything
 * other than Aegis scanning/probing its own known, planted flaws inside
 * a disposable Docker sandbox that Aegis itself controls.
 *
 * Flaw #1 (Phase 1): a hardcoded secret committed directly in code.
 * Flaw #2 (Phase 4-5): an admin route with no auth check at all.
 * Flaw #3 (Phase 6, IDOR): an order route that checks auth but not ownership.
 */

const express = require("express");
const app = express();
app.use(express.json());

// --- PLANTED FLAW: leaked secret, for Gitleaks to catch ---
// (fake AWS access key ID, matches gitleaks' built-in aws-access-token rule)
const AWS_ACCESS_KEY_ID = "AKIAQGXHZ3AB6PMKLNOP";

// --- Auth middleware, used correctly on /api/profile below ---
function requireAuth(req, res, next) {
  const token = req.headers.authorization;
  if (token === "Bearer demo-valid-token") return next();
  return res.status(401).json({ error: "Unauthorized" });
}

// Fake "database" -- sensitive-looking data to make the flaw's impact real.
const users = [
  { id: 1, name: "Alice", email: "alice@example.com", ssn: "123-45-6789" },
  { id: 2, name: "Bob", email: "bob@example.com", ssn: "987-65-4321" },
];

// Orders belonging to different users -- the fixed test identity below
// ("demo-valid-token") represents user id 1, so it should only ever be able
// to read order 1, never order 2. (Small sequential ids on purpose: Aegis's
// IDOR probe tries ids 1 and 2 as a general heuristic against any repo.)
const orders = [
  { id: 1, ownerId: 1, item: "Widget A", total: 42.5 },
  { id: 2, ownerId: 2, item: "Widget B", total: 17.0 },
];

app.get("/", (req, res) => {
  res.send("Aegis demo target is running.");
});

// Correctly protected -- gives the reasoning agent something to NOT flag,
// so it has to actually discriminate rather than flag every route.
app.get("/api/profile", requireAuth, (req, res) => {
  res.json({ message: "Your profile", user: users[0] });
});

// --- PLANTED FLAW: no auth middleware at all on a sensitive admin route ---
app.get("/api/admin/users", (req, res) => {
  res.json({ users });
});

// --- PLANTED FLAW (IDOR): requires auth, but never checks that the order
// actually belongs to the caller -- any logged-in user can read anyone's
// order just by changing the id in the URL.
app.get("/api/orders/:id", requireAuth, (req, res) => {
  const order = orders.find((o) => o.id === Number(req.params.id));
  if (!order) return res.status(404).json({ error: "Not found" });
  res.json({ order });
});

// Correctly protected contrast -- checks the order's ownerId against the
// caller before returning it, so the reasoning step has to discriminate.
app.get("/api/my-order/:id", requireAuth, (req, res) => {
  const CALLER_USER_ID = 1; // the fixed test identity "demo-valid-token" represents user 1
  const order = orders.find((o) => o.id === Number(req.params.id));
  if (!order) return res.status(404).json({ error: "Not found" });
  if (order.ownerId !== CALLER_USER_ID) {
    return res.status(403).json({ error: "Forbidden" });
  }
  res.json({ order });
});

app.listen(3001, () => {
  console.log("Demo target running on http://localhost:3001");
});

module.exports = app;
