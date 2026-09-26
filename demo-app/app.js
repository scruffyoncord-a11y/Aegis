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

app.listen(3001, () => {
  console.log("Demo target running on http://localhost:3001");
});

module.exports = app;
