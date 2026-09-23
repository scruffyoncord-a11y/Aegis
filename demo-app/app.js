/**
 * Aegis demo target — DELIBERATELY VULNERABLE.
 *
 * This is a tiny Express app used only to test and demo Aegis's own
 * detection pipeline. It is never deployed and never used for anything
 * other than Aegis scanning its own known, planted flaws.
 *
 * Flaw #1 (for Phase 1): a hardcoded secret committed directly in code.
 */

const express = require("express");
const app = express();

// --- PLANTED FLAW: leaked secret, for Gitleaks to catch ---
// (fake AWS access key ID, matches gitleaks' built-in aws-access-token rule)
const AWS_ACCESS_KEY_ID = "AKIAQGXHZ3AB6PMKLNOP";

app.get("/", (req, res) => {
  res.send("Aegis demo target is running.");
});

app.listen(3001, () => {
  console.log("Demo target running on http://localhost:3001");
});

module.exports = app;
