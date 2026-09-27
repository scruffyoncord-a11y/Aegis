"""Fix generation and re-verification for Phase 1-3 findings.

For each finding Aegis can propose a patch. The patch is generated and
verified against a *temporary copy* of the repo -- the original working tree
is never touched until the user explicitly applies it. Verification means:
apply the patch to the copy, re-run the same detector, and confirm the finding
is gone. A fix is only reported "verified" when the re-scan comes back clean.
"""

from __future__ import annotations

import difflib
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Callable

from app.detectors.cloud_config import scan_cloud_config
from app.detectors.dependencies import scan_dependencies
from app.detectors.routes import extract_routes
from app.detectors.secrets import scan_secrets
from app.detectors.supabase import scan_supabase
from app.probes.idor import run_idor_probe
from app.probes.missing_auth import run_missing_auth_probe
from app.sandbox import SandboxBuildError, SandboxUnavailable


def _scan_cloud_all(repo_path: str) -> list[dict[str, Any]]:
    """cloud-misconfig findings can come from either Firebase or Supabase --
    re-verification has to check both, since a single finding type spans
    two independent detectors."""
    return scan_cloud_config(repo_path) + scan_supabase(repo_path)


# Which detector re-checks each finding type.
_DETECTOR_FOR_TYPE: dict[str, Callable[[str], list[dict[str, Any]]]] = {
    "secret": scan_secrets,
    "dependency-vuln": scan_dependencies,
    "dependency-missing": scan_dependencies,
    "cloud-misconfig": _scan_cloud_all,
    "missing-auth": run_missing_auth_probe,
    "idor": run_idor_probe,
}


class FixResult:
    def __init__(
        self,
        finding: dict[str, Any],
        diffs: dict[str, str],
        note: str,
        verified: bool,
    ):
        self.finding = finding
        self.diffs = diffs  # {relative_path: unified_diff}
        self.note = note
        self.verified = verified

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_match": self.finding.get("match"),
            "finding_type": self.finding.get("type"),
            "diffs": self.diffs,
            "note": self.note,
            "verified": self.verified,
        }


def _unified(rel_path: str, before: str, after: str) -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{rel_path}",
            tofile=f"b/{rel_path}",
        )
    )


# --------------------------------------------------------------------------- #
# Per-type patch builders: each edits files under `work` (a repo copy) and
# returns (diffs, note). They do NOT verify -- fix_and_verify does that.
# --------------------------------------------------------------------------- #

def _fix_secret(finding: dict, work: Path, original: Path) -> tuple[dict[str, str], str]:
    rel = finding["file"]
    target = _resolve_in(work, rel, original)
    if target is None:
        return {}, "Could not locate the file to patch."

    # "match" is gitleaks' whole matched LINE (e.g. `TOKEN = "abc"`), not the
    # secret value alone -- searching for that wrapped in quotes can never
    # match anything real in the source. "secret_value" (added alongside
    # "match" in detectors/secrets.py) is the actual value to replace; fall
    # back to "match" only for a finding built by something else that never
    # set it, rather than failing outright.
    secret = finding.get("secret_value") or finding["match"]
    before = target.read_text(encoding="utf-8")
    is_python = target.suffix == ".py"

    # Derive an env var name from `const NAME = "secret"` (JS/TS) or a bare
    # `NAME = "secret"` (Python has no declaration keyword) if present.
    var_match = re.search(
        r"(?:(?:const|let|var)\s+)?([A-Z][A-Z0-9_]*)\s*=\s*[\"']" + re.escape(secret),
        before,
    )
    env_name = var_match.group(1) if var_match else "SECRET_VALUE"

    # The replacement has to be valid in whatever language `target` actually
    # is -- `process.env.NAME` is JS/TS syntax, and writing that into a .py
    # file would produce a fix that "verifies" (the literal secret is gone)
    # but doesn't run.
    replacement = f'os.environ["{env_name}"]' if is_python else f"process.env.{env_name}"
    after = before.replace(f'"{secret}"', replacement)
    after = after.replace(f"'{secret}'", replacement)
    if is_python and replacement in after and "import os" not in after:
        after = "import os\n" + after
    target.write_text(after, encoding="utf-8")

    diffs = {str(target.relative_to(work)): _unified(rel, before, after)}

    # .env (real value, git-ignored)
    env_file = work / ".env"
    env_before = env_file.read_text(encoding="utf-8") if env_file.exists() else ""
    env_after = env_before + f"{env_name}={secret}\n"
    env_file.write_text(env_after, encoding="utf-8")
    diffs[".env"] = _unified(".env", env_before, env_after)

    # .env.example (placeholder, safe to commit)
    ex_file = work / ".env.example"
    ex_before = ex_file.read_text(encoding="utf-8") if ex_file.exists() else ""
    ex_after = ex_before + f"{env_name}=your-value-here\n"
    ex_file.write_text(ex_after, encoding="utf-8")
    diffs[".env.example"] = _unified(".env.example", ex_before, ex_after)

    # .gitignore
    gi_file = work / ".gitignore"
    gi_before = gi_file.read_text(encoding="utf-8") if gi_file.exists() else ""
    if ".env" not in gi_before.split():
        gi_after = gi_before + ("\n" if gi_before and not gi_before.endswith("\n") else "") + ".env\n"
        gi_file.write_text(gi_after, encoding="utf-8")
        diffs[".gitignore"] = _unified(".gitignore", gi_before, gi_after)

    note = (
        f"Moved the secret out of code into an environment variable "
        f"({env_name}), stored the real value in .env (now git-ignored), and "
        f"added a .env.example placeholder. IMPORTANT: this key was already "
        f"exposed -- rotate/revoke it as well; code changes can't undo that."
    )
    return diffs, note


def _fix_dependency_vuln(finding: dict, work: Path, original: Path) -> tuple[dict[str, str], str]:
    manifest = _resolve_in(work, finding["file"], original)
    if manifest is None:
        return {}, "Could not locate the manifest to patch."
    before = manifest.read_text(encoding="utf-8")
    name, _, cur = finding["match"].partition("@")
    fixed = finding.get("fixed_version")
    if not fixed:
        return {}, f"No known fixed version for {name}; upgrade manually."
    after = re.sub(
        rf'("{re.escape(name)}"\s*:\s*")[^"]+(")',
        rf"\g<1>{fixed}\g<2>",
        before,
    )
    manifest.write_text(after, encoding="utf-8")
    return (
        {finding["file"]: _unified(finding["file"], before, after)},
        f"Bumped {name} from {cur} to {fixed} (first version without this "
        f"vulnerability). Run `npm install` to apply.",
    )


def _fix_dependency_missing(finding: dict, work: Path, original: Path) -> tuple[dict[str, str], str]:
    manifest = _resolve_in(work, finding["file"], original)
    if manifest is None:
        return {}, "Could not locate the manifest to patch."
    before = manifest.read_text(encoding="utf-8")
    name, _, _ = finding["match"].partition("@")
    # Remove the non-existent dependency line.
    after = re.sub(
        rf'^\s*"{re.escape(name)}"\s*:\s*"[^"]+",?\n',
        "",
        before,
        flags=re.MULTILINE,
    )
    # Clean a possible trailing comma left on the previous line.
    after = re.sub(r",(\s*})", r"\g<1>", after)
    manifest.write_text(after, encoding="utf-8")
    return (
        {finding["file"]: _unified(finding["file"], before, after)},
        f"Removed '{name}' -- it does not exist on npm. Replace it with the "
        f"real package you actually intended to use.",
    )


def _fix_firebase_misconfig(finding: dict, work: Path, original: Path) -> tuple[dict[str, str], str]:
    target = _resolve_in(work, finding["file"], original)
    if target is None:
        return {}, "Could not locate the rules file to patch."
    before = target.read_text(encoding="utf-8")
    # Replace trivially-true conditions with an auth requirement, skipping
    # comment lines so only real rules are patched.
    pattern = re.compile(
        r"(allow\s+[a-z,\s]+?\s*:\s*if\s+)(true|1\s*==\s*1|true\s*==\s*true)\b",
        re.IGNORECASE,
    )
    out_lines = []
    for line in before.splitlines(keepends=True):
        stripped = line.lstrip()
        if stripped.startswith(("//", "*", "/*")):
            out_lines.append(line)
        else:
            out_lines.append(pattern.sub(r"\g<1>request.auth != null", line))
    after = "".join(out_lines)
    target.write_text(after, encoding="utf-8")
    return (
        {str(target.relative_to(work)): _unified(finding["file"], before, after)},
        "Replaced the world-open condition with `if request.auth != null` "
        "(authenticated users only). For real security, scope this further to "
        "the owning user, e.g. `request.auth.uid == resource.data.ownerId`.",
    )


def _fix_supabase_misconfig(finding: dict, work: Path, original: Path) -> tuple[dict[str, str], str]:
    target = _resolve_in(work, finding["file"], original)
    if target is None:
        return {}, "Could not locate the migration file to patch."
    before = target.read_text(encoding="utf-8")
    rule = finding.get("rule", "")

    if rule == "supabase-rls-disabled":
        after = re.sub(
            r"(ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?[\"']?\w+[\"']?\s+)DISABLE(\s+ROW\s+LEVEL\s+SECURITY)",
            r"\g<1>ENABLE\g<2>",
            before,
            count=1,
            flags=re.IGNORECASE,
        )
        note = "Flipped DISABLE back to ENABLE ROW LEVEL SECURITY -- someone had explicitly turned it off."

    elif rule == "supabase-open-policy":
        # No inline "--" comment here: this sits before the statement's own
        # trailing ";" on the same line, and a "--" comment runs to end of
        # line -- it would swallow that ";" and leave invalid SQL. The TODO
        # goes in the returned note instead.
        after = re.sub(
            r"(USING|WITH\s+CHECK)\s*\(\s*true\s*\)",
            r"\g<1> (auth.uid() = user_id)",
            before,
            count=1,
            flags=re.IGNORECASE,
        )
        note = (
            "Replaced the open policy with a per-user ownership check template: "
            "`auth.uid() = user_id`. This is a placeholder -- replace `user_id` "
            "with the column that actually identifies the row's owner in this table."
        )

    elif rule == "supabase-rls-never-enabled":
        table_match = re.search(r"CREATE TABLE (\w+)", finding["match"], re.IGNORECASE)
        table = table_match.group(1) if table_match else None
        if not table:
            return {}, "Could not determine the table name to enable RLS on."
        after = before.rstrip() + f"\n\nALTER TABLE {table} ENABLE ROW LEVEL SECURITY;\n"
        note = (
            f"Added `ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;`. A table "
            f"with RLS enabled and no policies denies all access by default, "
            f"so add a policy scoped to the right owner before using this table."
        )

    else:
        return {}, f"No fixer for Supabase rule '{rule}'."

    target.write_text(after, encoding="utf-8")
    return {str(target.relative_to(work)): _unified(finding["file"], before, after)}, note


def _fix_cloud_misconfig(finding: dict, work: Path, original: Path) -> tuple[dict[str, str], str]:
    """Dispatches to the Firebase or Supabase fixer based on which detector
    produced this finding -- both share the `cloud-misconfig` type."""
    if str(finding.get("rule", "")).startswith("supabase-"):
        return _fix_supabase_misconfig(finding, work, original)
    return _fix_firebase_misconfig(finding, work, original)


def _fix_missing_auth(finding: dict, work: Path, original: Path) -> tuple[dict[str, str], str]:
    """Dispatches by the target app's framework -- the fix shape differs per
    framework (Express middleware arg, FastAPI Depends dependency, Flask
    decorator), but all reuse the app's OWN existing auth rather than
    inventing a function that doesn't exist."""
    framework = finding.get("framework", "express")
    entry_file = finding.get("entry_file", "app.js")
    target = work / entry_file
    if not target.exists():
        return {}, "Could not locate the app's entry file to patch."

    routes = extract_routes(str(work), entry_file, framework)
    method, _, path = finding["match"].partition(" ")
    target_route = next(
        (r for r in routes if r["method"] == method and r["path"] == path), None
    )
    if target_route is None:
        return {}, "Could not re-locate the vulnerable route to patch."

    lines = target.read_text(encoding="utf-8").splitlines(keepends=True)
    idx = target_route["line"] - 1
    before = "".join(lines)
    text = before

    if framework == "express":
        auth_name = next(
            (r["middleware"][0] for r in routes if r["has_auth_looking_middleware"]),
            None,
        )
        if not auth_name:
            return {}, "No existing auth middleware found in this app to reuse -- add one, then re-scan."
        lines[idx] = re.sub(
            r"""((?:app|router)\.\w+\s*\(\s*['"`][^'"`]+['"`]\s*,\s*)""",
            rf"\g<1>{auth_name}, ",
            lines[idx],
            count=1,
        )
        note = f"Added the existing `{auth_name}` middleware to this route -- the same check other protected routes use."

    elif framework == "fastapi":
        auth_name = _find_fastapi_auth(text)
        if not auth_name:
            return {}, "No existing FastAPI auth dependency (Depends(...)) found in this app to reuse -- add one, then re-scan."
        # Insert `, dependencies=[Depends(<name>)]` before the decorator's closing ")".
        lines[idx] = re.sub(
            r"""(@\s*(?:app|router)\.\w+\s*\(\s*['"][^'"]+['"])(\s*\))""",
            rf"\g<1>, dependencies=[Depends({auth_name})]\g<2>",
            lines[idx],
            count=1,
        )
        note = f"Added `dependencies=[Depends({auth_name})]` to this route -- the same dependency other protected routes use."

    elif framework == "flask":
        auth_name = _find_flask_auth(text)
        if not auth_name:
            return {}, "No existing Flask auth decorator (@login_required etc.) found in this app to reuse -- add one, then re-scan."
        # Stack the auth decorator right below the route decorator (Flask
        # requires it between the route decorator and the function).
        indent = re.match(r"\s*", lines[idx]).group(0)
        lines.insert(idx + 1, f"{indent}@{auth_name}\n")
        note = f"Added the existing `@{auth_name}` decorator to this route -- the same check other protected routes use."

    else:
        return {}, f"No missing-auth fixer for framework '{framework}'."

    after = "".join(lines)
    target.write_text(after, encoding="utf-8")
    return {entry_file: _unified(entry_file, before, after)}, note


def _fix_idor(finding: dict, work: Path, original: Path) -> tuple[dict[str, str], str]:
    """Reuses an existing ownership-check pattern found elsewhere in the same
    file, on a route that looks up a resource variable of the SAME name --
    the same "reuse what the app already does correctly" approach as the
    missing-auth fixer. If no sibling check exists to copy, fails
    honestly rather than inventing a field name that might not exist.
    """
    framework = finding.get("framework", "express")
    entry_file = finding.get("entry_file", "app.js")
    target = work / entry_file
    if not target.exists():
        return {}, "Could not locate the app's entry file to patch."

    text = target.read_text(encoding="utf-8")
    routes = extract_routes(str(work), entry_file, framework)
    method, _, path = finding["match"].partition(" ")
    target_route = next(
        (r for r in routes if r["method"] == method and r["path"] == path), None
    )
    if target_route is None:
        return {}, "Could not re-locate the vulnerable route to patch."

    lines = target.read_text(encoding="utf-8").splitlines(keepends=True)
    idx = target_route["line"] - 1
    before = "".join(lines)

    if framework == "express":
        var_match = re.search(r"const\s+(\w+)\s*=\s*\w+\.find\(", target_route["handler_snippet"])
        guard = _find_express_ownership_guard(text, var_match.group(1)) if var_match else None
        if not guard:
            return {}, "No existing ownership check on this resource found elsewhere in the app to reuse -- add one manually, then re-scan."
        # Express's not-found check is one line (`if (!order) return ...;`),
        # so the indent to match and the line to insert after are the same line.
        indent_from = insert_after = _line_index_of(
            lines, r"if\s*\(!" + re.escape(var_match.group(1)) + r"\)", idx
        )
    elif framework == "fastapi":
        var_match = re.search(r"(\w+)\s*=\s*next\(", target_route["handler_snippet"])
        guard = _find_fastapi_ownership_guard(text, var_match.group(1)) if var_match else None
        if not guard:
            return {}, "No existing ownership check on this resource found elsewhere in the app to reuse -- add one manually, then re-scan."
        # FastAPI's not-found check is a 2-line block (`if order is None:` /
        # `    raise HTTPException(...)`). The new guard must be inserted
        # AFTER the raise (not right after the `if` line, which would nest
        # it INSIDE that if-block and crash on a None order), but indented
        # to match the `if` line's level, not the more-indented raise line.
        indent_from = _line_index_of(
            lines, r"if\s+" + re.escape(var_match.group(1)) + r"\s+is\s+None", idx
        )
        insert_after = (
            _line_index_of(lines, r"raise\s+HTTPException", indent_from)
            if indent_from is not None
            else None
        )
    else:
        return {}, f"No IDOR fixer for framework '{framework}'."

    if insert_after is None or indent_from is None:
        return {}, "Could not find where in the handler to insert the ownership check."

    # The captured guard text still carries ITS OWN original indentation
    # from wherever it was copied from -- strip that first, then reapply a
    # clean, consistent indent relative to the target location (the first
    # line at the target's own level, every line after it one level deeper).
    # Without this, the two indents compound (target indent + source
    # indent), producing valid-but-ugly, inconsistently indented output.
    indent = re.match(r"\s*", lines[indent_from]).group(0)
    stripped_guard_lines = [ln.strip() for ln in guard.splitlines()]
    guard_lines = [f"{indent}{stripped_guard_lines[0]}\n"]
    for ln in stripped_guard_lines[1:-1]:
        guard_lines.append(f"{indent}    {ln}\n")  # inner lines: one level deeper
    if len(stripped_guard_lines) > 1:
        last = stripped_guard_lines[-1]
        # A lone closing bracket (Express's `}`) aligns with the opening
        # line, not the inner statement; anything else stays one level in.
        last_indent = indent if last in ("}", ")", "});") else f"{indent}    "
        guard_lines.append(f"{last_indent}{last}\n")
    lines[insert_after + 1 : insert_after + 1] = guard_lines

    after = "".join(lines)
    target.write_text(after, encoding="utf-8")
    return (
        {entry_file: _unified(entry_file, before, after)},
        "Added the ownership check another route in this app already uses on the same resource.",
    )


def _line_index_of(lines: list[str], pattern: str, from_idx: int) -> int | None:
    """The index of the first line matching pattern, searching forward from
    from_idx (used to find the "not found" guard's closing line, right
    after which the ownership check belongs)."""
    for i in range(from_idx, min(from_idx + 10, len(lines))):
        if re.search(pattern, lines[i]):
            return i
    return None


def _find_express_ownership_guard(text: str, var_name: str) -> str | None:
    """An existing `if (VAR.field !== ...) { return res.status(403)...}`
    block elsewhere in the file, for the same resource variable name."""
    m = re.search(
        rf"if\s*\({re.escape(var_name)}\.\w+\s*!==?\s*[^)]+\)\s*\{{\s*"
        rf"return\s+res\.status\(403\)[^\n]*\n\s*\}}",
        text,
    )
    return m.group(0) if m else None


def _find_fastapi_ownership_guard(text: str, var_name: str) -> str | None:
    """An existing `if VAR["field"] != ...: raise HTTPException(403, ...)`
    block elsewhere in the file, for the same resource variable name."""
    m = re.search(
        rf'if\s+{re.escape(var_name)}\[[^\]]+\]\s*!=\s*[^\n:]+:\s*\n\s*'
        rf"raise HTTPException\(status_code=403[^\n]*\)",
        text,
    )
    return m.group(0) if m else None


def _find_fastapi_auth(text: str) -> str | None:
    """The name inside an existing Depends(...) that looks auth-related."""
    for m in re.finditer(r"Depends\(\s*(\w+)\s*\)", text):
        name = m.group(1)
        if re.search(r"auth|current_user|login|token|session|verify", name, re.IGNORECASE):
            return name
    return None


def _find_flask_auth(text: str) -> str | None:
    """The name of an existing auth-looking decorator (@login_required etc.)."""
    for m in re.finditer(r"@\s*(\w+(?:_required)?)\b", text):
        name = m.group(1)
        if re.search(r"auth|login_required|jwt_required|token_required|requires_auth", name, re.IGNORECASE):
            return name
    return None


_BUILDERS: dict[str, Callable[[dict, Path, Path], tuple[dict[str, str], str]]] = {
    "secret": _fix_secret,
    "dependency-vuln": _fix_dependency_vuln,
    "dependency-missing": _fix_dependency_missing,
    "cloud-misconfig": _fix_cloud_misconfig,
    "missing-auth": _fix_missing_auth,
    "idor": _fix_idor,
}


def _resolve_in(root: Path, rel: str | Path, original: Path | None = None) -> Path | None:
    """Find a file under `root` (the disposable copy being patched) by
    relative path or basename.

    `rel` is usually root-relative already, but gitleaks (secrets.py) hands
    back the FULL absolute path it was invoked against -- and `root / rel`
    for an absolute `rel` silently discards `root` (that's plain pathlib
    behaviour, not a typo), so the naive join used to resolve straight back
    to a path in the ORIGINAL repo, which happened to exist too. A builder
    that reads/writes that path is patching the wrong copy entirely -- the
    "only ever a temp copy, verified before anything real is touched"
    guarantee this whole module exists for. So: an absolute `rel` is first
    translated to original-relative (then joined onto `root` normally); if
    it isn't under `original` either, only then does this fall back to a
    basename search.
    """
    rel = Path(rel)
    if rel.is_absolute():
        if original is not None:
            try:
                rel = rel.relative_to(original)
            except ValueError:
                rel = Path(rel.name)
        else:
            rel = Path(rel.name)
    candidate = root / rel
    if candidate.exists():
        return candidate
    matches = list(root.rglob(rel.name))
    return matches[0] if matches else None


def _still_present(finding: dict, findings: list[dict]) -> bool:
    """Is a finding with the same type+match still in the re-scan results?"""
    for f in findings:
        if f.get("type") == finding.get("type") and f.get("match") == finding.get("match"):
            return True
    return False


def fix_and_verify(finding: dict, repo_path: str) -> FixResult:
    """Generate a fix on a temp copy, re-scan, and confirm the finding is gone."""
    builder = _BUILDERS.get(finding.get("type", ""))
    if builder is None:
        return FixResult(finding, {}, "No fixer for this finding type.", False)

    original = Path(repo_path).resolve()
    tmp = Path(tempfile.mkdtemp(prefix="aegis-fix-"))
    work = tmp / original.name
    try:
        shutil.copytree(original, work)
        diffs, note = builder(finding, work, original)
        if not diffs:
            return FixResult(finding, {}, note, False)

        detector = _DETECTOR_FOR_TYPE.get(finding["type"])
        verified = True
        if detector is not None:
            try:
                rescan = detector(str(work))
                verified = not _still_present(finding, rescan)
            except (SandboxUnavailable, SandboxBuildError) as e:
                note += f" (Could not re-verify: {e})"
                verified = False

        return FixResult(finding, diffs, note, verified)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
