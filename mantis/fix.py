"""Stage 8: fix author + worktree.

For each confirmed finding:
1. Ensure a sibling git worktree exists.
2. Dispatch the fix-author agent with the slice + rule file path.
3. Apply the returned unified diff via `git apply`.
4. Re-run the SAST scan in the worktree against the changed file with
   the original rule; verify the rule no longer fires.
5. If verification fails, revert the change and record the failure.

Mantis never modifies the user's working tree — all edits happen in the
worktree at `../<repo>.audit-fix-<short>/`.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from mantis.agents import Agent
from mantis.deep import DeepResult
from mantis.providers import Provider
from mantis.scan import Finding, parse_scan_output
from mantis.slice import Slice


_UNIFIED_DIFF_HEADER = re.compile(r"^(?:diff --git|---|\+\+\+)", re.MULTILINE)


@dataclass
class FixResult:
    finding_id: str
    status: str   # applied | reverted | failed | skipped
    diff: str = ""
    worktree: Optional[Path] = None
    files_changed: list[str] = field(default_factory=list)
    verification: str = ""
    notes: str = ""
    error: Optional[str] = None
    tokens_in: int = 0
    tokens_out: int = 0


class FixError(Exception):
    pass


def _run_git(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=False)


def _short_sha(repo: Path) -> str:
    res = _run_git(["rev-parse", "--short", "HEAD"], repo)
    return res.stdout.strip() or "noref"


def ensure_worktree(repo: Path) -> Path:
    """Create a sibling worktree if one does not exist. Idempotent."""
    if not (repo / ".git").exists():
        raise FixError(f"{repo} is not a git repository (no .git directory)")

    # Reject unborn HEAD — `git worktree add ... HEAD` will fail anyway.
    verify_head = _run_git(["rev-parse", "--verify", "HEAD"], repo)
    if verify_head.returncode != 0:
        raise FixError(f"repo has no commits (unborn HEAD); cannot create worktree")

    short = _short_sha(repo)
    worktree = repo.parent / f"{repo.name}.audit-fix-{short}"

    if worktree.exists():
        # If the dir exists but is not a valid worktree, refuse to use it.
        check = _run_git(["rev-parse", "--is-inside-work-tree"], worktree)
        if check.returncode != 0 or check.stdout.strip() != "true":
            raise FixError(
                f"{worktree} exists but is not a git worktree; remove it or pick a different short sha"
            )
        return worktree

    branch = f"mantis-fix-{short}"
    res = _run_git(["worktree", "add", "-B", branch, str(worktree), "HEAD"], repo)
    if res.returncode != 0:
        raise FixError(f"git worktree add failed: {res.stderr.strip() or res.stdout.strip()}")
    return worktree


def check_uncommitted(repo: Path) -> list[str]:
    """Return a list of paths with uncommitted/staged changes, empty if clean."""
    res = _run_git(["status", "--porcelain"], repo)
    if res.returncode != 0:
        return []
    out: list[str] = []
    for line in res.stdout.splitlines():
        if line.strip():
            out.append(line.strip())
    return out


def _find_rule_file(rule_id: str, rules_root: Path) -> Optional[Path]:
    if not rules_root.is_dir():
        return None
    # Match by exact rule id in the file body.
    import yaml
    for path in rules_root.rglob("*.yaml"):
        if "packs" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if rule_id in text:
            return path
    return None


def build_fix_user_prompt(slice_obj: Slice, rule_file: Optional[Path], worktree: Path) -> str:
    finding = slice_obj.finding
    finding_id = finding.id
    rule_excerpt = ""
    if rule_file and rule_file.is_file():
        try:
            rule_excerpt = rule_file.read_text(encoding="utf-8")[:4000]
        except OSError:
            rule_excerpt = ""

    parts = [
        f"FINDING_ID: {finding_id}",
        f"WORKTREE: {worktree}",
        f"FILE_TO_PATCH: {finding.path}",
        f"RULE_ID: {finding.rule_id}",
        "",
        "SLICE:",
        slice_obj.to_text(),
    ]
    if rule_excerpt:
        parts.append("")
        parts.append("RULE FILE (so you understand what pattern must stop matching):")
        parts.append("```yaml")
        parts.append(rule_excerpt)
        parts.append("```")
    parts.append("")
    parts.append("Respond with FINDING / PATCH (unified diff) / VERIFY / NOTES per your instructions.")
    parts.append("The PATCH must be a unified diff against the WORKTREE path, using `--- a/<file>` / `+++ b/<file>` headers.")
    return "\n".join(parts)


def extract_diff(text: str) -> str:
    """Pull the unified diff out of an LLM response, accepting common wrappers."""
    if not text:
        return ""

    fenced = re.search(r"```(?:diff|patch)?\s*\n(?P<body>.*?)```", text, re.DOTALL)
    if fenced:
        body = fenced.group("body").strip()
        if _UNIFIED_DIFF_HEADER.search(body):
            return body + ("\n" if not body.endswith("\n") else "")

    if _UNIFIED_DIFF_HEADER.search(text):
        # Take everything from the first diff/--- line onward.
        m = _UNIFIED_DIFF_HEADER.search(text)
        return text[m.start():].strip() + "\n"

    return ""


def files_in_diff(diff: str) -> list[str]:
    files: list[str] = []
    for line in diff.splitlines():
        if line.startswith("+++ "):
            path = line[4:].strip()
            if path.startswith("b/"):
                path = path[2:]
            if path and path != "/dev/null":
                files.append(path)
    seen = set()
    out = []
    for f in files:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


def apply_patch(diff: str, worktree: Path) -> tuple[bool, str]:
    res = subprocess.run(
        ["git", "apply", "--whitespace=nowarn", "-"],
        cwd=worktree,
        input=diff,
        capture_output=True,
        text=True,
        check=False,
    )
    return res.returncode == 0, (res.stderr or res.stdout).strip()


def revert_files(worktree: Path, files: list[str]) -> None:
    if not files:
        return
    subprocess.run(["git", "checkout", "--", *files], cwd=worktree,
                   capture_output=True, text=True, check=False)


def verify_fix(worktree: Path, finding: Finding, sast_bin: str,
               rule_file: Optional[Path],
               *, pre_pack_count: Optional[int] = None,
               pack_rule_files: Optional[list[Path]] = None) -> tuple[bool, str]:
    """Return (rule_no_longer_fires_AND_no_regression, message).

    Verifies two things:
      1) The original rule no longer fires on the changed file.
      2) (Optional) Running the full pack against the changed file does
         not introduce NEW findings beyond what was present pre-fix.
    """
    target_file = worktree / finding.path
    if not target_file.is_file():
        return False, f"target file missing in worktree: {finding.path}"
    if not rule_file or not rule_file.is_file():
        return False, "could not locate rule file for verification"
    try:
        res = subprocess.run(
            [sast_bin, "--quiet", "--config", str(rule_file), "--json", str(target_file)],
            capture_output=True, text=True, timeout=120, check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return False, f"scanner failed: {e}"

    if res.returncode >= 2 and not res.stdout.strip():
        return False, f"scanner error: {res.stderr.strip()[:200]}"

    try:
        new_out = parse_scan_output(res.stdout)
    except Exception as e:  # ScanError, etc.
        return False, f"parse error: {e}"

    still_firing = any(
        nf.rule_id == finding.rule_id and nf.start_line == finding.start_line
        for nf in new_out.findings
    )
    if still_firing:
        return False, "original rule still fires on the same line"

    # Optional pack-wide regression check.
    if pack_rule_files and pre_pack_count is not None:
        cmd = [sast_bin, "--quiet"]
        for rf in pack_rule_files:
            cmd.extend(["--config", str(rf)])
        cmd += ["--json", str(target_file)]
        try:
            pack_res = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300, check=False,
            )
            pack_out = parse_scan_output(pack_res.stdout)
            if len(pack_out.findings) > pre_pack_count:
                return False, (
                    f"patch introduces regression: pack finding count {pre_pack_count} "
                    f"-> {len(pack_out.findings)}"
                )
        except Exception:
            # Pack-wide check is best-effort; do not block the fix on its failure.
            pass

    return True, "rule no longer fires"


def author_fix(
    provider: Provider,
    agent_body: str,
    slice_obj: Slice,
    deep: DeepResult,
    worktree: Path,
    sast_bin: str,
    rules_root: Path,
) -> FixResult:
    finding = slice_obj.finding
    finding_id = deep.finding_id

    if deep.verdict != "confirmed":
        return FixResult(finding_id=finding_id, status="skipped",
                         notes=f"deep verdict was {deep.verdict!r}, not confirmed")

    rule_file = _find_rule_file(finding.rule_id, rules_root)
    user = build_fix_user_prompt(slice_obj, rule_file, worktree)

    try:
        resp = provider.complete(
            tier="mid",
            system=agent_body,
            user=user,
            max_tokens=2000,
            temperature=0.1,
        )
    except Exception as e:
        return FixResult(finding_id=finding_id, status="failed",
                         error=f"{type(e).__name__}: {e}")

    diff = extract_diff(resp.text)
    if not diff:
        return FixResult(finding_id=finding_id, status="failed",
                         notes="no unified diff in fix-author response",
                         tokens_in=resp.tokens_in, tokens_out=resp.tokens_out)

    changed = files_in_diff(diff)
    ok, msg = apply_patch(diff, worktree)
    if not ok:
        return FixResult(
            finding_id=finding_id, status="failed", diff=diff, files_changed=changed,
            notes=f"git apply failed: {msg}", worktree=worktree,
            tokens_in=resp.tokens_in, tokens_out=resp.tokens_out,
        )

    verified, verify_msg = verify_fix(worktree, finding, sast_bin, rule_file)
    if not verified:
        revert_files(worktree, changed)
        return FixResult(
            finding_id=finding_id, status="reverted", diff=diff, files_changed=changed,
            verification=verify_msg, worktree=worktree,
            tokens_in=resp.tokens_in, tokens_out=resp.tokens_out,
        )

    return FixResult(
        finding_id=finding_id, status="applied", diff=diff, files_changed=changed,
        verification=verify_msg, worktree=worktree,
        tokens_in=resp.tokens_in, tokens_out=resp.tokens_out,
    )


def fix_all(
    confirmed: list[tuple[Slice, DeepResult]],
    agents: list[Agent],
    provider: Provider,
    repo: Path,
    sast_bin: str,
    rules_root: Path,
) -> tuple[list[FixResult], Optional[Path]]:
    if not confirmed:
        return [], None
    from mantis.triage import find_agent
    agent = find_agent(agents, "fix-author")

    try:
        worktree = ensure_worktree(repo)
    except FixError as e:
        return [
            FixResult(
                finding_id=f"{s.finding.rule_id}@{s.finding.path}:{s.finding.start_line}",
                status="failed",
                notes=f"worktree creation failed: {e}",
            )
            for s, _ in confirmed
        ], None

    results: list[FixResult] = []
    for slice_obj, deep in confirmed:
        results.append(author_fix(
            provider, agent.body, slice_obj, deep, worktree, sast_bin, rules_root,
        ))
    return results, worktree
