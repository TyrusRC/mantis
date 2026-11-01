"""Stage 8: fix author + worktree.

For each confirmed finding:
1. Ensure a sibling git worktree exists.
2. Dispatch the fix-author agent with the slice + rule file path.
3. Apply the returned unified diff via `git apply`.
4. Scan the changed files with the original rule + pack before and after
   the patch; verify the rule's hit count dropped and nothing new fired.
5. If verification fails, revert the change and record the failure.

Mantis never modifies the user's working tree — all edits happen in the
worktree at `../<repo>.audit-fix-<short>/`.
"""
from __future__ import annotations

import re
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from mantis.agents import Agent
from mantis.deep import DeepResult
from mantis.gitsafe import GIT
from mantis.providers import Provider
from mantis.scan import Finding, parse_scan_output, scanner_flags
from mantis.slice import Slice
from mantis.untrusted import fence


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
    return subprocess.run([*GIT, *args], cwd=cwd, capture_output=True, text=True, check=False)


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


def _same_rule(scanner_id: str, rule_id: str) -> bool:
    # OpenGrep prefixes check_id with the rule file's dotted directory path
    # (relative to cwd), so the same rule surfaces as `rules.web.<id>` or
    # `mantis.resources.rules.web.<id>` depending on where the scan ran.
    return scanner_id == rule_id or scanner_id.endswith("." + rule_id)


def _find_rule_file(rule_id: str, rules_root: Path) -> Optional[Path]:
    if not rules_root.is_dir():
        return None
    for path in rules_root.rglob("*.yaml"):
        if "packs" in path.parts or path.name.startswith("_"):
            continue
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            continue
        rules = doc.get("rules") if isinstance(doc, dict) else None
        for r in rules or []:
            if isinstance(r, dict) and r.get("id") and _same_rule(rule_id, str(r["id"])):
                return path
    return None


def _rel_path(path: str, repo: Optional[Path]) -> str:
    p = Path(path)
    if p.is_absolute() and repo is not None:
        try:
            return str(p.resolve().relative_to(repo.resolve()))
        except ValueError:
            pass
    return path


def _matched_rule_yaml(rule_file: Optional[Path], rule_id: str) -> str:
    """Just the rule that fired, not the whole (often multi-rule) file."""
    if not rule_file or not rule_file.is_file():
        return ""
    try:
        doc = yaml.safe_load(rule_file.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return ""
    for r in (doc.get("rules") if isinstance(doc, dict) else None) or []:
        if isinstance(r, dict) and r.get("id") and _same_rule(rule_id, str(r["id"])):
            return yaml.safe_dump(r, sort_keys=False, allow_unicode=True)[:4000]
    return ""


def build_fix_user_prompt(slice_obj: Slice, rule_file: Optional[Path], worktree: Path,
                          rel_path: Optional[str] = None) -> str:
    finding = slice_obj.finding
    rule_excerpt = _matched_rule_yaml(rule_file, finding.rule_id)

    # NOTE: fence() redacts key-shaped values, so a patch whose context lines hold
    # a live secret will not apply and is reported as failed. Accepted: secrets
    # stay on the machine; the fix for those is a manual rotation anyway.
    parts = [
        f"FINDING_ID: {finding.id}",
        f"WORKTREE: {worktree}",
        f"FILE_TO_PATCH: {rel_path or finding.path}",
        f"RULE_ID: {finding.rule_id}",
        "",
        "SLICE:",
        fence(slice_obj.to_text(), "untrusted-slice"),
    ]
    if rule_excerpt:
        parts.append("")
        parts.append("MATCHED RULE (the pattern that must stop matching):")
        parts.append("```yaml")
        parts.append(rule_excerpt.rstrip())
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
        [*GIT, "apply", "--whitespace=nowarn", "-"],
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
    subprocess.run([*GIT, "checkout", "--", *files], cwd=worktree,
                   capture_output=True, text=True, check=False)


def scan_counts(worktree: Path, files: list[str], rule_files: list[Path],
                sast_bin: str) -> Counter:
    """Count findings per (scanner rule id, relative path) over `files` in the worktree.

    Raises FixError on scanner failure so callers fail closed.
    """
    present = [f for f in dict.fromkeys(files) if (worktree / f).is_file()]
    if not present:
        return Counter()
    # Same flags as the audit scan, or taint findings never reproduce here.
    cmd = [sast_bin, "--quiet", *scanner_flags(sast_bin)]
    for rf in dict.fromkeys(rule_files):
        cmd.extend(["--config", str(rf)])
    cmd += ["--json", *present]
    try:
        res = subprocess.run(cmd, cwd=worktree, capture_output=True, text=True,
                             timeout=300, check=False)
    except (subprocess.TimeoutExpired, OSError) as e:
        raise FixError(f"scanner failed: {e}") from e
    if res.returncode >= 2 and not res.stdout.strip():
        raise FixError(f"scanner error: {res.stderr.strip()[:200]}")
    try:
        out = parse_scan_output(res.stdout)
    except Exception as e:  # ScanError, etc.
        raise FixError(f"parse error: {e}") from e
    return Counter((nf.rule_id, nf.path) for nf in out.findings)


def verify_fix(worktree: Path, rel_path: str, rule_id: str, sast_bin: str,
               rule_files: list[Path], files: list[str],
               before: Counter) -> tuple[bool, str]:
    """Return (fixed_AND_no_regression, message).

    `before` is `scan_counts` over the same files/rules taken before the
    patch was applied. Counting (instead of matching the original line)
    means a patch that merely moves the sink does not pass.
    """
    try:
        after = scan_counts(worktree, files, rule_files, sast_bin)
    except FixError as e:
        return False, str(e)

    def hits(c: Counter) -> int:
        return sum(n for (rid, p), n in c.items() if p == rel_path and _same_rule(rid, rule_id))

    if hits(before) == 0:
        return False, "original finding not reproduced before patch; cannot verify"
    if hits(after) >= hits(before):
        return False, f"original rule still fires ({hits(before)} -> {hits(after)})"
    new = after - before
    if new:
        listed = ", ".join(f"{rid} @ {p}" for rid, p in sorted(new))
        return False, f"patch introduces new finding(s): {listed}"
    return True, f"rule no longer fires ({hits(before)} -> {hits(after)}); no new findings"


def author_fix(
    provider: Provider,
    agent_body: str,
    slice_obj: Slice,
    deep: DeepResult,
    worktree: Path,
    sast_bin: str,
    rules_root: Path,
    *,
    repo: Optional[Path] = None,
    pack_rule_files: Optional[list[Path]] = None,
) -> FixResult:
    finding = slice_obj.finding
    finding_id = deep.finding_id

    if deep.verdict != "confirmed":
        return FixResult(finding_id=finding_id, status="skipped",
                         notes=f"deep verdict was {deep.verdict!r}, not confirmed")

    rule_file = _find_rule_file(finding.rule_id, rules_root)
    rel_path = _rel_path(finding.path, repo)
    user = build_fix_user_prompt(slice_obj, rule_file, worktree, rel_path)

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
    verify_files = [rel_path, *changed]
    verify_rules = [rule_file, *(pack_rule_files or [])] if rule_file else []
    before: Counter = Counter()
    if verify_rules:
        try:
            before = scan_counts(worktree, verify_files, verify_rules, sast_bin)
        except FixError as e:
            return FixResult(finding_id=finding_id, status="failed", diff=diff,
                             files_changed=changed, notes=f"pre-patch scan failed: {e}",
                             tokens_in=resp.tokens_in, tokens_out=resp.tokens_out)

    ok, msg = apply_patch(diff, worktree)
    if not ok:
        return FixResult(
            finding_id=finding_id, status="failed", diff=diff, files_changed=changed,
            notes=f"git apply failed: {msg}", worktree=worktree,
            tokens_in=resp.tokens_in, tokens_out=resp.tokens_out,
        )

    if verify_rules:
        verified, verify_msg = verify_fix(worktree, rel_path, finding.rule_id, sast_bin,
                                          verify_rules, verify_files, before)
    else:
        verified, verify_msg = False, "could not locate rule file for verification"
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
    pack_rule_files: Optional[list[Path]] = None,
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
            repo=repo, pack_rule_files=pack_rule_files,
        ))
    return results, worktree
