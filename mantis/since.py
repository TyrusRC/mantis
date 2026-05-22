"""Resolve `--since <ref>` into a list of changed files for incremental scans.

Special refs:
  - `uncommitted` or `dirty`: every modified/added file in the working tree
    (`git status --porcelain`), including untracked.
  - `staged`: index vs. HEAD.
  - any other string: passed to `git diff --name-only <ref>...HEAD` (committed
    diff vs. that ref). Use a branch name (e.g. `main`) or a SHA.

Returns absolute Paths. Files that no longer exist on disk (deleted in the
diff) are silently dropped — the scanner can't scan what isn't there.
"""
from __future__ import annotations

import subprocess
from pathlib import Path


class SinceError(Exception):
    pass


def _git_run(args: list[str], cwd: Path, timeout: int = 5) -> tuple[int, str]:
    try:
        out = subprocess.run(
            ["git", "-C", str(cwd), *args],
            capture_output=True, text=True, timeout=timeout,
        )
        return out.returncode, out.stdout
    except (OSError, subprocess.SubprocessError) as e:
        raise SinceError(f"git invocation failed: {e}") from e


def _is_git_repo(target: Path) -> bool:
    rc, _ = _git_run(["rev-parse", "--is-inside-work-tree"], target)
    return rc == 0


def resolve_since(target: Path, ref: str) -> list[Path]:
    if not _is_git_repo(target):
        raise SinceError(f"{target} is not a git repository; cannot use --since")

    if ref in ("uncommitted", "dirty"):
        rc, out = _git_run(["status", "--porcelain", "--untracked-files=all"], target)
        if rc != 0:
            raise SinceError(f"git status failed: {out}")
        rel = []
        for line in out.splitlines():
            if len(line) < 4:
                continue
            # porcelain v1: 'XY <path>' (renames use ' -> '; take the new name)
            path = line[3:]
            if " -> " in path:
                path = path.split(" -> ", 1)[1]
            rel.append(path)
    elif ref == "staged":
        rc, out = _git_run(["diff", "--name-only", "--cached"], target)
        if rc != 0:
            raise SinceError(f"git diff --cached failed: {out}")
        rel = [l for l in out.splitlines() if l]
    else:
        rc, out = _git_run(["diff", "--name-only", f"{ref}...HEAD"], target)
        if rc != 0:
            raise SinceError(
                f"git diff against {ref!r} failed (unknown ref or no merge base): "
                f"{out.strip()}"
            )
        rel = [l for l in out.splitlines() if l]

    seen: set[str] = set()
    out_paths: list[Path] = []
    for r in rel:
        if r in seen:
            continue
        seen.add(r)
        p = (target / r).resolve()
        if p.is_file():
            out_paths.append(p)
    return out_paths
