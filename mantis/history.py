"""Audit run history.

Each `mantis audit` invocation writes its report to
`<target>/.mantis/runs/<id>.md` and updates the `<target>/.mantis/latest.md`
pointer (symlink where the filesystem supports it, copy otherwise). A
back-compat `<target>/security-audit-report.md` symlink continues to point
at the latest run so existing IDE/editor flows keep working.

Run id format: `YYYYMMDD-HHMMSS-<sha7>` where `<sha7>` is the target repo's
short HEAD or `nogit` if the target isn't a git checkout.
"""
from __future__ import annotations

import datetime as dt
import difflib
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

RUN_DIR_NAME = ".mantis"
RUNS_SUBDIR = "runs"
LATEST_SYMLINK = "latest.md"
LEGACY_REPORT = "security-audit-report.md"
RUN_ID_RE = re.compile(r"^(\d{8}-\d{6})-([0-9a-f]{7,40}|nogit)$")


@dataclass
class RunEntry:
    id: str
    path: Path
    mtime: float


def _git_short_sha(target: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(target), "rev-parse", "--short=7", "HEAD"],
            capture_output=True, text=True, timeout=3,
        )
        sha = out.stdout.strip()
        if out.returncode == 0 and re.fullmatch(r"[0-9a-f]{7,40}", sha):
            return sha
    except (OSError, subprocess.SubprocessError):
        pass
    return "nogit"


def runs_dir(target: Path) -> Path:
    return target / RUN_DIR_NAME / RUNS_SUBDIR


def new_run_id(target: Path) -> str:
    ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"{ts}-{_git_short_sha(target)}"


def report_path_for(target: Path, run_id: str) -> Path:
    return runs_dir(target) / f"{run_id}.md"


def update_pointers(target: Path, report: Path) -> None:
    """Point .mantis/latest.md and security-audit-report.md at `report`."""
    parent = target / RUN_DIR_NAME
    parent.mkdir(parents=True, exist_ok=True)

    latest = parent / LATEST_SYMLINK
    legacy = target / LEGACY_REPORT
    rel_in_dotmantis = report.relative_to(parent)
    rel_in_target = report.relative_to(target)

    for link, rel in ((latest, rel_in_dotmantis), (legacy, rel_in_target)):
        try:
            if link.is_symlink() or link.exists():
                link.unlink()
            link.symlink_to(rel)
        except OSError:
            try:
                shutil.copy2(report, link)
            except OSError:
                pass


def list_runs(target: Path) -> list[RunEntry]:
    d = runs_dir(target)
    if not d.is_dir():
        return []
    out: list[RunEntry] = []
    for p in d.iterdir():
        if not p.is_file() or not p.name.endswith(".md"):
            continue
        stem = p.stem
        if not RUN_ID_RE.match(stem):
            continue
        out.append(RunEntry(id=stem, path=p, mtime=p.stat().st_mtime))
    out.sort(key=lambda r: r.id, reverse=True)
    return out


def resolve_run(target: Path, ref: str) -> RunEntry | None:
    runs = list_runs(target)
    if not runs:
        return None
    if ref == "latest":
        return runs[0]
    if ref.lstrip("-").isdigit() and ref.startswith("-"):
        idx = int(ref[1:])
        return runs[idx] if idx < len(runs) else None
    for r in runs:
        if r.id == ref or r.id.startswith(ref):
            return r
    return None


def _summary_line(entry: RunEntry) -> str:
    ts = dt.datetime.fromtimestamp(entry.mtime).strftime("%Y-%m-%d %H:%M:%S")
    size = entry.path.stat().st_size
    return f"{entry.id}  {ts}  {size:>7}B"


def cmd_history(args) -> int:
    target = Path(getattr(args, "path", ".") or ".").resolve()
    runs = list_runs(target)
    if not runs:
        print(f"no audit history at {target}/.mantis/runs/", end="")
        print(" — run `mantis audit` first.")
        return 0
    print(f"audit history for {target} ({len(runs)} run{'s' if len(runs) != 1 else ''})")
    print()
    for i, r in enumerate(runs):
        tag = " (latest)" if i == 0 else ""
        print(f"  {_summary_line(r)}{tag}")
    return 0


def cmd_show(args) -> int:
    target = Path(getattr(args, "path", ".") or ".").resolve()
    ref = getattr(args, "ref", "latest") or "latest"
    entry = resolve_run(target, ref)
    if not entry:
        print(f"no run matching {ref!r}", flush=True)
        return 2
    text = entry.path.read_text(encoding="utf-8", errors="replace")
    print(text)
    return 0


def cmd_diff(args) -> int:
    target = Path(getattr(args, "path", ".") or ".").resolve()
    a_ref = args.a or "-1"
    b_ref = args.b or "latest"
    a = resolve_run(target, a_ref)
    b = resolve_run(target, b_ref)
    if not a or not b:
        print(f"could not resolve runs: a={a_ref} -> {a}, b={b_ref} -> {b}",
              flush=True)
        return 2
    a_lines = a.path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    b_lines = b.path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    sys_stdout_lines = difflib.unified_diff(
        a_lines, b_lines, fromfile=f"a/{a.id}.md", tofile=f"b/{b.id}.md", n=3,
    )
    import sys
    sys.stdout.writelines(sys_stdout_lines)
    return 0
