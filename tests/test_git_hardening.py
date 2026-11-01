"""Audited repos are untrusted: their hooks / fsmonitor must not run when mantis calls git."""
from __future__ import annotations

import subprocess
from pathlib import Path

from mantis.fix import check_uncommitted, ensure_worktree
from mantis.since import resolve_since


def _hostile_repo(tmp_path: Path) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    repo.mkdir()
    marker = tmp_path / "PWNED"
    run = lambda *a: subprocess.run(["git", *a], cwd=repo, check=True, capture_output=True)
    run("init", "-q")
    run("config", "user.email", "t@t")
    run("config", "user.name", "t")
    (repo / "app.py").write_text("x = 1\n")
    run("add", ".")
    run("commit", "-q", "-m", "init")
    payload = f"#!/bin/sh\necho ran >> {marker}\n"
    hook = repo / ".git" / "hooks" / "post-checkout"
    hook.write_text(payload)
    hook.chmod(0o755)
    fsmon = tmp_path / "fsmon.sh"
    fsmon.write_text(payload)
    fsmon.chmod(0o755)
    run("config", "core.fsmonitor", str(fsmon))
    return repo, marker


def test_worktree_add_does_not_run_repo_hooks(tmp_path):
    repo, marker = _hostile_repo(tmp_path)
    ensure_worktree(repo)
    assert not marker.exists()


def test_status_does_not_run_repo_fsmonitor(tmp_path):
    repo, marker = _hostile_repo(tmp_path)
    check_uncommitted(repo)
    assert not marker.exists()


def test_since_does_not_run_repo_fsmonitor(tmp_path):
    repo, marker = _hostile_repo(tmp_path)
    (repo / "app.py").write_text("x = 2\n")
    resolve_since(repo, "HEAD")
    assert not marker.exists()
