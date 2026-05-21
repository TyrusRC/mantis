from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from mantis.agents import Agent
from mantis.deep import DeepResult
from mantis.fix import (
    FixError,
    apply_patch,
    author_fix,
    build_fix_user_prompt,
    ensure_worktree,
    extract_diff,
    files_in_diff,
    fix_all,
)
from mantis.providers import LLMResponse
from mantis.scan import Finding
from mantis.slice import Slice, SliceChunk


# ---- diff extraction ----

def test_extract_diff_fenced():
    text = """Some preamble.

```diff
diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1 @@
-x = 1
+x = 2
```

trailing prose
"""
    out = extract_diff(text)
    assert "diff --git" in out
    assert "x = 2" in out


def test_extract_diff_unfenced():
    text = "preface\n--- a/foo\n+++ b/foo\n@@ -1 +1 @@\n-a\n+b\n"
    out = extract_diff(text)
    assert "+++ b/foo" in out


def test_extract_diff_no_diff_returns_empty():
    assert extract_diff("no diff here, just words") == ""


def test_files_in_diff():
    diff = (
        "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@\n-x\n+y\n"
        "diff --git a/b.py b/b.py\n--- a/b.py\n+++ b/b.py\n@@\n-foo\n+bar\n"
    )
    assert files_in_diff(diff) == ["a.py", "b.py"]


# ---- worktree ----

def _init_git(repo: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
    (repo / "app.py").write_text("def f():\n    bad()\n")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=repo, check=True)


def test_ensure_worktree_creates_sibling(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git(repo)
    wt = ensure_worktree(repo)
    assert wt.is_dir()
    assert wt.parent == repo.parent
    assert wt.name.startswith("repo.audit-fix-")
    assert (wt / "app.py").is_file()


def test_ensure_worktree_idempotent(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git(repo)
    wt1 = ensure_worktree(repo)
    wt2 = ensure_worktree(repo)
    assert wt1 == wt2


def test_ensure_worktree_raises_when_no_git(tmp_path):
    not_a_repo = tmp_path / "plain"
    not_a_repo.mkdir()
    with pytest.raises(FixError):
        ensure_worktree(not_a_repo)


def test_ensure_worktree_rejects_unborn_head(tmp_path):
    repo = tmp_path / "fresh"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    # Do NOT commit anything — HEAD is unborn.
    with pytest.raises(FixError) as ei:
        ensure_worktree(repo)
    assert "unborn HEAD" in str(ei.value)


def test_ensure_worktree_rejects_non_worktree_dir(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git(repo)
    # Pre-create the worktree path with junk so it's NOT a real worktree.
    from mantis.fix import _short_sha
    short = _short_sha(repo)
    junk = repo.parent / f"{repo.name}.audit-fix-{short}"
    junk.mkdir()
    (junk / "stray.txt").write_text("stray content\n")
    with pytest.raises(FixError) as ei:
        ensure_worktree(repo)
    assert "not a git worktree" in str(ei.value)


def test_check_uncommitted_reports_dirty(tmp_path):
    from mantis.fix import check_uncommitted
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git(repo)
    # Touch a tracked file to make it dirty.
    (repo / "app.py").write_text("changed\n")
    out = check_uncommitted(repo)
    assert len(out) >= 1


def test_apply_patch_success(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git(repo)
    wt = ensure_worktree(repo)
    diff = (
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,2 +1,2 @@\n"
        " def f():\n"
        "-    bad()\n"
        "+    safe()\n"
    )
    ok, msg = apply_patch(diff, wt)
    assert ok, msg
    assert "safe()" in (wt / "app.py").read_text()


def test_apply_patch_bad_diff_fails(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git(repo)
    wt = ensure_worktree(repo)
    ok, _ = apply_patch("not a diff", wt)
    assert ok is False


# ---- author_fix end-to-end with stubs ----

def _slice(rule="r1", file="app.py", line=2):
    f = Finding(rule_id=rule, severity="ERROR", confidence="HIGH",
                path=file, start_line=line, end_line=line, message="m")
    return Slice(finding=f, sink_func="f", sink_file=file, sink_line=line,
                 chunks=[SliceChunk(file=file, start_line=1, end_line=2,
                                    role="sink", func="f", code="def f():\n    bad()")],
                 reachability="yes")


def _deep(verdict="confirmed", finding_id="r1@app.py:2"):
    return DeepResult(finding_id=finding_id, verdict=verdict, severity="high")


def _agent(name="fix-author"):
    return Agent(name=name, description="", tier="mid", model="sonnet",
                 tools=[], body="be a fixer", path=Path("/x"))


class _DiffProvider:
    def __init__(self, diff_text):
        self.diff_text = diff_text

    def complete(self, tier, system, user, max_tokens=4096, temperature=0.2):
        return LLMResponse(text=self.diff_text, tokens_in=5, tokens_out=10, model="fake")


def test_author_fix_skipped_when_not_confirmed(tmp_path):
    result = author_fix(_DiffProvider(""), "sys", _slice(), _deep("rejected"),
                        tmp_path, "opengrep", tmp_path / "rules")
    assert result.status == "skipped"


def test_author_fix_failed_when_no_diff(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git(repo)
    wt = ensure_worktree(repo)
    result = author_fix(_DiffProvider("no diff in this response"), "sys",
                        _slice(), _deep(), wt, "opengrep", tmp_path / "rules")
    assert result.status == "failed"
    assert "no unified diff" in result.notes


def test_author_fix_reverted_when_verify_fails(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git(repo)
    wt = ensure_worktree(repo)
    diff = (
        "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n"
        "@@ -1,2 +1,2 @@\n def f():\n-    bad()\n+    safe()\n"
    )
    # Stub verify_fix to fail.
    monkeypatch.setattr("mantis.fix.verify_fix", lambda *a, **k: (False, "rule still fires"))
    # Stub rule-file lookup.
    monkeypatch.setattr("mantis.fix._find_rule_file", lambda *a, **k: None)
    result = author_fix(_DiffProvider(diff), "sys", _slice(), _deep(),
                        wt, "opengrep", tmp_path / "rules")
    assert result.status == "reverted"
    # File should be back to original.
    assert "bad()" in (wt / "app.py").read_text()


def test_author_fix_applied_on_verify_success(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git(repo)
    wt = ensure_worktree(repo)
    diff = (
        "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n"
        "@@ -1,2 +1,2 @@\n def f():\n-    bad()\n+    safe()\n"
    )
    monkeypatch.setattr("mantis.fix.verify_fix", lambda *a, **k: (True, "fixed"))
    monkeypatch.setattr("mantis.fix._find_rule_file", lambda *a, **k: None)
    result = author_fix(_DiffProvider(diff), "sys", _slice(), _deep(),
                        wt, "opengrep", tmp_path / "rules")
    assert result.status == "applied"
    assert "safe()" in (wt / "app.py").read_text()


def test_fix_all_when_no_confirmed(tmp_path):
    results, wt = fix_all([], [_agent()], _DiffProvider(""), tmp_path,
                          "opengrep", tmp_path / "rules")
    assert results == []
    assert wt is None


def test_fix_all_worktree_failure_returns_failures(tmp_path):
    not_a_repo = tmp_path / "plain"
    not_a_repo.mkdir()
    confirmed = [(_slice(), _deep())]
    results, wt = fix_all(confirmed, [_agent()], _DiffProvider(""),
                          not_a_repo, "opengrep", tmp_path / "rules")
    assert wt is None
    assert len(results) == 1
    assert results[0].status == "failed"
    assert "worktree" in results[0].notes
