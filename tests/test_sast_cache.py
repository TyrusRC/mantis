"""SAST cache: entries are content-addressed, so they must be rebased onto the file being loaded."""
from __future__ import annotations

from pathlib import Path



# ---- cached entries belong to the file being loaded, not the first file scanned ----

import shutil as _shutil

import pytest as _pytest


@_pytest.mark.skipif(_shutil.which("opengrep") is None, reason="opengrep not installed")
def test_identical_files_keep_their_own_paths_across_cached_runs(tmp_path, monkeypatch):
    from mantis.sast_cache import run_scan_cached
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    rule = tmp_path / "r.yaml"
    rule.write_text("rules:\n  - id: t-eval\n    languages: [python]\n    severity: ERROR\n"
                    "    message: m\n    pattern: eval(...)\n")
    tree = tmp_path / "tree"
    for d in ("a", "b"):
        (tree / d).mkdir(parents=True)
        (tree / d / "x.py").write_text("eval(data)\n")
    for _ in range(2):  # second pass is served from the cache
        out, _stats = run_scan_cached(tree, [rule], "opengrep")
        paths = sorted(str(Path(f.path).resolve().relative_to(tree.resolve())) for f in out.findings)
        assert paths == ["a/x.py", "b/x.py"]


def test_cache_key_depends_on_severity_filter(tmp_path, monkeypatch):
    import mantis.sast_cache as sc
    seen = []
    monkeypatch.setattr(sc, "_entry_path", lambda scanner, pack_h, fh: seen.append(pack_h) or tmp_path / "e.json")
    monkeypatch.setattr(sc, "_load_entry", lambda p: [])
    monkeypatch.setattr(sc, "scanner_version", lambda b: "v")
    monkeypatch.setattr(sc, "hash_pack", lambda rf: "p")
    (tmp_path / "f.py").write_text("x")
    sc.run_scan_cached(tmp_path, [tmp_path / "r.yaml"], "og", paths=[tmp_path / "f.py"], severities=("ERROR",))
    sc.run_scan_cached(tmp_path, [tmp_path / "r.yaml"], "og", paths=[tmp_path / "f.py"], severities=("ERROR", "INFO"))
    assert seen[0] != seen[1]
