from __future__ import annotations

from mantis.reachability import _is_dead_path, classify_reachability
from mantis.scan import Finding
from mantis.slice import SliceChunk


def _f(path):
    return Finding(rule_id="r", severity="ERROR", confidence="HIGH",
                   path=path, start_line=1, end_line=1, message="m")


def _chunk(file, role="caller"):
    return SliceChunk(file=file, start_line=1, end_line=1, role=role,
                      func="f", code="...")


def test_test_dir_is_dead():
    assert _is_dead_path("src/tests/foo.py") is True
    assert _is_dead_path("/src/__tests__/foo.ts") is True
    assert _is_dead_path("packages/spec/x.js") is True


def test_filename_test_is_dead():
    assert _is_dead_path("pkg/foo_test.go") is True
    assert _is_dead_path("UserTest.java") is True
    assert _is_dead_path("app.test.tsx") is True


def test_live_path_not_dead():
    assert _is_dead_path("src/app/handler.py") is False
    assert _is_dead_path("internal/server.go") is False


def test_finding_in_dead_path_is_not_reachable():
    assert classify_reachability(_f("src/tests/foo.py"), "fn", []) == "no"


def test_finding_in_live_path_with_no_callers_is_reachable():
    assert classify_reachability(_f("src/app/handler.py"), "fn", []) == "yes"


def test_all_callers_in_dead_paths_is_not_reachable():
    chunks = [_chunk("src/tests/a.py"), _chunk("src/__tests__/b.js")]
    assert classify_reachability(_f("src/app/x.py"), "fn", chunks) == "no"


def test_any_caller_in_live_path_is_reachable():
    chunks = [_chunk("src/tests/a.py"), _chunk("src/app/y.py")]
    assert classify_reachability(_f("src/app/x.py"), "fn", chunks) == "yes"
