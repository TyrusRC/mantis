"""Tests for the optional tree-sitter path in slice extraction.

These tests verify graceful degradation: when tree-sitter is not
installed, `find_enclosing_function_ts` returns None and `slice.py`
falls back to ast/regex. If tree-sitter IS installed, the optional
test at the bottom verifies it parses real code correctly.
"""
from __future__ import annotations

import pytest

from mantis import _treesitter as ts


def test_is_available_returns_bool():
    ts.reset_for_tests()
    assert isinstance(ts.is_available(), bool)


def test_find_returns_none_when_unavailable(monkeypatch):
    ts.reset_for_tests()
    monkeypatch.setattr(ts, "_AVAILABLE", False)
    assert ts.find_enclosing_function_ts("def f(): pass\n", 1, "python") is None


def test_unknown_language_returns_none():
    assert ts.find_enclosing_function_ts("x = 1\n", 1, "totally-fake") is None


@pytest.mark.skipif(not ts.is_available(),
                    reason="tree-sitter-language-pack not installed (optional extra)")
def test_python_enclosing_via_treesitter():
    src = (
        "def outer():\n"
        "    return 1\n"
        "\n"
        "def inner_target(x):\n"
        "    y = x + 1\n"
        "    return y\n"
    )
    result = ts.find_enclosing_function_ts(src, 5, "python")
    assert result is not None
    name, start, _ = result
    assert name == "inner_target"
    assert start == 4


@pytest.mark.skipif(not ts.is_available(),
                    reason="tree-sitter-language-pack not installed (optional extra)")
def test_javascript_enclosing_via_treesitter():
    src = (
        "const a = 1;\n"
        "function vulnerable(req) {\n"
        "  eval(req.body);\n"
        "}\n"
    )
    result = ts.find_enclosing_function_ts(src, 3, "javascript")
    assert result is not None
    assert result[0] == "vulnerable"


@pytest.mark.skipif(not ts.is_available(),
                    reason="tree-sitter-language-pack not installed (optional extra)")
def test_go_enclosing_via_treesitter():
    src = (
        "package main\n"
        "import \"fmt\"\n"
        "func vuln(x string) {\n"
        "    fmt.Println(x)\n"
        "}\n"
    )
    result = ts.find_enclosing_function_ts(src, 4, "go")
    assert result is not None
    assert result[0] == "vuln"
