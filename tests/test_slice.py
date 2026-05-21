from __future__ import annotations

from pathlib import Path

from mantis.scan import Finding
from mantis.slice import (
    extract_slice,
    find_enclosing_function,
    find_enclosing_function_python,
    find_enclosing_function_regex,
)


def _finding(path: str, line: int, rule="r1") -> Finding:
    return Finding(rule_id=rule, severity="ERROR", confidence="HIGH",
                   path=path, start_line=line, end_line=line + 1,
                   message="test", metadata={})


def test_find_enclosing_python_simple():
    src = (
        "def outer():\n"
        "    return 1\n"
        "\n"
        "def vulnerable(user):\n"
        "    q = 'SELECT * FROM t WHERE id=' + user\n"
        "    return run(q)\n"
        "\n"
        "def other():\n"
        "    pass\n"
    )
    name, start, end = find_enclosing_function_python(src, 5)
    assert name == "vulnerable"
    assert start == 4
    assert end >= 6


def test_find_enclosing_python_nested_picks_innermost():
    src = (
        "def outer():\n"
        "    def inner():\n"
        "        bad()\n"
        "    inner()\n"
    )
    name, start, _ = find_enclosing_function_python(src, 3)
    assert name == "inner"
    assert start == 2


def test_find_enclosing_javascript_function():
    src = (
        "const a = 1;\n"
        "function vulnerable(req) {\n"
        "  eval(req.body);\n"
        "}\n"
        "function other() {}\n"
    )
    result = find_enclosing_function_regex(src, 3, "javascript")
    assert result is not None
    name, start, end = result
    assert name == "vulnerable"
    assert start == 2


def test_find_enclosing_kotlin():
    src = (
        "class Foo {\n"
        "  fun doThing(s: String) {\n"
        "    eval(s)\n"
        "  }\n"
        "}\n"
    )
    result = find_enclosing_function_regex(src, 3, "kotlin")
    assert result is not None
    name, *_ = result
    assert name == "doThing"


def test_find_enclosing_swift():
    src = (
        "class Foo {\n"
        "  func vulnerable(input: String) {\n"
        "    let url = URL(string: input)!\n"
        "  }\n"
        "}\n"
    )
    result = find_enclosing_function_regex(src, 3, "swift")
    assert result is not None
    assert result[0] == "vulnerable"


def test_find_enclosing_unknown_language_returns_none():
    src = "some text with no functions\nstill nothing\n"
    assert find_enclosing_function(src, 1, "unknown") is None


def test_extract_slice_python_falls_back_when_no_function(tmp_path):
    p = tmp_path / "raw.py"
    p.write_text("x = 1\ny = 2\nz = 3\n")
    sl = extract_slice(_finding("raw.py", 2), tmp_path)
    assert sl.chunks
    # No enclosing function -> falls back to window with empty func name.
    assert sl.sink_func == ""


def test_extract_slice_python_with_function(tmp_path):
    src = (
        "import sqlite3\n"
        "def run_query(uid):\n"
        "    q = 'SELECT * FROM t WHERE id=' + uid\n"
        "    return sqlite3.connect(':memory:').execute(q)\n"
    )
    p = tmp_path / "app.py"
    p.write_text(src)
    sl = extract_slice(_finding("app.py", 3), tmp_path)
    assert sl.sink_func == "run_query"
    assert sl.chunks[0].role == "sink"
    assert "SELECT" in sl.chunks[0].code


def test_extract_slice_marks_test_path_not_reachable(tmp_path):
    (tmp_path / "tests").mkdir()
    p = tmp_path / "tests" / "test_app.py"
    p.write_text("def test_thing():\n    bad()\n")
    sl = extract_slice(_finding("tests/test_app.py", 2), tmp_path)
    assert sl.reachability == "no"


def test_extract_slice_reachable_when_in_app_path(tmp_path):
    p = tmp_path / "app.py"
    p.write_text("def handler(req):\n    bad()\n")
    sl = extract_slice(_finding("app.py", 2), tmp_path)
    assert sl.reachability == "yes"


def test_brace_counter_skips_strings(tmp_path):
    """Brace count must not be confused by braces in string literals."""
    from mantis.slice import _estimate_end_by_braces
    lines = [
        "function f() {",
        '    const s = "look { a brace }";',
        '    const t = "}";',
        "    return s;",
        "}",
        "next_line()",
    ]
    end = _estimate_end_by_braces(lines, 0)
    # end is 0-indexed line containing the closing brace -> line 4 -> "}"
    assert end == 4


def test_brace_counter_skips_line_comments(tmp_path):
    from mantis.slice import _estimate_end_by_braces
    lines = [
        "function f() {",
        "    // } not real",
        "    /* } also not real */",
        "    return 1;",
        "}",
    ]
    assert _estimate_end_by_braces(lines, 0) == 4


def test_brace_counter_skips_template_literals(tmp_path):
    from mantis.slice import _estimate_end_by_braces
    lines = [
        "function f() {",
        "    const s = `hello { ${x} }`;",
        "    return s;",
        "}",
    ]
    assert _estimate_end_by_braces(lines, 0) == 3


def test_extract_slice_to_text_contains_required_headers(tmp_path):
    p = tmp_path / "app.py"
    p.write_text("def f():\n    bad()\n")
    sl = extract_slice(_finding("app.py", 2), tmp_path)
    text = sl.to_text()
    assert "SLICE for" in text
    assert "SINK:" in text
    assert "REACHABLE_FROM_ENTRYPOINT:" in text
    assert "DEPTH_USED:" in text
