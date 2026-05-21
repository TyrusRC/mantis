from __future__ import annotations

from pathlib import Path

from mantis.callgraph import (
    CallGraph,
    _ENTRYPOINT_FUNCTION_NAMES,
    index_project,
    reaches_entrypoint,
)


def test_indexes_simple_project(tmp_path):
    (tmp_path / "app.py").write_text(
        "def main():\n"
        "    helper()\n"
        "\n"
        "def helper():\n"
        "    leaf()\n"
        "\n"
        "def leaf():\n"
        "    return 1\n"
    )
    g = index_project(tmp_path)
    assert g.indexed_files == 1
    assert "main" in g.defs
    assert "helper" in g.callers
    assert "leaf" in g.callers
    assert "main" in g.entrypoints  # by function-name convention


def test_path_based_entrypoint(tmp_path):
    (tmp_path / "main.py").write_text(
        "def boot():\n"
        "    serve()\n"
        "\n"
        "def serve():\n"
        "    return 0\n"
    )
    g = index_project(tmp_path)
    assert "boot" in g.entrypoints
    assert "serve" in g.entrypoints


def test_decorator_based_entrypoint(tmp_path):
    (tmp_path / "views.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/x')\n"
        "def handle():\n"
        "    return inner()\n"
        "\n"
        "def inner():\n"
        "    return 1\n"
    )
    g = index_project(tmp_path)
    assert "handle" in g.entrypoints
    assert "inner" not in g.entrypoints


def test_reaches_entrypoint_yes(tmp_path):
    (tmp_path / "app.py").write_text(
        "def main():\n"
        "    a()\n"
        "\n"
        "def a():\n"
        "    b()\n"
        "\n"
        "def b():\n"
        "    return 1\n"
    )
    g = index_project(tmp_path)
    assert reaches_entrypoint(g, "b") == "yes"
    assert reaches_entrypoint(g, "a") == "yes"


def test_reaches_entrypoint_no_when_only_called_by_self(tmp_path):
    (tmp_path / "lib.py").write_text(
        "def main():\n"
        "    pass\n"
        "\n"
        "def orphan():\n"
        "    sibling()\n"
        "\n"
        "def sibling():\n"
        "    pass\n"
    )
    g = index_project(tmp_path)
    # orphan and sibling are not called from main; only orphan -> sibling
    # but orphan has no callers from main.
    assert reaches_entrypoint(g, "sibling") == "no"


def test_reaches_unknown_for_missing_func(tmp_path):
    (tmp_path / "x.py").write_text("def foo(): pass\n")
    g = index_project(tmp_path)
    assert reaches_entrypoint(g, "nonexistent") == "unknown"


def test_skips_test_dirs(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text("def test_thing(): pass\n")
    (tmp_path / "app.py").write_text("def main(): pass\n")
    g = index_project(tmp_path)
    # Tests dir IS indexed (we don't skip it at the graph level — the
    # reachability classifier handles dead paths via _is_dead_path).
    # We just want to make sure both files get visited.
    assert g.indexed_files == 2
