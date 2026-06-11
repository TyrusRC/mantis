from __future__ import annotations

from pathlib import Path

from mantis.dedup import cluster_findings
from mantis.scan import Finding


def _f(rule_id: str, path: str, line: int) -> Finding:
    return Finding(
        rule_id=rule_id, severity="ERROR", confidence="HIGH",
        path=path, start_line=line, end_line=line, message="x",
    )


def test_cluster_collapses_same_rule_in_same_function(tmp_path: Path):
    src = tmp_path / "app.py"
    src.write_text(
        "def helper(s):\n"
        "    x = run(s)\n"
        "    y = run(s)\n"
        "    z = run(s)\n"
        "    return x, y, z\n"
    )
    findings = [
        _f("py-sqli", str(src), 2),
        _f("py-sqli", str(src), 3),
        _f("py-sqli", str(src), 4),
    ]
    clusters, stats = cluster_findings(findings, tmp_path)
    assert stats == {"total": 3, "clusters": 1, "collapsed": 2}
    assert clusters[0].representative.start_line == 2
    assert len(clusters[0].siblings) == 2
    assert clusters[0].enclosing_function == "helper"


def test_cluster_keeps_different_rules_distinct(tmp_path: Path):
    src = tmp_path / "app.py"
    src.write_text("def f():\n    a = 1\n    b = 2\n")
    findings = [_f("rule-a", str(src), 2), _f("rule-b", str(src), 3)]
    clusters, stats = cluster_findings(findings, tmp_path)
    assert stats["clusters"] == 2
    assert stats["collapsed"] == 0


def test_cluster_keeps_different_files_distinct(tmp_path: Path):
    (tmp_path / "a.py").write_text("def f():\n    x = 1\n")
    (tmp_path / "b.py").write_text("def f():\n    x = 1\n")
    findings = [
        _f("py-sqli", str(tmp_path / "a.py"), 2),
        _f("py-sqli", str(tmp_path / "b.py"), 2),
    ]
    clusters, stats = cluster_findings(findings, tmp_path)
    assert stats["clusters"] == 2


def test_cluster_picks_lowest_line_as_representative(tmp_path: Path):
    src = tmp_path / "app.py"
    src.write_text("def helper():\n    a = 1\n    b = 2\n    c = 3\n")
    findings = [
        _f("rule", str(src), 4),
        _f("rule", str(src), 2),
        _f("rule", str(src), 3),
    ]
    clusters, _ = cluster_findings(findings, tmp_path)
    assert clusters[0].representative.start_line == 2
    assert [s.start_line for s in clusters[0].siblings] == [4, 3]


def test_cluster_empty_input(tmp_path: Path):
    clusters, stats = cluster_findings([], tmp_path)
    assert clusters == []
    assert stats == {"total": 0, "clusters": 0, "collapsed": 0}
