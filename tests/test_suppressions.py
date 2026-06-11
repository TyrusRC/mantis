from __future__ import annotations

from pathlib import Path

import pytest

from mantis.scan import Finding
from mantis.suppressions import (
    SuppressionParseError,
    SuppressionRule,
    apply_suppressions,
    load_suppressions,
    severity_at_or_above,
)


def _f(rule_id: str, path: str, severity: str = "ERROR") -> Finding:
    return Finding(
        rule_id=rule_id, severity=severity, confidence="HIGH",
        path=path, start_line=1, end_line=1, message="x",
    )


def test_load_missing_file_returns_empty(tmp_path: Path):
    assert load_suppressions(tmp_path) == []


def test_load_basic(tmp_path: Path):
    (tmp_path / ".mantisignore").write_text(
        "- rule_id: web-a03-sql-injection\n"
        "  path: \"tests/**\"\n"
        "  reason: test fixtures\n"
        "- rule_id: secret-aws\n"
    )
    rules = load_suppressions(tmp_path)
    assert len(rules) == 2
    assert rules[0].rule_id == "web-a03-sql-injection"
    assert rules[0].path == "tests/**"
    assert rules[0].reason == "test fixtures"
    assert rules[1].path is None


def test_load_invalid_top_level(tmp_path: Path):
    (tmp_path / ".mantisignore").write_text("rule_id: x\n")
    with pytest.raises(SuppressionParseError):
        load_suppressions(tmp_path)


def test_load_invalid_entry(tmp_path: Path):
    (tmp_path / ".mantisignore").write_text("- just-a-string\n")
    with pytest.raises(SuppressionParseError):
        load_suppressions(tmp_path)


def test_apply_no_rules_passes_all_through(tmp_path: Path):
    findings = [_f("r1", "a.py"), _f("r2", "b.py")]
    kept, dropped = apply_suppressions(findings, [], tmp_path)
    assert kept == findings
    assert dropped == []


def test_apply_rule_id_only(tmp_path: Path):
    findings = [_f("r1", "a.py"), _f("r2", "b.py")]
    rules = [SuppressionRule(rule_id="r1")]
    kept, dropped = apply_suppressions(findings, rules, tmp_path)
    assert [f.rule_id for f in kept] == ["r2"]
    assert [f.rule_id for f in dropped] == ["r1"]


def test_apply_rule_id_suffix(tmp_path: Path):
    """Scanner reports fully-qualified rule IDs like
    'mantis.resources.rules.iac.iac-k8s-host-network'. Users want to write
    the short form in .mantisignore."""
    findings = [
        _f("mantis.resources.rules.iac.iac-k8s-host-network", "k8s/x.yaml"),
        _f("other-rule", "k8s/x.yaml"),
    ]
    rules = [SuppressionRule(rule_id="iac-k8s-host-network")]
    kept, dropped = apply_suppressions(findings, rules, tmp_path)
    assert [f.rule_id for f in kept] == ["other-rule"]
    assert [f.rule_id for f in dropped] == [
        "mantis.resources.rules.iac.iac-k8s-host-network",
    ]


def test_apply_rule_id_glob(tmp_path: Path):
    findings = [_f("iac-k8s-privileged", "x"), _f("iac-tf-rds", "x"), _f("web-a03", "x")]
    rules = [SuppressionRule(rule_id="iac-*")]
    kept, _ = apply_suppressions(findings, rules, tmp_path)
    assert [f.rule_id for f in kept] == ["web-a03"]


def test_apply_path_glob(tmp_path: Path):
    findings = [
        _f("r1", "tests/foo.py"),
        _f("r1", "src/bar.py"),
    ]
    rules = [SuppressionRule(rule_id="r1", path="tests/**")]
    kept, dropped = apply_suppressions(findings, rules, tmp_path)
    assert [f.path for f in kept] == ["src/bar.py"]
    assert [f.path for f in dropped] == ["tests/foo.py"]


def test_apply_absolute_path_matched_via_relative_glob(tmp_path: Path):
    abs_path = str((tmp_path / "tests" / "x.py"))
    findings = [_f("r1", abs_path)]
    rules = [SuppressionRule(rule_id="r1", path="tests/*")]
    kept, dropped = apply_suppressions(findings, rules, tmp_path)
    assert kept == []
    assert len(dropped) == 1


def test_severity_at_or_above():
    assert severity_at_or_above("ERROR", "high")
    assert severity_at_or_above("WARNING", "medium")
    assert severity_at_or_above("INFO", "low")
    assert not severity_at_or_above("WARNING", "high")
    assert not severity_at_or_above("INFO", "medium")
    assert not severity_at_or_above("nonsense", "high")
