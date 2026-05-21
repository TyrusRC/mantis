from __future__ import annotations

import json
from pathlib import Path

import pytest

from mantis.scan import (
    Finding,
    ScanError,
    ScanOutput,
    dedupe_findings,
    parse_scan_output,
)


def _sample_output(results, errors=None):
    return json.dumps({
        "results": results,
        "errors": errors or [],
        "paths": {"scanned": []},
    })


def test_parse_empty_output():
    out = parse_scan_output("")
    assert out.findings == []
    assert out.errors == []
    out2 = parse_scan_output(_sample_output([]))
    assert out2.findings == []


def test_parse_single_finding():
    out = _sample_output([{
        "check_id": "rule-x",
        "path": "src/a.py",
        "start": {"line": 10, "col": 1},
        "end":   {"line": 12, "col": 1},
        "extra": {
            "severity": "ERROR",
            "message": "SQL injection via concatenation",
            "metadata": {"confidence": "HIGH", "cwe": "CWE-89"},
        },
    }])
    res = parse_scan_output(out)
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.rule_id == "rule-x"
    assert f.severity == "ERROR"
    assert f.confidence == "HIGH"
    assert f.path == "src/a.py"
    assert f.start_line == 10
    assert f.metadata["cwe"] == "CWE-89"
    assert f.id == "rule-x@src/a.py:10"


def test_parse_handles_missing_metadata():
    out = _sample_output([{
        "check_id": "rule-y",
        "path": "src/b.py",
        "start": {"line": 1},
        "end": {"line": 1},
        "extra": {"severity": "WARNING", "message": "msg"},
    }])
    f = parse_scan_output(out).findings[0]
    assert f.confidence == "UNKNOWN"
    assert f.metadata == {}


def test_parse_surfaces_scanner_errors():
    raw = _sample_output([], errors=[
        {"message": "rule load failed for rules/x.yaml"},
        "literal error string",
    ])
    res = parse_scan_output(raw)
    assert res.findings == []
    assert len(res.errors) == 2
    assert "rule load failed" in res.errors[0]
    assert res.errors[1] == "literal error string"


def test_dedupe_same_rule_path_line():
    a = Finding(rule_id="r", severity="E", confidence="H", path="p",
                start_line=5, end_line=6, message="m")
    b = Finding(rule_id="r", severity="E", confidence="H", path="p",
                start_line=5, end_line=8, message="other")
    c = Finding(rule_id="r", severity="E", confidence="H", path="p",
                start_line=9, end_line=10, message="m")
    out = dedupe_findings([a, b, c])
    assert len(out) == 2
    assert out[0].start_line == 5
    assert out[1].start_line == 9


def test_parse_invalid_json_raises():
    with pytest.raises(ScanError):
        parse_scan_output("{not json")
