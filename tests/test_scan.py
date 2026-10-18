from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

import mantis.scan as scan_mod
from mantis.scan import (
    Finding,
    ScanError,
    dedupe_findings,
    filter_valid_rule_files,
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


def test_filter_valid_rule_files_splits_correctly(monkeypatch):
    # Odd-indexed files are "invalid" — proves results land in the right
    # bucket regardless of which thread finishes first.
    files = [Path(f"rule{i}.yaml") for i in range(10)]

    def fake_validate(sast_bin, path, timeout=30):
        return int(path.stem.removeprefix("rule")) % 2 == 0

    monkeypatch.setattr(scan_mod, "validate_rule_file", fake_validate)
    valid, invalid = filter_valid_rule_files(files, "opengrep")
    assert sorted(valid, key=str) == [Path(f"rule{i}.yaml") for i in range(0, 10, 2)]
    assert sorted(invalid, key=str) == [Path(f"rule{i}.yaml") for i in range(1, 10, 2)]
    assert len(valid) + len(invalid) == len(files)


def test_filter_valid_rule_files_runs_concurrently_not_sequentially(monkeypatch):
    # The whole point of parallelizing: N files that each take `delay` should
    # take roughly `delay` total, not N * delay. A regression back to a plain
    # for-loop would make this test take ~1s instead of ~0.15s.
    files = [Path(f"rule{i}.yaml") for i in range(8)]
    delay = 0.15

    def fake_validate(sast_bin, path, timeout=30):
        time.sleep(delay)
        return True

    monkeypatch.setattr(scan_mod, "validate_rule_file", fake_validate)
    start = time.monotonic()
    valid, invalid = filter_valid_rule_files(files, "opengrep", max_workers=8)
    elapsed = time.monotonic() - start

    assert len(valid) == len(files)
    assert invalid == []
    assert elapsed < delay * len(files) / 2, (
        f"took {elapsed:.2f}s for {len(files)} files at {delay}s each — "
        "looks sequential, not parallel"
    )
