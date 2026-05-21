from __future__ import annotations

from pathlib import Path

from mantis.report import RunMeta, write_report
from mantis.scan import Finding
from mantis.triage import TriageResult


def _make_finding(sev="ERROR", path="src/a.py", line=10, cwe="CWE-89"):
    return Finding(rule_id="rule-x", severity=sev, confidence="HIGH",
                   path=path, start_line=line, end_line=line + 1,
                   message="SQL concat", metadata={"cwe": cwe, "owasp": "A03:2025 Injection"})


def _triage(finding, verdict="TRUE", reason="confirmed"):
    return TriageResult(finding=finding, verdict=verdict, reason=reason, raw_response="")


def test_report_writes_all_sections(tmp_path):
    findings = [
        _make_finding(sev="ERROR", line=10),
        _make_finding(sev="WARNING", path="src/b.py", line=20),
    ]
    triage = [_triage(findings[0], "TRUE"), _triage(findings[1], "FALSE", "in test dir")]
    meta = RunMeta(
        target=tmp_path,
        mode="quick",
        packs=["fast"],
        sast_bin="opengrep",
        provider="google",
        duration_seconds=42.5,
        tokens_in=1234,
        tokens_out=567,
    )
    out = write_report(tmp_path / "report.md", meta, findings, triage)
    text = out.read_text()
    assert "Security Audit Report" in text
    assert "**Mode:** quick" in text
    assert "**SAST:** opengrep" in text
    assert "**Provider:** google" in text
    assert "## Summary" in text
    assert "## Findings" in text
    assert "rule-x" in text
    assert "src/a.py:10" in text
    assert "Triaged out" in text
    assert "CWE-89" in text


def test_report_handles_empty_findings(tmp_path):
    meta = RunMeta(
        target=tmp_path, mode="quick", packs=["fast"],
        sast_bin="opengrep", provider=None,
        duration_seconds=1.0, tokens_in=0, tokens_out=0,
        notes=["no findings"],
    )
    out = write_report(tmp_path / "report.md", meta, [], [])
    text = out.read_text()
    assert "## Summary" in text
    assert "## Notes" in text
    assert "no findings" in text


def test_report_status_incomplete_shown(tmp_path):
    meta = RunMeta(
        target=tmp_path, mode="deep", packs=["deep"],
        sast_bin="semgrep", provider="anthropic",
        duration_seconds=10, tokens_in=100, tokens_out=50,
        status="incomplete",
        notes=["triage budget exceeded"],
    )
    out = write_report(tmp_path / "report.md", meta, [], [])
    text = out.read_text()
    assert "STATUS: incomplete" in text


def test_report_collision_rotates_to_backup(tmp_path):
    # Write an initial report, then a second one — the first must be renamed
    # to a .bak file, not silently overwritten.
    meta = RunMeta(target=tmp_path, mode="quick", packs=["fast"],
                   sast_bin="opengrep", provider=None,
                   duration_seconds=1, tokens_in=0, tokens_out=0)
    out = tmp_path / "report.md"
    write_report(out, meta, [], [])
    out.write_text("V1 report\n")    # mark v1
    write_report(out, meta, [], [])
    assert out.read_text().startswith("# Security Audit Report")
    backups = list(tmp_path.glob("report.*.bak.md"))
    assert backups, "expected a rotated .bak file"
    assert "V1 report" in backups[0].read_text()


def test_report_buckets_by_severity(tmp_path):
    f_high = _make_finding(sev="ERROR", line=1)
    f_med  = _make_finding(sev="WARNING", path="src/m.py", line=2)
    f_low  = _make_finding(sev="INFO", path="src/l.py", line=3)
    triage = [_triage(f_high), _triage(f_med, "NEEDS-DEEP", "unclear"),
              _triage(f_low, "FALSE", "comment")]
    meta = RunMeta(target=tmp_path, mode="deep", packs=["deep"],
                   sast_bin="opengrep", provider=None,
                   duration_seconds=5, tokens_in=0, tokens_out=0)
    out = write_report(tmp_path / "r.md", meta, [f_high, f_med, f_low], triage)
    text = out.read_text()
    assert "Critical/High" in text
    assert "Medium" in text
    assert "Low" in text
    # FALSE finding goes into "Triaged out" section, not findings
    assert "Triaged out" in text
