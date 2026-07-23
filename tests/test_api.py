"""Programmatic API tests: `from mantis import audit` with a mocked scanner."""
from __future__ import annotations

import os
from pathlib import Path

import pytest


def _write_fake_sast(tmp_path, results):
    """Create a fake scanner binary on a fresh bin dir that emits `results`."""
    import json

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "opengrep"
    payload = {"results": results}
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import sys, json\n"
        # `--validate` (rule-file validation) must succeed quietly.
        "if '--validate' in sys.argv:\n"
        "    sys.exit(0)\n"
        f"print(json.dumps({payload!r}))\n"
    )
    fake.chmod(0o755)
    return bin_dir


_ONE_FINDING = [{
    "check_id": "test-rule",
    "path": "app.py",
    "start": {"line": 5, "col": 1},
    "end":   {"line": 5, "col": 20},
    "extra": {
        "severity": "ERROR",
        "message": "hardcoded secret",
        "metadata": {"confidence": "HIGH", "cwe": "CWE-798",
                     "masvs-v2": ["MASVS-STORAGE-1"]},
    },
}]


@pytest.fixture
def target(tmp_path, monkeypatch):
    bin_dir = _write_fake_sast(tmp_path, _ONE_FINDING)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.delenv("AUDIT_SAST_BIN", raising=False)
    monkeypatch.delenv("MANTIS_SAST_BIN", raising=False)
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "app.py").write_text("x = 1\ny = 2\nz = 3\nq = 4\nSECRET = 'abc'\n")
    return proj


def test_audit_returns_native_sast_records(target):
    from mantis import audit

    findings = audit(str(target))
    assert len(findings) == 1
    f = findings[0]
    assert f["rule_id"] == "test-rule"
    assert f["severity"] == "ERROR"
    assert f["path"] == "app.py"
    assert f["start_line"] == 5
    assert f["message"] == "hardcoded secret"
    assert f["metadata"]["masvs-v2"] == ["MASVS-STORAGE-1"]
    assert f["verdict"] is None  # SAST-only default


def test_audit_sast_only_needs_no_provider(target, monkeypatch):
    """Default (llm=False) must never construct an LLM provider."""
    def boom(cfg):
        raise AssertionError("Provider must not be constructed when llm=False")

    monkeypatch.setattr("mantis.providers.Provider", boom)
    from mantis import audit

    findings = audit(str(target))
    assert findings and findings[0]["verdict"] is None


def test_audit_writes_no_report_or_history(target):
    from mantis import audit

    audit(str(target))
    # The library API is side-effect-free: no CLI report, no run history.
    assert not (target / "security-audit-report.md").exists()
    assert not (target / ".mantis").exists()


def test_audit_not_a_directory_raises(tmp_path):
    from mantis import audit

    afile = tmp_path / "not_a_dir.py"
    afile.write_text("x = 1\n")
    with pytest.raises(NotADirectoryError):
        audit(str(afile))


def test_audit_llm_attaches_triage_verdict(target, monkeypatch):
    from mantis.config import Config
    from mantis.providers import LLMResponse

    class _StubProvider:
        def __init__(self, config):
            self.config = config

        def complete(self, tier, system, user, max_tokens=4096, temperature=0.2):
            return LLMResponse(
                text="test-rule@app.py:5 | TRUE | exploitable",
                tokens_in=5, tokens_out=8, model="fake",
            )

    monkeypatch.setattr("mantis.providers.Provider", lambda cfg: _StubProvider(cfg))
    monkeypatch.setattr(
        "mantis.config.load_config",
        lambda target, explicit=None, *, skip_provider_validation=False: Config(
            models={"fast": "x/y", "mid": "x/y", "deep": "x/y"},
            provider="google", sast_bin="auto", max_findings=100,
        ),
    )

    from mantis import audit

    findings = audit(str(target), llm=True)
    assert len(findings) == 1
    assert findings[0]["verdict"] == "TRUE"
