"""End-to-end pipeline test with a mocked SAST binary and mocked LLM provider."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from mantis.config import Config
from mantis.runner import Pipeline


REPO = Path(__file__).resolve().parent.parent


@pytest.fixture
def fake_sast(tmp_path):
    """Create a fake scanner binary that emits a fixed JSON result."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "opengrep"
    payload = {
        "results": [{
            "check_id": "test-rule",
            "path": "app.py",
            "start": {"line": 5, "col": 1},
            "end":   {"line": 5, "col": 20},
            "extra": {
                "severity": "ERROR",
                "message": "test finding",
                "metadata": {"confidence": "HIGH", "cwe": "CWE-89"},
            },
        }],
    }
    fake.write_text(
        "#!/usr/bin/env python3\nimport json\n"
        f"print(json.dumps({payload!r}))\n"
    )
    fake.chmod(0o755)
    return bin_dir, fake


class _StubProvider:
    """Drop-in for mantis.providers.Provider that does not need litellm."""

    def __init__(self, config: Config):
        self.config = config
        self.calls: list = []

    def complete(self, tier, system, user, max_tokens=4096, temperature=0.2):
        from mantis.providers import LLMResponse
        finding_id = "test-rule@app.py:5"
        self.calls.append({"tier": tier})
        return LLMResponse(
            text=f"{finding_id} | TRUE | test verdict",
            tokens_in=5, tokens_out=8, model="fake",
        )


@pytest.fixture
def patched_provider(monkeypatch):
    captured: list = []

    def _factory(cfg):
        p = _StubProvider(cfg)
        captured.append(p)
        return p

    monkeypatch.setattr("mantis.providers.Provider", _factory)
    return captured


def _cfg() -> Config:
    return Config(
        models={"fast": "x/y", "mid": "x/y", "deep": "x/y"},
        provider="google",
        sast_bin="auto",
        max_findings=100,
    )


def test_pipeline_end_to_end(tmp_path, fake_sast, patched_provider, monkeypatch):
    bin_dir, _ = fake_sast
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.delenv("AUDIT_SAST_BIN", raising=False)

    target = tmp_path / "proj"
    target.mkdir()
    (target / "app.py").write_text("x = 1\ny = 2\nz = 3\nq = 4\nbad code here\n")

    from mantis.agents import discover_agents
    from mantis.sast import resolve_sast_binary
    pipe = Pipeline(
        target=target,
        config=_cfg(),
        sast_bin=resolve_sast_binary("auto"),
        agents=discover_agents(REPO / "agents"),
        mode="quick",
    )
    rc = pipe.run()
    assert rc == 0
    report = (target / "security-audit-report.md").read_text()
    assert "test-rule" in report
    assert "Critical/High" in report
    assert len(patched_provider) == 1
    assert patched_provider[0].calls[0]["tier"] == "fast"


def test_pipeline_no_findings(tmp_path, fake_sast, monkeypatch):
    bin_dir, fake = fake_sast
    fake.write_text("#!/usr/bin/env python3\nprint('{\"results\": []}')\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.delenv("AUDIT_SAST_BIN", raising=False)

    target = tmp_path / "proj"
    target.mkdir()

    from mantis.agents import discover_agents
    from mantis.sast import resolve_sast_binary
    pipe = Pipeline(
        target=target,
        config=_cfg(),
        sast_bin=resolve_sast_binary("auto"),
        agents=discover_agents(REPO / "agents"),
        mode="quick",
    )
    rc = pipe.run()
    assert rc == 0
    report = (target / "security-audit-report.md").read_text()
    assert "no findings" in report.lower()


def test_pipeline_skip_llm_bypasses_provider(tmp_path, fake_sast, monkeypatch):
    """With skip_llm=True the pipeline should not import / construct a Provider."""
    bin_dir, _ = fake_sast
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.delenv("AUDIT_SAST_BIN", raising=False)

    def boom(cfg):
        raise AssertionError("Provider must not be constructed when skip_llm=True")

    monkeypatch.setattr("mantis.providers.Provider", boom)

    target = tmp_path / "proj"
    target.mkdir()
    (target / "app.py").write_text("x = 1\n" * 10)

    from mantis.agents import discover_agents
    from mantis.sast import resolve_sast_binary
    pipe = Pipeline(
        target=target,
        config=_cfg(),
        sast_bin=resolve_sast_binary("auto"),
        agents=discover_agents(REPO / "agents"),
        mode="quick",
        skip_llm=True,
    )
    assert pipe.run() == 0
    report = (target / "security-audit-report.md").read_text()
    assert "LLM stages skipped" in report
    # Raw finding from the fake scanner is still recorded.
    assert "test-rule" in report


def test_pipeline_unknown_mode_returns_error(tmp_path, fake_sast, monkeypatch):
    bin_dir, _ = fake_sast
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.delenv("AUDIT_SAST_BIN", raising=False)

    target = tmp_path / "proj"
    target.mkdir()

    from mantis.agents import discover_agents
    from mantis.sast import resolve_sast_binary
    pipe = Pipeline(
        target=target,
        config=_cfg(),
        sast_bin=resolve_sast_binary("auto"),
        agents=discover_agents(REPO / "agents"),
        mode="invalid-mode",
    )
    assert pipe.run() == 2
