"""Tests for the dual-chain triage path (G2 — Semgrep Assistant pattern)."""
from __future__ import annotations

from pathlib import Path

import pytest

from mantis.agents import Agent
from mantis.providers import LLMResponse
from mantis.scan import Finding
from mantis.triage import (
    reconcile_dual,
    triage_all,
    triage_finding_dual,
)


def _finding(path="app.py", line=2):
    return Finding(rule_id="r1", severity="ERROR", confidence="HIGH",
                   path=path, start_line=line, end_line=line + 1,
                   message="bad", metadata={})


def _agent():
    return Agent(name="triage-analyst", description="", tier="fast",
                 model="haiku", tools=[], body="be a triage analyst",
                 path=Path("/x"))


class _DualProvider:
    """Returns one response per call in order; tracks system prompt prefixes."""

    def __init__(self, responses: list[str]):
        self.responses = list(responses)
        self.calls = []

    def complete(self, tier, system, user, max_tokens=4096, temperature=0.2):
        self.calls.append({"tier": tier, "system_head": system[:200]})
        text = self.responses.pop(0) if self.responses else ""
        return LLMResponse(text=text, tokens_in=5, tokens_out=10, model="fake")


# ---- reconcile_dual ----

def test_reconcile_both_true():
    assert reconcile_dual("TRUE", "TRUE") == "TRUE"


def test_reconcile_both_false():
    assert reconcile_dual("FALSE", "FALSE") == "FALSE"


def test_reconcile_disagreement_escalates():
    assert reconcile_dual("TRUE", "FALSE") == "NEEDS-DEEP"
    assert reconcile_dual("FALSE", "TRUE") == "NEEDS-DEEP"


def test_reconcile_needs_deep_wins():
    assert reconcile_dual("NEEDS-DEEP", "TRUE") == "NEEDS-DEEP"
    assert reconcile_dual("TRUE", "NEEDS-DEEP") == "NEEDS-DEEP"
    assert reconcile_dual("NEEDS-DEEP", "NEEDS-DEEP") == "NEEDS-DEEP"


def test_reconcile_error_handling():
    assert reconcile_dual("ERROR", "ERROR") == "ERROR"
    # one error -> the surviving verdict wins
    assert reconcile_dual("ERROR", "TRUE") == "TRUE"
    assert reconcile_dual("FALSE", "ERROR") == "FALSE"


# ---- triage_finding_dual ----

def test_dual_both_chains_called(tmp_path):
    (tmp_path / "app.py").write_text("def f():\n    bad()\n")
    p = _DualProvider([
        "r1@app.py:2 | TRUE | reaches sink",
        "r1@app.py:2 | FALSE | sanitized inline",
    ])
    result = triage_finding_dual(p, "system body", _finding(), tmp_path)
    assert len(p.calls) == 2
    # First call should have the TP prefix in system head.
    assert "TRUE POSITIVE" in p.calls[0]["system_head"]
    assert "FALSE POSITIVE" in p.calls[1]["system_head"]
    # Disagreement -> NEEDS-DEEP
    assert result.verdict == "NEEDS-DEEP"
    assert "TP=TRUE" in result.reason
    assert "FP=FALSE" in result.reason


def test_dual_agreement_yields_clear_verdict(tmp_path):
    (tmp_path / "app.py").write_text("def f():\n    bad()\n")
    p = _DualProvider([
        "r1@app.py:2 | TRUE | sink hit",
        "r1@app.py:2 | TRUE | no sanitizer found",
    ])
    result = triage_finding_dual(p, "system", _finding(), tmp_path)
    assert result.verdict == "TRUE"


def test_dual_provider_error_one_chain(tmp_path):
    (tmp_path / "app.py").write_text("def f(): pass\n")

    class FlakyProvider:
        def __init__(self):
            self.calls = 0

        def complete(self, *a, **k):
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("network down")
            return LLMResponse(text="r1@app.py:2 | FALSE | safe",
                               tokens_in=5, tokens_out=5, model="x")

    result = triage_finding_dual(FlakyProvider(), "sys", _finding(), tmp_path)
    # TP errored, FP returned FALSE -> reconcile picks FALSE
    assert result.verdict == "FALSE"


def test_triage_all_uses_dual_when_mode_dual(tmp_path):
    (tmp_path / "app.py").write_text("def f():\n    bad()\n")
    p = _DualProvider([
        "r1@app.py:2 | TRUE | x",
        "r1@app.py:2 | TRUE | x",
        "r1@app.py:2 | TRUE | x",
        "r1@app.py:2 | TRUE | x",
    ])
    findings = [_finding(line=2), _finding(line=2)]
    results = triage_all(findings, [_agent()], p, tmp_path, mode="dual")
    assert len(results) == 2
    assert len(p.calls) == 4  # 2 findings * 2 chains


def test_triage_all_uses_single_by_default(tmp_path):
    (tmp_path / "app.py").write_text("def f():\n    bad()\n")
    p = _DualProvider(["r1@app.py:2 | TRUE | x"] * 4)
    results = triage_all([_finding()], [_agent()], p, tmp_path)
    assert len(p.calls) == 1
