"""Tests for the experimental Tree-of-AST hunter."""
from __future__ import annotations

from pathlib import Path

import pytest

from mantis.agents import Agent
from mantis.providers import LLMResponse
from mantis.scan import Finding
from mantis.slice import Slice, SliceChunk
from mantis.toast import (
    ToastFinding,
    build_user_prompt,
    hunt_on_slice,
    parse_toast_response,
    vote_quorum_filter,
)


def _slice():
    f = Finding(rule_id="r1", severity="ERROR", confidence="HIGH",
                path="app.py", start_line=5, end_line=6, message="m")
    return Slice(finding=f, sink_func="vuln", sink_file="app.py", sink_line=5,
                 chunks=[SliceChunk(file="app.py", start_line=4, end_line=10,
                                    role="sink", func="vuln",
                                    code="def vuln(x):\n    eval(x)\n")],
                 reachability="yes")


def _agent():
    return Agent(name="toast-hunter", description="", tier="deep", model="opus",
                 tools=[], body="be a ToAST hunter", path=Path("/x"))


SAMPLE_RESPONSE = """TOAST_FINDINGS:

[1] source: req.body.cmd at app.py:3
    sink:   eval at app.py:5
    flow:   request body field reaches eval through no sanitization
    verdict: PLAUSIBLE
    cwe: CWE-94
    impact: Attacker controls eval input; arbitrary code execution.

[2] source: env.API_KEY at app.py:7
    sink:   logger.info at app.py:9
    flow:   secret logged
    verdict: UNCERTAIN
    cwe: CWE-532
    impact: Secret may appear in logs.

TOTAL_NEW: 1
NOTES: original eval finding excluded.
"""


def test_parse_finds_two_blocks():
    findings = parse_toast_response(SAMPLE_RESPONSE)
    assert len(findings) == 2
    assert findings[0].verdict == "PLAUSIBLE"
    assert findings[0].cwe == "CWE-94"
    assert "eval" in findings[0].sink
    assert findings[1].verdict == "UNCERTAIN"


def test_parse_empty_findings_returns_empty():
    assert parse_toast_response("TOAST_FINDINGS: none\nNOTES: ok") == []


def test_parse_garbage_returns_empty():
    assert parse_toast_response("random text with no blocks") == []


def test_vote_quorum_keeps_majority():
    s1 = [ToastFinding(source="X", sink="Y", flow="f", verdict="PLAUSIBLE", impact="long impact a")]
    s2 = [ToastFinding(source="x ", sink="y", flow="f", verdict="PLAUSIBLE", impact="long impact bb")]
    s3 = [ToastFinding(source="other", sink="other", flow="f", verdict="PLAUSIBLE")]
    out = vote_quorum_filter([s1, s2, s3], quorum=2)
    assert len(out) == 1
    # Picked the longer-impact representative.
    assert out[0].impact == "long impact bb"


def test_vote_quorum_skips_uncertain():
    s1 = [ToastFinding(source="X", sink="Y", flow="f", verdict="UNCERTAIN")]
    s2 = [ToastFinding(source="X", sink="Y", flow="f", verdict="UNCERTAIN")]
    assert vote_quorum_filter([s1, s2], quorum=1) == []


def test_vote_quorum_normalizes_whitespace_and_case():
    s1 = [ToastFinding(source="Req.Body", sink="EVAL", flow="f", verdict="PLAUSIBLE")]
    s2 = [ToastFinding(source="req.body", sink="eval ", flow="f", verdict="PLAUSIBLE")]
    out = vote_quorum_filter([s1, s2], quorum=2)
    assert len(out) == 1


class _MultiProvider:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def complete(self, tier, system, user, max_tokens=4096, temperature=0.2):
        self.calls.append({"tier": tier, "temperature": temperature})
        text = self.responses.pop(0) if self.responses else ""
        return LLMResponse(text=text, tokens_in=12, tokens_out=22, model="fake")


def test_hunt_on_slice_quorum_reached():
    # Two samples both report the same finding -> quorum=2 keeps it.
    p = _MultiProvider([SAMPLE_RESPONSE] * 3)
    result = hunt_on_slice(p, "system", _slice(), samples=3, quorum=2)
    assert len(p.calls) == 3
    assert p.calls[0]["tier"] == "deep"
    # Temperature should be > 0 so the samples diverge.
    assert p.calls[0]["temperature"] > 0
    assert len(result.new_findings) == 1
    assert result.tokens_in == 36
    assert result.notes == ""


def test_hunt_on_slice_no_quorum():
    # Only one sample reports it; quorum=2 drops it.
    diff_response = """TOAST_FINDINGS:

[1] source: req.cookies.session at app.py:1
    sink:   open at app.py:4
    flow:   cookie used as filename
    verdict: PLAUSIBLE
    cwe: CWE-22
    impact: arbitrary file read

TOTAL_NEW: 1
"""
    p = _MultiProvider([SAMPLE_RESPONSE, diff_response, "TOAST_FINDINGS: none"])
    result = hunt_on_slice(p, "system", _slice(), samples=3, quorum=2)
    assert result.new_findings == []
    assert "quorum" in result.notes


def test_hunt_on_slice_handles_errors():
    class Boom:
        def complete(self, *a, **k):
            raise RuntimeError("nope")
    result = hunt_on_slice(Boom(), "system", _slice(), samples=2, quorum=1)
    assert result.error is not None
    assert result.new_findings == []


def test_build_user_prompt_includes_slice_and_disclaimer():
    sl = _slice()
    prompt = build_user_prompt(sl)
    assert "do not re-flag" in prompt.lower()
    assert "SLICE" in prompt
    assert "TOAST_FINDINGS" in prompt
