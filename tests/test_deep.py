from __future__ import annotations

from pathlib import Path

import pytest

from mantis.agents import Agent
from mantis.deep import (
    DeepResult,
    build_user_prompt,
    deep_review,
    deep_review_many,
    parse_deep_output,
)
from mantis.providers import LLMResponse
from mantis.scan import Finding
from mantis.slice import Slice, SliceChunk


def _slice(finding_id="r1@a.py:5") -> Slice:
    f = Finding(rule_id="r1", severity="ERROR", confidence="HIGH",
                path="a.py", start_line=5, end_line=6, message="m")
    return Slice(
        finding=f,
        sink_func="vulnerable",
        sink_file="a.py",
        sink_line=5,
        chunks=[SliceChunk(file="a.py", start_line=4, end_line=10, role="sink",
                           func="vulnerable", code="def vulnerable(x):\n    eval(x)\n")],
        reachability="yes",
    )


def _agent(body):
    return Agent(name="deep-reviewer", description="", tier="deep", model="opus",
                 tools=[], body=body, path=Path("/x"))


def test_parse_full_response():
    text = """FINDING: r1@a.py:5
VERDICT: confirmed
SEVERITY: high
CVSS: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  SCORE: 9.8
MAPPING:
  OWASP: A03:2025 Injection
  CWE: CWE-94
  CVE: none
IMPACT: Attacker controls input to eval, achieving RCE.
POC:
  1. POST /run with body=__import__('os').system('id')
  2. Observe RCE in response logs
RECOMMENDATION: fix-author
NOTES: very direct path; sanitization absent
"""
    r = parse_deep_output(text, "r1@a.py:5")
    assert r.verdict == "confirmed"
    assert r.severity == "high"
    assert r.cvss_score == "9.8"
    assert r.mapping["CWE"] == "CWE-94"
    assert r.mapping["OWASP"] == "A03:2025 Injection"
    assert "RCE" in r.impact
    assert len(r.poc) == 2
    assert r.recommendation == "fix-author"
    assert "sanitization" in r.notes


def test_parse_insufficient_slice():
    text = "INSUFFICIENT_SLICE: missing caller of validate_input"
    r = parse_deep_output(text, "x")
    assert r.verdict == "insufficient"
    assert "validate_input" in r.insufficient_reason


def test_parse_rejected():
    text = "FINDING: x\nVERDICT: rejected\nIMPACT: pattern matches but input is constant\n"
    r = parse_deep_output(text, "x")
    assert r.verdict == "rejected"


def test_parse_unknown_response_is_error():
    r = parse_deep_output("nonsense response", "x")
    assert r.verdict == "error"


def test_build_user_prompt_includes_slice():
    sl = _slice()
    prompt = build_user_prompt(sl, "")
    assert "ORIGINAL FINDING" in prompt
    assert "SLICE:" in prompt
    assert "vulnerable" in prompt


def test_build_user_prompt_with_checklist_caps_size():
    sl = _slice()
    checklist = "x" * 50000
    prompt = build_user_prompt(sl, checklist)
    assert len(prompt) < 100000  # checklist gets truncated to 8000 chars


class _FakeProvider:
    def __init__(self, text):
        self.text = text
        self.calls = []

    def complete(self, tier, system, user, max_tokens=4096, temperature=0.2):
        self.calls.append({"tier": tier})
        return LLMResponse(text=self.text, tokens_in=10, tokens_out=20, model="fake")


def test_deep_review_happy_path():
    provider = _FakeProvider("FINDING: r1@a.py:5\nVERDICT: confirmed\nSEVERITY: high\n")
    result = deep_review(provider, "be a deep reviewer", _slice())
    assert result.verdict == "confirmed"
    assert provider.calls[0]["tier"] == "deep"
    assert result.tokens_in == 10


def test_deep_review_provider_error():
    class Boom:
        def complete(self, *a, **k):
            raise RuntimeError("nope")
    result = deep_review(Boom(), "sys", _slice())
    assert result.verdict == "error"
    assert "nope" in result.error


def test_deep_review_many_caps():
    provider = _FakeProvider("VERDICT: confirmed\n")
    agent = _agent("system body")
    slices = [_slice() for _ in range(5)]
    results = deep_review_many(slices, [agent], provider, max_calls=2)
    assert len(results) == 2
