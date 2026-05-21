from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from mantis.agents import Agent
from mantis.providers import LLMResponse
from mantis.scan import Finding
from mantis.triage import (
    build_user_prompt,
    parse_verdict,
    read_window,
    triage_all,
    triage_finding,
)


def _agent(name="triage-analyst", body="be a triage analyst"):
    return Agent(name=name, description="", tier="fast", model="haiku",
                 tools=[], body=body, path=Path("/x"))


def _finding(rule="r1", path="src/a.py", line=10):
    return Finding(rule_id=rule, severity="ERROR", confidence="HIGH",
                   path=path, start_line=line, end_line=line + 2,
                   message="bad thing", metadata={"cwe": "CWE-89"})


class FakeProvider:
    def __init__(self, response_text: str, tokens_in: int = 12, tokens_out: int = 18):
        self.response_text = response_text
        self.tokens_in = tokens_in
        self.tokens_out = tokens_out
        self.calls: list = []

    def complete(self, tier, system, user, max_tokens=4096, temperature=0.2):
        self.calls.append({"tier": tier, "system": system, "user": user,
                           "max_tokens": max_tokens, "temperature": temperature})
        return LLMResponse(text=self.response_text, tokens_in=self.tokens_in,
                            tokens_out=self.tokens_out, model="fake-model")


def test_parse_verdict_true():
    v, r = parse_verdict("r1@p:10 | TRUE | sql concat reaches sink")
    assert v == "TRUE"
    assert "sql concat" in r


def test_parse_verdict_false():
    v, r = parse_verdict("anything | FALSE | match in test file")
    assert v == "FALSE"


def test_parse_verdict_needs_deep():
    v, r = parse_verdict("x | NEEDS-DEEP | cannot resolve sanitizer")
    assert v == "NEEDS-DEEP"


def test_parse_verdict_unparseable():
    v, r = parse_verdict("the model said something nonsensical")
    assert v == "ERROR"
    assert "unparseable" in r


def test_parse_verdict_picks_first_matching_line():
    text = "preamble\nbad line\nr1 | TRUE | reason here\ntrailing\n"
    v, r = parse_verdict(text)
    assert v == "TRUE"
    assert "reason here" in r


def test_read_window(tmp_path):
    p = tmp_path / "a.py"
    p.write_text("\n".join(f"line{i}" for i in range(1, 101)))
    out = read_window(p, 50, radius=2)
    assert "line48" in out
    assert "line52" in out
    assert "line40" not in out
    assert ">>" in out  # target marker


def test_read_window_missing_file(tmp_path):
    out = read_window(tmp_path / "nope", 5)
    assert "file not found" in out


def test_build_user_prompt_includes_metadata():
    f = _finding()
    prompt = build_user_prompt(f, "code here")
    assert "r1" in prompt
    assert "src/a.py:10" in prompt
    assert "code here" in prompt
    assert "TRUE|FALSE|NEEDS-DEEP" in prompt


def test_triage_finding_happy(tmp_path):
    f = _finding(path="x.py", line=2)
    (tmp_path / "x.py").write_text("a\nbad code\nc\n")
    provider = FakeProvider("r1@x.py:2 | TRUE | bad code")
    result = triage_finding(provider, "system body", f, tmp_path)
    assert result.verdict == "TRUE"
    assert provider.calls[0]["tier"] == "fast"
    assert "system body" in provider.calls[0]["system"]
    assert result.tokens_in == 12


def test_triage_finding_provider_error(tmp_path):
    f = _finding(path="x.py", line=1)
    (tmp_path / "x.py").write_text("a\n")

    class BadProvider:
        def complete(self, *a, **k):
            raise RuntimeError("network down")

    result = triage_finding(BadProvider(), "sys", f, tmp_path)
    assert result.verdict == "ERROR"
    assert "network down" in result.reason


def test_triage_all_iterates(tmp_path):
    (tmp_path / "a.py").write_text("line1\nline2\n")
    findings = [_finding(path="a.py", line=1), _finding(rule="r2", path="a.py", line=2)]
    agents = [_agent()]
    provider = FakeProvider("r@a.py:1 | TRUE | because")
    results = triage_all(findings, agents, provider, tmp_path)
    assert len(results) == 2
    assert all(r.verdict == "TRUE" for r in results)
    assert len(provider.calls) == 2


def test_triage_all_respects_max(tmp_path):
    (tmp_path / "a.py").write_text("x\n")
    findings = [_finding(path="a.py", line=1) for _ in range(5)]
    provider = FakeProvider("r@a.py:1 | TRUE | x")
    results = triage_all(findings, [_agent()], provider, tmp_path, max_findings=2)
    assert len(results) == 2
    assert len(provider.calls) == 2


def test_triage_all_missing_agent_raises(tmp_path):
    with pytest.raises(KeyError):
        triage_all([_finding()], [_agent(name="other")], FakeProvider("x"), tmp_path)
