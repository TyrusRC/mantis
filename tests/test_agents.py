from __future__ import annotations

from pathlib import Path

import pytest

from mantis.agents import AgentParseError, discover_agents, parse_agent


REPO = Path(__file__).resolve().parent.parent


def test_discover_real_agents_dir():
    agents = discover_agents(REPO / "agents")
    names = {a.name for a in agents}
    assert names == {
        "deep-reviewer", "deobfuscator", "fix-author",
        "sast-orchestrator", "slice-extractor", "triage-analyst",
        "toast-hunter",
    }


def test_every_real_agent_has_tier_and_model():
    for a in discover_agents(REPO / "agents"):
        assert a.tier in {"fast", "mid", "deep"}, f"{a.name}: bad tier {a.tier!r}"
        assert a.model, f"{a.name}: missing model"


def test_tier_mapping_is_stable():
    by_name = {a.name: a for a in discover_agents(REPO / "agents")}
    assert by_name["triage-analyst"].tier == "fast"
    assert by_name["deep-reviewer"].tier == "deep"
    assert by_name["slice-extractor"].tier == "mid"
    assert by_name["sast-orchestrator"].tier == "mid"
    assert by_name["fix-author"].tier == "mid"
    assert by_name["deobfuscator"].tier == "mid"


def test_parse_agent_extracts_fields(tmp_path):
    p = tmp_path / "x.md"
    p.write_text("""---
name: example
description: foo bar
tools: Read, Grep
model: haiku
tier: fast
---

body line 1
body line 2
""")
    a = parse_agent(p)
    assert a.name == "example"
    assert a.description == "foo bar"
    assert a.model == "haiku"
    assert a.tier == "fast"
    assert a.tools == ["Read", "Grep"]
    assert "body line 1" in a.body
    assert "body line 2" in a.body


def test_parse_agent_missing_tier_raises(tmp_path):
    p = tmp_path / "x.md"
    p.write_text("""---
name: x
description: y
model: haiku
---
body
""")
    with pytest.raises(AgentParseError) as ei:
        parse_agent(p)
    assert "tier" in str(ei.value)


def test_parse_agent_invalid_tier_raises(tmp_path):
    p = tmp_path / "x.md"
    p.write_text("""---
name: x
description: y
tier: turbo
model: haiku
---
body
""")
    with pytest.raises(AgentParseError):
        parse_agent(p)


def test_parse_agent_missing_frontmatter_raises(tmp_path):
    p = tmp_path / "x.md"
    p.write_text("no frontmatter here")
    with pytest.raises(AgentParseError):
        parse_agent(p)


def test_parse_agent_tools_as_list(tmp_path):
    p = tmp_path / "x.md"
    p.write_text("""---
name: x
description: y
tier: fast
model: haiku
tools:
  - Read
  - Grep
  - Bash
---
body
""")
    a = parse_agent(p)
    assert a.tools == ["Read", "Grep", "Bash"]


def test_discover_empty_dir(tmp_path):
    assert discover_agents(tmp_path) == []


def test_discover_nonexistent_dir(tmp_path):
    assert discover_agents(tmp_path / "nope") == []
