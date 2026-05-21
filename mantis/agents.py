"""Parser for agents/*.md — the source of truth for both MCP and standalone modes."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml


VALID_TIERS = {"fast", "mid", "deep"}


@dataclass
class Agent:
    name: str
    description: str
    tier: str
    model: Optional[str]
    tools: list[str]
    body: str
    path: Path


class AgentParseError(Exception):
    pass


def _split_frontmatter(text: str, path: Path) -> tuple[dict, str]:
    if not text.startswith("---"):
        raise AgentParseError(f"{path}: missing frontmatter")
    parts = text.split("---", 2)
    if len(parts) < 3:
        raise AgentParseError(f"{path}: malformed frontmatter (need closing '---')")
    try:
        fm = yaml.safe_load(parts[1]) or {}
    except yaml.YAMLError as e:
        raise AgentParseError(f"{path}: invalid YAML frontmatter: {e}") from e
    if not isinstance(fm, dict):
        raise AgentParseError(f"{path}: frontmatter must be a mapping")
    return fm, parts[2].lstrip("\n")


def _parse_tools(raw) -> list[str]:
    if raw is None or raw == "":
        return []
    if isinstance(raw, list):
        return [str(t).strip() for t in raw if str(t).strip()]
    if isinstance(raw, str):
        return [t.strip() for t in raw.split(",") if t.strip()]
    raise AgentParseError(f"tools must be a string or list, got {type(raw).__name__}")


def parse_agent(path: Path) -> Agent:
    text = path.read_text(encoding="utf-8")
    fm, body = _split_frontmatter(text, path)

    name = fm.get("name") or path.stem
    description = fm.get("description") or ""

    tier = fm.get("tier")
    if tier not in VALID_TIERS:
        raise AgentParseError(
            f"{path}: 'tier' must be one of {sorted(VALID_TIERS)}, got {tier!r}"
        )

    model = fm.get("model")
    tools = _parse_tools(fm.get("tools"))

    return Agent(
        name=name,
        description=description,
        tier=tier,
        model=model,
        tools=tools,
        body=body,
        path=path,
    )


def discover_agents(agents_dir: Path) -> list[Agent]:
    if not agents_dir.is_dir():
        return []
    return sorted(
        [parse_agent(p) for p in agents_dir.glob("*.md")],
        key=lambda a: a.name,
    )
