"""Stage 7: deep review.

Wraps deep-reviewer.md as the system prompt. Pass slice + optional
checklist as user content. Parse the structured output documented in
agents/deep-reviewer.md.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from mantis.agents import Agent
from mantis.providers import Provider
from mantis.slice import Slice


from mantis.cli import REPO_ROOT as REPO_ROOT  # type: ignore[import]

CHECKLIST_DIR = REPO_ROOT / "checklists"


@dataclass
class DeepResult:
    finding_id: str
    verdict: str          # confirmed | rejected | partial | insufficient | error
    severity: str = ""
    cvss_vector: str = ""
    cvss_score: str = ""
    mapping: dict[str, str] = field(default_factory=dict)
    impact: str = ""
    poc: list[str] = field(default_factory=list)
    recommendation: str = ""
    notes: str = ""
    raw: str = ""
    insufficient_reason: str = ""
    tokens_in: int = 0
    tokens_out: int = 0
    error: Optional[str] = None


def _load_checklist(focus: Optional[str], mode: Optional[str]) -> str:
    if not CHECKLIST_DIR.is_dir():
        return ""
    name: Optional[str] = None
    if focus == "prompt-injection" or mode == "llm":
        name = "otg-llm.md"
    elif focus == "business-logic":
        name = "otg-business-logic.md"
    if not name:
        return ""
    p = CHECKLIST_DIR / name
    if not p.is_file():
        return ""
    try:
        return p.read_text(encoding="utf-8")
    except OSError:
        return ""


def build_user_prompt(slice_obj: Slice, checklist_body: str) -> str:
    finding = slice_obj.finding
    finding_id = finding.id
    parts = [
        f"ORIGINAL FINDING:",
        f"  id: {finding_id}",
        f"  rule: {finding.rule_id}",
        f"  severity: {finding.severity}  confidence: {finding.confidence}",
        f"  message: {finding.message}",
        "",
        "SLICE:",
        slice_obj.to_text(),
    ]
    if checklist_body:
        parts.append("")
        parts.append("APPLICABLE OWASP TESTING-GUIDE CHECKLIST (use these checks alongside the slice):")
        # Cap checklist size to keep prompts manageable.
        parts.append(checklist_body[:8000])
    parts.append("")
    parts.append("Respond exactly in the structured format from your instructions (FINDING / VERDICT / SEVERITY / CVSS / MAPPING / IMPACT / POC / RECOMMENDATION).")
    return "\n".join(parts)


_FIELD_LINE = re.compile(r"^\s*(?P<key>[A-Z]+):\s*(?P<val>.*?)\s*$")
_POC_STEP = re.compile(r"^\s*\d+\.\s+(?P<step>.+?)\s*$")


def parse_deep_output(text: str, finding_id: str) -> DeepResult:
    if not text:
        return DeepResult(finding_id=finding_id, verdict="error", error="empty response")

    insuf = re.search(r"INSUFFICIENT_SLICE\s*:\s*(.+)", text)
    if insuf:
        return DeepResult(
            finding_id=finding_id,
            verdict="insufficient",
            insufficient_reason=insuf.group(1).strip()[:300],
            raw=text,
        )

    result = DeepResult(finding_id=finding_id, verdict="error", raw=text)
    in_mapping = False
    in_poc = False
    impact_lines: list[str] = []
    in_impact = False
    notes_lines: list[str] = []
    in_notes = False

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.lstrip()

        if in_mapping:
            m = re.match(r"^\s+(?P<key>[A-Za-z][A-Za-z0-9_-]*)\s*:\s*(?P<val>.+?)\s*$", line)
            if m:
                result.mapping[m.group("key").upper()] = m.group("val").strip()
                continue
            in_mapping = False
        if in_poc:
            m = _POC_STEP.match(line)
            if m:
                result.poc.append(m.group("step"))
                continue
            if stripped and not line.startswith(" "):
                in_poc = False
        if in_impact:
            if stripped and not _FIELD_LINE.match(stripped):
                impact_lines.append(stripped)
                continue
            in_impact = False
        if in_notes:
            if stripped and not _FIELD_LINE.match(stripped):
                notes_lines.append(stripped)
                continue
            in_notes = False

        m = _FIELD_LINE.match(line)
        if not m:
            continue
        key = m.group("key").upper()
        val = m.group("val").strip()

        if key == "FINDING":
            continue
        if key == "VERDICT":
            v = val.lower().split()[0] if val else "error"
            if v not in ("confirmed", "rejected", "partial"):
                v = "error"
            result.verdict = v
        elif key == "SEVERITY":
            result.severity = val.lower()
        elif key == "CVSS":
            score = re.search(r"SCORE:\s*([0-9.]+)", val)
            if score:
                result.cvss_score = score.group(1)
                result.cvss_vector = val.split("SCORE:")[0].strip()
            else:
                result.cvss_vector = val
        elif key == "MAPPING":
            in_mapping = True
        elif key == "IMPACT":
            if val:
                impact_lines.append(val)
            in_impact = True
        elif key == "POC":
            in_poc = True
        elif key == "RECOMMENDATION":
            result.recommendation = val.lower()
        elif key == "NOTES":
            if val:
                notes_lines.append(val)
            in_notes = True

    result.impact = " ".join(impact_lines).strip()
    result.notes = " ".join(notes_lines).strip()
    return result


def deep_review(
    provider: Provider,
    agent_body: str,
    slice_obj: Slice,
    focus: Optional[str] = None,
    mode: Optional[str] = None,
) -> DeepResult:
    finding = slice_obj.finding
    finding_id = finding.id
    checklist = _load_checklist(focus, mode)
    user = build_user_prompt(slice_obj, checklist)

    try:
        resp = provider.complete(
            tier="deep",
            system=agent_body,
            user=user,
            max_tokens=1500,
            temperature=0.1,
        )
    except Exception as e:
        return DeepResult(finding_id=finding_id, verdict="error",
                          error=f"{type(e).__name__}: {e}")

    out = parse_deep_output(resp.text, finding_id)
    out.tokens_in = resp.tokens_in
    out.tokens_out = resp.tokens_out
    return out


def deep_review_many(
    slices: list[Slice],
    agents: list[Agent],
    provider: Provider,
    *,
    focus: Optional[str] = None,
    mode: Optional[str] = None,
    max_calls: Optional[int] = None,
) -> list[DeepResult]:
    from mantis.triage import find_agent
    agent = find_agent(agents, "deep-reviewer")
    capped = slices[:max_calls] if max_calls else slices
    return [deep_review(provider, agent.body, s, focus=focus, mode=mode) for s in capped]
