"""Stage 7: deep review.

Wraps deep-reviewer.md (+ the applicable OWASP testing-guide checklist) as
the system prompt, so the stable part of every call is one cacheable prefix.
The slice is the user content, fenced as untrusted data. Parses the
structured output documented in agents/deep-reviewer.md.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Optional

from mantis.agents import Agent
from mantis.providers import Provider
from mantis.slice import Slice
from mantis.untrusted import fence, injection_markers


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


CHECKLIST_CAP = 8000

# CWE -> checklist. Focus / mode override this; anything unmapped gets none.
_CWE_CHECKLIST = {
    **dict.fromkeys(("287", "288", "290", "294", "306", "307", "521", "522", "640", "798", "916"),
                    "otg-auth.md"),
    **dict.fromkeys(("352", "384", "539", "565", "598", "613", "614", "1004", "1275"),
                    "otg-session.md"),
    **dict.fromkeys(("261", "295", "310", "311", "312", "319", "321", "323", "326", "327",
                     "328", "329", "330", "331", "338", "347", "759", "760"), "otg-crypto.md"),
    **dict.fromkeys(("1426", "1427"), "otg-llm.md"),
}
_FOCUS_CHECKLIST = {"prompt-injection": "otg-llm.md", "business-logic": "otg-business-logic.md",
                    "auth": "otg-auth.md", "session": "otg-session.md", "crypto": "otg-crypto.md"}


def _cwes(finding) -> list[str]:
    raw = (finding.metadata or {}).get("cwe") or []
    items = raw if isinstance(raw, list) else [raw]
    return [m.group(1) for c in items for m in [re.search(r"(\d+)", str(c))] if m]


def checklist_for(slice_obj: Slice, focus: Optional[str], mode: Optional[str]) -> tuple[str, str]:
    """Return (checklist file name, body) for this slice, or ("", "")."""
    name = _FOCUS_CHECKLIST.get(focus or "") or ("otg-llm.md" if mode == "llm" else "")
    if not name:
        name = next((_CWE_CHECKLIST[c] for c in _cwes(slice_obj.finding) if c in _CWE_CHECKLIST), "")
    if not name and "llm" in slice_obj.finding.rule_id.lower():
        name = "otg-llm.md"
    p = CHECKLIST_DIR / name if name else None
    if not p or not p.is_file():
        return "", ""
    try:
        return name, p.read_text(encoding="utf-8")
    except OSError:
        return "", ""


def build_system_prompt(agent_body: str, checklist_body: str) -> str:
    if not checklist_body:
        return agent_body
    return (agent_body + "\n\nAPPLICABLE OWASP TESTING-GUIDE CHECKLIST "
            "(use these checks alongside the slice):\n" + checklist_body[:CHECKLIST_CAP])


def build_user_prompt(slice_obj: Slice) -> str:
    finding = slice_obj.finding
    parts = [
        "ORIGINAL FINDING:",
        f"  id: {finding.id}",
        f"  rule: {finding.rule_id}",
        f"  severity: {finding.severity}  confidence: {finding.confidence}",
        f"  message: {finding.message}",
        "",
        "SLICE:",
        fence(slice_obj.to_text(), "untrusted-slice"),
        "",
        "Respond exactly in the structured format from your instructions (FINDING / VERDICT / SEVERITY / CVSS / MAPPING / IMPACT / POC / RECOMMENDATION).",
    ]
    return "\n".join(parts)


_FIELD_LINE = re.compile(r"^\s*(?P<key>[A-Z]+):\s*(?P<val>.*?)\s*$")
_POC_STEP = re.compile(r"^\s*\d+\.\s+(?P<step>.+?)\s*$")


_DEEP_VERDICTS = ("confirmed", "rejected", "partial")
_MD_PREFIX = re.compile(r"^\s*(?:[#>\-*]+\s*)+")


def _normalize_line(line: str) -> str:
    """Drop markdown decoration so `**VERDICT:** confirmed` reads as `VERDICT: confirmed`."""
    indent = line[: len(line) - len(line.lstrip())]
    body = _MD_PREFIX.sub("", line) if _MD_PREFIX.match(line) and not re.match(r"^\s*\d+\.", line) else line.lstrip()
    return indent + body.replace("**", "").replace("`", "")


def _parse_json_reply(text: str, finding_id: str) -> Optional[DeepResult]:
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return None
    try:
        data = json.loads(m.group(0))
    except ValueError:
        return None
    if not isinstance(data, dict) or "verdict" not in {k.lower() for k in data}:
        return None
    d = {k.lower(): v for k, v in data.items()}
    v = str(d.get("verdict", "")).strip().lower().strip(".`*")
    return DeepResult(
        finding_id=finding_id, verdict=v if v in _DEEP_VERDICTS else "error",
        severity=str(d.get("severity", "")).lower(), impact=str(d.get("impact", "")),
        recommendation=str(d.get("recommendation", "")).lower(),
        poc=[str(x) for x in d.get("poc", [])] if isinstance(d.get("poc"), list) else [],
        notes=str(d.get("notes", "")), raw=text,
    )


def parse_deep_output(text: str, finding_id: str) -> DeepResult:
    if not text:
        return DeepResult(finding_id=finding_id, verdict="error", error="empty response")

    result = _parse_structured(text, finding_id)
    if result.verdict == "error":
        as_json = _parse_json_reply(text, finding_id)
        if as_json and as_json.verdict != "error":
            return as_json
        # INSUFFICIENT_SLICE only counts when no verdict was given; a passing
        # mention inside NOTES must not discard a confirmed finding.
        insuf = re.search(r"(?m)^\W*INSUFFICIENT_SLICE\W*:?\s*(.+)", text)
        if insuf:
            return DeepResult(finding_id=finding_id, verdict="insufficient",
                              insufficient_reason=insuf.group(1).strip()[:300], raw=text)
    return result


def _parse_structured(text: str, finding_id: str) -> DeepResult:
    result = DeepResult(finding_id=finding_id, verdict="error", raw=text)
    in_mapping = False
    in_poc = False
    impact_lines: list[str] = []
    in_impact = False
    notes_lines: list[str] = []
    in_notes = False

    for raw_line in text.splitlines():
        line = _normalize_line(raw_line.rstrip())
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
            v = val.lower().split()[0].strip(".,;:!`*") if val else "error"
            result.verdict = v if v in _DEEP_VERDICTS else "error"
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
    finding_id = slice_obj.finding.id
    _, checklist = checklist_for(slice_obj, focus, mode)
    user = build_user_prompt(slice_obj)

    try:
        resp = provider.complete(
            tier="deep",
            system=build_system_prompt(agent_body, checklist),
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
    markers = injection_markers(slice_obj.to_text())
    if out.verdict == "rejected" and markers:
        # Text aimed at the reviewer sits in the slice: don't let it close the finding.
        out.verdict = "partial"
        out.notes = (f"injection markers in slice ({', '.join(markers[:3])}); "
                     f"rejection not trusted. {out.notes}").strip()
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
