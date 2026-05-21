"""Stage 7b (experimental): Tree-of-AST hunter.

Implements a Locate-Trace-Vote pass on a slice that already survived
the deep-reviewer. The intent is to find vulnerabilities pre-defined
rules could not express — see the README "Architecture" section for
the source paper.

The "vote" step is implemented as an ensemble of N independent LLM
samples; we keep findings reported by at least `vote_quorum` of the N
samples. N is small (default 3) because each sample is on the deep tier.

This is behind the `--experimental-toast` flag and only fires in
`bugbounty` mode by default. Off in every other mode regardless of flag.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from mantis.agents import Agent
from mantis.providers import Provider
from mantis.slice import Slice


DEFAULT_SAMPLES = 3
DEFAULT_QUORUM = 2


@dataclass
class ToastFinding:
    source: str
    sink: str
    flow: str
    verdict: str          # PLAUSIBLE | UNCERTAIN | REFUTED
    cwe: str = "unknown"
    impact: str = ""


@dataclass
class ToastResult:
    finding_id: str
    new_findings: list[ToastFinding] = field(default_factory=list)
    samples: int = 0
    quorum: int = 0
    raw_responses: list[str] = field(default_factory=list)
    tokens_in: int = 0
    tokens_out: int = 0
    notes: str = ""
    error: Optional[str] = None


# Parsers ------------------------------------------------------------

_BLOCK_RE = re.compile(
    r"\[\d+\]\s*"
    r"source:\s*(?P<source>.+?)\s*\n"
    r"\s*sink:\s*(?P<sink>.+?)\s*\n"
    r"\s*flow:\s*(?P<flow>.+?)\s*\n"
    r"\s*verdict:\s*(?P<verdict>PLAUSIBLE|UNCERTAIN|REFUTED)\s*\n"
    r"(?:\s*cwe:\s*(?P<cwe>.+?)\s*\n)?"
    r"(?:\s*impact:\s*(?P<impact>.+?)\s*(?=\n\s*\[|\nTOTAL_|\Z))?",
    re.IGNORECASE | re.DOTALL,
)


def parse_toast_response(text: str) -> list[ToastFinding]:
    if not text or "TOAST_FINDINGS: none" in text:
        return []
    out: list[ToastFinding] = []
    for m in _BLOCK_RE.finditer(text):
        out.append(ToastFinding(
            source=(m.group("source") or "").strip()[:200],
            sink=(m.group("sink") or "").strip()[:200],
            flow=(m.group("flow") or "").strip()[:400],
            verdict=(m.group("verdict") or "UNCERTAIN").strip().upper(),
            cwe=(m.group("cwe") or "unknown").strip()[:80],
            impact=(m.group("impact") or "").strip()[:500],
        ))
    return out


def _finding_key(f: ToastFinding) -> tuple[str, str]:
    """Normalize a finding for ensemble counting: (source, sink) pair."""
    return (
        re.sub(r"\s+", " ", f.source.lower()).strip(),
        re.sub(r"\s+", " ", f.sink.lower()).strip(),
    )


def vote_quorum_filter(
    samples: list[list[ToastFinding]],
    quorum: int,
) -> list[ToastFinding]:
    """Keep only findings PLAUSIBLE in >= `quorum` samples."""
    counter: Counter[tuple[str, str]] = Counter()
    by_key: dict[tuple[str, str], ToastFinding] = {}
    for sample in samples:
        seen_in_sample: set[tuple[str, str]] = set()
        for f in sample:
            if f.verdict != "PLAUSIBLE":
                continue
            k = _finding_key(f)
            if k in seen_in_sample:
                continue
            seen_in_sample.add(k)
            counter[k] += 1
            # Keep the most-detailed representative.
            if k not in by_key or len(f.impact) > len(by_key[k].impact):
                by_key[k] = f
    return [by_key[k] for k, n in counter.items() if n >= quorum]


def build_user_prompt(slice_obj: Slice) -> str:
    finding = slice_obj.finding
    finding_id = finding.id
    return (
        f"ORIGINAL FINDING (already deep-reviewed; do not re-flag): {finding_id}\n"
        f"Rule: {finding.rule_id}\n\n"
        f"SLICE:\n{slice_obj.to_text()}\n\n"
        f"Find NEW vulnerabilities in this slice beyond what the original rule expressed.\n"
        f"Output in the TOAST_FINDINGS format from your instructions."
    )


def hunt_on_slice(
    provider: Provider,
    agent_body: str,
    slice_obj: Slice,
    *,
    samples: int = DEFAULT_SAMPLES,
    quorum: int = DEFAULT_QUORUM,
) -> ToastResult:
    finding = slice_obj.finding
    finding_id = finding.id
    user = build_user_prompt(slice_obj)

    result = ToastResult(finding_id=finding_id, samples=samples, quorum=quorum)
    per_sample: list[list[ToastFinding]] = []

    for i in range(samples):
        try:
            resp = provider.complete(
                tier="deep",
                system=agent_body,
                user=user,
                max_tokens=1500,
                # Use a non-zero temperature so the N samples actually diverge.
                temperature=0.6,
            )
        except Exception as e:
            result.error = f"sample {i}: {type(e).__name__}: {e}"
            result.raw_responses.append(f"(error: {e})")
            continue
        result.raw_responses.append(resp.text)
        result.tokens_in += resp.tokens_in
        result.tokens_out += resp.tokens_out
        per_sample.append(parse_toast_response(resp.text))

    if not per_sample:
        result.notes = "no successful samples"
        return result

    result.new_findings = vote_quorum_filter(per_sample, quorum)
    if not result.new_findings:
        result.notes = f"no finding reached quorum ({quorum}/{samples})"
    return result


def hunt_all(
    slices: list[Slice],
    agents: list[Agent],
    provider: Provider,
    *,
    samples: int = DEFAULT_SAMPLES,
    quorum: int = DEFAULT_QUORUM,
    max_calls: Optional[int] = None,
) -> list[ToastResult]:
    from mantis.triage import find_agent
    agent = find_agent(agents, "toast-hunter")
    capped = slices[:max_calls] if max_calls else slices
    return [hunt_on_slice(provider, agent.body, s, samples=samples, quorum=quorum)
            for s in capped]
