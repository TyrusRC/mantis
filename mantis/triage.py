"""Stage 5: triage findings via the configured LLM provider.

Uses the triage-analyst agent body as the system prompt. Reads a +/-40
line window around each finding from disk (the LLM never reads files
itself in standalone mode — the CLI hands it the window).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Optional

from mantis.agents import Agent
from mantis.providers import Provider
from mantis.scan import Finding


Verdict = Literal["TRUE", "FALSE", "NEEDS-DEEP", "ERROR"]


@dataclass
class TriageResult:
    finding: Finding
    verdict: Verdict
    reason: str
    raw_response: str
    tokens_in: int = 0
    tokens_out: int = 0
    error: Optional[str] = None


WINDOW_LINES = 40
_VERDICT_LINE = re.compile(
    r"^\s*(?P<id>\S+)\s*\|\s*(?P<verdict>TRUE|FALSE|NEEDS-DEEP)\s*\|\s*(?P<reason>.+?)\s*$",
    re.IGNORECASE,
)


def read_window(path: Path, line: int, radius: int = WINDOW_LINES) -> str:
    if not path.is_file():
        return f"(file not found: {path})"
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return f"(read error: {e})"
    lines = text.splitlines()
    start = max(0, line - radius - 1)
    end = min(len(lines), line + radius)
    out: list[str] = []
    for i in range(start, end):
        marker = ">> " if i + 1 == line else "   "
        out.append(f"{i + 1:6d} {marker}{lines[i]}")
    return "\n".join(out)


def build_user_prompt(finding: Finding, window: str) -> str:
    finding_id = finding.id
    return (
        f"Finding ID: {finding_id}\n"
        f"Rule: {finding.rule_id}\n"
        f"Severity: {finding.severity}  Confidence: {finding.confidence}\n"
        f"Path: {finding.path}:{finding.start_line}-{finding.end_line}\n"
        f"Message: {finding.message}\n\n"
        f"Code window (target line marked with `>>`):\n"
        f"```\n{window}\n```\n\n"
        f"Output exactly one line:\n"
        f"`{finding_id} | TRUE|FALSE|NEEDS-DEEP | <one-sentence reason, <=140 chars>`"
    )


def parse_verdict(text: str) -> tuple[Verdict, str]:
    for line in (text or "").splitlines():
        m = _VERDICT_LINE.match(line)
        if m:
            v = m.group("verdict").upper()
            reason = m.group("reason").strip()[:160]
            return v, reason  # type: ignore[return-value]
    snippet = (text or "").strip().replace("\n", " ")[:120]
    return "ERROR", f"unparseable verdict: {snippet!r}"


def triage_finding(
    provider: Provider,
    agent_body: str,
    finding: Finding,
    target_root: Path,
) -> TriageResult:
    abs_path = target_root / finding.path if not Path(finding.path).is_absolute() else Path(finding.path)
    window = read_window(abs_path, finding.start_line)
    user = build_user_prompt(finding, window)

    try:
        resp = provider.complete(
            tier="fast",
            system=agent_body,
            user=user,
            max_tokens=200,
            temperature=0.0,
        )
    except Exception as e:  # provider errors should not abort the whole pipeline
        return TriageResult(
            finding=finding,
            verdict="ERROR",
            reason=f"provider error: {type(e).__name__}: {e}"[:160],
            raw_response="",
            error=str(e),
        )

    verdict, reason = parse_verdict(resp.text)
    return TriageResult(
        finding=finding,
        verdict=verdict,
        reason=reason,
        raw_response=resp.text,
        tokens_in=resp.tokens_in,
        tokens_out=resp.tokens_out,
    )


def find_agent(agents: list[Agent], name: str) -> Agent:
    for a in agents:
        if a.name == name:
            return a
    raise KeyError(f"agent not found: {name}")


def triage_all(
    findings: list[Finding],
    agents: list[Agent],
    provider: Provider,
    target_root: Path,
    *,
    max_findings: Optional[int] = None,
    mode: str = "single",
) -> list[TriageResult]:
    triage_agent = find_agent(agents, "triage-analyst")
    capped = findings[:max_findings] if max_findings else findings
    if mode == "dual":
        return [
            triage_finding_dual(provider, triage_agent.body, f, target_root)
            for f in capped
        ]
    return [
        triage_finding(provider, triage_agent.body, f, target_root)
        for f in capped
    ]


# --- Dual-chain triage (TP-evidence + FP-evidence + reconcile) ---

_TP_PREFIX = """You are a security analyst building the case that THIS FINDING IS A TRUE POSITIVE.
Your job: argue that the code is genuinely vulnerable. Look hard for:
- Untrusted input reaching the sink with no sanitization
- Plausible attacker control of the source
- Missing or bypassable mitigations

Output the standard verdict line. Choose TRUE if you find concrete evidence of
exploitability. Choose FALSE only if you genuinely cannot construct a case after
careful inspection. NEEDS-DEEP only when the slice is insufficient to decide.

"""

_FP_PREFIX = """You are a security analyst building the case that THIS FINDING IS A FALSE POSITIVE.
Your job: argue that the code is safe. Look hard for:
- Inline sanitization, escaping, or parameterization
- Match in a test, fixture, example, or documentation file
- Input is constant or controlled by trusted code only
- Framework auto-protects (ORM bindings, auto-escape, prepared statements)
- Dead or unreachable code

Output the standard verdict line. Choose FALSE if you find compelling evidence the
finding is safe. Choose TRUE if no mitigation is present. NEEDS-DEEP when slice insufficient.

"""


def reconcile_dual(tp_verdict: Verdict, fp_verdict: Verdict) -> Verdict:
    """Combine the two chains' verdicts.

    The Semgrep Assistant pattern: each chain searches asymmetrically.
    Agreement is high-confidence; disagreement promotes to NEEDS-DEEP.
    """
    if tp_verdict == "ERROR" or fp_verdict == "ERROR":
        return "ERROR" if (tp_verdict == "ERROR" and fp_verdict == "ERROR") else \
               (fp_verdict if tp_verdict == "ERROR" else tp_verdict)
    if tp_verdict == fp_verdict:
        return tp_verdict
    if "NEEDS-DEEP" in (tp_verdict, fp_verdict):
        return "NEEDS-DEEP"
    # TP=TRUE / FP=FALSE  -> disagreement, escalate
    # TP=FALSE / FP=TRUE  -> rare, escalate
    return "NEEDS-DEEP"


def triage_finding_dual(
    provider: Provider,
    agent_body: str,
    finding: Finding,
    target_root: Path,
) -> TriageResult:
    abs_path = target_root / finding.path if not Path(finding.path).is_absolute() else Path(finding.path)
    window = read_window(abs_path, finding.start_line)
    user = build_user_prompt(finding, window)

    tp_verdict: Verdict = "ERROR"
    fp_verdict: Verdict = "ERROR"
    tp_reason = ""
    fp_reason = ""
    raw_parts: list[str] = []
    tokens_in = 0
    tokens_out = 0
    err: Optional[str] = None

    for label, prefix in (("TP", _TP_PREFIX), ("FP", _FP_PREFIX)):
        try:
            resp = provider.complete(
                tier="fast",
                system=prefix + agent_body,
                user=user,
                max_tokens=250,
                temperature=0.0,
            )
            v, r = parse_verdict(resp.text)
            tokens_in += resp.tokens_in
            tokens_out += resp.tokens_out
            raw_parts.append(f"[{label}] {resp.text}")
            if label == "TP":
                tp_verdict, tp_reason = v, r
            else:
                fp_verdict, fp_reason = v, r
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            raw_parts.append(f"[{label}] error: {err}")
            if label == "TP":
                tp_verdict = "ERROR"
            else:
                fp_verdict = "ERROR"

    final = reconcile_dual(tp_verdict, fp_verdict)
    reason = f"TP={tp_verdict}: {tp_reason} | FP={fp_verdict}: {fp_reason}"
    return TriageResult(
        finding=finding,
        verdict=final,
        reason=reason[:300],
        raw_response="\n".join(raw_parts),
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        error=err,
    )
