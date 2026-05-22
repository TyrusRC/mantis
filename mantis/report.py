"""Stage 9: write security-audit-report.md.

Mirrors the schema documented in agents/sast-orchestrator.md (Report
section). Standalone mode produces the same output format the MCP
orchestrator writes.
"""
from __future__ import annotations

import datetime as dt
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from mantis.scan import Finding
from mantis.triage import TriageResult


@dataclass
class RunMeta:
    target: Path
    mode: str
    packs: list[str]
    sast_bin: str
    provider: Optional[str]
    duration_seconds: float
    tokens_in: int
    tokens_out: int
    status: str = "complete"   # complete | incomplete
    notes: list[str] = None    # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.notes is None:
            self.notes = []


_SEV_ORDER = ("ERROR", "WARNING", "INFO")


def _sev_label(s: str) -> str:
    return {"ERROR": "Critical/High", "WARNING": "Medium", "INFO": "Low"}.get(s, s)


def _format_metadata_inline(meta: dict) -> str:
    parts: list[str] = []
    for k in ("owasp", "owasp-mobile-2024", "cwe", "cve", "masvs-v2", "masvs"):
        v = meta.get(k)
        if v:
            parts.append(f"{k}={v}")
    return "  ".join(parts) if parts else "(no mapping metadata)"


def _bucket(results: list[TriageResult]) -> dict[str, dict[str, list[TriageResult]]]:
    """Bucket by severity then verdict."""
    out: dict[str, dict[str, list[TriageResult]]] = defaultdict(lambda: defaultdict(list))
    for r in results:
        out[r.finding.severity.upper()][r.verdict].append(r)
    return out


def _summary_table(results: list[TriageResult], raw_findings: list[Finding]) -> str:
    by_sev = _bucket(results)
    raw_by_sev: Counter[str] = Counter(f.severity.upper() for f in raw_findings)
    lines = [
        "| Severity | Confirmed | Triaged out | Needs deep | Errored | Total raw |",
        "|---|---|---|---|---|---|",
    ]
    for sev in _SEV_ORDER:
        row = by_sev.get(sev, {})
        lines.append(
            f"| {_sev_label(sev)} | "
            f"{len(row.get('TRUE', []))} | "
            f"{len(row.get('FALSE', []))} | "
            f"{len(row.get('NEEDS-DEEP', []))} | "
            f"{len(row.get('ERROR', []))} | "
            f"{raw_by_sev.get(sev, 0)} |"
        )
    return "\n".join(lines)


def _mapping_summary(results: list[TriageResult]) -> str:
    cwe = Counter()
    cve = Counter()
    masvs = Counter()
    owasp = Counter()
    for r in results:
        if r.verdict != "TRUE":
            continue
        m = r.finding.metadata or {}
        for v in (m.get("cwe"),):
            if v:
                cwe[str(v)] += 1
        cve_val = m.get("cve")
        if cve_val:
            if isinstance(cve_val, list):
                for c in cve_val:
                    cve[str(c)] += 1
            else:
                cve[str(cve_val)] += 1
        for v in (m.get("masvs-v2"), m.get("masvs")):
            if v:
                masvs[str(v)] += 1
        for k in ("owasp", "owasp-mobile-2024"):
            v = m.get(k)
            if v:
                owasp[str(v)] += 1
    parts: list[str] = []
    if owasp:
        parts.append("OWASP: " + ", ".join(f"{k} ({n})" for k, n in owasp.most_common(8)))
    if cwe:
        parts.append("CWE top 5: " + ", ".join(f"{k} ({n})" for k, n in cwe.most_common(5)))
    if masvs:
        parts.append("MASVS: " + ", ".join(f"{k} ({n})" for k, n in masvs.most_common(8)))
    if cve:
        parts.append("CVE: " + ", ".join(f"{k} ({n})" for k, n in cve.most_common(10)))
    return "\n".join(parts) if parts else "(no mapping metadata on confirmed findings)"


def _findings_section(results: list[TriageResult]) -> str:
    by_sev = _bucket(results)
    out: list[str] = ["## Findings"]
    sev_to_header = {"ERROR": "### Critical / High", "WARNING": "### Medium", "INFO": "### Low"}
    for sev in _SEV_ORDER:
        confirmed = by_sev.get(sev, {}).get("TRUE", [])
        needs_deep = by_sev.get(sev, {}).get("NEEDS-DEEP", [])
        items = sorted(confirmed + needs_deep, key=lambda r: (r.finding.path, r.finding.start_line))
        if not items:
            continue
        out.append(sev_to_header[sev])
        groups: dict[tuple[str, int], list[TriageResult]] = {}
        order: list[tuple[str, int]] = []
        for r in items:
            key = (r.finding.path, r.finding.start_line)
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(r)
        for key in order:
            group = groups[key]
            head = group[0]
            f = head.finding
            verdict_tag = " (NEEDS-DEEP)" if head.verdict == "NEEDS-DEEP" else ""
            if len(group) == 1:
                out.append(f"- **{f.rule_id}** — `{f.path}:{f.start_line}`{verdict_tag}")
            else:
                ids = ", ".join(sorted({r.finding.rule_id for r in group}))
                out.append(f"- **{f.path}:{f.start_line}**{verdict_tag} — {len(group)} rules: {ids}")
            out.append(f"  - {f.message.splitlines()[0] if f.message else '(no message)'}")
            out.append(f"  - **Triage:** {head.reason}")
            out.append(f"  - **Mapping:** {_format_metadata_inline(f.metadata or {})}")
        out.append("")
    return "\n".join(out)


def _deep_section(deep_results: list) -> str:
    out = ["## Deep review"]
    confirmed = [d for d in deep_results if d.verdict == "confirmed"]
    rejected = [d for d in deep_results if d.verdict == "rejected"]
    partial = [d for d in deep_results if d.verdict == "partial"]
    insufficient = [d for d in deep_results if d.verdict == "insufficient"]
    errored = [d for d in deep_results if d.verdict == "error"]
    out.append(
        f"{len(confirmed)} confirmed, {len(partial)} partial, {len(rejected)} rejected, "
        f"{len(insufficient)} insufficient slice, {len(errored)} errored."
    )
    if confirmed or partial:
        for d in confirmed + partial:
            out.append("")
            out.append(f"### {d.finding_id} — {d.verdict}")
            if d.severity:
                out.append(f"- **Severity:** {d.severity}")
            if d.cvss_vector or d.cvss_score:
                out.append(f"- **CVSS:** {d.cvss_vector}" + (f"  (score {d.cvss_score})" if d.cvss_score else ""))
            if d.mapping:
                kvs = "  ".join(f"{k}={v}" for k, v in d.mapping.items())
                out.append(f"- **Mapping:** {kvs}")
            if d.impact:
                out.append(f"- **Impact:** {d.impact}")
            if d.poc:
                out.append("- **PoC:**")
                for i, step in enumerate(d.poc, 1):
                    out.append(f"    {i}. {step}")
            if d.recommendation:
                out.append(f"- **Recommendation:** {d.recommendation}")
            if d.notes:
                out.append(f"- Notes: {d.notes}")
    if insufficient:
        out.append("")
        out.append("### Insufficient slices")
        for d in insufficient[:10]:
            out.append(f"- {d.finding_id} — {d.insufficient_reason}")
    return "\n".join(out)


def _fix_section(fix_results: list, worktree) -> str:
    out = ["## Fixes"]
    if worktree:
        out.append(f"Worktree: `{worktree}`")
    if not fix_results:
        out.append("(no fixes attempted)")
        return "\n".join(out)
    applied = [r for r in fix_results if r.status == "applied"]
    reverted = [r for r in fix_results if r.status == "reverted"]
    failed = [r for r in fix_results if r.status == "failed"]
    skipped = [r for r in fix_results if r.status == "skipped"]
    out.append(
        f"{len(applied)} applied, {len(reverted)} reverted, "
        f"{len(failed)} failed, {len(skipped)} skipped."
    )
    for r in applied + reverted + failed:
        out.append("")
        out.append(f"### {r.finding_id} — {r.status}")
        if r.files_changed:
            out.append(f"- Files: {', '.join(r.files_changed)}")
        if r.verification:
            out.append(f"- Verification: {r.verification}")
        if r.notes:
            out.append(f"- Notes: {r.notes}")
        if r.diff and r.status in ("applied", "reverted"):
            out.append("")
            out.append("```diff")
            diff = r.diff if len(r.diff) <= 4000 else r.diff[:4000] + "\n... (truncated)"
            out.append(diff.rstrip())
            out.append("```")
    return "\n".join(out)


def _toast_section(toast_results: list) -> str:
    out = ["## Experimental — Tree-of-AST candidate findings"]
    out.append(
        "These are findings beyond the rule set, surfaced by an ensemble LLM pass. "
        "Treat as candidates for human review — not confirmed vulnerabilities."
    )
    any_new = False
    for tr in toast_results:
        if not tr.new_findings:
            continue
        any_new = True
        out.append("")
        out.append(f"### {tr.finding_id} — {len(tr.new_findings)} candidate(s) (quorum {tr.quorum}/{tr.samples})")
        for i, f in enumerate(tr.new_findings, 1):
            out.append(f"{i}. **source:** `{f.source}`  →  **sink:** `{f.sink}`")
            if f.flow:
                out.append(f"   - flow: {f.flow}")
            if f.cwe:
                out.append(f"   - CWE: {f.cwe}")
            if f.impact:
                out.append(f"   - impact: {f.impact}")
    if not any_new:
        out.append("")
        out.append("(no candidates reached quorum)")
    return "\n".join(out)


def _filtered_section(results: list[TriageResult], packs: list[str]) -> str:
    false_positives = [r for r in results if r.verdict == "FALSE"]
    errors = [r for r in results if r.verdict == "ERROR"]
    out = ["## Triaged out", f"{len(false_positives)} findings dismissed as false positives, {len(errors)} errored."]
    if errors:
        out.append("\n### Errors")
        for r in errors[:25]:
            out.append(f"- `{r.finding.rule_id}` at `{r.finding.path}:{r.finding.start_line}` — {r.reason}")
    return "\n".join(out)


def write_report(
    out_path: Path,
    meta: RunMeta,
    raw_findings: list[Finding],
    triage_results: list[TriageResult],
    *,
    slices: Optional[list] = None,
    deep_results: Optional[list] = None,
    fix_results: Optional[list] = None,
    fix_worktree: Optional[Path] = None,
    toast_results: Optional[list] = None,
) -> Path:
    duration = f"{int(meta.duration_seconds // 60)}m {int(meta.duration_seconds % 60)}s"
    tokens_in_k = meta.tokens_in / 1000
    tokens_out_k = meta.tokens_out / 1000
    when = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    target_name = meta.target.name or str(meta.target)

    parts: list[str] = []
    parts.append(f"# Security Audit Report — {target_name}")
    parts.append("")
    if meta.status != "complete":
        parts.append(f"**STATUS: {meta.status}**")
        parts.append("")
    parts.append(f"**Target:** {meta.target}")
    parts.append(
        f"**Mode:** {meta.mode}  •  **Packs:** {', '.join(meta.packs) or '(none)'}  •  "
        f"**SAST:** {meta.sast_bin}  •  **Provider:** {meta.provider or '(unspecified)'}"
    )
    parts.append(
        f"**Scan duration:** {duration}  •  "
        f"**Token cost:** ~{tokens_in_k:.1f}k input / {tokens_out_k:.1f}k output"
    )
    parts.append(f"**Generated:** {when}")
    parts.append("")
    if meta.notes:
        parts.append("## Notes")
        for n in meta.notes:
            parts.append(f"- {n}")
        parts.append("")
    parts.append("## Summary")
    parts.append(_summary_table(triage_results, raw_findings))
    parts.append("")
    parts.append(_mapping_summary(triage_results))
    parts.append("")
    parts.append(_findings_section(triage_results))
    parts.append("")
    if deep_results:
        parts.append(_deep_section(deep_results))
        parts.append("")
    parts.append(_filtered_section(triage_results, meta.packs))
    parts.append("")
    if fix_results is not None and (fix_results or fix_worktree):
        parts.append(_fix_section(fix_results, fix_worktree))
        parts.append("")
    if toast_results:
        parts.append(_toast_section(toast_results))
        parts.append("")
    parts.append("## Footer")
    parts.append(f"- mantis pipeline mode: standalone (stages 0/1/5/9)")
    parts.append(f"- Packs: {', '.join(meta.packs)}")
    parts.append(f"- SAST binary: {meta.sast_bin}")
    if meta.provider:
        parts.append(f"- LLM provider: {meta.provider}")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists():
        ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        backup = out_path.with_name(f"{out_path.stem}.{ts}.bak{out_path.suffix}")
        try:
            out_path.rename(backup)
        except OSError:
            pass
    try:
        out_path.write_text("\n".join(parts) + "\n", encoding="utf-8")
    except PermissionError as e:
        # Target is read-only; fall back to /tmp/<target-name>-<ts>.md so we
        # don't lose the audit result.
        import tempfile
        fallback = Path(tempfile.gettempdir()) / f"mantis-{target_name}-{dt.datetime.now().strftime('%Y%m%d-%H%M%S')}.md"
        fallback.write_text("\n".join(parts) + "\n", encoding="utf-8")
        raise PermissionError(
            f"target write failed ({e}); wrote fallback at {fallback}"
        )
    return out_path
