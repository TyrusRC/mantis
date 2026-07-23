"""Programmatic API: run an audit and get structured findings back.

Unlike `mantis audit` (the CLI) this writes no report, no history, and prints
nothing. It returns findings as plain dicts for a caller to consume.

    from mantis import audit
    findings = audit("path/to/src")             # SAST only, no provider needed
    findings = audit("path/to/src", llm=True)   # + LLM triage verdicts

Each record uses mantis's native, consumer-agnostic shape:

    {
        "rule_id": str,
        "severity": "ERROR" | "WARNING" | "INFO",
        "confidence": str,
        "path": str,
        "start_line": int,
        "end_line": int,
        "message": str,
        "metadata": dict,          # cwe, owasp, owasp-mobile-2024, masvs-v2, ...
        "verdict": str | None,     # None with llm=False; TRUE/FALSE/NEEDS-DEEP otherwise
    }
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional


def _record(finding, verdict: Optional[str]) -> dict:
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "path": finding.path,
        "start_line": finding.start_line,
        "end_line": finding.end_line,
        "message": finding.message.strip(),
        "metadata": dict(finding.metadata),
        "verdict": verdict,
    }


def audit(
    path,
    *,
    mode: Optional[str] = None,
    llm: bool = False,
    config: Optional[str] = None,
    sast_bin: Optional[str] = None,
) -> list[dict]:
    """Audit a source tree and return findings as a list of dicts.

    SAST-only by default (no LLM provider required). Pass ``llm=True`` to also
    run triage, which attaches a per-finding verdict (TRUE / FALSE / NEEDS-DEEP).

    Raises ``NotADirectoryError`` when ``path`` is not a directory, and
    propagates ``ConfigError`` / ``SastError`` / ``ScanError`` from the stages.
    """
    from mantis.cli import REPO_ROOT
    from mantis.config import load_config
    from mantis.inventory import packs_for, take_inventory
    from mantis.sast import resolve_sast_binary
    from mantis.scan import (
        ScanError, compose_pack_files, dedupe_findings,
        filter_valid_rule_files, run_scan,
    )
    from mantis.suppressions import apply_suppressions, load_suppressions

    target = Path(path).resolve()
    if not target.is_dir():
        raise NotADirectoryError(f"target not found: {target}")

    cfg = load_config(target, explicit=config, skip_provider_validation=not llm)
    sast = resolve_sast_binary(sast_bin or cfg.sast_bin)

    inv = take_inventory(target)
    packs = packs_for(mode, inv)
    rule_files = compose_pack_files(packs, REPO_ROOT / "scripts")
    valid_rules, _invalid = filter_valid_rule_files(rule_files, sast)
    if not valid_rules:
        raise ScanError("no valid rule files in composed pack")

    scan_out = run_scan(target, valid_rules, sast)
    kept, _suppressed = apply_suppressions(
        dedupe_findings(scan_out.findings), load_suppressions(target), target,
    )

    if not llm or not kept:
        return [_record(f, None) for f in kept]

    # LLM path: triage only (a verdict per finding). Deep-review/fix stay CLI-only.
    from mantis.agents import discover_agents
    from mantis.providers import Provider
    from mantis.triage import triage_all

    agents = discover_agents(REPO_ROOT / "agents")
    provider = Provider(cfg)
    results = triage_all(kept, agents, provider, target, mode=cfg.triage_mode or "single")
    return [_record(r.finding, r.verdict) for r in results]
