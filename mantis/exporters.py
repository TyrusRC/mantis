"""Alternative report exporters: JSON and SARIF v2.1.0.

Both are written alongside the canonical markdown report. They share the
same structured-finding shape so downstream tools (CI, editors) can
consume either.
"""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Iterable

from mantis import __version__


def _finding_record(r) -> dict:
    f = r.finding
    return {
        "rule_id": f.rule_id,
        "severity": f.severity,
        "confidence": f.confidence,
        "path": f.path,
        "start_line": f.start_line,
        "end_line": f.end_line,
        "message": f.message.strip(),
        "verdict": r.verdict,
        "verdict_reason": (r.reason or "").strip(),
        "cwe": f.metadata.get("cwe"),
        "owasp": f.metadata.get("owasp") or f.metadata.get("owasp-mobile-2024"),
        "category": f.metadata.get("category"),
    }


def write_json(out_path: Path, meta, triage_results: Iterable, raw_findings: Iterable) -> Path:
    payload = {
        "schema": "mantis.audit/v1",
        "mantis_version": __version__,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "target": str(meta.target),
        "mode": meta.mode,
        "packs": list(meta.packs),
        "sast_bin": meta.sast_bin,
        "provider": meta.provider,
        "duration_seconds": meta.duration_seconds,
        "tokens_in": meta.tokens_in,
        "tokens_out": meta.tokens_out,
        "status": meta.status,
        "notes": list(meta.notes or []),
        "totals": {
            "raw_findings": len(list(raw_findings)),
            "triaged": len(list(triage_results)),
        },
        "findings": [_finding_record(r) for r in triage_results],
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                        encoding="utf-8")
    return out_path


_SEVERITY_SARIF = {"ERROR": "error", "WARNING": "warning", "INFO": "note"}


def _sarif_level(sev: str) -> str:
    return _SEVERITY_SARIF.get((sev or "").upper(), "warning")


def _sarif_result(r, target: Path) -> dict:
    f = r.finding
    try:
        rel = str(Path(f.path).resolve().relative_to(target))
    except ValueError:
        rel = f.path
    props: dict = {"verdict": r.verdict}
    if r.reason:
        props["verdict_reason"] = r.reason.strip()
    if f.metadata.get("cwe"):
        props["cwe"] = f.metadata["cwe"]
    if f.metadata.get("owasp"):
        props["owasp"] = f.metadata["owasp"]
    if f.metadata.get("confidence"):
        props["confidence"] = f.metadata["confidence"]
    return {
        "ruleId": f.rule_id,
        "level": _sarif_level(f.severity),
        "message": {"text": f.message.strip()},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": rel},
                "region": {"startLine": f.start_line, "endLine": f.end_line},
            }
        }],
        "properties": props,
    }


def _sarif_rule(rule_id: str, sample) -> dict:
    f = sample.finding
    return {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": rule_id},
        "fullDescription": {"text": f.message.strip()[:512]},
        "defaultConfiguration": {"level": _sarif_level(f.severity)},
        "properties": {
            "category": f.metadata.get("category"),
            "cwe": f.metadata.get("cwe"),
            "owasp": f.metadata.get("owasp") or f.metadata.get("owasp-mobile-2024"),
        },
    }


def write_sarif(out_path: Path, meta, triage_results) -> Path:
    target = Path(meta.target).resolve()
    rules_by_id: dict[str, dict] = {}
    for r in triage_results:
        rid = r.finding.rule_id
        if rid not in rules_by_id:
            rules_by_id[rid] = _sarif_rule(rid, r)
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "mantis",
                    "version": __version__,
                    "informationUri": "https://pypi.org/project/mantis-sast/",
                    "rules": list(rules_by_id.values()),
                }
            },
            "results": [_sarif_result(r, target) for r in triage_results],
            "invocations": [{
                "executionSuccessful": meta.status == "complete",
                "commandLine": f"mantis audit {meta.mode}",
                "workingDirectory": {"uri": str(target)},
            }],
        }],
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(sarif, indent=2, ensure_ascii=False),
                        encoding="utf-8")
    return out_path
