#!/usr/bin/env python3
"""Build rules/_manifest.yaml from every rule file under rules/.

Reads each YAML, extracts per-rule metadata, emits a single index file plus
a summary block (totals by severity, language, category, OWASP / MASVS / CWE
distribution). The manifest drives pack composition, coverage reporting, and
agent rule selection.
"""
from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.stderr.write("PyYAML required: pip install pyyaml\n")
    sys.exit(2)

REPO = Path(__file__).resolve().parent.parent
RULES_DIR = REPO / "rules"
OUT = RULES_DIR / "_manifest.yaml"


def normalize_list(v):
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def collect():
    entries = []
    for path in sorted(RULES_DIR.rglob("*.yaml")):
        if path.name == "_manifest.yaml":
            continue
        rel = path.relative_to(REPO).as_posix()
        if rel.startswith("rules/packs/"):
            # Pack specs are metadata for pack_compose.py, not Semgrep rules.
            continue
        try:
            with path.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            entries.append({"file": rel, "error": f"yaml-parse-error: {e}"})
            continue
        if not isinstance(data, dict) or "rules" not in data:
            entries.append({"file": rel, "error": "no-rules-key"})
            continue
        for rule in data.get("rules") or []:
            md = rule.get("metadata") or {}
            entries.append({
                "file": rel,
                "id": rule.get("id"),
                "severity": rule.get("severity"),
                "languages": normalize_list(rule.get("languages")),
                "category": md.get("category"),
                "cwe": normalize_list(md.get("cwe")),
                "owasp_mobile": md.get("owasp-mobile-2024") or md.get("owasp-mobile"),
                "owasp": md.get("owasp"),
                "masvs": md.get("masvs-v2") or md.get("masvs"),
                "maswe": md.get("maswe"),
                "cve": normalize_list(md.get("cve")),
                "cvss": md.get("cvss_score") or md.get("cvss"),
                "confidence": md.get("confidence"),
                "pack": normalize_list(md.get("pack")),
                "source": md.get("source"),
            })
    return entries


def summarize(entries):
    sev = Counter()
    lang = Counter()
    cat = Counter()
    owasp = Counter()
    masvs = Counter()
    confidence = Counter()
    files = set()
    rule_count = 0
    errors = []
    for e in entries:
        if "error" in e:
            errors.append(e)
            continue
        rule_count += 1
        files.add(e["file"])
        if e.get("severity"):
            sev[e["severity"]] += 1
        for l in e.get("languages") or []:
            lang[l] += 1
        if e.get("category"):
            cat[e["category"]] += 1
        if e.get("owasp_mobile"):
            owasp[str(e["owasp_mobile"])] += 1
        if e.get("masvs"):
            masvs[str(e["masvs"])] += 1
        if e.get("confidence"):
            confidence[str(e["confidence"])] += 1
    return {
        "total_rules": rule_count,
        "total_files": len(files),
        "by_severity": dict(sev),
        "by_language": dict(lang),
        "by_category": dict(cat),
        "by_owasp_mobile": dict(owasp),
        "by_masvs": dict(masvs),
        "by_confidence": dict(confidence),
        "parse_errors": errors,
    }


def main():
    entries = collect()
    summary = summarize(entries)
    out = {
        "_meta": {
            "generated_by": "scripts/build_manifest.py",
            "schema_version": 1,
            "note": "Auto-generated. Do not edit by hand. Re-run the script after changing rules/.",
        },
        "summary": summary,
        "rules": [e for e in entries if "error" not in e],
    }
    with OUT.open("w", encoding="utf-8") as f:
        yaml.safe_dump(out, f, sort_keys=False, width=120)
    print(f"wrote {OUT.relative_to(REPO)}")
    print(f"  {summary['total_rules']} rules across {summary['total_files']} files")
    if summary["parse_errors"]:
        print(f"  WARN: {len(summary['parse_errors'])} parse error(s):")
        for err in summary["parse_errors"]:
            print(f"    - {err['file']}: {err['error']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
