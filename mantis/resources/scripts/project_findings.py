#!/usr/bin/env python3
"""Project an opengrep --json result file down to one line per finding.

MCP mode: keeps the raw scanner JSON out of the orchestrator's context.

    project_findings.py <scan.json>

Prints a header, one line per scanner error, then one line per finding:

    # results=<n> errors=<m>
    ERR | <type> | <message, whitespace-collapsed, <=200 chars>
    f<n> | <rule-id> | <path>:<line> | <SEVERITY>[ [nosemgrep]] | <message, <=200 chars>[ | source <path>:<line> <code>]

`f<n>` is the 1-based index into the JSON `results` array; asset_map.py uses the
same ids. The rule id drops the dotted config-path prefix opengrep adds.
"""
from __future__ import annotations

import json
import sys

MSG_CAP = 200


def one_line(text: str) -> str:
    return " ".join((text or "").split())[:MSG_CAP]


def _taint_source(extra: dict) -> str:
    try:
        loc, code = (extra.get("dataflow_trace") or {})["taint_source"][1]
        return f"{loc['path']}:{loc['start']['line']} {one_line(str(code))[:120]}"
    except (KeyError, TypeError, ValueError, IndexError):
        return ""


def project(data: dict) -> list[str]:
    results = data.get("results") or []
    errors = data.get("errors") or []
    out = [f"# results={len(results)} errors={len(errors)}"]
    for e in errors:
        out.append(f"ERR | {e.get('type', 'error')} | {one_line(str(e.get('message', '')))}")
    for i, r in enumerate(results, 1):
        extra = r.get("extra") or {}
        rule = (r.get("check_id") or "unknown").rsplit(".", 1)[-1]
        line = (r.get("start") or {}).get("line", 0)
        sev = str(extra.get("severity") or "INFO").upper()
        tags = " [nosemgrep]" if extra.get("is_ignored") else ""
        src = _taint_source(extra)
        out.append(f"f{i} | {rule} | {r.get('path', '')}:{line} | {sev}{tags} | "
                   f"{one_line(extra.get('message', ''))}" + (f" | source {src}" if src else ""))
    return out


def main() -> int:
    if len(sys.argv) != 2:
        sys.stderr.write("usage: project_findings.py <scan.json>\n")
        return 2
    with open(sys.argv[1], encoding="utf-8") as f:
        data = json.load(f)
    print("\n".join(project(data)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
