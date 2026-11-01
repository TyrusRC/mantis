#!/usr/bin/env python3
"""Stage 0b for MCP mode: run the shipped asset map + STRIDE threat model.

    asset_map.py <target> [--findings <scan.json>]

Prints the asset-map summary and the auto-generated threat model. With
--findings, also prints one compact asset-context block per finding, keyed by
the same `f<n>` ids project_findings.py emits.

Imports the `mantis` package this script ships inside (stdlib-only modules), so
it works from a source checkout and from a pip/pipx install alike. Exits 3 if
the package is not importable; the orchestrator then falls back to an
inventory-only threat model.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Only trust <pkg-parent>/mantis/resources/scripts/asset_map.py; a copied
# install has no package above it, and we must not import whatever sits there.
_HERE = Path(__file__).resolve()
if _HERE.parents[1].name != "resources" or _HERE.parents[2].name != "mantis":
    sys.stderr.write("mantis asset map unavailable: not inside the mantis package\n")
    raise SystemExit(3)
sys.path.insert(0, str(_HERE.parents[3]))

try:
    from mantis.assetmap import build_asset_map
except ImportError as e:
    sys.stderr.write(f"mantis asset map unavailable: {e}\n")
    raise SystemExit(3)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--findings", help="opengrep --json output file")
    args = ap.parse_args()

    target = Path(args.target).resolve()
    if not target.is_dir():
        sys.stderr.write(f"target not found: {target}\n")
        return 2
    amap = build_asset_map(target)
    print(f"# assets: {amap.summary()} ({amap.indexed_files} files indexed)")
    print(amap.threat_model())

    if args.findings:
        with open(args.findings, encoding="utf-8") as f:
            results = json.load(f).get("results") or []
        print("\n# asset context per finding")
        for i, r in enumerate(results, 1):
            ctx = amap.context_for(r.get("path", ""), (r.get("start") or {}).get("line", 0))
            if ctx:
                print(f"f{i}:\n  {ctx}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
