#!/usr/bin/env python3
"""Compose a Semgrep rule set from a pack spec.

A pack spec (rules/packs/<name>.yaml) declares filters over rules/_manifest.yaml.
This script applies the filters and prints the matching rule file paths,
deduplicated, suitable for piping into Semgrep:

    semgrep $(./scripts/pack_compose.py rules/packs/fast.yaml --as-args) <target>

Or, with --print-files, just the file paths one per line.

Pack spec schema:

    name: fast
    description: ...
    filters:                       # AND'd together. omit any to skip the gate.
      severity: [ERROR]            # rule severity in this list
      confidence: [HIGH]           # rule metadata.confidence in this list
      languages_any: [swift]       # rule languages intersect this list
      pack_tag: [fast]             # rule metadata.pack contains any of these
      paths_under: [rules/ios/]    # rule file starts with one of these
      rule_id_globs: []            # rule id matches one of these globs
      has_cve: true                # rule metadata.cve is set
    exclude:                       # subtract matching rules
      rule_id_globs: []
      paths_under: []
"""
from __future__ import annotations

import argparse
import fnmatch
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.stderr.write("PyYAML required: pip install pyyaml\n")
    sys.exit(2)

REPO = Path(__file__).resolve().parent.parent
MANIFEST = REPO / "rules" / "_manifest.yaml"


def load_manifest():
    if not MANIFEST.exists():
        sys.stderr.write(f"manifest not found: {MANIFEST}\n")
        sys.stderr.write("run scripts/build_manifest.py first\n")
        sys.exit(2)
    with MANIFEST.open() as f:
        return yaml.safe_load(f)


def match_globs(value, globs):
    return any(fnmatch.fnmatchcase(value or "", g) for g in globs)


def rule_matches(rule, filters):
    if not filters:
        return True
    sev = filters.get("severity")
    if sev and rule.get("severity") not in sev:
        return False
    conf = filters.get("confidence")
    if conf and rule.get("confidence") not in conf:
        return False
    langs_any = filters.get("languages_any")
    if langs_any:
        rl = set(rule.get("languages") or [])
        if not (rl & set(langs_any)):
            return False
    pack_tag = filters.get("pack_tag")
    if pack_tag:
        rp = rule.get("pack") or []
        if not (set(rp) & set(pack_tag)):
            return False
    paths_under = filters.get("paths_under")
    if paths_under and not any(rule["file"].startswith(p) for p in paths_under):
        return False
    rid_globs = filters.get("rule_id_globs")
    if rid_globs and not match_globs(rule.get("id"), rid_globs):
        return False
    if filters.get("has_cve") and not rule.get("cve"):
        return False
    return True


def excluded(rule, exclude):
    if not exclude:
        return False
    if match_globs(rule.get("id"), exclude.get("rule_id_globs") or []):
        return True
    paths_under = exclude.get("paths_under") or []
    if paths_under and any(rule["file"].startswith(p) for p in paths_under):
        return True
    return False


def compose(spec, manifest):
    filters = spec.get("filters") or {}
    exclude = spec.get("exclude") or {}
    files = []
    seen = set()
    for rule in manifest.get("rules") or []:
        if not rule_matches(rule, filters):
            continue
        if excluded(rule, exclude):
            continue
        f = rule["file"]
        if f not in seen:
            seen.add(f)
            files.append(f)
    return files


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("spec", help="path to a pack spec yaml under rules/packs/")
    ap.add_argument("--as-args", action="store_true",
                    help="print as `--config <path>` for splicing into a semgrep call")
    ap.add_argument("--print-files", action="store_true",
                    help="print one rule file path per line (default)")
    args = ap.parse_args()

    spec_path = Path(args.spec)
    if not spec_path.exists():
        sys.stderr.write(f"spec not found: {spec_path}\n")
        sys.exit(2)
    with spec_path.open() as f:
        spec = yaml.safe_load(f)

    manifest = load_manifest()
    files = compose(spec, manifest)

    if not files:
        sys.stderr.write(f"no rules matched pack '{spec.get('name', spec_path.stem)}'\n")
        sys.exit(1)

    if args.as_args:
        print(" ".join(f"--config {f}" for f in files))
    else:
        for f in files:
            print(f)
    sys.stderr.write(f"# {len(files)} rule file(s) in pack '{spec.get('name', spec_path.stem)}'\n")


if __name__ == "__main__":
    main()
