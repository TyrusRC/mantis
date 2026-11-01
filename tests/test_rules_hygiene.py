"""Guards over the shipped rule set: every file loads, ids are unique, metadata is complete."""
from __future__ import annotations

import shutil
from collections import Counter
from pathlib import Path

import pytest
import yaml

from mantis.scan import filter_valid_rule_files

RULES = Path(__file__).resolve().parent.parent / "mantis" / "resources" / "rules"
FILES = sorted(p for p in RULES.rglob("*.yaml")
               if "packs" not in p.parts and not p.name.startswith("_"))


def _rules():
    for f in FILES:
        for r in (yaml.safe_load(f.read_text()) or {}).get("rules") or []:
            yield f, r


@pytest.mark.skipif(shutil.which("opengrep") is None, reason="opengrep not installed")
def test_every_rule_file_passes_scanner_validate():
    _, invalid = filter_valid_rule_files(FILES, "opengrep")
    assert invalid == []


def test_rule_ids_are_unique():
    dupes = {i: n for i, n in Counter(r["id"] for _, r in _rules()).items() if n > 1}
    assert dupes == {}


def test_every_rule_has_required_metadata():
    missing = [f"{f.relative_to(RULES)}:{r['id']}:{k}"
               for f, r in _rules()
               for k in ("category", "cwe", "confidence")
               if not (r.get("metadata") or {}).get(k)]
    assert missing == []


# ---- rule fixtures: each `ruleid: a, b` comment names exactly the rules that must fire on that line
# (or on the next line, when the comment stands alone) ----

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "rules"
_CASES = {
    "a07": ["web/owasp-top10-2025-a07-auth-failures.yaml"],
    "native": ["native/decompiled-c-vulns.yaml"],
    "xxe": ["web/spring-java-taint.yaml"],
    "node": ["web/owasp-top10-2025-a03-nosql-and-pathtraversal.yaml",
             "web/owasp-top10-2025-a01-open-redirect.yaml",
             "web/owasp-top10-2025-a10-ssrf.yaml"],
    # notes.txt repeats build.gradle without annotations: generic rules must stay in *.gradle.
    "gradle": ["cross-platform/owasp-m2-supply-chain-security.yaml",
               "cross-platform/react-native-binary-protection.yaml"],
}


def _expected(case_dir: Path) -> set[tuple[str, int, str]]:
    out = set()
    for f in (p for p in case_dir.rglob("*") if p.is_file()):
        for n, line in enumerate(f.read_text().splitlines(), 1):
            if "ruleid:" in line:
                # A comment-only line annotates the next line (needed inside multi-line patterns).
                own_line = line.lstrip().startswith(("#", "//"))
                for rid in line.split("ruleid:", 1)[1].split(","):
                    out.add((str(f.relative_to(case_dir)), n + own_line, rid.strip()))
    return out


@pytest.mark.skipif(shutil.which("opengrep") is None, reason="opengrep not installed")
@pytest.mark.parametrize("case", sorted(_CASES))
def test_rule_fixtures_fire_exactly_where_annotated(case, tmp_path):
    from mantis.scan import run_scan
    case_dir = FIXTURES / case
    # The scanner's default ignore list skips anything under tests/.
    target = shutil.copytree(case_dir, tmp_path / case)
    out = run_scan(target, [RULES / r for r in _CASES[case]], "opengrep",
                   severities=("ERROR", "WARNING", "INFO"))
    assert out.errors == []
    actual = {(str(Path(f.path).relative_to(target)), f.start_line, f.rule_id.rsplit(".", 1)[-1])
              for f in out.findings}
    assert actual == _expected(case_dir)


@pytest.mark.parametrize("case", sorted(_CASES))
def test_rule_fixture_cases_are_not_vacuous(case):
    # Without annotations, "no findings == no expectations" passes on a dead rule.
    expected = _expected(FIXTURES / case)
    assert expected, f"{case}: fixture has no `ruleid:` annotations"
    ids = {r["id"] for rel in _CASES[case]
           for r in (yaml.safe_load((RULES / rel).read_text()) or {}).get("rules", [])}
    assert {rid for _, _, rid in expected} <= ids
