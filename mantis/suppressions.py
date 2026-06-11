"""Persistent finding suppressions via .mantisignore.

Format (YAML list at <target>/.mantisignore):

    - rule_id: web-a03-sql-injection
      path: "tests/**"
      reason: test fixtures intentionally vulnerable
    - rule_id: secret-generic-password-assignment
      path: "docs/examples/**"

A finding is suppressed when its rule_id matches AND its path matches
the glob (or the glob is absent). Suppressions apply before triage so
suppressed findings never burn LLM tokens.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

import yaml

from mantis.scan import Finding


SUPPRESSION_FILENAME = ".mantisignore"


@dataclass
class SuppressionRule:
    rule_id: Optional[str] = None
    path: Optional[str] = None
    reason: str = ""

    def matches(self, finding: Finding, target: Path) -> bool:
        if self.rule_id:
            fid = finding.rule_id
            if not (self.rule_id == fid
                    or fid.endswith("." + self.rule_id)
                    or fnmatch.fnmatch(fid, self.rule_id)):
                return False
        if self.path:
            fp = Path(finding.path)
            try:
                if fp.is_absolute():
                    rel = str(fp.relative_to(target))
                else:
                    rel = str(fp)
            except ValueError:
                rel = str(fp)
            if not (fnmatch.fnmatch(rel, self.path)
                    or fnmatch.fnmatch(finding.path, self.path)):
                return False
        return True


class SuppressionParseError(Exception):
    pass


def load_suppressions(target: Path) -> list[SuppressionRule]:
    path = target / SUPPRESSION_FILENAME
    if not path.is_file():
        return []
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    except yaml.YAMLError as e:
        raise SuppressionParseError(f"{path}: {e}") from e
    if not isinstance(raw, list):
        raise SuppressionParseError(
            f"{path}: top level must be a YAML list of suppression entries"
        )
    rules: list[SuppressionRule] = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise SuppressionParseError(f"{path}: entry {i} is not a mapping")
        rules.append(SuppressionRule(
            rule_id=entry.get("rule_id"),
            path=entry.get("path"),
            reason=str(entry.get("reason") or ""),
        ))
    return rules


def apply_suppressions(
    findings: Iterable[Finding],
    rules: list[SuppressionRule],
    target: Path,
) -> tuple[list[Finding], list[Finding]]:
    """Split findings into (kept, suppressed) lists preserving order."""
    if not rules:
        return list(findings), []
    kept: list[Finding] = []
    dropped: list[Finding] = []
    for f in findings:
        if any(r.matches(f, target) for r in rules):
            dropped.append(f)
        else:
            kept.append(f)
    return kept, dropped


_SEV_RANK = {"INFO": 0, "LOW": 0, "WARNING": 1, "MEDIUM": 1, "ERROR": 2, "HIGH": 2, "CRITICAL": 3}


def severity_at_or_above(finding_sev: str, threshold: str) -> bool:
    fs = _SEV_RANK.get((finding_sev or "").upper())
    ts = _SEV_RANK.get((threshold or "").upper())
    if fs is None or ts is None:
        return False
    return fs >= ts
