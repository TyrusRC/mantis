"""Semantic dedup of SAST findings.

Cluster findings by ``(rule_id, path, enclosing_function)`` so 12
SQLi findings inside one helper become one cluster — one triage call,
one slice, one deep-review call. The representative is the lowest-line
finding in each cluster; sibling dupes ride along in the report.

The enclosing-function lookup reuses ``mantis.slice.find_enclosing_function``
so the cluster key matches the slice the deep-reviewer would have seen.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from mantis.scan import Finding
from mantis.slice import EXT_TO_LANG, find_enclosing_function


@dataclass
class Cluster:
    representative: Finding
    siblings: list[Finding] = field(default_factory=list)
    enclosing_function: Optional[str] = None

    @property
    def count(self) -> int:
        return 1 + len(self.siblings)


def _enclosing_function_name(finding: Finding, target: Path) -> Optional[str]:
    """Best-effort enclosing-function lookup. None if file/lang unknown."""
    fp = Path(finding.path)
    if not fp.is_absolute():
        fp = (target / fp).resolve()
    ext = fp.suffix.lower()
    lang = EXT_TO_LANG.get(ext)
    if not lang or not fp.is_file():
        return None
    try:
        text = fp.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    res = find_enclosing_function(text, finding.start_line, lang)
    return res[0] if res else None


def _cluster_key(finding: Finding, fn_name: Optional[str]) -> tuple[str, str, str]:
    # Module-level findings (no enclosing function — e.g. Express route
    # registrations, top-level config) collapse to one cluster per
    # (rule_id, path). Without this fallback every line would be its own
    # cluster — exactly what we want to avoid.
    return (finding.rule_id, finding.path, fn_name or "_module")


def cluster_findings(
    findings: Iterable[Finding], target: Path,
) -> tuple[list[Cluster], dict[str, int]]:
    """Group findings by (rule_id, path, enclosing_function).

    Returns (clusters, stats). Stats reports total / clusters / collapsed.
    Representative is the lowest-line finding per cluster; ordering across
    clusters is preserved (first occurrence wins, stable for tests).
    """
    by_key: dict[tuple[str, str, str], Cluster] = {}
    order: list[tuple[str, str, str]] = []
    total = 0
    for f in findings:
        total += 1
        fn = _enclosing_function_name(f, target)
        key = _cluster_key(f, fn)
        c = by_key.get(key)
        if c is None:
            by_key[key] = Cluster(representative=f, enclosing_function=fn)
            order.append(key)
        else:
            if f.start_line < c.representative.start_line:
                c.siblings.append(c.representative)
                c.representative = f
            else:
                c.siblings.append(f)
    clusters = [by_key[k] for k in order]
    collapsed = total - len(clusters)
    return clusters, {"total": total, "clusters": len(clusters), "collapsed": collapsed}
