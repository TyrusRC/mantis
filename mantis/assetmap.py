"""Stage 0b: asset map.

Scan source files for structural assets -- entry points, trust boundaries,
data stores, external calls -- by regex pattern matching across all
supported languages. One pass per file, all applicable patterns at once.

The asset map enriches downstream stages:
- Triage: compact context ("this finding is in a route handler / behind auth")
- Reachability: entry-point detection for non-Python languages
- Slice: trust-boundary and data-store annotations
- Deep review: attack-surface context

Pattern definitions live in ``asset_patterns.py``; STRIDE threat-model
generation lives in ``threatmodel.py``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from mantis.asset_patterns import EXT_EXTRA, LANG_PATTERNS
from mantis.slice import EXT_TO_LANG

MAX_INDEX_FILES = 5000
MAX_FILE_SIZE_BYTES = 1_500_000

_SKIP_DIRS = frozenset({
    "node_modules", "vendor", ".git", "build", "dist",
    ".venv", "venv", "__pycache__", ".tox", ".mypy_cache",
    ".pytest_cache", "target", ".gradle", ".idea",
})

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class AssetNode:
    kind: str       # entrypoint | middleware | datastore | external | sensitive
    name: str       # human-readable (e.g. "POST /api/login", "login_required")
    file: str       # relative path from target root
    line: int
    detail: str     # pattern label (e.g. "flask-route", "jwt-verify")
    language: str


@dataclass
class AssetMap:
    nodes: list[AssetNode] = field(default_factory=list)
    _by_file: dict[str, list[AssetNode]] = field(default_factory=dict)
    _by_kind: dict[str, list[AssetNode]] = field(default_factory=dict)
    indexed_files: int = 0

    def _index(self) -> None:
        self._by_file.clear()
        self._by_kind.clear()
        for n in self.nodes:
            self._by_file.setdefault(n.file, []).append(n)
            self._by_kind.setdefault(n.kind, []).append(n)

    @property
    def entry_points(self) -> list[AssetNode]:
        return self._by_kind.get("entrypoint", [])

    @property
    def trust_boundaries(self) -> list[AssetNode]:
        return self._by_kind.get("middleware", [])

    @property
    def data_stores(self) -> list[AssetNode]:
        return self._by_kind.get("datastore", [])

    @property
    def externals(self) -> list[AssetNode]:
        return self._by_kind.get("external", [])

    def has_entry_point(self, file: str) -> bool:
        return any(n.kind == "entrypoint" for n in self._by_file.get(file, []))

    def nearest_entry_point(self, file: str, line: int) -> Optional[AssetNode]:
        eps = [n for n in self._by_file.get(file, []) if n.kind == "entrypoint"]
        if not eps:
            return None
        return min(eps, key=lambda n: abs(n.line - line))

    def is_guarded(self, file: str, line: int) -> tuple[bool, Optional[str]]:
        """Check if a location appears to be behind auth middleware."""
        mw = [n for n in self._by_file.get(file, []) if n.kind == "middleware"]
        if not mw:
            return False, None
        guards = [n for n in mw if n.line < line]
        if guards:
            closest = max(guards, key=lambda n: n.line)
            return True, closest.name
        return False, None

    def context_for(self, file: str, line: int, max_items: int = 6) -> str:
        """Compact asset-context string for triage/deep prompts."""
        nodes = self._by_file.get(file, [])
        if not nodes:
            return ""
        lines: list[str] = []

        ep = self.nearest_entry_point(file, line)
        if ep:
            lines.append(f"ENTRY: {ep.name} (line {ep.line})")

        guarded, guard_name = self.is_guarded(file, line)
        lines.append(f"AUTH: {guard_name}" if guarded else "AUTH: unguarded")

        seen = 0
        kind_tag = {"datastore": "DATA", "external": "EXTL", "sensitive": "SENS"}
        for n in sorted(nodes, key=lambda n: abs(n.line - line)):
            if n.kind in ("entrypoint", "middleware"):
                continue
            tag = kind_tag.get(n.kind, n.kind[:4].upper())
            lines.append(f"{tag}: {n.name} (line {n.line})")
            seen += 1
            if seen >= max_items:
                break
        return "\n  ".join(lines)

    def summary(self) -> str:
        counts = {k: len(v) for k, v in self._by_kind.items()}
        parts = [f"{counts.get(k, 0)} {k}" for k in
                 ("entrypoint", "middleware", "datastore", "external", "sensitive")
                 if counts.get(k)]
        return ", ".join(parts) if parts else "no assets detected"

    def threat_model(self) -> str:
        """Auto-generate a STRIDE-based threat model from discovered assets."""
        from mantis.threatmodel import build_threat_model
        return build_threat_model(self)


# ---------------------------------------------------------------------------
# Name extraction
# ---------------------------------------------------------------------------

def _extract_name(match: re.Match, line_text: str) -> str:
    gd = match.groupdict()
    method = gd.get("method", "")
    path = gd.get("path", "")
    name = gd.get("name", "")

    if method and path:
        return f"{method.upper()} {path}"
    if path:
        return path
    if method:
        return method.upper()
    if name:
        return name
    groups = [g for g in match.groups() if g]
    if groups:
        return groups[0][:80]
    return line_text.strip()[:80]


def _lang_for_ext(suffix: str) -> str:
    return EXT_TO_LANG.get(suffix, "") or EXT_EXTRA.get(suffix, "")


# ---------------------------------------------------------------------------
# File scanner
# ---------------------------------------------------------------------------

def _scan_file(text: str, language: str, rel_path: str) -> list[AssetNode]:
    patterns = LANG_PATTERNS.get(language)
    if not patterns:
        return []

    nodes: list[AssetNode] = []
    for i, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        for rx, kind, label in patterns:
            m = rx.search(line)
            if m:
                nodes.append(AssetNode(
                    kind=kind,
                    name=_extract_name(m, line),
                    file=rel_path,
                    line=i,
                    detail=label,
                    language=language,
                ))
                break  # one match per line is enough
    return nodes


# ---------------------------------------------------------------------------
# Tree walker / public API
# ---------------------------------------------------------------------------

def _walk_source_files(target: Path) -> list[tuple[Path, str]]:
    target = target.resolve()
    out: list[tuple[Path, str]] = []
    for p in target.rglob("*"):
        if not p.is_file():
            continue
        if any(part in _SKIP_DIRS for part in p.relative_to(target).parts):
            continue
        lang = _lang_for_ext(p.suffix.lower())
        if not lang:
            continue
        try:
            if p.stat().st_size > MAX_FILE_SIZE_BYTES:
                continue
        except OSError:
            continue
        out.append((p, lang))
        if len(out) >= MAX_INDEX_FILES:
            break
    return out


def build_asset_map(target: Path, stack=None) -> AssetMap:
    """Build the asset map for a target directory.

    ``stack`` is the ``inventory.Stack`` (optional, currently unused but
    reserved for future language-priority hinting).
    """
    target = target.resolve()
    amap = AssetMap()
    files = _walk_source_files(target)

    for abs_path, language in files:
        try:
            text = abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            rel = str(abs_path.relative_to(target))
        except ValueError:
            rel = str(abs_path)
        nodes = _scan_file(text, language, rel)
        amap.nodes.extend(nodes)
        amap.indexed_files += 1

    amap._index()
    return amap
