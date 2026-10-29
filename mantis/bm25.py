"""Lightweight BM25 scorer for asset-to-finding linking.

When direct call-graph tracing (grep-based callers in slice.py, Python AST
in callgraph.py) fails to link a finding to an entry point, BM25 term
overlap ranks which entry point is most likely to be the finding's attack
surface. This handles indirect calls, dynamic dispatch, callback patterns,
and multi-file chains that grep misses.

Operates on pre-tokenised code windows. No external dependencies.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field


_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_STOP = frozenset({
    "the", "and", "for", "from", "import", "return", "self", "none",
    "true", "false", "def", "class", "if", "else", "elif", "try",
    "except", "finally", "with", "as", "in", "not", "or", "is",
    "pass", "break", "continue", "raise", "yield", "lambda", "async",
    "await", "var", "let", "const", "function", "new", "this",
    "public", "private", "protected", "static", "void", "int",
    "string", "bool", "null", "undefined",
})


def tokenise(text: str) -> list[str]:
    return [t.lower() for t in _TOKEN_RE.findall(text) if t.lower() not in _STOP and len(t) > 1]


@dataclass
class BM25Index:
    """Tiny in-memory BM25 index. Docs are keyed by an opaque string id."""
    k1: float = 1.5
    b: float = 0.75
    _docs: dict[str, list[str]] = field(default_factory=dict)
    _df: dict[str, int] = field(default_factory=dict)
    _avgdl: float = 0.0
    _n: int = 0

    def add(self, doc_id: str, text: str) -> None:
        tokens = tokenise(text)
        self._docs[doc_id] = tokens
        seen: set[str] = set()
        for t in tokens:
            if t not in seen:
                self._df[t] = self._df.get(t, 0) + 1
                seen.add(t)
        self._n = len(self._docs)
        total = sum(len(d) for d in self._docs.values())
        self._avgdl = total / self._n if self._n else 0.0

    def score(self, query_tokens: list[str], doc_id: str) -> float:
        doc = self._docs.get(doc_id)
        if not doc:
            return 0.0
        dl = len(doc)
        tf_map: dict[str, int] = {}
        for t in doc:
            tf_map[t] = tf_map.get(t, 0) + 1
        s = 0.0
        for qt in query_tokens:
            df = self._df.get(qt, 0)
            if df == 0:
                continue
            idf = math.log((self._n - df + 0.5) / (df + 0.5) + 1.0)
            tf = tf_map.get(qt, 0)
            num = tf * (self.k1 + 1)
            den = tf + self.k1 * (1 - self.b + self.b * dl / self._avgdl) if self._avgdl else tf + self.k1
            s += idf * num / den
        return s

    def rank(self, query_text: str, top_k: int = 5) -> list[tuple[str, float]]:
        qt = tokenise(query_text)
        if not qt:
            return []
        scores = [(did, self.score(qt, did)) for did in self._docs]
        scores.sort(key=lambda x: -x[1])
        return [(did, sc) for did, sc in scores[:top_k] if sc > 0]


def build_entry_point_index(asset_map, target_root) -> BM25Index:
    """Index entry-point file windows for BM25 ranking against findings."""
    from pathlib import Path
    idx = BM25Index()
    seen_files: set[str] = set()
    for ep in asset_map.entry_points:
        if ep.file in seen_files:
            continue
        seen_files.add(ep.file)
        fpath = Path(target_root) / ep.file
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        start = max(0, ep.line - 20)
        end = min(len(lines), ep.line + 30)
        window = "\n".join(lines[start:end])
        idx.add(f"{ep.file}:{ep.line}:{ep.name}", window)
    return idx


def link_finding_to_entry_points(
    finding_window: str, index: BM25Index, top_k: int = 3
) -> list[tuple[str, float]]:
    """Rank entry points by BM25 relevance to a finding's code window."""
    return index.rank(finding_window, top_k=top_k)
