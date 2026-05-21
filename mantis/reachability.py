"""Reachability gate.

Three layers, in priority order:
1. Python call-graph (when an indexed CallGraph is supplied).
2. Coarse path heuristics: test / spec / example / fixture / demo dirs
   and *_test.go / *Test.java / *.test.* filenames -> 'no'.
3. Caller-chunk evaluation: if every caller is in a dead path, 'no';
   otherwise 'yes'. Default to 'yes' on insufficient info (conservative
   — drop only when clearly dead).

The Python call-graph layer is the only new precision; non-Python
projects continue to use the path heuristic.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from mantis.callgraph import CallGraph
    from mantis.scan import Finding
    from mantis.slice import SliceChunk


_DEAD_PATH_TOKENS = (
    "/test/", "/tests/", "/testing/", "/__tests__/", "/spec/", "/specs/",
    "/example/", "/examples/", "/demo/", "/demos/", "/sample/", "/samples/",
    "/fixture/", "/fixtures/", "/mock/", "/mocks/",
    "/docs/", "/doc/",
)

_DEAD_FILENAME_PATTERNS = (
    re.compile(r"_test\.go$"),
    re.compile(r"[._-]test\.py$"),
    re.compile(r"[Tt]est\.java$"),
    re.compile(r"[._-](test|spec)\.[jt]sx?$"),
    re.compile(r"Tests\.swift$"),
    re.compile(r"Test\.kt$"),
)


def _is_dead_path(path: str) -> bool:
    norm = path.replace("\\", "/")
    if not norm.startswith("/"):
        norm = "/" + norm
    if any(tok in norm.lower() for tok in _DEAD_PATH_TOKENS):
        return True
    return any(pat.search(norm) for pat in _DEAD_FILENAME_PATTERNS)


def classify_reachability(
    finding,
    sink_func: str,
    chunks: list,
    callgraph: Optional["CallGraph"] = None,
) -> str:
    """Return 'yes', 'no', or 'unknown'.

    Path heuristic always runs first — anything in test/spec/example
    dirs is dead regardless of call graph (we don't want to chase
    callers in tests). Otherwise:
    - If a Python call graph is supplied AND the sink_func is in it,
      walk from sink to entry points; that result wins.
    - Else fall back to per-caller path inspection of the slice chunks.
    """
    if _is_dead_path(finding.path):
        return "no"

    if callgraph is not None and sink_func and finding.path.endswith(".py"):
        from mantis.callgraph import reaches_entrypoint
        cg_result = reaches_entrypoint(callgraph, sink_func)
        if cg_result in ("yes", "no"):
            return cg_result
        # cg returned 'unknown' -> fall through to path heuristic.

    callers = [c for c in chunks if getattr(c, "role", "") == "caller"]
    if not callers:
        return "yes"
    if all(_is_dead_path(c.file) for c in callers):
        return "no"
    return "yes"
