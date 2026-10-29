"""Context graph: structural code graph for security-aware analysis.

Inspired by graphify's architecture: tree-sitter parse -> extract nodes
and edges -> build a directed graph -> query for reachability and impact.

When tree-sitter is available, extracts:
- Nodes: functions, classes, routes/handlers, imports
- Edges: calls (EXTRACTED), imports (EXTRACTED), inferred routes (INFERRED)

When tree-sitter is unavailable, falls back to the regex-based asset map
and Python AST callgraph (the existing behavior).

The context graph enriches:
- Reachability: precise call-chain traversal from finding to entry point
- Slice: callers/callees with typed edges and confidence
- Triage: "this finding is 2 hops from an unguarded route" vs just
  "this file has a route nearby"
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from mantis._treesitter import is_available as _ts_available
from mantis.slice import EXT_TO_LANG


MAX_INDEX_FILES = 5000
MAX_FILE_SIZE_BYTES = 1_500_000

_SKIP_DIRS = frozenset({
    "node_modules", "vendor", ".git", "build", "dist",
    ".venv", "venv", "__pycache__", ".tox", ".mypy_cache",
    ".pytest_cache", "target", ".gradle", ".idea",
})

# tree-sitter node types that represent call expressions
_CALL_NODE_TYPES = {
    "python": {"call"},
    "javascript": {"call_expression", "new_expression"},
    "typescript": {"call_expression", "new_expression"},
    "java": {"method_invocation", "object_creation_expression"},
    "kotlin": {"call_expression"},
    "swift": {"call_expression"},
    "go": {"call_expression"},
    "ruby": {"call", "method_call"},
    "php": {"function_call_expression", "method_call_expression"},
    "rust": {"call_expression"},
}

_FUNC_NODE_TYPES = {
    "python": {"function_definition", "async_function_definition"},
    "javascript": {"function_declaration", "method_definition", "arrow_function"},
    "typescript": {"function_declaration", "method_definition", "arrow_function"},
    "java": {"method_declaration", "constructor_declaration"},
    "kotlin": {"function_declaration"},
    "swift": {"function_declaration"},
    "go": {"function_declaration", "method_declaration"},
    "ruby": {"method", "singleton_method"},
    "php": {"method_declaration", "function_definition"},
    "rust": {"function_item"},
}

_IMPORT_NODE_TYPES = {
    "python": {"import_statement", "import_from_statement"},
    "javascript": {"import_statement"},
    "typescript": {"import_statement"},
    "java": {"import_declaration"},
    "kotlin": {"import_header"},
    "go": {"import_spec"},
    "ruby": {"call"},  # require/require_relative
    "php": {"use_declaration"},
    "rust": {"use_declaration"},
}


@dataclass
class GraphNode:
    id: str             # file:name or file:L<line>
    kind: str           # function | class | route | import | file
    name: str
    file: str           # relative path
    line: int
    end_line: int = 0


@dataclass
class GraphEdge:
    source: str         # node id
    target: str         # node id
    relation: str       # calls | imports | defines | routes_to
    confidence: str     # EXTRACTED | INFERRED


@dataclass
class ContextGraph:
    """Lightweight directed code graph for security analysis."""
    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: list[GraphEdge] = field(default_factory=list)
    _callers: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    _callees: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    indexed_files: int = 0

    def _index_edges(self) -> None:
        self._callers.clear()
        self._callees.clear()
        for e in self.edges:
            if e.relation == "calls":
                self._callers.setdefault(e.target, []).append((e.source, e.confidence))
                self._callees.setdefault(e.source, []).append((e.target, e.confidence))

    def callers_of(self, func_name: str) -> list[tuple[str, str]]:
        """Return [(caller_node_id, confidence), ...] for a function name."""
        results = []
        for nid, node in self.nodes.items():
            if node.name == func_name and node.kind == "function":
                results.extend(self._callers.get(nid, []))
        return results

    def reaches_entry_point(self, func_name: str, file: str,
                            max_hops: int = 6) -> str:
        """BFS from func back through callers to find an entry point.

        Returns 'yes', 'no', or 'unknown'.
        """
        start_ids = [
            nid for nid, n in self.nodes.items()
            if n.name == func_name and n.file == file
            and n.kind in ("function", "route")
        ]
        if not start_ids:
            return "unknown"

        # If the function itself is a route, it's directly reachable
        for sid in start_ids:
            if self.nodes[sid].kind == "route":
                return "yes"

        visited: set[str] = set(start_ids)
        frontier: deque[tuple[str, int]] = deque((sid, 0) for sid in start_ids)

        while frontier:
            current, depth = frontier.popleft()
            node = self.nodes.get(current)
            if node and node.kind == "route":
                return "yes"
            if depth >= max_hops:
                continue
            for caller_id, _ in self._callers.get(current, []):
                if caller_id not in visited:
                    visited.add(caller_id)
                    caller = self.nodes.get(caller_id)
                    if caller and caller.kind == "route":
                        return "yes"
                    frontier.append((caller_id, depth + 1))

        return "no" if visited else "unknown"

    def hop_count_to_entry(self, func_name: str, file: str,
                           max_hops: int = 6) -> Optional[int]:
        """Return the shortest hop count from func to any entry point, or None."""
        start_ids = [
            nid for nid, n in self.nodes.items()
            if n.name == func_name and n.file == file
            and n.kind in ("function", "route")
        ]
        if not start_ids:
            return None

        for sid in start_ids:
            if self.nodes[sid].kind == "route":
                return 0

        visited: set[str] = set(start_ids)
        frontier: deque[tuple[str, int]] = deque((sid, 0) for sid in start_ids)

        while frontier:
            current, depth = frontier.popleft()
            node = self.nodes.get(current)
            if node and node.kind == "route":
                return depth
            if depth >= max_hops:
                continue
            for caller_id, _ in self._callers.get(current, []):
                if caller_id not in visited:
                    visited.add(caller_id)
                    caller = self.nodes.get(caller_id)
                    if caller and caller.kind == "route":
                        return depth + 1
                    frontier.append((caller_id, depth + 1))
        return None


# ---------------------------------------------------------------------------
# Tree-sitter-based extraction
# ---------------------------------------------------------------------------

_ROUTE_DECORATOR_PATTERNS = {
    "route", "get", "post", "put", "delete", "patch", "options", "head",
    "websocket", "api_view", "require_http_methods",
}

_ENTRYPOINT_NAMES = {
    "main", "handler", "lambda_handler", "handle_request",
    "viewDidLoad", "onCreate", "onStartCommand", "onReceive",
}


def _is_route_function(node, language: str, source_bytes: bytes) -> bool:
    """Check if a function node is a route handler (decorated or named)."""
    # Check function name against known entry point names
    name = _extract_function_name(node)
    if name and name in _ENTRYPOINT_NAMES:
        return True

    # Python/JS: check for decorators above the function
    if language in ("python",):
        # In Python tree-sitter, decorated_definition wraps the function
        parent = node.parent
        if parent and parent.type == "decorated_definition":
            for child in parent.children:
                if child.type == "decorator":
                    dec_text = source_bytes[child.start_byte:child.end_byte].decode("utf-8", errors="replace")
                    dec_lower = dec_text.lower()
                    if any(p in dec_lower for p in _ROUTE_DECORATOR_PATTERNS):
                        return True
                    if ".route(" in dec_lower or "handlefunc" in dec_lower:
                        return True

    # Go: check for http.ResponseWriter parameter
    if language == "go":
        params = node.child_by_field_name("parameters") if hasattr(node, 'child_by_field_name') else None
        if params:
            params_text = source_bytes[params.start_byte:params.end_byte].decode("utf-8", errors="replace")
            if "http.ResponseWriter" in params_text or "http.Request" in params_text:
                return True

    # Java/Kotlin: check for annotations
    if language in ("java", "kotlin"):
        for child in (node.parent.children if node.parent else []):
            if child.type in ("annotation", "marker_annotation"):
                ann_text = source_bytes[child.start_byte:child.end_byte].decode("utf-8", errors="replace")
                ann_lower = ann_text.lower()
                if any(p in ann_lower for p in ("getmapping", "postmapping", "requestmapping",
                                                 "putmapping", "deletemapping", "patchmapping",
                                                 "@get", "@post", "@put", "@delete", "@path")):
                    return True

    return False


def _extract_function_name(node) -> Optional[str]:
    """Get function name from a tree-sitter function node."""
    name_node = None
    try:
        name_node = node.child_by_field_name("name")
    except Exception:
        pass
    if name_node is None:
        for c in node.children:
            if c.type in ("identifier", "field_identifier", "type_identifier",
                          "simple_identifier", "property_identifier"):
                name_node = c
                break
    if name_node is None:
        return None
    return name_node.text.decode("utf-8", errors="replace") if isinstance(name_node.text, bytes) else str(name_node.text)


def _extract_call_name(node, source_bytes: bytes) -> Optional[str]:
    """Get the called function name from a call expression node."""
    func_node = None
    try:
        func_node = node.child_by_field_name("function")
    except Exception:
        pass
    if func_node is None:
        for c in node.children:
            if c.type in ("identifier", "field_identifier", "member_expression",
                          "attribute", "scoped_identifier"):
                func_node = c
                break
    if func_node is None:
        return None

    if func_node.type in ("member_expression", "attribute"):
        # obj.method() -> just "method"
        for c in func_node.children:
            if c.type in ("property_identifier", "identifier", "field_identifier"):
                text = source_bytes[c.start_byte:c.end_byte]
                return text.decode("utf-8", errors="replace")
        return None

    text = source_bytes[func_node.start_byte:func_node.end_byte]
    return text.decode("utf-8", errors="replace")


def _extract_file_ts(text: str, language: str, rel_path: str) -> tuple[list[GraphNode], list[GraphEdge]]:
    """Extract nodes and edges from a single file using tree-sitter."""
    from mantis._treesitter import _get_parser

    parser = _get_parser(language)
    if parser is None:
        return [], []

    source_bytes = text.encode("utf-8")
    try:
        tree = parser.parse(source_bytes)
    except Exception:
        return [], []

    func_types = _FUNC_NODE_TYPES.get(language, set())
    call_types = _CALL_NODE_TYPES.get(language, set())

    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    func_ranges: list[tuple[str, int, int, str]] = []  # (node_id, start, end, name)

    def walk(node):
        if node.type in func_types:
            name = _extract_function_name(node)
            if name:
                nid = f"{rel_path}:{name}"
                start = node.start_point[0] + 1
                end = node.end_point[0] + 1
                kind = "route" if _is_route_function(node, language, source_bytes) else "function"
                nodes.append(GraphNode(
                    id=nid, kind=kind, name=name,
                    file=rel_path, line=start, end_line=end,
                ))
                func_ranges.append((nid, start, end, name))

        if node.type in call_types:
            callee_name = _extract_call_name(node, source_bytes)
            if callee_name:
                call_line = node.start_point[0] + 1
                caller_id = _enclosing_func(func_ranges, call_line)
                if caller_id:
                    edges.append(GraphEdge(
                        source=caller_id,
                        target=callee_name,  # unresolved; resolved later
                        relation="calls",
                        confidence="EXTRACTED",
                    ))

        for child in node.children:
            walk(child)

    walk(tree.root_node)
    return nodes, edges


def _enclosing_func(func_ranges: list[tuple[str, int, int, str]], line: int) -> Optional[str]:
    """Find the function node_id that encloses a given line."""
    best: Optional[str] = None
    best_start = -1
    for nid, start, end, _ in func_ranges:
        if start <= line <= end and start > best_start:
            best = nid
            best_start = start
    return best


# ---------------------------------------------------------------------------
# Graph builder
# ---------------------------------------------------------------------------

def _resolve_call_targets(all_nodes: dict[str, GraphNode], edges: list[GraphEdge]) -> list[GraphEdge]:
    """Resolve unresolved call targets (bare function names) to node IDs."""
    name_to_ids: dict[str, list[str]] = {}
    for nid, node in all_nodes.items():
        if node.kind == "function":
            name_to_ids.setdefault(node.name, []).append(nid)

    resolved: list[GraphEdge] = []
    for edge in edges:
        if edge.target in all_nodes:
            resolved.append(edge)
            continue
        candidates = name_to_ids.get(edge.target, [])
        if len(candidates) == 1:
            resolved.append(GraphEdge(
                source=edge.source, target=candidates[0],
                relation=edge.relation, confidence="EXTRACTED",
            ))
        elif candidates:
            for cand in candidates:
                resolved.append(GraphEdge(
                    source=edge.source, target=cand,
                    relation=edge.relation, confidence="INFERRED",
                ))
    return resolved


def build_context_graph(target: Path, stack=None) -> Optional[ContextGraph]:
    """Build a context graph from the target directory.

    Returns None if tree-sitter is not available (callers should fall
    back to the regex asset map + Python callgraph).
    """
    if not _ts_available():
        return None

    target = target.resolve()
    graph = ContextGraph()
    all_edges: list[GraphEdge] = []

    count = 0
    for p in target.rglob("*"):
        if not p.is_file():
            continue
        if any(part in _SKIP_DIRS for part in p.relative_to(target).parts):
            continue
        lang = EXT_TO_LANG.get(p.suffix.lower(), "")
        if not lang or lang not in _FUNC_NODE_TYPES:
            continue
        try:
            if p.stat().st_size > MAX_FILE_SIZE_BYTES:
                continue
        except OSError:
            continue

        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        try:
            rel = str(p.relative_to(target))
        except ValueError:
            rel = str(p)

        nodes, edges = _extract_file_ts(text, lang, rel)
        for n in nodes:
            graph.nodes[n.id] = n
        all_edges.extend(edges)
        graph.indexed_files += 1
        count += 1
        if count >= MAX_INDEX_FILES:
            break

    graph.edges = _resolve_call_targets(graph.nodes, all_edges)
    graph._index_edges()
    return graph
