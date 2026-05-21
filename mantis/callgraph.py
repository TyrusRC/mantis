"""Python call-graph indexer.

Walks a project's .py files with `ast`, recording every `def`/`async def`
and every call site. Builds:
- defs:    name -> list of (file, line, end_line)
- callers: name -> set of (file, line) where `name(` is invoked
- file_funcs: file -> list of (name, start, end)

Used by the reachability gate to decide if a finding's enclosing
function is transitively callable from a likely entry point.

Non-Python files are ignored; the reachability gate falls back to path
heuristics for them.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional


MAX_INDEX_FILES = 5000
MAX_FILE_SIZE_BYTES = 1_500_000

# Path tokens that mark a file as definitely-an-entrypoint.
_ENTRYPOINT_PATH_TOKENS = (
    "/main.py", "/__main__.py", "/manage.py", "/wsgi.py", "/asgi.py",
    "/server.py", "/app.py", "/run.py", "/cli.py", "/entrypoint.py",
    "/handler.py", "/lambda_function.py",
)

# Function names that we always treat as entry points regardless of file.
_ENTRYPOINT_FUNCTION_NAMES = {
    "main", "lambda_handler", "handler", "handle_request",
    "wsgi_application", "asgi_application",
}

# Decorators that mark a function as an HTTP/IPC route (entry point).
_ROUTE_DECORATORS = (
    "route", "get", "post", "put", "delete", "patch", "head", "options",
    "endpoint", "api_view", "view", "method_decorator",
)


@dataclass
class CallGraph:
    defs: dict[str, list[tuple[str, int, int]]] = field(default_factory=dict)
    callers: dict[str, set[tuple[str, int]]] = field(default_factory=dict)
    file_funcs: dict[str, list[tuple[str, int, int]]] = field(default_factory=dict)
    entrypoints: set[str] = field(default_factory=set)
    indexed_files: int = 0


class _Visitor(ast.NodeVisitor):
    def __init__(self, file_rel: str, graph: CallGraph) -> None:
        self.file = file_rel
        self.graph = graph
        self._func_stack: list[str] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._record_def(node)
        self._func_stack.append(node.name)
        self.generic_visit(node)
        self._func_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._record_def(node)
        self._func_stack.append(node.name)
        self.generic_visit(node)
        self._func_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        name = _callee_name(node.func)
        if name:
            self.graph.callers.setdefault(name, set()).add((self.file, node.lineno))
        self.generic_visit(node)

    def _record_def(self, node) -> None:
        start = node.lineno
        end = getattr(node, "end_lineno", None) or start
        self.graph.defs.setdefault(node.name, []).append((self.file, start, end))
        self.graph.file_funcs.setdefault(self.file, []).append((node.name, start, end))
        if _is_entrypoint_def(node, self.file):
            self.graph.entrypoints.add(node.name)


def _callee_name(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _is_entrypoint_def(node, file_rel: str) -> bool:
    norm = "/" + file_rel.replace("\\", "/").lstrip("/")
    if any(tok in norm for tok in _ENTRYPOINT_PATH_TOKENS):
        return True
    if node.name in _ENTRYPOINT_FUNCTION_NAMES:
        return True
    for d in getattr(node, "decorator_list", []) or []:
        if isinstance(d, ast.Call):
            d = d.func
        if isinstance(d, ast.Attribute):
            if d.attr.lower() in _ROUTE_DECORATORS:
                return True
        elif isinstance(d, ast.Name):
            if d.id.lower() in _ROUTE_DECORATORS:
                return True
    return False


def index_project(target: Path) -> CallGraph:
    graph = CallGraph()
    target = target.resolve()
    files: list[Path] = []
    for p in target.rglob("*.py"):
        if any(part in {"node_modules", "vendor", ".git", "build", "dist",
                        ".venv", "venv", "__pycache__"} for part in p.parts):
            continue
        try:
            if p.stat().st_size > MAX_FILE_SIZE_BYTES:
                continue
        except OSError:
            continue
        files.append(p)
        if len(files) >= MAX_INDEX_FILES:
            break

    for p in files:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(text, filename=str(p))
        except (SyntaxError, OSError):
            continue
        rel = _safe_rel(p, target)
        _Visitor(rel, graph).visit(tree)
        graph.indexed_files += 1
    return graph


def _safe_rel(p: Path, target: Path) -> str:
    try:
        return str(p.relative_to(target))
    except ValueError:
        return str(p)


def reaches_entrypoint(graph: CallGraph, start_func: str, *, max_hops: int = 6) -> str:
    """Return 'yes' / 'no' / 'unknown' for reachability from any entrypoint."""
    if not start_func or start_func not in graph.defs:
        return "unknown"
    if start_func in graph.entrypoints:
        return "yes"

    visited: set[str] = {start_func}
    frontier: set[str] = {start_func}
    for _ in range(max_hops):
        next_frontier: set[str] = set()
        for fn in frontier:
            for (caller_file, _line) in graph.callers.get(fn, ()):
                enclosing = _enclosing_func(graph, caller_file, _line)
                if enclosing is None:
                    continue
                if enclosing in graph.entrypoints:
                    return "yes"
                if enclosing not in visited:
                    visited.add(enclosing)
                    next_frontier.add(enclosing)
        if not next_frontier:
            break
        frontier = next_frontier
    return "no" if visited else "unknown"


def _enclosing_func(graph: CallGraph, file_rel: str, line: int) -> Optional[str]:
    funcs = graph.file_funcs.get(file_rel)
    if not funcs:
        return None
    candidates = [(name, start, end) for (name, start, end) in funcs
                  if start <= line <= end]
    if not candidates:
        return None
    candidates.sort(key=lambda t: t[1])  # innermost = largest start
    return candidates[-1][0]
