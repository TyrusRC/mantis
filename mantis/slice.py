"""Stage 6: slice extraction.

Heuristic slice for a finding: identify the enclosing function, fetch
a small set of callers via grep, cap the output at 4k tokens. This is
deliberately a first-cut implementation — proper tree-sitter / SCIP
support is a future milestone. The interface mirrors slice-extractor.md
so the deep-reviewer prompt sees the same shape regardless of mode.
"""
from __future__ import annotations

import ast
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from mantis.scan import Finding


SLICE_TOKEN_BUDGET = 4000
CHARS_PER_TOKEN = 4   # rough OpenAI-ish heuristic
MAX_CALLER_HOPS = 3
MAX_CALLERS_PER_HOP = 3

EXT_TO_LANG = {
    ".py": "python", ".pyi": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".java": "java",
    ".kt": "kotlin", ".kts": "kotlin",
    ".swift": "swift",
    ".m": "objc", ".mm": "objc",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".rs": "rust",
}

# Sister extensions a language is commonly called from. Used by the caller
# grep so a JSX caller of a TS sink (or .kt caller of a .kts sink) is found.
LANG_SIBLING_EXTS = {
    "python":     [".py", ".pyi"],
    "javascript": [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"],
    "typescript": [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"],
    "java":       [".java"],
    "kotlin":     [".kt", ".kts", ".java"],
    "swift":      [".swift", ".m", ".mm"],
    "objc":       [".m", ".mm", ".swift"],
    "go":         [".go"],
    "ruby":       [".rb"],
    "php":        [".php"],
    "rust":       [".rs"],
}


@dataclass
class SliceChunk:
    file: str
    start_line: int
    end_line: int
    role: str          # sink | caller | callee
    func: str
    code: str


@dataclass
class Slice:
    finding: Finding
    sink_func: str
    sink_file: str
    sink_line: int
    chunks: list[SliceChunk] = field(default_factory=list)
    depth_callers: int = 0
    depth_callees: int = 0
    reachability: str = "unknown"
    sanitizers: list[str] = field(default_factory=list)
    insufficient_reason: Optional[str] = None
    total_chars: int = 0

    @property
    def insufficient(self) -> bool:
        return self.insufficient_reason is not None

    def to_text(self) -> str:
        finding_id = self.finding.id
        lines = [
            f"SLICE for {finding_id}",
            f"SINK: {self.sink_file}:{self.sink_line}",
            f"SINK_FUNC: {self.sink_func or '(unknown)'}",
            f"REACHABLE_FROM_ENTRYPOINT: {self.reachability}",
            f"SANITIZERS_FOUND: {', '.join(self.sanitizers) if self.sanitizers else 'none'}",
            f"DEPTH_USED: callers={self.depth_callers} callees={self.depth_callees}",
            "",
        ]
        for i, c in enumerate(self.chunks, 1):
            lines.append(f"[{i}] {c.file}:{c.start_line}-{c.end_line}  role={c.role}  func={c.func}")
            lines.append(c.code)
            lines.append("")
        return "\n".join(lines)


def _detect_language(path: Path) -> str:
    return EXT_TO_LANG.get(path.suffix.lower(), "unknown")


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _strip_long_blank_runs(text: str) -> str:
    return re.sub(r"\n{3,}", "\n\n", text)


# --- enclosing-function detection ---

_FUNC_HEAD_PATTERNS: dict[str, list[re.Pattern]] = {
    "javascript": [
        re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+(?P<name>[A-Za-z0-9_$]+)\s*\("),
        re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+(?P<name>[A-Za-z0-9_$]+)\s*=\s*(?:async\s+)?(?:\([^)]*\)|[A-Za-z0-9_$]+)\s*=>"),
        re.compile(r"^\s*(?P<name>[A-Za-z0-9_$]+)\s*[:=]\s*(?:async\s+)?function\s*\("),
        re.compile(r"^\s*(?:public|private|protected|static|async)\s+(?P<name>[A-Za-z0-9_$]+)\s*\([^)]*\)\s*[{:]"),
    ],
    "typescript": [
        re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+(?P<name>[A-Za-z0-9_$]+)\s*[<(]"),
        re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+(?P<name>[A-Za-z0-9_$]+)\s*[:=].*?=>"),
        re.compile(r"^\s*(?:public|private|protected|static|async)\s+(?P<name>[A-Za-z0-9_$]+)\s*\("),
    ],
    "java": [
        re.compile(r"^\s*(?:public|private|protected|static|final|synchronized|\s)+[\w<>\[\],\s]+\s+(?P<name>[A-Za-z0-9_]+)\s*\([^)]*\)\s*(?:throws[^{]*)?\{"),
    ],
    "kotlin": [
        re.compile(r"^\s*(?:override\s+|public\s+|private\s+|internal\s+|inline\s+|suspend\s+)*fun\s+(?:[A-Za-z0-9_<>?]+\s*\.\s*)?(?P<name>[A-Za-z0-9_]+)\s*\("),
    ],
    "swift": [
        re.compile(r"^\s*(?:public\s+|private\s+|fileprivate\s+|internal\s+|open\s+|static\s+|class\s+|override\s+|@\w+\s+)*func\s+(?P<name>[A-Za-z0-9_]+)\s*[(<]"),
    ],
    "objc": [
        re.compile(r"^[\s+\-]?\s*\([^)]*\)\s*(?P<name>[A-Za-z0-9_:]+)\s*\{?"),
    ],
    "go": [
        re.compile(r"^\s*func\s+(?:\([^)]*\)\s+)?(?P<name>[A-Za-z0-9_]+)\s*\("),
    ],
    "ruby": [
        re.compile(r"^\s*def\s+(?P<name>[A-Za-z0-9_!?=]+)"),
    ],
    "php": [
        re.compile(r"^\s*(?:public|private|protected|static|\s)*function\s+(?P<name>[A-Za-z0-9_]+)\s*\("),
    ],
    "rust": [
        re.compile(r"^\s*(?:pub(?:\([^)]+\))?\s+)?(?:async\s+)?fn\s+(?P<name>[A-Za-z0-9_]+)"),
    ],
}


def find_enclosing_function_python(text: str, line: int) -> Optional[tuple[str, int, int]]:
    """Return (name, start_line, end_line) for the function enclosing `line` in Python source."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return None

    best: Optional[tuple[str, int, int]] = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.lineno
            end = getattr(node, "end_lineno", None) or start + 50
            if start <= line <= end:
                if best is None or start > best[1]:
                    best = (node.name, start, end)
    return best


def find_enclosing_function_regex(text: str, line: int, language: str) -> Optional[tuple[str, int, int]]:
    """Walk backward from `line` to find a function-header line; estimate end by brace/indent."""
    patterns = _FUNC_HEAD_PATTERNS.get(language) or []
    if not patterns:
        return None

    lines = text.splitlines()
    if line < 1 or line > len(lines):
        return None

    for i in range(min(line, len(lines)) - 1, -1, -1):
        for pat in patterns:
            m = pat.match(lines[i])
            if m:
                name = m.group("name")
                end = _estimate_function_end(lines, i, language)
                return (name, i + 1, end + 1)
    return None


def _estimate_function_end(lines: list[str], start_idx: int, language: str) -> int:
    if language == "python":
        return start_idx  # Python uses ast; this is a fallback only
    if language in ("ruby",):
        return _estimate_end_by_indent(lines, start_idx)
    return _estimate_end_by_braces(lines, start_idx)


def _estimate_end_by_braces(lines: list[str], start_idx: int) -> int:
    """Count braces while skipping content inside strings and comments."""
    depth = 0
    started = False
    state = "code"        # code | sq | dq | tplsq | tpldq | line_comment | block_comment | tpl
    template_depth_stack: list[int] = []  # for nested ${...} in template literals
    i = start_idx
    while i < len(lines):
        line = lines[i]
        j = 0
        while j < len(line):
            ch = line[j]
            nxt = line[j + 1] if j + 1 < len(line) else ""

            if state == "line_comment":
                # ends at line break
                break

            if state == "block_comment":
                if ch == "*" and nxt == "/":
                    state = "code"
                    j += 2
                    continue
                j += 1
                continue

            if state == "sq":
                if ch == "\\":
                    j += 2
                    continue
                if ch == "'":
                    state = "code"
                j += 1
                continue

            if state == "dq":
                if ch == "\\":
                    j += 2
                    continue
                if ch == '"':
                    state = "code"
                j += 1
                continue

            if state == "tpl":
                if ch == "\\":
                    j += 2
                    continue
                if ch == "`":
                    state = "code"
                    j += 1
                    continue
                if ch == "$" and nxt == "{":
                    state = "code"
                    template_depth_stack.append(depth)
                    depth += 1
                    started = True
                    j += 2
                    continue
                j += 1
                continue

            # state == "code"
            if ch == "/" and nxt == "/":
                state = "line_comment"
                j += 2
                continue
            if ch == "/" and nxt == "*":
                state = "block_comment"
                j += 2
                continue
            if ch == "'":
                state = "sq"
                j += 1
                continue
            if ch == '"':
                state = "dq"
                j += 1
                continue
            if ch == "`":
                state = "tpl"
                j += 1
                continue
            if ch == "{":
                depth += 1
                started = True
            elif ch == "}":
                depth -= 1
                if template_depth_stack and depth == template_depth_stack[-1]:
                    template_depth_stack.pop()
                    state = "tpl"
                    j += 1
                    continue
                if started and depth == 0:
                    return i
            j += 1

        if state == "line_comment":
            state = "code"
        i += 1
    return min(len(lines) - 1, start_idx + 200)


def _estimate_end_by_indent(lines: list[str], start_idx: int) -> int:
    base = len(lines[start_idx]) - len(lines[start_idx].lstrip())
    for i in range(start_idx + 1, len(lines)):
        stripped = lines[i].lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(lines[i]) - len(stripped)
        if indent <= base:
            return i - 1
    return min(len(lines) - 1, start_idx + 200)


def find_enclosing_function(text: str, line: int, language: str) -> Optional[tuple[str, int, int]]:
    """Prefer tree-sitter when installed; else ast (Python) or regex (others)."""
    from mantis._treesitter import find_enclosing_function_ts
    ts_result = find_enclosing_function_ts(text, line, language)
    if ts_result:
        return ts_result
    if language == "python":
        py = find_enclosing_function_python(text, line)
        if py:
            return py
    return find_enclosing_function_regex(text, line, language)


# --- caller discovery via grep ---

_GREP_BIN_PRIORITY = ("rg", "grep")


def _grep_callers(name: str, root: Path, language: str,
                  exclude_path: Optional[Path] = None,
                  limit: int = MAX_CALLERS_PER_HOP) -> list[tuple[Path, int]]:
    if not name or not name.isidentifier():
        return []
    pattern = rf"\b{re.escape(name)}\s*\("
    binary = next((b for b in _GREP_BIN_PRIORITY if _which(b)), None)
    if not binary:
        return []

    exts = LANG_SIBLING_EXTS.get(language) or []
    if not exts:
        return []

    if binary == "rg":
        cmd = ["rg", "-n", "--no-heading", pattern]
        for e in exts:
            cmd += ["--glob", f"*{e}"]
        cmd += ["--max-count", str(limit), str(root)]
    else:
        cmd = ["grep", "-rEn"]
        for e in exts:
            cmd += ["--include", f"*{e}"]
        cmd += [pattern, str(root)]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20, check=False)
    except (subprocess.TimeoutExpired, OSError):
        return []

    hits: list[tuple[Path, int]] = []
    for raw in (result.stdout or "").splitlines():
        parts = raw.split(":", 2)
        if len(parts) < 3:
            continue
        try:
            line_no = int(parts[1])
        except ValueError:
            continue
        p = Path(parts[0])
        if exclude_path and p.resolve() == exclude_path.resolve():
            continue
        if "node_modules" in p.parts or "vendor" in p.parts or "build" in p.parts:
            continue
        hits.append((p, line_no))
        if len(hits) >= limit:
            break
    return hits


def _which(name: str) -> bool:
    import shutil as _shutil
    return _shutil.which(name) is not None


# --- main entry point ---

def extract_slice(finding: Finding, target_root: Path) -> Slice:
    sink_file = target_root / finding.path if not Path(finding.path).is_absolute() else Path(finding.path)
    text = _read_text(sink_file)
    if not text:
        return Slice(
            finding=finding,
            sink_func="",
            sink_file=str(sink_file),
            sink_line=finding.start_line,
            insufficient_reason=f"could not read {sink_file}",
        )

    language = _detect_language(sink_file)
    enclosing = find_enclosing_function(text, finding.start_line, language)

    chunks: list[SliceChunk] = []
    used_chars = 0
    budget_chars = SLICE_TOKEN_BUDGET * CHARS_PER_TOKEN

    if enclosing:
        name, start, end = enclosing
        sink_code = _extract_line_range(text, start, end)
        sink_code = _strip_long_blank_runs(sink_code)
        chunk = SliceChunk(
            file=finding.path,
            start_line=start,
            end_line=end,
            role="sink",
            func=name,
            code=sink_code,
        )
        chunks.append(chunk)
        used_chars += len(sink_code)
        sink_func = name
    else:
        # Fall back to a ±40 line window if we cannot resolve the function.
        start = max(1, finding.start_line - 40)
        end = finding.start_line + 40
        sink_code = _extract_line_range(text, start, end)
        chunks.append(SliceChunk(
            file=finding.path,
            start_line=start,
            end_line=end,
            role="sink",
            func="",
            code=sink_code,
        ))
        used_chars += len(sink_code)
        sink_func = ""

    depth_callers = 0
    if sink_func and used_chars < budget_chars:
        for caller_path, caller_line in _grep_callers(
            sink_func, target_root, language, exclude_path=sink_file
        ):
            if used_chars >= budget_chars:
                break
            caller_text = _read_text(caller_path)
            if not caller_text:
                continue
            caller_lang = _detect_language(caller_path)
            caller_enc = find_enclosing_function(caller_text, caller_line, caller_lang)
            if not caller_enc:
                continue
            cname, cstart, cend = caller_enc
            ccode = _extract_line_range(caller_text, cstart, cend)
            ccode = _strip_long_blank_runs(ccode)
            remaining = budget_chars - used_chars
            if len(ccode) > remaining:
                ccode = ccode[:remaining] + "\n# ... (truncated for budget)"
            try:
                rel = caller_path.relative_to(target_root)
            except ValueError:
                rel = caller_path
            chunks.append(SliceChunk(
                file=str(rel),
                start_line=cstart,
                end_line=cend,
                role="caller",
                func=cname,
                code=ccode,
            ))
            used_chars += len(ccode)
            depth_callers += 1
            if depth_callers >= MAX_CALLER_HOPS:
                break

    from mantis.reachability import classify_reachability
    reachability = classify_reachability(finding, sink_func, chunks, callgraph=_callgraph_for(target_root))

    return Slice(
        finding=finding,
        sink_func=sink_func,
        sink_file=str(sink_file),
        sink_line=finding.start_line,
        chunks=chunks,
        depth_callers=depth_callers,
        depth_callees=0,
        reachability=reachability,
        total_chars=used_chars,
    )


def _extract_line_range(text: str, start: int, end: int) -> str:
    lines = text.splitlines()
    start_idx = max(0, start - 1)
    end_idx = min(len(lines), end)
    return "\n".join(lines[start_idx:end_idx])


_CALLGRAPH_CACHE: dict[Path, object] = {}


def _callgraph_for(target_root: Path):
    """Lazy, per-target Python call-graph index. Cached for the process."""
    key = target_root.resolve()
    if key in _CALLGRAPH_CACHE:
        return _CALLGRAPH_CACHE[key]
    try:
        from mantis.callgraph import index_project
        graph = index_project(key)
    except Exception:
        graph = None
    _CALLGRAPH_CACHE[key] = graph
    return graph


def reset_callgraph_cache() -> None:
    _CALLGRAPH_CACHE.clear()
