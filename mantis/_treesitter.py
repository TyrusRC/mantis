"""Optional tree-sitter integration for slice extraction.

Imports lazily and degrades gracefully if tree-sitter is not installed.
Returns None when unavailable so callers can fall back to ast / regex.

To enable, install the optional extra:
    pipx install ./[tree-sitter]
or:
    pip install tree-sitter-language-pack
"""
from __future__ import annotations

from typing import Optional


_LANG_TO_TS = {
    "python": "python",
    "javascript": "javascript",
    "typescript": "typescript",
    "java": "java",
    "kotlin": "kotlin",
    "swift": "swift",
    "objc": "objc",
    "go": "go",
    "ruby": "ruby",
    "php": "php",
    "rust": "rust",
}

_FUNCTION_NODE_TYPES = {
    "python": {"function_definition", "async_function_definition"},
    "javascript": {
        "function_declaration", "function_expression", "arrow_function",
        "method_definition", "generator_function_declaration",
    },
    "typescript": {
        "function_declaration", "function_expression", "arrow_function",
        "method_definition", "method_signature",
    },
    "java": {"method_declaration", "constructor_declaration"},
    "kotlin": {"function_declaration"},
    "swift": {"function_declaration"},
    "objc": {"method_definition", "method_declaration"},
    "go": {"function_declaration", "method_declaration"},
    "ruby": {"method", "singleton_method"},
    "php": {"method_declaration", "function_definition"},
    "rust": {"function_item"},
}

_PARSER_CACHE: dict[str, object] = {}
_AVAILABLE: Optional[bool] = None


def is_available() -> bool:
    """True when tree-sitter and the language pack are importable."""
    global _AVAILABLE
    if _AVAILABLE is None:
        try:
            from tree_sitter_language_pack import get_parser  # noqa: F401
            _AVAILABLE = True
        except Exception:
            _AVAILABLE = False
    return _AVAILABLE


def reset_for_tests() -> None:
    """Allow tests to reset the cached availability flag."""
    global _AVAILABLE
    _AVAILABLE = None
    _PARSER_CACHE.clear()


def _get_parser(language: str):
    if language in _PARSER_CACHE:
        return _PARSER_CACHE[language]
    ts_lang = _LANG_TO_TS.get(language)
    if not ts_lang:
        return None
    try:
        from tree_sitter_language_pack import get_parser
        parser = get_parser(ts_lang)
        _PARSER_CACHE[language] = parser
        return parser
    except Exception:
        return None


def find_enclosing_function_ts(
    text: str, line: int, language: str
) -> Optional[tuple[str, int, int]]:
    """Return (name, start_line, end_line) via tree-sitter, or None."""
    if not is_available():
        return None
    parser = _get_parser(language)
    if parser is None:
        return None
    func_types = _FUNCTION_NODE_TYPES.get(language)
    if not func_types:
        return None

    try:
        tree = parser.parse(bytes(text, "utf-8"))
    except Exception:
        return None

    target_idx = max(0, line - 1)

    def walk(node, best):
        if node.start_point[0] > target_idx or node.end_point[0] < target_idx:
            return best
        if node.type in func_types:
            best = node
        for child in node.children:
            best = walk(child, best)
        return best

    match = walk(tree.root_node, None)
    if match is None:
        return None

    name_node = None
    try:
        name_node = match.child_by_field_name("name")
    except Exception:
        name_node = None
    if name_node is None:
        for c in match.children:
            if c.type in ("identifier", "field_identifier", "type_identifier",
                          "simple_identifier", "property_identifier"):
                name_node = c
                break
    if name_node is None:
        return None

    name = text[name_node.start_byte:name_node.end_byte]
    start_line = match.start_point[0] + 1
    end_line = match.end_point[0] + 1
    return (name, start_line, end_line)
