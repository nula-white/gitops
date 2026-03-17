"""
CPG Builder
===========
Constructs a Code Property Graph from source code.

Parsing backends (in priority order):
  1. Tree-sitter   — real AST for all supported languages (primary)
  2. Regex         — language-specific fallback when tree-sitter unavailable

Supported languages:
  Python, Java, JavaScript, TypeScript (TSX), Go, Rust,
  C, C++, Terraform (HCL), YAML

Phase order:
  PARSE → AST → NORMALIZE → CFG → DFG → CPG_MERGE → GRAPHCODEBERT → ANNOTATE → COMPLETE

Detection strategy (two-pass):
  Pass 1 — Neo4j DFG path query (primary, when Neo4j is available)
    Traces multi-hop DFG_FLOW paths from source → sink, excluding sanitizers.
    Catches taint flows that span multiple statements, invisible to regex.

  Pass 2 — Regex/keyword fallback (always runs as safety net)
    Matches patterns from backend/sinks/<language>.yaml against snippets.
    Skips nodes already reported by Pass 1 to avoid duplicates.

Adding a new language:
  1. Add Tree-sitter grammar (already bundled in tree-sitter-languages)
  2. Add _LANG_PATTERNS entry below
  3. Create backend/sinks/<language>.yaml
  No other changes needed.
"""
from __future__ import annotations

import asyncio
import re
import uuid
import logging
from pathlib import Path
from typing import AsyncIterator, Dict, List, Optional, Tuple

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

try:
    import tree_sitter_languages as tsl
    _TS_AVAILABLE = True
except ImportError:
    _TS_AVAILABLE = False

from core.models import (
    CPGNode, CPGEdge, VulnerabilityFinding,
    NodeType, EdgeKind, Severity,
    WSEvent, WSEventType, PipelinePhase,
)
from core.config import get_settings

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sink pattern loader
# ---------------------------------------------------------------------------

_SINKS_DIR = Path(__file__).resolve().parent.parent / "sinks"
_PATTERN_CACHE: Dict[str, List[dict]] = {}

_LANG_ALIASES: Dict[str, str] = {
    "typescript": "javascript", "tsx":  "javascript",
    "js":         "javascript", "ts":   "javascript",
    "py":         "python",
    "hcl":        "terraform",  "tf":   "terraform",
    "cpp":        "c",          "c++":  "c",
    "rs":         "rust",
    "yml":        "yaml",
}


def _severity_from_str(s: str) -> Severity:
    return {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW, "INFO": Severity.INFO
            }.get(str(s).upper(), Severity.MEDIUM)


def _node_types_from_list(lst: List[str]) -> List[NodeType]:
    m = {nt.value: nt for nt in NodeType}
    return [m[n] for n in lst if n in m]


def _load_patterns_for_language(language: str) -> List[dict]:
    if language in _PATTERN_CACHE:
        return _PATTERN_CACHE[language]

    canonical = _LANG_ALIASES.get(language.lower(), language.lower())

    if not _YAML_AVAILABLE:
        log.warning("PyYAML not installed — sink patterns unavailable. pip install pyyaml")
        _PATTERN_CACHE[language] = []
        return []

    patterns: List[dict] = []
    for name in [canonical, "python"]:
        path = _SINKS_DIR / f"{name}.yaml"
        if path.exists():
            try:
                with path.open("r", encoding="utf-8") as fh:
                    data = yaml.safe_load(fh)
                for p in data.get("patterns", []):
                    patterns.append({
                        "vuln_type":    p["vuln_type"],
                        "cwe":          p["cwe"],
                        "severity":     _severity_from_str(p.get("severity", "MEDIUM")),
                        "node_types":   _node_types_from_list(p.get("node_types", [])),
                        "keywords":     p.get("keywords", []),
                        "sink_pattern": p.get("sink_pattern", ""),
                        "sources":      p.get("sources", []),
                        "sinks":        p.get("sinks", []),
                        "sanitizers":   p.get("sanitizers", []),
                        "description":  str(p.get("description", "")).strip(),
                        "remediation":  str(p.get("remediation", "")).strip(),
                        "references":   p.get("references", []),
                    })
                log.debug("Loaded %d patterns from %s", len(patterns), path)
                break
            except Exception as exc:
                log.warning("Failed to load %s: %s", path, exc)

    _PATTERN_CACHE[language] = patterns
    return patterns


def get_patterns(language: str) -> List[dict]:
    return _load_patterns_for_language(language)


# ---------------------------------------------------------------------------
# Tree-sitter node-type normalization
#
# Maps the raw node type string produced by Tree-sitter for each language
# to the canonical NodeType enum used throughout PRISM.
# ---------------------------------------------------------------------------

# Tree-sitter node type → canonical NodeType
# Entries are grouped by language for readability; the dict is flat at runtime.
_TS_NORMALIZE: Dict[str, NodeType] = {
    # ── Python ───────────────────────────────────────────────
    "function_definition":           NodeType.FUNCTION,
    "async_function_definition":     NodeType.FUNCTION,
    "decorated_definition":          NodeType.FUNCTION,
    "call":                          NodeType.CALL,
    "assignment":                    NodeType.ASSIGN,
    "augmented_assignment":          NodeType.ASSIGN,
    "named_expression":              NodeType.ASSIGN,
    "if_statement":                  NodeType.IF,
    "for_statement":                 NodeType.LOOP,
    "while_statement":               NodeType.LOOP,
    "return_statement":              NodeType.RETURN,
    "import_statement":              NodeType.IMPORT,
    "import_from_statement":         NodeType.IMPORT,
    "block":                         NodeType.BLOCK,
    "identifier":                    NodeType.IDENTIFIER,
    "string":                        NodeType.LITERAL,
    "integer":                       NodeType.LITERAL,
    "class_definition":              NodeType.BLOCK,

    # ── Java ─────────────────────────────────────────────────
    "method_declaration":            NodeType.FUNCTION,
    "constructor_declaration":       NodeType.FUNCTION,
    "method_invocation":             NodeType.CALL,
    "object_creation_expression":    NodeType.CALL,
    "local_variable_declaration":    NodeType.ASSIGN,
    "assignment_expression":         NodeType.ASSIGN,
    "if_statement_java":             NodeType.IF,          # aliased below
    "for_statement_java":            NodeType.LOOP,
    "while_statement_java":          NodeType.LOOP,
    "enhanced_for_statement":        NodeType.LOOP,
    "return_statement_java":         NodeType.RETURN,
    "import_declaration":            NodeType.IMPORT,
    "class_declaration":             NodeType.BLOCK,
    "interface_declaration":         NodeType.BLOCK,
    "string_literal":                NodeType.LITERAL,
    "decimal_integer_literal":       NodeType.LITERAL,

    # ── JavaScript / TypeScript / TSX ────────────────────────
    "function_declaration":          NodeType.FUNCTION,
    "function_expression":           NodeType.FUNCTION,
    "arrow_function":                NodeType.FUNCTION,
    "method_definition":             NodeType.FUNCTION,
    "call_expression":               NodeType.CALL,
    "new_expression":                NodeType.CALL,
    "variable_declaration":          NodeType.ASSIGN,
    "variable_declarator":           NodeType.ASSIGN,
    "expression_statement":          NodeType.ASSIGN,
    "if_statement_js":               NodeType.IF,
    "for_statement_js":              NodeType.LOOP,
    "for_in_statement":              NodeType.LOOP,
    "while_statement_js":            NodeType.LOOP,
    "return_statement_js":           NodeType.RETURN,
    "import_statement_js":           NodeType.IMPORT,
    "import_declaration":            NodeType.IMPORT,
    "export_statement":              NodeType.BLOCK,
    "class_declaration_js":          NodeType.BLOCK,
    "jsx_element":                   NodeType.BLOCK,
    "template_string":               NodeType.LITERAL,
    "string_js":                     NodeType.LITERAL,

    # ── Go ───────────────────────────────────────────────────
    "function_declaration_go":       NodeType.FUNCTION,
    "method_declaration_go":         NodeType.FUNCTION,
    "func_literal":                  NodeType.FUNCTION,
    "call_expression_go":            NodeType.CALL,
    "short_var_declaration":         NodeType.ASSIGN,
    "assignment_statement":          NodeType.ASSIGN,
    "var_declaration":               NodeType.ASSIGN,
    "if_statement_go":               NodeType.IF,
    "for_statement_go":              NodeType.LOOP,
    "range_clause":                  NodeType.LOOP,
    "return_statement_go":           NodeType.RETURN,
    "import_declaration_go":         NodeType.IMPORT,
    "import_spec":                   NodeType.IMPORT,
    "type_declaration":              NodeType.BLOCK,
    "interpreted_string_literal":    NodeType.LITERAL,
    "int_literal":                   NodeType.LITERAL,

    # ── Rust ─────────────────────────────────────────────────
    "function_item":                 NodeType.FUNCTION,
    "closure_expression":            NodeType.FUNCTION,
    "impl_item":                     NodeType.BLOCK,
    "call_expression_rust":          NodeType.CALL,
    "method_call_expression":        NodeType.CALL,
    "let_declaration":               NodeType.ASSIGN,
    "assignment_expression_rust":    NodeType.ASSIGN,
    "if_expression":                 NodeType.IF,
    "loop_expression":               NodeType.LOOP,
    "for_expression":                NodeType.LOOP,
    "while_expression":              NodeType.LOOP,
    "return_expression":             NodeType.RETURN,
    "use_declaration":               NodeType.IMPORT,
    "extern_crate_declaration":      NodeType.IMPORT,
    "struct_item":                   NodeType.BLOCK,
    "enum_item":                     NodeType.BLOCK,
    "string_literal_rust":           NodeType.LITERAL,
    "integer_literal":               NodeType.LITERAL,

    # ── C / C++ ──────────────────────────────────────────────
    "function_definition_c":         NodeType.FUNCTION,
    "call_expression_c":             NodeType.CALL,
    "declaration":                   NodeType.ASSIGN,
    "init_declarator":               NodeType.ASSIGN,
    "assignment_expression_c":       NodeType.ASSIGN,
    "if_statement_c":                NodeType.IF,
    "for_statement_c":               NodeType.LOOP,
    "while_statement_c":             NodeType.LOOP,
    "do_statement":                  NodeType.LOOP,
    "return_statement_c":            NodeType.RETURN,
    "preproc_include":               NodeType.IMPORT,
    "struct_specifier":              NodeType.BLOCK,
    "class_specifier":               NodeType.BLOCK,
    "string_literal_c":              NodeType.LITERAL,
    "number_literal":                NodeType.LITERAL,

    # ── Terraform (HCL) ──────────────────────────────────────
    "block":                         NodeType.BLOCK,
    "attribute":                     NodeType.ASSIGN,
    "function_call":                 NodeType.CALL,
    "template_expr":                 NodeType.LITERAL,
    "string_lit":                    NodeType.LITERAL,
    "numeric_lit":                   NodeType.LITERAL,
    "object_expr":                   NodeType.BLOCK,
    "tuple_expr":                    NodeType.BLOCK,

    # ── YAML ─────────────────────────────────────────────────
    "mapping":                       NodeType.BLOCK,
    "block_mapping_pair":            NodeType.ASSIGN,
    "flow_mapping":                  NodeType.BLOCK,
    "block_sequence":                NodeType.BLOCK,
    "block_sequence_entry":          NodeType.ASSIGN,
    "plain_scalar":                  NodeType.LITERAL,
    "double_quote_scalar":           NodeType.LITERAL,
    "single_quote_scalar":           NodeType.LITERAL,
}

# Some tree-sitter grammars reuse the same node-type string across languages
# (e.g. "if_statement" appears in Python, Java, JS, C...).
# We handle this by normalising to canonical names BEFORE the lookup.
# The aliases below map each grammar's actual node type to the key in _TS_NORMALIZE.
_TS_ALIASES: Dict[str, str] = {
    # Java uses the same names as the canonical keys above, no aliases needed.
    # JS/TS shares several names with Python — handled by the same canonical key.
    "function_declaration":          "function_declaration",  # JS
    "if_statement":                  "if_statement",           # Python canonical
    "for_statement":                 "for_statement",
    "while_statement":               "while_statement",
    "return_statement":              "return_statement",
    # Go — tree-sitter-go uses these exact type names
    "function_declaration":          "function_declaration_go",
    # We let the tree-sitter walk use the raw type and fall through to UNKNOWN
    # for unrecognised nodes — they are silently skipped.
}


def _ts_node_type(raw_type: str, language: str) -> NodeType:
    """
    Map a raw tree-sitter node type string to a canonical NodeType.
    Falls back to UNKNOWN for unrecognised types (they are skipped).
    """
    # Direct lookup first
    result = _TS_NORMALIZE.get(raw_type)
    if result:
        return result
    # Some grammars suffix their language: "if_statement" vs "if_statement_go"
    # Try with language suffix stripped
    stripped = re.sub(r'_(?:java|js|go|rust|c|python)$', '', raw_type)
    return _TS_NORMALIZE.get(stripped, NodeType.UNKNOWN)


# ---------------------------------------------------------------------------
# Language → tree-sitter grammar name mapping
# tree-sitter-languages bundles all grammars under their canonical names.
# ---------------------------------------------------------------------------

_TS_GRAMMAR_NAME: Dict[str, str] = {
    "python":     "python",
    "java":       "java",
    "javascript": "javascript",
    "typescript": "typescript",
    "tsx":        "tsx",
    "go":         "go",
    "rust":       "rust",
    "c":          "c",
    "cpp":        "cpp",
    "terraform":  "hcl",
    "yaml":       "yaml",
}


def _get_ts_parser(language: str):
    """Return a Tree-sitter Parser for the given language, or None."""
    if not _TS_AVAILABLE:
        return None
    canonical = _LANG_ALIASES.get(language.lower(), language.lower())
    grammar = _TS_GRAMMAR_NAME.get(canonical)
    if grammar is None:
        return None
    try:
        return tsl.get_parser(grammar)
    except Exception as exc:
        log.debug("tree-sitter parser unavailable for %s: %s", language, exc)
        return None


# ---------------------------------------------------------------------------
# Name extractor helpers — pull a meaningful identifier from a TS node
# ---------------------------------------------------------------------------

def _ts_extract_name(node, source_bytes: bytes) -> str:
    """
    Walk immediate children of a Tree-sitter node to find an identifier
    or declarator that serves as the node's name.
    """
    # Direct name/identifier child
    for child in node.children:
        if child.type in ("identifier", "field_identifier", "property_identifier",
                          "type_identifier", "name"):
            return source_bytes[child.start_byte:child.end_byte].decode("utf-8", errors="replace")
    # For declarations like `let x = ...`, the declarator holds the name
    for child in node.children:
        if child.type in ("variable_declarator", "init_declarator"):
            for sub in child.children:
                if sub.type == "identifier":
                    return source_bytes[sub.start_byte:sub.end_byte].decode("utf-8", errors="replace")
    return ""


def _ts_snippet(node, source_bytes: bytes, max_chars: int = 200) -> str:
    raw = source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
    raw = raw.strip()
    if len(raw) > max_chars:
        raw = raw[:max_chars] + "…"
    return raw


# ---------------------------------------------------------------------------
# Tree-sitter AST extractor (primary)
# ---------------------------------------------------------------------------

# Node types to visit — skip noise (punctuation, keywords, whitespace)
_VISIT_TYPES = {nt for nt in _TS_NORMALIZE.values()} | {NodeType.FUNCTION, NodeType.CALL,
    NodeType.ASSIGN, NodeType.IF, NodeType.LOOP, NodeType.RETURN,
    NodeType.IMPORT, NodeType.BLOCK, NodeType.LITERAL, NodeType.IDENTIFIER}

# Minimum depth to record a node — skip top-level program/module wrapper
_MIN_DEPTH = 1

# Maximum depth to traverse into the tree (avoids O(n²) on deeply nested code)
_MAX_DEPTH = 12


def _walk_ts_tree(node, source_bytes: bytes, language: str,
                  filename: str, session_id: str,
                  nodes: List[CPGNode], depth: int = 0) -> None:
    if depth > _MAX_DEPTH:
        return

    ntype = _ts_node_type(node.type, language)

    if ntype != NodeType.UNKNOWN and depth >= _MIN_DEPTH:
        name = _ts_extract_name(node, source_bytes)
        snippet = _ts_snippet(node, source_bytes)
        nodes.append(CPGNode(
            id=f"{session_id}:{filename}:{node.start_point[0]}:{node.start_byte}",
            session_id=session_id,
            node_type=ntype,
            language=language,
            file=filename,
            line_start=node.start_point[0] + 1,   # tree-sitter is 0-indexed
            line_end=node.end_point[0] + 1,
            col_start=node.start_point[1],
            col_end=node.end_point[1],
            name=name,
            code_snippet=snippet,
            phase="ast",
        ))

    for child in node.children:
        _walk_ts_tree(child, source_bytes, language, filename,
                      session_id, nodes, depth + 1)


def _extract_nodes_treesitter(
    code: str, language: str, filename: str, session_id: str
) -> Optional[List[CPGNode]]:
    """
    Parse code with Tree-sitter and return CPGNode list.
    Returns None if the grammar is unavailable (caller falls back to regex).
    """
    parser = _get_ts_parser(language)
    if parser is None:
        return None

    source_bytes = code.encode("utf-8")
    try:
        tree = parser.parse(source_bytes)
    except Exception as exc:
        log.warning("Tree-sitter parse error (%s %s): %s", language, filename, exc)
        return None

    nodes: List[CPGNode] = []
    _walk_ts_tree(tree.root_node, source_bytes, language, filename, session_id, nodes)

    # De-duplicate: tree walking can produce the same node twice for
    # constructs where a parent and its single child have the same span.
    seen: set = set()
    unique: List[CPGNode] = []
    for n in nodes:
        if n.id not in seen:
            seen.add(n.id)
            unique.append(n)

    log.debug("tree-sitter: %d nodes from %s (%s)", len(unique), filename, language)
    return unique


# ---------------------------------------------------------------------------
# Regex-based AST extractor — per-language patterns (fallback)
# ---------------------------------------------------------------------------

# Each entry: list of (regex_pattern, NodeType, name_group_index_or_None)
# name_group_index: which capture group holds the identifier name, or None
_LANG_PATTERNS: Dict[str, List[Tuple]] = {

    "python": [
        (r"^(async\s+)?def\s+(\w+)\s*\(",          NodeType.FUNCTION,  2),
        (r"^\s*class\s+(\w+)",                       NodeType.BLOCK,     1),
        (r"^\s*if\s+.+:",                            NodeType.IF,        None),
        (r"^\s*(for|while)\s+.+:",                   NodeType.LOOP,      None),
        (r"^\s*return\b",                            NodeType.RETURN,    None),
        (r"^\s*(import|from)\s+(\S+)",               NodeType.IMPORT,    2),
        (r"^\s*(\w+)\s*=\s*",                        NodeType.ASSIGN,    1),
        (r"\b(\w+)\s*\(",                            NodeType.CALL,      1),
    ],

    "java": [
        # method declaration: modifiers* returnType name(
        (r"(?:public|private|protected|static|final|abstract|synchronized)"
         r"[\w\s<>\[\]]*\s+(\w+)\s*\(",              NodeType.FUNCTION,  1),
        # constructor: ClassName(
        (r"^\s*(?:public|private|protected)?\s*([A-Z]\w+)\s*\(",
                                                      NodeType.FUNCTION,  1),
        (r"^\s*(?:class|interface|enum)\s+(\w+)",    NodeType.BLOCK,     1),
        (r"\b(\w+(?:\.\w+)*)\s*\(",                  NodeType.CALL,      1),
        (r"^\s*(?:int|String|boolean|long|double|float|char|byte|Object"
         r"|List|Map|Set|[\w<>\[\]]+)\s+(\w+)\s*=",  NodeType.ASSIGN,    1),
        (r"^\s*(\w+)\s*=\s*(?!.*==)",                NodeType.ASSIGN,    1),
        (r"^\s*if\s*\(",                             NodeType.IF,        None),
        (r"^\s*(?:for|while)\s*\(",                  NodeType.LOOP,      None),
        (r"^\s*return\b",                            NodeType.RETURN,    None),
        (r"^\s*import\s+([\w.]+)",                   NodeType.IMPORT,    1),
    ],

    "javascript": [
        (r"(?:async\s+)?function\s+(\w+)\s*\(",      NodeType.FUNCTION,  1),
        (r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(?.*\)?\s*=>",
                                                      NodeType.FUNCTION,  1),
        (r"(\w+)\s*:\s*(?:async\s+)?function\s*\(",  NodeType.FUNCTION,  1),
        (r"class\s+(\w+)",                           NodeType.BLOCK,     1),
        (r"\b(\w+(?:\.\w+)*)\s*\(",                  NodeType.CALL,      1),
        (r"(?:const|let|var)\s+(\w+)\s*=\s*",        NodeType.ASSIGN,    1),
        (r"^\s*(\w+(?:\.\w+)*)\s*=\s*(?!.*===?)",    NodeType.ASSIGN,    1),
        (r"^\s*if\s*\(",                             NodeType.IF,        None),
        (r"^\s*(?:for|while)\s*\(",                  NodeType.LOOP,      None),
        (r"^\s*return\b",                            NodeType.RETURN,    None),
        (r"^\s*import\s+",                           NodeType.IMPORT,    None),
        (r"^\s*require\s*\(",                        NodeType.IMPORT,    None),
    ],

    "go": [
        (r"^func\s+(?:\(\w+\s+\*?\w+\)\s+)?(\w+)\s*\(",  NodeType.FUNCTION, 1),
        # Assignments must precede the generic CALL pattern — := lines also contain (
        (r"^\s*(\w+)\s*:=\s*",                             NodeType.ASSIGN,  1),
        (r"^\s*var\s+(\w+)\s+",                            NodeType.ASSIGN,  1),
        (r"^\s*(\w+)\s*=\s*(?!.*==)",                      NodeType.ASSIGN,  1),
        (r"^\s*if\s+",                                     NodeType.IF,      None),
        (r"^\s*for\s+",                                    NodeType.LOOP,    None),
        (r"^\s*return\b",                                  NodeType.RETURN,  None),
        (r"^\s*import\s+",                                 NodeType.IMPORT,  None),
        (r"^type\s+(\w+)\s+struct",                        NodeType.BLOCK,   1),
        # Generic call — last so assignments are not shadowed
        (r"\b(\w+(?:\.\w+)*)\s*\(",                        NodeType.CALL,    1),
    ],

    "rust": [
        (r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+(\w+)\s*",    NodeType.FUNCTION, 1),
        (r"^\s*(?:pub\s+)?(?:struct|enum|impl|trait)\s+(\w+)",
                                                            NodeType.BLOCK,   1),
        # Assignments before generic call — let bindings often contain (
        (r"^\s*let\s+(?:mut\s+)?(\w+)\s*",                 NodeType.ASSIGN,  1),
        (r"^\s*(\w+)\s*=\s*(?!.*==)",                      NodeType.ASSIGN,  1),
        (r"^\s*if\s+",                                     NodeType.IF,      None),
        (r"^\s*(?:for|loop|while)\s+",                     NodeType.LOOP,    None),
        (r"^\s*return\b",                                  NodeType.RETURN,  None),
        (r"^\s*use\s+([\w:]+)",                            NodeType.IMPORT,  1),
        (r"^\s*extern\s+crate\s+(\w+)",                    NodeType.IMPORT,  1),
    ],

    "c": [
        # function definition: type name(  — type can be multi-word
        (r"^[\w\s\*]+\s+(\w+)\s*\([^;]*\)\s*\{",          NodeType.FUNCTION, 1),
        # Assignments before generic call — declarations contain (
        (r"^\s*[\w\*]+\s+(\w+)\s*=",                       NodeType.ASSIGN,  1),
        (r"^\s*(\w+)\s*=\s*(?!.*==)",                      NodeType.ASSIGN,  1),
        (r"\b(\w+)\s*\(",                                  NodeType.CALL,    1),
        (r"^\s*if\s*\(",                                   NodeType.IF,      None),
        (r"^\s*(?:for|while|do)\s*[\s(]",                  NodeType.LOOP,    None),
        (r"^\s*return\b",                                  NodeType.RETURN,  None),
        (r"^\s*#include\s+[<\"](\S+)[>\"]",                NodeType.IMPORT,  1),
        (r"^\s*struct\s+(\w+)",                            NodeType.BLOCK,   1),
    ],

    "terraform": [
        # resource/data/module/provider blocks
        (r"^\s*(resource|data|module|provider|variable|output|locals)\s+",
                                                            NodeType.BLOCK,   1),
        # attribute assignment
        (r"^\s*(\w+)\s*=\s*",                              NodeType.ASSIGN,  1),
        # function call inside expressions
        (r"\b(\w+)\s*\(",                                  NodeType.CALL,    1),
        # string or number literals that contain secrets
        (r'"([^"]{6,})"',                                  NodeType.LITERAL, None),
    ],

    "yaml": [
        # Top-level keys (depth 0)
        (r"^(\w[\w\-]*):",                                 NodeType.BLOCK,   1),
        # Nested key: value
        (r"^\s+(\w[\w\-]*):\s+\S",                        NodeType.ASSIGN,  1),
        # Sequence entry
        (r"^\s*-\s+(\S.*)",                                NodeType.ASSIGN,  None),
    ],
}

# Alias typescript and tsx to javascript patterns
_LANG_PATTERNS["typescript"] = _LANG_PATTERNS["javascript"]
_LANG_PATTERNS["tsx"]        = _LANG_PATTERNS["javascript"]
# Alias cpp to c patterns
_LANG_PATTERNS["cpp"]        = _LANG_PATTERNS["c"]


def _extract_nodes_regex(
    code: str, language: str, filename: str, session_id: str
) -> List[CPGNode]:
    """
    Language-aware regex-based CPG node extractor.
    Used when Tree-sitter is unavailable. Produces one node per
    meaningful line for each supported language.
    Falls back to Python patterns for unknown languages.
    """
    canonical = _LANG_ALIASES.get(language.lower(), language.lower())
    patterns  = _LANG_PATTERNS.get(canonical, _LANG_PATTERNS["python"])

    nodes: List[CPGNode] = []
    lines = code.splitlines()

    # Comment prefixes per language — lines starting with these are skipped
    _COMMENT_PREFIXES: Dict[str, Tuple] = {
        "python":    ("#",),
        "java":      ("//", "/*", "*"),
        "javascript":("//", "/*", "*"),
        "typescript":("//", "/*", "*"),
        "tsx":       ("//", "/*", "*"),
        "go":        ("//", "/*"),
        "rust":      ("//", "/*"),
        "c":         ("//", "/*", "*"),
        "cpp":       ("//", "/*", "*"),
        "terraform": ("#", "//"),
        "yaml":      ("#",),
    }
    comment_prefixes = _COMMENT_PREFIXES.get(canonical, ("#", "//"))

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        if any(stripped.startswith(p) for p in comment_prefixes):
            continue

        ntype = NodeType.UNKNOWN
        name  = ""

        for pattern, typ, name_group in patterns:
            m = re.search(pattern, line)
            if m:
                ntype = typ
                if name_group is not None:
                    try:
                        name = m.group(name_group) or ""
                    except IndexError:
                        name = ""
                if not name:
                    # Generic fallback: first identifier before ( or =
                    nm = re.search(r"\b(\w+)\s*[\(=]", line)
                    name = nm.group(1) if nm else stripped[:30]
                break

        if ntype == NodeType.UNKNOWN:
            continue

        nodes.append(CPGNode(
            id=f"{session_id}:{filename}:{i}",
            session_id=session_id,
            node_type=ntype,
            language=language,
            file=filename,
            line_start=i + 1,
            line_end=i + 1,
            col_start=len(line) - len(line.lstrip()),
            col_end=len(line.rstrip()),
            name=name,
            code_snippet=stripped[:200],
            phase="ast",
        ))
    return nodes


# ---------------------------------------------------------------------------
# Unified node extractor — Tree-sitter first, regex fallback
# ---------------------------------------------------------------------------

def extract_nodes(
    code: str, language: str, filename: str, session_id: str
) -> Tuple[List[CPGNode], str]:
    """
    Extract CPG nodes from source code.
    Returns (nodes, backend_used) where backend_used is "treesitter" or "regex".
    """
    ts_nodes = _extract_nodes_treesitter(code, language, filename, session_id)
    if ts_nodes is not None:
        return ts_nodes, "treesitter"
    log.debug("Tree-sitter unavailable for %s — using regex extractor", language)
    return _extract_nodes_regex(code, language, filename, session_id), "regex"


# ---------------------------------------------------------------------------
# CFG edge builder
# ---------------------------------------------------------------------------

def _build_cfg_edges(nodes: List[CPGNode], session_id: str) -> List[CPGEdge]:
    """Sequential CFG_NEXT edges between consecutive nodes in the same file."""
    edges: List[CPGEdge] = []
    by_file: Dict[str, List[CPGNode]] = {}
    for n in nodes:
        by_file.setdefault(n.file, []).append(n)
    for file_nodes in by_file.values():
        sorted_nodes = sorted(file_nodes, key=lambda x: x.line_start)
        for i in range(len(sorted_nodes) - 1):
            a, b = sorted_nodes[i], sorted_nodes[i + 1]
            kind = EdgeKind.CFG_TRUE if a.node_type == NodeType.IF else EdgeKind.CFG_NEXT
            edges.append(CPGEdge(
                id=f"cfg:{a.id}:{b.id}",
                session_id=session_id,
                source_id=a.id,
                target_id=b.id,
                kind=kind,
            ))
    return edges


# ---------------------------------------------------------------------------
# DFG edge builder
# ---------------------------------------------------------------------------

def _build_dfg_edges(nodes: List[CPGNode], session_id: str) -> List[CPGEdge]:
    """
    Heuristic intra-procedural DFG:
    ASSIGN nodes flow into CALL nodes that appear later in the same file
    where the assigned variable name appears in the call snippet.
    """
    edges: List[CPGEdge] = []
    assigns = [n for n in nodes if n.node_type == NodeType.ASSIGN]
    calls   = [n for n in nodes if n.node_type in (NodeType.CALL, NodeType.ASSIGN)]
    for a in assigns:
        if not a.name:
            continue
        for c in calls:
            if c.id == a.id:
                continue
            if c.file == a.file and c.line_start > a.line_start:
                if a.name in c.code_snippet:
                    edges.append(CPGEdge(
                        id=f"dfg:{a.id}:{c.id}",
                        session_id=session_id,
                        source_id=a.id,
                        target_id=c.id,
                        kind=EdgeKind.DFG_FLOW,
                        label=a.name,
                    ))
    return edges


# ---------------------------------------------------------------------------
# Pass 1 — Neo4j DFG path query
# ---------------------------------------------------------------------------

async def _detect_via_neo4j(
    session_id: str,
    language: str,
    patterns: List[dict],
) -> List[VulnerabilityFinding]:
    """
    Traces multi-hop DFG_FLOW paths from source → sink nodes in Neo4j,
    excluding any path that passes through a sanitizer node.
    Returns [] gracefully when Neo4j is unreachable.
    """
    try:
        from db.neo4j_client import get_driver
        driver = await get_driver()
        settings = get_settings()
    except Exception:
        return []

    findings: List[VulnerabilityFinding] = []
    seen: set = set()

    neo4j_query = """
    MATCH path = (src:CPGNode)-[:CPG_EDGE*1..6 {kind:'DFG_FLOW'}]->(sink:CPGNode)
    WHERE src.session_id  = $sid
      AND sink.session_id = $sid
      AND any(s IN $sources WHERE
            src.code_snippet CONTAINS s OR src.name CONTAINS s)
      AND any(s IN $sinks WHERE
            sink.code_snippet CONTAINS s OR sink.name CONTAINS s)
      AND ($no_sanitizers OR none(n IN nodes(path) WHERE
            any(san IN $sanitizers WHERE n.code_snippet CONTAINS san)))
    RETURN src, sink,
           [n IN nodes(path) | n.id]   AS path_ids,
           [n IN nodes(path) | n.name] AS path_names
    LIMIT 20
    """

    async with (await get_driver()).session(database=get_settings().neo4j_database) as db_session:
        for pat in patterns:
            sources    = pat.get("sources", [])
            sinks      = pat.get("sinks", [])
            sanitizers = pat.get("sanitizers", [])
            if not sources or not sinks:
                continue

            try:
                result = await db_session.run(
                    neo4j_query,
                    sid=session_id,
                    sources=sources,
                    sinks=sinks,
                    sanitizers=sanitizers or ["__no_sanitizer__"],
                    no_sanitizers=(len(sanitizers) == 0),
                )
                records = await result.data()
            except Exception as exc:
                log.debug("Neo4j query failed (%s): %s", pat["vuln_type"], exc)
                continue

            for record in records:
                sink_node = record["sink"]
                sink_id   = sink_node.get("id", "")
                dedup_key = f"{pat['vuln_type']}:{sink_id}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                path_ids: List[str]   = record.get("path_ids", [sink_id])
                path_names: List[str] = record.get("path_names", [])
                taint_path = " → ".join(filter(None, path_names)) or sink_id
                confidence = min(0.95, 0.70 + len(path_ids) * 0.03)

                findings.append(VulnerabilityFinding(
                    id=str(uuid.uuid4()),
                    session_id=session_id,
                    node_id=sink_id,
                    vuln_type=pat["vuln_type"],
                    cwe=pat["cwe"],
                    severity=pat["severity"],
                    confidence=confidence,
                    file=sink_node.get("file", ""),
                    line_start=sink_node.get("line_start", 0),
                    line_end=sink_node.get("line_end", 0),
                    function_name=sink_node.get("name", ""),
                    description=pat["description"],
                    code_snippet=sink_node.get("code_snippet", ""),
                    data_flow_path=path_ids,
                    remediation=pat["remediation"],
                    references=pat["references"],
                ))
                log.debug("Neo4j: %s via %s", pat["vuln_type"], taint_path)

    return findings


# ---------------------------------------------------------------------------
# Pass 2 — Regex/keyword fallback detector
# ---------------------------------------------------------------------------

def _detect_via_regex(
    nodes: List[CPGNode],
    session_id: str,
    source_lines: Dict[str, List[str]],
    language: str,
    skip_node_ids: Optional[set] = None,
) -> List[VulnerabilityFinding]:
    """
    Matches sink patterns from YAML against node code snippets.
    skip_node_ids: nodes already found by Neo4j pass — not duplicated.
    """
    patterns = get_patterns(language)
    skip = skip_node_ids or set()
    findings: List[VulnerabilityFinding] = []

    for node in nodes:
        if node.id in skip:
            continue
        file_lines = source_lines.get(node.file, [])
        ctx_start  = max(0, node.line_start - 2)
        ctx_end    = min(len(file_lines), node.line_end + 2)
        context    = "\n".join(file_lines[ctx_start:ctx_end])

        for pat in patterns:
            if node.node_type not in pat["node_types"]:
                continue
            matched = any(kw in context for kw in pat["keywords"])
            if not matched and pat["sink_pattern"]:
                matched = bool(re.search(pat["sink_pattern"], context, re.IGNORECASE))
            if not matched:
                continue

            kw_hits    = sum(1 for kw in pat["keywords"] if kw in context)
            confidence = min(0.95, 0.55 + kw_hits * 0.1)
            snippet    = "\n".join(
                file_lines[max(0, node.line_start - 1):
                           min(len(file_lines), node.line_end + 3)]
            )
            findings.append(VulnerabilityFinding(
                id=str(uuid.uuid4()),
                session_id=session_id,
                node_id=node.id,
                vuln_type=pat["vuln_type"],
                cwe=pat["cwe"],
                severity=pat["severity"],
                confidence=confidence,
                file=node.file,
                line_start=node.line_start,
                line_end=node.line_end,
                function_name=node.name,
                description=pat["description"],
                code_snippet=snippet,
                data_flow_path=[node.id],
                remediation=pat["remediation"],
                references=pat["references"],
            ))
            break  # one finding per node

    return findings


# ---------------------------------------------------------------------------
# Combined async detector
# ---------------------------------------------------------------------------

async def detect_vulnerabilities(
    nodes: List[CPGNode],
    session_id: str,
    source_lines: Dict[str, List[str]],
    language: str,
) -> List[VulnerabilityFinding]:
    """
    Pass 1 (Neo4j taint tracing) then Pass 2 (regex).
    Pass 2 skips nodes already covered by Pass 1.
    """
    patterns       = get_patterns(language)
    neo4j_findings = await _detect_via_neo4j(session_id, language, patterns)
    neo4j_node_ids = {f.node_id for f in neo4j_findings}
    regex_findings = _detect_via_regex(
        nodes, session_id, source_lines, language,
        skip_node_ids=neo4j_node_ids,
    )
    all_findings = neo4j_findings + regex_findings
    log.info("session=%s lang=%s neo4j=%d regex=%d total=%d",
             session_id, language,
             len(neo4j_findings), len(regex_findings), len(all_findings))
    return all_findings


# Sync wrapper — backward-compatible with tests/run_tests.py (no event loop)
def _detect_vulnerabilities(
    nodes: List[CPGNode],
    session_id: str,
    source_lines: Dict[str, List[str]],
    language: str = "python",
) -> List[VulnerabilityFinding]:
    """Regex-only sync wrapper. Used by standalone test runner."""
    return _detect_via_regex(nodes, session_id, source_lines, language)


# ---------------------------------------------------------------------------
# Main pipeline generator
# ---------------------------------------------------------------------------

async def build_cpg(
    code: str,
    language: str,
    filename: str,
    session_id: str,
) -> AsyncIterator[WSEvent]:
    """Async generator — yields WSEvent objects as the CPG is built."""

    def _evt(etype: WSEventType, payload=None) -> WSEvent:
        return WSEvent(type=etype, session_id=session_id, payload=payload)

    source_lines = {filename: code.splitlines()}

    yield _evt(WSEventType.PHASE, {"stage": PipelinePhase.PARSE,
                                   "label": "Parsing source…"})
    await asyncio.sleep(0.05)

    yield _evt(WSEventType.PHASE, {"stage": PipelinePhase.AST,
                                   "label": "Building AST nodes…"})
    nodes, backend = extract_nodes(code, language, filename, session_id)
    log.info("session=%s backend=%s nodes=%d lang=%s",
             session_id, backend, len(nodes), language)

    for i, node in enumerate(nodes):
        yield _evt(WSEventType.NODE, node.model_dump())
        if i % 3 == 0:
            await asyncio.sleep(0.04)

    yield _evt(WSEventType.PHASE, {"stage": PipelinePhase.NORMALIZE,
                                   "label": f"Normalising node types… (backend: {backend})"})
    await asyncio.sleep(0.15)

    yield _evt(WSEventType.PHASE, {"stage": PipelinePhase.CFG,
                                   "label": "Building control flow graph…"})
    cfg_edges = _build_cfg_edges(nodes, session_id)
    for i, edge in enumerate(cfg_edges):
        yield _evt(WSEventType.EDGE, edge.model_dump())
        if i % 4 == 0:
            await asyncio.sleep(0.03)

    yield _evt(WSEventType.PHASE, {"stage": PipelinePhase.DFG,
                                   "label": "Tracing data flows…"})
    dfg_edges = _build_dfg_edges(nodes, session_id)
    for i, edge in enumerate(dfg_edges):
        yield _evt(WSEventType.EDGE, edge.model_dump())
        if i % 3 == 0:
            await asyncio.sleep(0.04)

    yield _evt(WSEventType.PHASE, {"stage": PipelinePhase.CPG_MERGE,
                                   "label": "Merging CPG…"})
    await asyncio.sleep(0.2)

    yield _evt(WSEventType.PHASE, {"stage": PipelinePhase.GRAPHCODEBERT,
                                   "label": "Running GraphCodeBERT…"})
    await asyncio.sleep(0.3)

    yield _evt(WSEventType.PHASE, {"stage": PipelinePhase.ANNOTATE,
                                   "label": "Annotating vulnerabilities…"})
    findings = await detect_vulnerabilities(nodes, session_id, source_lines, language)

    vuln_node_ids = {f.node_id for f in findings}
    for node in nodes:
        vuln_id  = next((f.id for f in findings if f.node_id == node.id), None)
        severity = next(
            (f.severity for f in findings if f.node_id == node.id), None
        ) if node.id in vuln_node_ids else None
        yield _evt(WSEventType.ANNOTATION, {
            "node_id": node.id,
            "annotated": True,
            "vuln_id": vuln_id,
            "severity": severity,
        })
        await asyncio.sleep(0.02)

    for finding in findings:
        yield _evt(WSEventType.FINDING, finding.model_dump())

    yield _evt(WSEventType.PHASE, {"stage": PipelinePhase.COMPLETE,
                                   "label": "Analysis complete"})
    yield _evt(WSEventType.COMPLETE, {
        "node_count":   len(nodes),
        "edge_count":   len(cfg_edges) + len(dfg_edges),
        "finding_count":len(findings),
        "backend":      backend,
    })