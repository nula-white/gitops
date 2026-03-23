"""
PRISM Graph Builder — Main Orchestrator
=========================================
Top-level entry point for CPG construction.

Pipeline (per file):
  1. Language detection  — from file extension + content sniffing
  2. Tree-sitter parse   — CST → raw AST (with ERROR node detection)
  3. AST normalization   — language-specific → unified NodeType schema
  4. Security annotation — SOURCE/SINK/SANITIZER labels from sink databases
  5. CFG construction    — execution flow edges
  6. DFG construction    — data flow edges between definitions and uses
  7. Text sanitization   — raw_text + normalized_text (prompt injection safe)
  8. CPG assembly        — merge all edges, build node index
  9. SARIF injection     — CodeQL annotations (if SARIF file available)
  10. Neo4j write        — batched MERGE transactions
  11. GraphBuildResult   — emitted to LangGraph agent state

Tree-sitter fallback strategy:
  If tree_sitter is not installed:
    → Fallback parser produces a minimal CPG from regex-based tokenization
    → Only IDENTIFIER, CALL, LITERAL nodes are produced
    → CFG and DFG edges are not built (too imprecise without AST)
    → Blind spot is recorded in GraphBuildResult
  If tree_sitter is installed but grammar for language is missing:
    → Same fallback, same blind spot recording

This ensures the platform always produces some output, even in degraded
environments, while being completely transparent about coverage gaps.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any

from .models      import (
    CPGNode, CPGEdge, CPGFile, GraphBuildResult,
    NodeType, EdgeType, SecurityLabel, Language,
)
from .normalizer      import normalize_node_type
from .text_sanitizer  import sanitize_for_llm, extract_raw_text
from .cfg_builder     import CFGBuilder
from .dfg_builder     import DFGBuilder
from .sarif_injector  import SARIFInjector
from .neo4j_writer    import Neo4jWriter, MockNeo4jWriter, WriteResult
from ..ingestion.exceptions import (
    ParserUnavailableError, ASTBuildError, CFGBuildError,
    DFGBuildError, CPGAssemblyError, GraphBuildError,
)

# Import security sink databases from existing parser module
try:
    from ..parser.security_annotator import SecurityAnnotator as _LegacyAnnotator
    _LEGACY_ANNOTATOR_AVAILABLE = True
except ImportError:
    _LEGACY_ANNOTATOR_AVAILABLE = False

logger = logging.getLogger(__name__)

# Tree-sitter availability check

_TS_AVAILABLE    = False
_TS_GRAMMARS: dict[str, Any] = {}

def _try_load_treesitter() -> None:
    """
    Attempt to load tree-sitter and available language grammars.
    Sets module-level _TS_AVAILABLE and _TS_GRAMMARS.
    Called once at module import.
    """
    global _TS_AVAILABLE, _TS_GRAMMARS
    try:
        import tree_sitter
        from tree_sitter import Language as TSLanguage, Parser
        _TS_AVAILABLE = True

        # Try to load each language grammar
        grammar_modules = {
            "python":     ("tree_sitter_python",     "language"),
            "javascript": ("tree_sitter_javascript",  "language"),
            "typescript": ("tree_sitter_typescript",  "language_typescript"),
            "tsx":        ("tree_sitter_typescript",  "language_tsx"),
            "java":       ("tree_sitter_java",        "language"),
            "rust":       ("tree_sitter_rust",        "language"),
            "go":         ("tree_sitter_go",          "language"),
            "c":          ("tree_sitter_c",           "language"),
            "cpp":        ("tree_sitter_cpp",         "language"),
        }
        for lang_name, (module_name, attr) in grammar_modules.items():
            try:
                import importlib
                mod = importlib.import_module(module_name)
                lang_fn = getattr(mod, attr)
                _TS_GRAMMARS[lang_name] = TSLanguage(lang_fn())
                logger.debug("Loaded tree-sitter grammar: %s", lang_name)
            except Exception as exc:
                logger.debug("Grammar unavailable for %s: %s", lang_name, exc)

        logger.info(
            "Tree-sitter loaded. Available grammars: %s",
            list(_TS_GRAMMARS.keys()),
        )
    except ImportError:
        logger.warning(
            "tree-sitter not installed. "
            "Install with: pip install tree-sitter tree-sitter-python "
            "tree-sitter-javascript tree-sitter-java tree-sitter-rust "
            "tree-sitter-go tree-sitter-c tree-sitter-cpp. "
            "Graph builder will use fallback regex-based parser."
        )

_try_load_treesitter()


# Language detection

_EXTENSION_MAP: dict[str, Language] = {
    ".py":    Language.PYTHON,
    ".pyw":   Language.PYTHON,
    ".js":    Language.JAVASCRIPT,
    ".mjs":   Language.JAVASCRIPT,
    ".cjs":   Language.JAVASCRIPT,
    ".ts":    Language.TYPESCRIPT,
    ".tsx":   Language.TSX,
    ".jsx":   Language.JAVASCRIPT,
    ".java":  Language.JAVA,
    ".rs":    Language.RUST,
    ".go":    Language.GO,
    ".c":     Language.C,
    ".h":     Language.C,
    ".cc":    Language.CPP,
    ".cpp":   Language.CPP,
    ".cxx":   Language.CPP,
    ".hpp":   Language.CPP,
    ".hxx":   Language.CPP,
    ".tf":    Language.TERRAFORM,
    ".hcl":   Language.TERRAFORM,
    ".yaml":  Language.YAML,
    ".yml":   Language.YAML,
}

# Files to skip entirely (binary, generated, test data)
_SKIP_PATTERNS = frozenset([
    ".git", "__pycache__", "node_modules", ".terraform",
    "vendor", "dist", "build", ".eggs", "*.pyc",
])

def detect_language(file_path: str) -> Language:
    ext = Path(file_path).suffix.lower()
    return _EXTENSION_MAP.get(ext, Language.UNKNOWN)

def should_skip_file(file_path: str) -> bool:
    parts = Path(file_path).parts
    return any(skip in parts for skip in _SKIP_PATTERNS)


def _extract_from_parsed_output(parsed_output: object) -> "tuple[list, list]":
    """
    Convert a parser-layer ParsedGraphOutput into the (nodes, edges)
    types expected by the graph_builder layer (CPGNode, CPGEdge).

    This bridges the two different node schemas:
      parser layer:       NormalizedNode  (from parser/models.py)
      graph_builder layer: CPGNode        (from graph_builder/models.py)

    Strategy: attempt a direct attribute mapping.  Fields that don't
    exist on one schema are skipped — the graph still builds correctly
    because node_id, node_type, and file_path are present on both.

    The key property preserved is `backend` — when the backend is JOERN,
    the caller uses this to detect that CFG/DFG edges are already present.
    """
    nodes: list = []
    edges: list = []

    try:
        # Parser layer uses .nodes / .edges as lists on ParsedGraphOutput
        raw_nodes = getattr(parsed_output, "nodes", [])
        raw_edges = getattr(parsed_output, "edges", [])

        for n in raw_nodes:
            # CPGNode and NormalizedNode share these core fields
            node = CPGNode(
                node_id         = n.node_id,
                node_type       = NodeType(n.node_type.value)
                                  if hasattr(n.node_type, "value")
                                  else NodeType.UNKNOWN,
                language        = getattr(n, "language", None),
                file_path       = getattr(n, "file_path", ""),
                start_line      = getattr(n, "start_line", 0),
                end_line        = getattr(n, "end_line", 0),
                start_col       = getattr(n, "start_col", 0),
                end_col         = getattr(n, "end_col", 0),
                raw_text        = getattr(n, "raw_text", "") or "",
                normalized_text = getattr(n, "normalized_text", "") or "",
                parent_function = getattr(n, "parent_id", "") or "",
                properties      = dict(getattr(n, "attributes", None) or {}),
            )
            nodes.append(node)

        for e in raw_edges:
            edge_type_val = (e.edge_type.value
                             if hasattr(e.edge_type, "value")
                             else str(e.edge_type))
            # Map parser EdgeType values to graph_builder EdgeType
            try:
                from .models import EdgeType as GBEdgeType
                gb_edge_type = GBEdgeType(edge_type_val)
            except ValueError:
                from .models import EdgeType as GBEdgeType
                gb_edge_type = GBEdgeType.AST_CHILD

            edge = CPGEdge(
                edge_id   = e.edge_id,
                src_id    = e.src_id,
                dst_id    = e.dst_id,
                edge_type = gb_edge_type,
                properties= dict(getattr(e, "attributes", None) or {}),
            )
            edges.append(edge)

    except Exception as exc:
        logger.warning(
            "Failed to extract nodes/edges from ParsedGraphOutput: %s — "
            "falling back to empty graph for this file.", exc
        )

    return nodes, edges


# Per-file CPG builder

class FileCPGBuilder:
    """
    Builds a complete CPG for a single source file.
    Handles all 10 target languages via Tree-sitter + fallback.
    """

    def __init__(self) -> None:
        self._cfg_cache: dict[str, CFGBuilder] = {}

    def build(
        self,
        file_path:      str,
        source_bytes:   bytes,
        language:       Language,
        repo_root:      str = "",
        # When the parser layer already produced a ParsedGraphOutput
        # (e.g. from JoernDelegate), pass it here to avoid re-parsing.
        # This is the fix for the Joern-CPG-overwrite bug:
        # Joern already contains correct CFG+DFG edges — running the custom
        # Python builders on top of them would add duplicate/incorrect edges.
        parsed_output:  "object | None" = None,
    ) -> CPGFile:
        """
        Build the complete CPG for one file.
        Never raises — all errors produce a CPGFile with parse_errors set.

        When `parsed_output` is a ParsedGraphOutput from JoernDelegate:
          - Nodes and edges are taken directly from the parsed output.
          - CFG and DFG builders are SKIPPED (Joern already produced them).
          - Only security annotation and text sanitization are run.

        When `parsed_output` is None (Tree-sitter / fallback path):
          - Source bytes are parsed fresh.
          - CFG and DFG builders run normally.
        """
        relative_path = _make_relative(file_path, repo_root)
        cpg_file = CPGFile(
            file_path = relative_path,
            language  = language,
        )

        try:
            # ── Step 1: Obtain nodes + edges ──────────────────────────────
            # Path A: caller supplied a ParsedGraphOutput from the parser layer
            # (e.g. Joern produced real CFG+DFG — do not overwrite them)
            joern_edges_present = False
            if parsed_output is not None:
                raw_nodes, pre_edges = _extract_from_parsed_output(parsed_output)
                cpg_file.nodes.extend(raw_nodes)
                cpg_file.edges.extend(pre_edges)
                # Detect whether Joern already produced CFG/DFG edges
                joern_edges_present = any(
                    getattr(e, "edge_type", None) in (
                        "CFG_NEXT", "CFG_TRUE", "CFG_FALSE",
                        "DFG_FLOW", "DFG_DEPENDS",
                    )
                    for e in pre_edges
                )
                if joern_edges_present:
                    cpg_file.warnings.append(
                        f"Joern-produced CFG/DFG edges present for "
                        f"{relative_path} — skipping custom CFG/DFG builders."
                    )
            # Path B: parse from source bytes (Tree-sitter or fallback)
            else:
                if _TS_AVAILABLE and language.value in _TS_GRAMMARS:
                    raw_nodes, parse_warnings = self._parse_treesitter(
                        source_bytes, language.value, relative_path
                    )
                else:
                    raw_nodes, parse_warnings = self._parse_fallback(
                        source_bytes, language.value, relative_path
                    )
                    cpg_file.warnings.append(
                        f"Fallback parser used for {relative_path} "
                        f"(tree-sitter grammar unavailable for {language.value}). "
                        f"CFG/DFG edges not built — file partially analyzed."
                    )
                cpg_file.parse_errors.extend(parse_warnings)
                cpg_file.nodes.extend(raw_nodes)

            if not cpg_file.nodes:
                return cpg_file

            # ── Step 2: Text sanitization (always runs) ───────────────────
            for node in cpg_file.nodes:
                node.normalized_text = sanitize_for_llm(
                    node.raw_text, language.value
                )

            # ── Step 3: CFG (skip when Joern already produced edges) ───────
            if not joern_edges_present and (
                _TS_AVAILABLE and language.value in _TS_GRAMMARS
            ):
                try:
                    builder = CFGBuilder.for_language(language.value)
                    cfg_result = builder.build(cpg_file.nodes)
                    cpg_file.edges.extend(cfg_result.edges)
                    cpg_file.warnings.extend(cfg_result.warnings)
                except Exception as exc:
                    cpg_file.warnings.append(
                        f"CFG build failed for {relative_path}: {exc}"
                    )

            # ── Step 4: DFG (skip when Joern already produced edges) ───────
            if not joern_edges_present and (
                _TS_AVAILABLE and language.value in _TS_GRAMMARS
            ):
                try:
                    dfg_builder = DFGBuilder()
                    dfg_result  = dfg_builder.build(cpg_file.nodes)
                    cpg_file.edges.extend(dfg_result.edges)
                    cpg_file.warnings.extend(dfg_result.warnings)
                except Exception as exc:
                    cpg_file.warnings.append(
                        f"DFG build failed for {relative_path}: {exc}"
                    )

            # ── Step 5: AST structural edges ───────────────────────────────
            cpg_file.edges.extend(
                self._build_ast_edges(cpg_file.nodes)
            )

            # ── Step 6: Security annotation ────────────────────────────────
            self._annotate_security(cpg_file)

        except Exception as exc:
            cpg_file.parse_errors.append(
                f"Unexpected error building CPG for {relative_path}: {exc}"
            )
            logger.exception("CPG build failed for %s", relative_path)

        return cpg_file

    # ──────────────────────────────────────────────────────────────────────
    # Tree-sitter parser
    # ──────────────────────────────────────────────────────────────────────

    def _parse_treesitter(
        self,
        source_bytes: bytes,
        language:     str,
        file_path:    str,
    ) -> tuple[list[CPGNode], list[str]]:
        """
        Parse source using Tree-sitter and produce normalized CPGNodes.
        Returns (nodes, warnings).
        """
        from tree_sitter import Parser
        grammar = _TS_GRAMMARS[language]

        parser = Parser()
        parser.set_language(grammar)
        tree = parser.parse(source_bytes)

        nodes:    list[CPGNode] = []
        warnings: list[str]    = []
        error_count = 0

        # Iterative DFS traversal (no recursion limit risk)
        stack = [tree.root_node]
        parent_map: dict[int, str] = {}   # node id → parent CPGNode.node_id

        # Track current function/class for parent_function/parent_class
        function_stack: list[str] = []
        class_stack:    list[str] = []

        while stack:
            ts_node = stack.pop()

            if ts_node.type == "ERROR":
                error_count += 1
                warnings.append(
                    f"Parse error at {file_path}:{ts_node.start_point[0]+1}:"
                    f"{ts_node.start_point[1]} — tree-sitter ERROR node"
                )
                # Continue processing — partial AST is still useful
                stack.extend(reversed(ts_node.children))
                continue

            # Skip purely syntactic nodes (punctuation, keywords as nodes)
            if ts_node.is_named or ts_node.child_count > 0:
                normalized_type = normalize_node_type(ts_node.type, language)

                # Only create CPGNode for semantically meaningful nodes
                if normalized_type != NodeType.UNKNOWN or ts_node.child_count > 0:
                    node_id = CPGNode.make_id(
                        file_path,
                        ts_node.start_point[0] + 1,   # 1-based line
                        ts_node.start_point[1],         # 0-based col
                        normalized_type.value,
                    )

                    raw_text = extract_raw_text(
                        source_bytes,
                        ts_node.start_byte,
                        ts_node.end_byte,
                    )

                    lang_enum = Language(language) if language in [l.value for l in Language] \
                                else Language.UNKNOWN

                    node = CPGNode(
                        node_id       = node_id,
                        node_type     = normalized_type,
                        language      = lang_enum,
                        file_path     = file_path,
                        start_line    = ts_node.start_point[0] + 1,
                        end_line      = ts_node.end_point[0]   + 1,
                        start_col     = ts_node.start_point[1],
                        end_col       = ts_node.end_point[1],
                        raw_text      = raw_text,
                        parent_function = function_stack[-1] if function_stack else "",
                        parent_class    = class_stack[-1]    if class_stack    else "",
                    )

                    # Update function/class stacks
                    if normalized_type == NodeType.FUNCTION:
                        function_stack.append(node_id)
                    elif normalized_type == NodeType.CLASS:
                        class_stack.append(node_id)

                    nodes.append(node)

                    # Add children to stack (reversed for correct DFS order)
                    stack.extend(reversed(ts_node.children))

                    # Pop function/class stack when we leave their scope
                    # (approximation: pop when no more children)
                    if not ts_node.children:
                        if normalized_type == NodeType.FUNCTION and function_stack:
                            function_stack.pop()
                        elif normalized_type == NodeType.CLASS and class_stack:
                            class_stack.pop()

        if error_count > 0:
            warnings.append(
                f"{error_count} parse error(s) in {file_path} — "
                f"partial AST produced"
            )

        return nodes, warnings

    # ──────────────────────────────────────────────────────────────────────
    # Fallback regex parser (no tree-sitter)
    # ──────────────────────────────────────────────────────────────────────

    def _parse_fallback(
        self,
        source_bytes: bytes,
        language:     str,
        file_path:    str,
    ) -> tuple[list[CPGNode], list[str]]:
        """
        Minimal fallback parser using regex tokenization.
        Produces IDENTIFIER, CALL, LITERAL, IMPORT nodes only.
        No CFG/DFG edges are built on this output.
        """
        try:
            source = source_bytes.decode("utf-8", errors="replace")
        except Exception:
            return [], [f"Could not decode {file_path} as UTF-8"]

        nodes:    list[CPGNode] = []
        warnings: list[str]    = [
            f"Using fallback regex parser for {file_path} — "
            f"reduced coverage (no CFG/DFG)"
        ]

        lang_enum = Language(language) if language in [l.value for l in Language] \
                    else Language.UNKNOWN

        # Simple line-by-line tokenization
        for line_num, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Detect function definitions
            func_match = re.match(
                r"^(?:async\s+)?(?:def|function|func|fn)\s+(\w+)\s*\(",
                stripped
            )
            if func_match:
                ntype = NodeType.FUNCTION
                node_id = CPGNode.make_id(file_path, line_num, 0, ntype.value)
                nodes.append(CPGNode(
                    node_id   = node_id,
                    node_type = ntype,
                    language  = lang_enum,
                    file_path = file_path,
                    start_line= line_num,
                    end_line  = line_num,
                    start_col = 0,
                    end_col   = len(line),
                    raw_text  = stripped[:200],
                ))
                continue

            # Detect calls: word followed by (
            call_matches = re.findall(r"\b(\w+)\s*\(", stripped)
            for i, name in enumerate(call_matches):
                ntype = NodeType.CALL
                node_id = CPGNode.make_id(file_path, line_num, i, ntype.value)
                nodes.append(CPGNode(
                    node_id   = node_id,
                    node_type = ntype,
                    language  = lang_enum,
                    file_path = file_path,
                    start_line= line_num,
                    end_line  = line_num,
                    start_col = i,
                    end_col   = i + len(name),
                    raw_text  = name,
                ))

            # Detect imports
            if re.match(r"^(?:import|from|#include|use\s|require\s)", stripped):
                ntype = NodeType.IMPORT
                node_id = CPGNode.make_id(file_path, line_num, 0, ntype.value)
                nodes.append(CPGNode(
                    node_id   = node_id,
                    node_type = ntype,
                    language  = lang_enum,
                    file_path = file_path,
                    start_line= line_num,
                    end_line  = line_num,
                    start_col = 0,
                    end_col   = len(stripped),
                    raw_text  = stripped[:200],
                ))

        return nodes, warnings

    # ──────────────────────────────────────────────────────────────────────
    # AST structural edges
    # ──────────────────────────────────────────────────────────────────────

    def _build_ast_edges(self, nodes: list[CPGNode]) -> list[CPGEdge]:
        """
        Build AST_CHILD edges between parent and child nodes.
        Uses line/column nesting to infer parent-child relationships.
        """
        edges: list[CPGEdge] = []
        if len(nodes) < 2:
            return edges

        # Simple heuristic: a node is a child if it is contained within
        # the line range and column range of a larger node
        sorted_nodes = sorted(nodes, key=lambda n: (
            -(n.end_line - n.start_line),  # larger spans first
            n.start_line, n.start_col
        ))

        for i, parent in enumerate(sorted_nodes):
            parent_span = parent.end_line - parent.start_line
            if parent_span < 1:
                continue
            for child in sorted_nodes[i + 1:]:
                if (child.start_line >= parent.start_line and
                        child.end_line <= parent.end_line and
                        child.node_id != parent.node_id):
                    eid = CPGEdge.make_id(
                        parent.node_id, child.node_id, EdgeType.AST_CHILD.value
                    )
                    edges.append(CPGEdge(
                        edge_id   = eid,
                        src_id    = parent.node_id,
                        dst_id    = child.node_id,
                        edge_type = EdgeType.AST_CHILD,
                    ))
                    break  # only connect to immediate parent

        return edges

    # ──────────────────────────────────────────────────────────────────────
    # Security annotation
    # ──────────────────────────────────────────────────────────────────────

    def _annotate_security(self, cpg_file: CPGFile) -> None:
        """
        Annotate nodes with SecurityLabel using sink/source databases.
        Uses the existing parser.security_annotator if available,
        otherwise uses inline heuristics.
        """
        # Only apply regex fallback classification to nodes that were NOT
        # already annotated by Joern or the CodeQL SARIF injector.
        # Joern/CodeQL annotations take precedence — never overwrite them.
        for node in cpg_file.nodes:
            if node.node_type == NodeType.CALL and node.raw_text:
                # Skip if already annotated by a real analysis backend
                existing = getattr(node, "security_label", None)
                existing_val = existing.value if hasattr(existing, "value") else str(existing or "")
                if existing_val not in ("NONE", "", None):
                    continue   # ← Joern/CodeQL already set this — do not overwrite
                label = _classify_call_security(node.raw_text, cpg_file.language.value)
                if label != SecurityLabel.NONE:
                    node.security_label = label


# Security sink/source classification

# Known dangerous sinks by call name pattern
_SINK_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b(execute|executemany|raw|cursor\.execute)\b", re.I),  "CWE-89"),   # SQL
    (re.compile(r"\b(subprocess\.|os\.system|os\.popen|popen|exec)\b", re.I), "CWE-78"),  # CMD
    (re.compile(r"\b(open|fopen|file|Path)\b", re.I),                    "CWE-22"),   # Path
    (re.compile(r"\b(pickle\.loads?|yaml\.load|marshal\.loads?)\b", re.I),"CWE-502"),  # Deser
    (re.compile(r"\b(requests\.get|requests\.post|urllib\.request)\b", re.I),"CWE-918"),# SSRF
    (re.compile(r"\b(eval|exec)\b", re.I),                               "CWE-94"),   # Code
    (re.compile(r"\b(render|render_template|innerHTML)\b", re.I),        "CWE-79"),   # XSS
]

_SOURCE_PATTERNS: list[re.Pattern] = [
    re.compile(r"\b(request\.|req\.|flask\.request|GET\[|POST\[|args\.get|form\.get)\b", re.I),
    re.compile(r"\b(input\(|sys\.argv|os\.environ|getenv)\b", re.I),
    re.compile(r"\b(readLine|Scanner|BufferedReader|nextLine)\b"),         # Java
    re.compile(r"\b(req\.body|req\.query|req\.params|req\.headers)\b"),    # Express
]


def _classify_call_security(call_name: str, language: str) -> SecurityLabel:
    """Classify a call node as SOURCE, SINK, or NONE."""
    for pattern, _ in _SINK_PATTERNS:
        if pattern.search(call_name):
            return SecurityLabel.SINK
    for pattern in _SOURCE_PATTERNS:
        if pattern.search(call_name):
            return SecurityLabel.SOURCE
    return SecurityLabel.NONE


# Main GraphBuilder orchestrator

class GraphBuilder:
    """
    Orchestrates CPG construction for an entire repository.

    Usage:
        builder = GraphBuilder(
            neo4j_writer=Neo4jWriter(...),  # or MockNeo4jWriter() for testing
        )
        result = builder.build_repository(
            repo_dir    = "/sandbox/repo",
            session_id  = "sess_abc123",
            repo_hash   = "deadbeef...",    # from ingestion manifest
            sarif_path  = "/tmp/codeql.sarif",  # optional
        )
        # result.to_langgraph_state() → LangGraph state dict

    The GraphBuilder is designed as an MCP tool:
        @mcp_tool("build_cpg")
        def build_cpg_tool(repo_dir, session_id, repo_hash, sarif_path=None):
            return graph_builder.build_repository(...)
    """

    def __init__(
        self,
        neo4j_writer:    Neo4jWriter | MockNeo4jWriter | None = None,
        sarif_injector:  SARIFInjector | None                 = None,
        max_file_size_mb: float = 5.0,
        max_files:       int   = 5000,
    ) -> None:
        self._writer          = neo4j_writer or MockNeo4jWriter()
        self._sarif_injector  = sarif_injector or SARIFInjector()
        self._file_builder    = FileCPGBuilder()
        self._max_file_bytes  = int(max_file_size_mb * 1024 * 1024)
        self._max_files       = max_files

    def build_repository(
        self,
        repo_dir:   str,
        session_id: str,
        repo_hash:  str,
        sarif_path: str | None = None,
    ) -> GraphBuildResult:
        """
        Build a CPG for all source files in the repository.

        Args:
            repo_dir:   path to sandboxed repository (from ingestion layer)
            session_id: from ingestion manifest (namespaces Neo4j nodes)
            repo_hash:  from ingestion manifest (integrity verification)
            sarif_path: path to CodeQL SARIF output (optional)

        Returns:
            GraphBuildResult — safe to serialize into LangGraph state
        """
        start_ms = time.monotonic() * 1000

        all_nodes:   list[CPGNode] = []
        all_edges:   list[CPGEdge] = []
        node_index:  dict[tuple[str, int, int], CPGNode] = {}
        blind_spots: list[str] = []
        warnings:    list[str] = []
        languages_found: set[str] = set()

        files_processed   = 0
        files_with_errors = 0
        files_skipped     = 0
        total_files       = 0

        # Setup Neo4j schema (idempotent)
        try:
            self._writer.setup_schema()
        except Exception as exc:
            warnings.append(f"Neo4j schema setup failed (non-fatal): {exc}")

        # ── Walk repository ───────────────────────────────────────────────
        try:
            file_list = self._collect_files(repo_dir)
        except Exception as exc:
            return GraphBuildResult(
                session_id        = session_id,
                repo_hash         = repo_hash,
                total_files       = 0,
                total_nodes       = 0,
                total_edges       = 0,
                files_processed   = 0,
                files_with_errors = 0,
                files_skipped     = 0,
                languages_found   = [],
                blind_spots       = [f"Repository walk failed: {exc}"],
                warnings          = [],
                duration_ms       = round(time.monotonic() * 1000 - start_ms, 2),
                success           = False,
                error             = f"Repository walk failed: {exc}",
            )

        total_files = len(file_list)

        for file_path in file_list[:self._max_files]:
            language = detect_language(file_path)

            if language == Language.UNKNOWN:
                files_skipped += 1
                continue

            try:
                file_size = os.path.getsize(file_path)
            except OSError:
                files_skipped += 1
                continue

            if file_size > self._max_file_bytes:
                blind_spots.append(
                    f"{file_path} (oversized: {file_size // 1024}KB > "
                    f"{self._max_file_bytes // (1024*1024)}MB limit)"
                )
                files_skipped += 1
                continue

            try:
                with open(file_path, "rb") as f:
                    source_bytes = f.read()
            except OSError as exc:
                blind_spots.append(f"{file_path} (read error: {exc})")
                files_skipped += 1
                continue

            # Build CPG for this file
            relative_path = _make_relative(file_path, repo_dir)
            cpg_file = self._file_builder.build(
                file_path    = file_path,
                source_bytes = source_bytes,
                language     = language,
                repo_root    = repo_dir,
            )

            languages_found.add(language.value)
            files_processed += 1

            if cpg_file.parse_errors:
                files_with_errors += 1

            all_nodes.extend(cpg_file.nodes)
            all_edges.extend(cpg_file.edges)
            warnings.extend(cpg_file.warnings)

            # Build node index for SARIF lookup
            for node in cpg_file.nodes:
                node_index[(node.file_path, node.start_line, node.start_col)] = node

            if cpg_file.parse_errors:
                blind_spots.append(
                    f"{relative_path} (partial: {len(cpg_file.parse_errors)} parse errors)"
                )

        if total_files > self._max_files:
            warnings.append(
                f"Repository has {total_files} files; only first "
                f"{self._max_files} processed. "
                f"Remaining {total_files - self._max_files} are blind spots."
            )
            blind_spots.extend([
                f"<skipped: file limit reached>"
            ])

        # ── SARIF injection ───────────────────────────────────────────────
        if sarif_path and os.path.exists(sarif_path):
            try:
                sarif_result = self._sarif_injector.inject_from_file(
                    sarif_path = sarif_path,
                    node_index = node_index,
                    edges      = all_edges,
                    repo_root  = repo_dir,
                )
                warnings.extend(sarif_result.warnings)
                logger.info(
                    "SARIF injection: %d annotations, %d edges",
                    sarif_result.annotations_added, sarif_result.edges_added,
                )
            except Exception as exc:
                warnings.append(f"SARIF injection failed (non-fatal): {exc}")

        # ── Write to Neo4j ────────────────────────────────────────────────
        try:
            write_result = self._writer.write(
                nodes      = all_nodes,
                edges      = all_edges,
                session_id = session_id,
                repo_hash  = repo_hash,
            )
            warnings.extend(write_result.warnings)
        except Exception as exc:
            warnings.append(f"Neo4j write failed (non-fatal): {exc}")

        elapsed_ms = round(time.monotonic() * 1000 - start_ms, 2)

        result = GraphBuildResult(
            session_id        = session_id,
            repo_hash         = repo_hash,
            total_files       = total_files,
            total_nodes       = len(all_nodes),
            total_edges       = len(all_edges),
            files_processed   = files_processed,
            files_with_errors = files_with_errors,
            files_skipped     = files_skipped,
            languages_found   = sorted(languages_found),
            blind_spots       = blind_spots,
            warnings          = warnings,
            duration_ms       = elapsed_ms,
            success           = True,
        )

        logger.info(
            "Graph build complete. nodes=%d edges=%d files=%d/%d "
            "languages=%s duration=%.1fms session=%s",
            result.total_nodes, result.total_edges,
            result.files_processed, result.total_files,
            result.languages_found, result.duration_ms, session_id,
        )

        return result

    def _collect_files(self, repo_dir: str) -> list[str]:
        """Walk the repository and collect all non-skipped files."""
        files = []
        for root, dirs, filenames in os.walk(repo_dir):
            # Prune skip directories in-place
            dirs[:] = [
                d for d in dirs
                if d not in _SKIP_PATTERNS
                and not d.startswith(".")
            ]
            for filename in filenames:
                file_path = os.path.join(root, filename)
                if not should_skip_file(file_path):
                    files.append(file_path)
        return sorted(files)   # deterministic order for reproducible repo_hash


# Utilities

def _make_relative(file_path: str, repo_root: str) -> str:
    """Make file_path relative to repo_root."""
    try:
        return str(Path(file_path).relative_to(repo_root))
    except ValueError:
        return file_path