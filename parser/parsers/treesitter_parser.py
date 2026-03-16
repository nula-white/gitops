"""
PRISM Tree-sitter Parser  —  Hardened for Zero-Trust Sandbox
============================================================
Primary backend for: Rust, Terraform HCL, YAML, TSX
Fallback backend  for: all languages when CodeQL is unavailable

Security hardening applied (see PRISM threat model):
  FIX-2  ReDoS defence    — all node text capped at LIMITS.max_node_text_chars
                            before any string operation
  FIX-3  Graph Explosion  — GraphSizeGuard circuit breaker in the walk loop;
                            depth cap enforced per node
  FIX-5  Prompt Injection — raw_text preserved for security annotation but
                            comment/string nodes emitting to LLM token sequence
                            are replaced with sentinel tokens ([COMMENT],
                            [STRING_LITERAL]) so injected instructions never
                            reach the GraphCodeBERT / LLM reasoning layer
"""

from __future__ import annotations

import hashlib
import logging
import time
from typing import Any

from ..models import (
    Edge, EdgeType, FileMetadata, GraphCodeBERTInput,
    Language, NormalizedNode, NodeType, ParsedGraphOutput,
    ParserBackend, SecurityAnnotationSummary, SecurityLabel,
)
from ..normalizer          import ASTNormalizer
from ..security_annotator  import SecurityAnnotator
from ..language_detector   import TREE_SITTER_GRAMMAR_MAP
from ..sandbox_config      import (
    LIMITS, sanitize_for_llm,
    COMMENT_NODE_TYPES, COMMENT_SENTINEL, STRING_LITERAL_SENTINEL,
)
from ..input_validator     import GraphSizeGuard, GraphExplosionError, InputValidator
from .base                 import AbstractParser

logger = logging.getLogger(__name__)

_PRIMARY_LANGUAGES: frozenset[Language] = frozenset({
    Language.RUST, Language.TERRAFORM_HCL, Language.YAML, Language.TSX,
})
_FALLBACK_LANGUAGES: frozenset[Language] = frozenset({
    Language.PYTHON, Language.JAVA, Language.JAVASCRIPT,
    Language.TYPESCRIPT, Language.C, Language.CPP, Language.GO,
})
_TOKEN_EMITTING_TYPES: frozenset[NodeType] = frozenset({
    NodeType.FUNCTION, NodeType.CALL, NodeType.IDENTIFIER,
    NodeType.LITERAL, NodeType.ATTRIBUTE, NodeType.ASSIGN,
    NodeType.IMPORT, NodeType.RETURN, NodeType.CLASS,
    NodeType.CONFIG_KEY, NodeType.CONFIG_VALUE,
    NodeType.RESOURCE, NodeType.VARIABLE,
})


class TreeSitterParser(AbstractParser):
    """
    Multi-language parser using tree-sitter-languages.
    Hardened against Graph Explosion, ReDoS, and Prompt Injection.
    """

    def __init__(self) -> None:
        self._normalizer   = ASTNormalizer()
        self._annotator    = SecurityAnnotator()
        self._validator    = InputValidator()
        self._ts_available = False
        self._lang_cache: dict[Language, Any] = {}
        self._try_import()

    def _try_import(self) -> None:
        try:
            import tree_sitter_languages  # noqa: F401
            import tree_sitter            # noqa: F401
            self._ts_available = True
            logger.info("tree-sitter-languages loaded successfully")
        except ImportError:
            logger.warning("tree-sitter-languages not installed.")

    @property
    def backend_name(self) -> str:
        return "tree_sitter"

    def can_parse(self, language: Language) -> bool:
        if not self._ts_available:
            return False
        return language in _PRIMARY_LANGUAGES or language in _FALLBACK_LANGUAGES

    def _get_ts_language(self, language: Language) -> Any | None:
        if language in self._lang_cache:
            return self._lang_cache[language]
        try:
            from tree_sitter_languages import get_language
            name = TREE_SITTER_GRAMMAR_MAP.get(language)
            if not name:
                return None
            lang = get_language(name)
            self._lang_cache[language] = lang
            return lang
        except Exception as exc:
            logger.warning(f"Grammar load failed for {language}: {exc}")
            return None

    def parse(
        self,
        source_code: str,
        file_path: str,
        language: Language,
    ) -> ParsedGraphOutput:
        start_ms     = time.monotonic() * 1000
        parse_errors: list[str] = []
        warnings:     list[str] = []

        # ── FIX-2 / FIX (Trojan Source): Validate input FIRST ────────────────
        val = self._validator.validate_string(source_code, file_path)
        if not val.is_parseable:
            return self._rejected_output(file_path, language, start_ms, val.rejection_reason or "")
        warnings.extend(val.warnings)
        source_code = val.sanitized_source

        source_bytes = source_code.encode("utf-8", errors="replace")
        file_hash    = hashlib.sha256(source_bytes).hexdigest()
        line_count   = source_code.count("\n") + 1

        # ── Tree-sitter parse ─────────────────────────────────────────────────
        ts_tree = None
        if self._ts_available:
            ts_lang = self._get_ts_language(language)
            if ts_lang:
                try:
                    from tree_sitter import Parser as TSParser
                    p = TSParser()
                    p.set_language(ts_lang)
                    ts_tree = p.parse(source_bytes)
                    if ts_tree.root_node.has_error:
                        warnings.append(f"Tree-sitter partial parse errors in {file_path}.")
                except Exception as exc:
                    parse_errors.append(f"Tree-sitter error: {exc}")
            else:
                parse_errors.append(f"No grammar for {language.value}")

        # ── Build graph ───────────────────────────────────────────────────────
        nodes: list[NormalizedNode] = []
        edges: list[Edge]           = []
        graph_truncated             = False

        if ts_tree:
            try:
                nodes, edges, graph_truncated = self._walk_tree(
                    ts_tree.root_node, source_code, source_bytes,
                    file_path, language, warnings,
                )
            except Exception as exc:
                parse_errors.append(f"Graph build error: {exc}")
                nodes, edges = self._minimal_program_node(file_path, language, source_code)

        if not nodes:
            nodes, edges = self._minimal_program_node(file_path, language, source_code)
            warnings.append("Fallback: minimal PROGRAM node produced.")

        if graph_truncated:
            warnings.append(
                f"Graph truncated at {LIMITS.max_nodes_per_file:,} nodes / "
                f"{LIMITS.max_edges_per_file:,} edges / "
                f"depth {LIMITS.max_ast_depth} (Graph Explosion defence)."
            )

        sec_summary = self._build_security_summary(nodes)
        gcb_input   = self._build_graphcodebert_input(nodes)
        elapsed_ms  = time.monotonic() * 1000 - start_ms

        metadata = FileMetadata(
            file_path=file_path,
            language=language,
            backend=ParserBackend.TREE_SITTER if ts_tree else ParserBackend.FALLBACK,
            file_hash=file_hash,
            size_bytes=len(source_bytes),
            line_count=line_count,
            encoding="utf-8",
            parse_duration_ms=round(elapsed_ms, 2),
            error_count=len(parse_errors),
            has_parse_errors=bool(parse_errors),
        )

        return ParsedGraphOutput(
            metadata=metadata, nodes=nodes, edges=edges,
            security_summary=sec_summary,
            graphcodebert_input=gcb_input,
            graph_hash=ParsedGraphOutput.compute_graph_hash(nodes, edges),
            parse_errors=parse_errors, warnings=warnings,
        )

    # -------------------------------------------------------------------------
    # Hardened tree walker
    # -------------------------------------------------------------------------

    def _walk_tree(
        self,
        root_node: Any,
        source_code: str,
        source_bytes: bytes,
        file_path: str,
        language: Language,
        warnings: list[str],
    ) -> tuple[list[NormalizedNode], list[Edge], bool]:
        """
        Iterative DFS with GraphSizeGuard circuit breaker.

        FIX-3: GraphSizeGuard raises GraphExplosionError at node/edge/depth limits.
               The exception is caught here; the walk stops and returns a
               truncated but structurally valid graph.
        FIX-2: raw_text capped at LIMITS.max_node_text_chars.
        FIX-5: comment/string nodes flagged in attributes for LLM-layer to sentinel-replace.
        """
        guard         = GraphSizeGuard(file_path)
        nodes:        list[NormalizedNode] = []
        edges:        list[Edge]           = []
        children_map: dict[str, list[str]] = {}
        raw_nodes:    list[dict]           = []
        truncated     = False

        stack: list[tuple[Any, str | None, int]] = [(root_node, None, 0)]

        try:
            while stack:
                ts_node, parent_id, depth = stack.pop()

                # FIX-3: depth check
                guard.check_depth(depth)

                # Skip unnamed punctuation nodes (but recurse into children)
                if not ts_node.is_named and depth > 0:
                    for child in reversed(ts_node.children):
                        stack.append((child, parent_id, depth))
                    continue

                # FIX-3: node count check
                guard.check_node()

                raw_type   = ts_node.type
                start_line = ts_node.start_point[0] + 1
                start_col  = ts_node.start_point[1]
                end_line   = ts_node.end_point[0] + 1
                end_col    = ts_node.end_point[1]

                # FIX-2: cap raw_text length immediately on extraction
                try:
                    raw_text = source_bytes[
                        ts_node.start_byte:ts_node.end_byte
                    ].decode("utf-8", errors="replace")[:LIMITS.max_node_text_chars]
                except Exception:
                    raw_text = ""

                node_id = NormalizedNode.make_id(file_path, start_line, start_col, raw_type)
                normalized_type = self._normalizer.normalize_type(raw_type, language)

                children_texts = [
                    source_bytes[c.start_byte:c.end_byte]
                    .decode("utf-8", errors="replace")[:64]
                    for c in ts_node.children if c.is_named
                ]

                name  = self._normalizer.extract_name(
                    raw_type, raw_text, normalized_type, language, children_texts
                )
                value = self._normalizer.extract_value(normalized_type, raw_text)

                sec_label, sec_conf, cwe_hints = self._annotator.annotate(
                    normalized_type, name, language, raw_text
                )

                # FIX-5: flag nodes whose text must be sentinelized for LLM
                is_comment = normalized_type.value in COMMENT_NODE_TYPES
                is_string  = normalized_type == NodeType.LITERAL and raw_type in (
                    "string", "string_literal", "interpreted_string_literal",
                    "raw_string_literal", "template_string", "string_content",
                )
                attrs: dict = {}
                if ts_node.has_error:
                    attrs["parse_error"] = True
                if is_comment:
                    attrs["llm_sentinel"] = COMMENT_SENTINEL
                if is_string:
                    attrs["llm_sentinel"] = STRING_LITERAL_SENTINEL

                raw_nodes.append({
                    "node_id": node_id, "node_type": normalized_type,
                    "raw_type": raw_type, "name": name, "value": value,
                    "raw_text": raw_text, "start_line": start_line,
                    "end_line": end_line, "start_col": start_col,
                    "end_col": end_col, "depth": depth,
                    "parent_id": parent_id, "sec_label": sec_label,
                    "sec_conf": sec_conf, "cwe_hints": cwe_hints,
                    "attrs": attrs,
                })

                if parent_id:
                    children_map.setdefault(parent_id, []).append(node_id)

                for child in reversed(ts_node.children):
                    stack.append((child, node_id, depth + 1))

        except GraphExplosionError as exc:
            logger.warning(str(exc))
            truncated = True

        # Build frozen NormalizedNode objects
        for raw in raw_nodes:
            nid      = raw["node_id"]
            children = tuple(children_map.get(nid, []))
            nodes.append(NormalizedNode(
                node_id=nid,
                node_type=raw["node_type"],
                raw_type=raw["raw_type"],
                language=language,
                backend=ParserBackend.TREE_SITTER,
                name=raw["name"],
                value=raw["value"],
                qualified_name=None,
                file_path=file_path,
                start_line=raw["start_line"],
                end_line=raw["end_line"],
                start_col=raw["start_col"],
                end_col=raw["end_col"],
                raw_text=raw["raw_text"],  # preserved for security annotation
                depth=raw["depth"],
                parent_id=raw["parent_id"],
                children_ids=children,
                security_label=raw["sec_label"],
                security_confidence=raw["sec_conf"],
                cwe_hints=raw["cwe_hints"],
                attributes=raw["attrs"],
            ))

        # Build AST edges with circuit breaker
        try:
            for node in nodes:
                for child_id in node.children_ids:
                    guard.check_edge()
                    eid = Edge.make_id(node.node_id, child_id, EdgeType.AST_CHILD.value)
                    edges.append(Edge(eid, EdgeType.AST_CHILD, node.node_id, child_id))

                child_list = list(node.children_ids)
                for i in range(len(child_list) - 1):
                    guard.check_edge()
                    eid = Edge.make_id(
                        child_list[i], child_list[i+1], EdgeType.AST_NEXT_SIBLING.value
                    )
                    edges.append(Edge(
                        eid, EdgeType.AST_NEXT_SIBLING, child_list[i], child_list[i+1]
                    ))
        except GraphExplosionError as exc:
            logger.warning(str(exc))
            truncated = True

        return nodes, edges, truncated

    # -------------------------------------------------------------------------
    # GraphCodeBERT input — with Prompt Injection defence (FIX-5)
    # -------------------------------------------------------------------------

    def _build_graphcodebert_input(
        self, nodes: list[NormalizedNode]
    ) -> GraphCodeBERTInput:
        """
        FIX-5: Comment and string literal nodes are replaced with sentinel
        tokens in the sequence visible to GraphCodeBERT / LLM layer.

        The raw_text on the NormalizedNode is untouched — it is needed by
        the SecurityAnnotator and DFG builder. Only the token sequence
        that enters the transformer is sanitized.
        """
        tokens:  list[str] = []
        ids:     list[str] = []
        types:   list[str] = []
        labels:  list[str] = []

        for node in nodes:
            if node.node_type not in _TOKEN_EMITTING_TYPES:
                continue
            if not node.raw_text:
                continue
            if len(tokens) >= LIMITS.max_graphcodebert_tokens:
                break

            # FIX-5: use sentinel for comment / string nodes in LLM sequence
            sentinel = node.attributes.get("llm_sentinel")
            if sentinel:
                if len(tokens) < LIMITS.max_graphcodebert_tokens:
                    tokens.append(sentinel)
                    ids.append(node.node_id)
                    types.append(node.node_type.value)
                    labels.append(node.security_label.value)
                continue

            # Normal nodes: sanitize text then emit word tokens
            safe_text = sanitize_for_llm(node.raw_text)
            words     = safe_text.split()[:4]
            for word in words:
                if len(tokens) >= LIMITS.max_graphcodebert_tokens:
                    break
                tokens.append(word)
                ids.append(node.node_id)
                types.append(node.node_type.value)
                labels.append(node.security_label.value)

        return GraphCodeBERTInput(
            tokens=tokens, token_node_ids=ids,
            dfg_edges=[], node_type_sequence=types,
            security_label_sequence=labels,
        )

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _build_security_summary(self, nodes: list[NormalizedNode]) -> SecurityAnnotationSummary:
        summary  = SecurityAnnotationSummary()
        cwe_map: dict[str, list[str]] = {}
        for node in nodes:
            match node.security_label:
                case SecurityLabel.SOURCE:     summary.sources.append(node.node_id)
                case SecurityLabel.SINK:       summary.sinks.append(node.node_id)
                case SecurityLabel.SANITIZER:  summary.sanitizers.append(node.node_id)
                case SecurityLabel.PROPAGATOR: summary.propagators.append(node.node_id)
                case SecurityLabel.SENSITIVE:  summary.sensitive_nodes.append(node.node_id)
            for cwe in node.cwe_hints:
                cwe_map.setdefault(cwe, []).append(node.node_id)
        summary.cwe_hints = cwe_map
        return summary

    def _minimal_program_node(
        self, file_path: str, language: Language, source_code: str
    ) -> tuple[list[NormalizedNode], list[Edge]]:
        prog_id = NormalizedNode.make_id(file_path, 0, 0, "PROGRAM")
        return [NormalizedNode(
            node_id=prog_id, node_type=NodeType.PROGRAM, raw_type="program",
            language=language, backend=ParserBackend.FALLBACK,
            name=file_path, value=None, qualified_name=None,
            file_path=file_path, start_line=0, end_line=0,
            start_col=0, end_col=0,
            raw_text=source_code[:LIMITS.max_node_text_chars],
            depth=0, parent_id=None, children_ids=(),
            security_label=SecurityLabel.NONE, security_confidence=0.0,
            cwe_hints=(), attributes={},
        )], []

    def _rejected_output(
        self, file_path: str, language: Language,
        start_ms: float, reason: str,
    ) -> ParsedGraphOutput:
        elapsed = time.monotonic() * 1000 - start_ms
        node_id = NormalizedNode.make_id(file_path, 0, 0, "PROGRAM")
        node = NormalizedNode(
            node_id=node_id, node_type=NodeType.PROGRAM, raw_type="program",
            language=language, backend=ParserBackend.FALLBACK,
            name=file_path, value=None, qualified_name=None,
            file_path=file_path, start_line=0, end_line=0,
            start_col=0, end_col=0, raw_text="",
            depth=0, parent_id=None, children_ids=(),
            security_label=SecurityLabel.NONE, security_confidence=0.0,
            cwe_hints=(), attributes={"rejected": True},
        )
        metadata = FileMetadata(
            file_path=file_path, language=language, backend=ParserBackend.FALLBACK,
            file_hash="", size_bytes=0, line_count=0,
            encoding="utf-8", parse_duration_ms=round(elapsed, 2),
            error_count=1, has_parse_errors=True,
        )
        return ParsedGraphOutput(
            metadata=metadata, nodes=[node], edges=[],
            security_summary=SecurityAnnotationSummary(),
            graphcodebert_input=GraphCodeBERTInput(
                tokens=[], token_node_ids=[], dfg_edges=[],
                node_type_sequence=[], security_label_sequence=[],
            ),
            graph_hash=ParsedGraphOutput.compute_graph_hash([node], []),
            parse_errors=[f"REJECTED: {reason}"], warnings=[],
        )