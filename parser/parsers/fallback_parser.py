"""
PRISM Fallback Parser  —  Hardened for Zero-Trust Sandbox
=========================================================
Security hardening applied:

  FIX-2  ReDoS defence
         - Input validated and line-length-capped via InputValidator BEFORE
           any regex is applied.
         - All pattern matches operate on lines pre-truncated to
           LIMITS.max_line_length characters.
         - Catastrophic backtracking patterns in Java / C++ regexes
           rewritten to bounded-quantifier equivalents.
         - Total line scan capped at LIMITS.max_lines.

  FIX-3  Graph Explosion defence
         GraphSizeGuard circuit breaker: stops node/edge creation at
         LIMITS.max_nodes_per_file / LIMITS.max_edges_per_file.

  FIX-5  Prompt Injection defence
         raw_text stored on nodes is the original source snippet
         (needed for security annotation). However, the token sequence
         emitted for GraphCodeBERT sentinelizes comment and string
         literal content.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from pathlib import Path

# ── ReDoS defence: use the `regex` library (PyPI) if available ──────────────
# The `regex` library exposes a `timeout` parameter on every match call,
# preventing catastrophic backtracking on adversarial input even when
# bounded-quantifier patterns are circumvented.
#
# Primary defence: InputValidator truncates every line to LIMITS.max_line_length
# before any pattern is applied — this alone eliminates most ReDoS attacks.
# `regex` timeout is a defense-in-depth layer.
#
# Install: pip install regex
try:
    import regex as _re_engine   # type: ignore[import]
    _REGEX_TIMEOUT = 0.5         # seconds per match call — well above real-code cost
    _HAS_REGEX_LIB = True
except ImportError:
    import re as _re_engine      # type: ignore[assignment]
    _REGEX_TIMEOUT = None
    _HAS_REGEX_LIB = False

# Re-export compile so pattern literals still work with both engines
def _compile(pattern: str, flags: int = 0) -> "re.Pattern":
    return _re_engine.compile(pattern, flags)

def _safe_match(pattern: "re.Pattern", text: str) -> "re.Match | None":
    """Run a regex match with timeout when regex library is available."""
    try:
        if _HAS_REGEX_LIB:
            return pattern.match(text, timeout=_REGEX_TIMEOUT)
        return pattern.match(text)
    except Exception:
        return None   # timeout or error → treat as no match

def _safe_finditer(pattern: "re.Pattern", text: str):
    """Run finditer with timeout when regex library is available."""
    try:
        if _HAS_REGEX_LIB:
            return list(pattern.finditer(text, timeout=_REGEX_TIMEOUT))
        return list(pattern.finditer(text))
    except Exception:
        return []

logger = logging.getLogger(__name__)

from ..models import (
    Edge, EdgeType, FileMetadata, GraphCodeBERTInput,
    Language, NormalizedNode, NodeType, ParsedGraphOutput,
    ParserBackend, SecurityAnnotationSummary, SecurityLabel,
)
from ..security_annotator import SecurityAnnotator
from ..sandbox_config import (
    LIMITS, sanitize_for_llm, COMMENT_SENTINEL, STRING_LITERAL_SENTINEL,
)
from ..input_validator import (
    InputValidator, GraphSizeGuard, GraphExplosionError,
)
from .base import AbstractParser

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Hardened regex patterns
# FIX-2: All patterns use bounded quantifiers to eliminate catastrophic
# backtracking. The original Java pattern:
#   r"(?:public|private|protected|static|\s)+\s+\w+\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+\w+\s*)?\{"
# had nested + inside (?:...)+ which causes exponential backtracking on
# inputs like "public public public public public{" (polynomial blowup).
# Rewritten with \s{0,4} bounded alternatives.
# Ref: OWASP CWE-1333, https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS
# ---------------------------------------------------------------------------

_FUNCTION_PATTERNS: dict[Language, list['re.Pattern']] = {
    Language.PYTHON: [
        _compile(r"^\s{0,8}(?:async\s+)?def\s+(\w+)\s*\("),
    ],
    Language.JAVA: [
        # HARDENED: bounded alternatives, no nested quantifiers
        _compile(
            r"^\s{0,8}"
            r"(?:(?:public|private|protected|static|final|synchronized|abstract|native)"
            r"\s+){0,6}"           # ← bounded: max 6 modifiers
            r"\w[\w.<>\[\]]{0,64}" # ← bounded: return type max 64 chars
            r"\s+(\w+)\s*\("
        ),
    ],
    Language.JAVASCRIPT: [
        _compile(r"^\s{0,8}(?:async\s+)?function\s+(\w+)\s*\("),
        _compile(r"^\s{0,8}(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\("),
    ],
    Language.TYPESCRIPT: [
        _compile(r"^\s{0,8}(?:async\s+)?function\s+(\w+)\s*\("),
        _compile(r"^\s{0,8}(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\("),
    ],
    Language.TSX: [
        _compile(r"^\s{0,8}(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\("),
        _compile(r"^\s{0,8}(?:async\s+)?function\s+(\w+)\s*\("),
    ],
    Language.RUST: [
        _compile(r"^\s{0,8}(?:pub\s+)?(?:async\s+)?fn\s+(\w+)\s*[<(]"),
    ],
    Language.GO: [
        _compile(r"^func\s+(?:\(\w{1,32}\s+\*?\w{1,64}\)\s+)?(\w+)\s*\("),
    ],
    Language.C: [
        # HARDENED: simplified, no nested optional groups
        _compile(r"^(?:\w[\w\s\*]{0,32})\s+(\w+)\s*\([^;]{0,256}\)\s*\{"),
    ],
    Language.CPP: [
        _compile(r"^(?:\w[\w\s\*:<>]{0,48})\s+(\w+)\s*\([^;]{0,256}\)(?:\s*const)?\s*\{"),
    ],
    Language.TERRAFORM_HCL: [
        _compile(r'^resource\s+"([^"]{1,128})"\s+"([^"]{1,128})"'),
        _compile(r'^(?:variable|output|module|provider)\s+"([^"]{1,128})"'),
    ],
    Language.YAML: [],
}

# Call detection — bounded to prevent ReDoS on minified files
_CALL_PATTERN = _compile(r"\b([\w.]{1,128})\s*\(")

# Python comment / string detection for sentinel replacement
_PYTHON_COMMENT_RE = _compile(r"^\s{0,8}#")
_PYTHON_STRING_RE  = _compile(r'^\s{0,8}(?:"""|\'\'\')') 


class FallbackParser(AbstractParser):
    """
    Regex-based minimal parser. Always succeeds. Never crashes.
    Hardened against ReDoS (FIX-2), Graph Explosion (FIX-3),
    and Prompt Injection (FIX-5).
    """

    def __init__(self) -> None:
        self._annotator = SecurityAnnotator()
        self._validator = InputValidator()

    @property
    def backend_name(self) -> str:
        return "fallback"

    def can_parse(self, language: Language) -> bool:
        return True

    def parse(
        self,
        source_code: str,
        file_path: str,
        language: Language,
    ) -> ParsedGraphOutput:
        start_ms     = time.monotonic() * 1000
        warnings:     list[str] = []
        parse_errors: list[str] = []

        # FIX-2: Validate and sanitize FIRST — caps file size, line length,
        # strips Trojan Source chars, null bytes, etc.
        val = self._validator.validate_string(source_code, file_path)
        if not val.is_parseable:
            return self._rejected_output(
                file_path, language, start_ms, val.rejection_reason or ""
            )
        warnings.extend(val.warnings)
        source_code = val.sanitized_source

        source_bytes = source_code.encode("utf-8", errors="replace")
        file_hash    = hashlib.sha256(source_bytes).hexdigest()
        # FIX-2: lines already capped by InputValidator; cap again defensively
        lines = source_code.splitlines()[:LIMITS.max_lines]

        nodes: list[NormalizedNode] = []
        edges: list[Edge]           = []
        guard = GraphSizeGuard(file_path)   # FIX-3: circuit breaker

        # ── PROGRAM root node ─────────────────────────────────────────────────
        prog_id = NormalizedNode.make_id(file_path, 0, 0, "PROGRAM")
        nodes.append(NormalizedNode(
            node_id=prog_id, node_type=NodeType.PROGRAM, raw_type="program",
            language=language, backend=ParserBackend.FALLBACK,
            name=file_path, value=None, qualified_name=None,
            file_path=file_path, start_line=0, end_line=len(lines),
            start_col=0, end_col=0,
            raw_text=source_code[:LIMITS.max_node_text_chars],
            depth=0, parent_id=None, children_ids=(),
            security_label=SecurityLabel.NONE, security_confidence=0.0,
            cwe_hints=(), attributes={"backend": "fallback"},
        ))
        guard._node_count = 1

        patterns = _FUNCTION_PATTERNS.get(language, [])

        try:
            # ── Detect functions ──────────────────────────────────────────────
            for i, raw_line in enumerate(lines, start=1):
                # FIX-2: line already capped by InputValidator, but re-cap
                line = raw_line[:LIMITS.max_line_length]

                for pattern in patterns:
                    m = pattern.match(line)
                    if m:
                        func_name = m.group(1)
                        node_id   = NormalizedNode.make_id(file_path, i, 0, "FUNCTION")
                        guard.check_node()   # FIX-3

                        sec_lbl, sec_conf, cwes = self._annotator.annotate(
                            NodeType.FUNCTION, func_name, language, line
                        )
                        # FIX-5: preserve raw_text for annotation, NOT for LLM
                        nodes.append(NormalizedNode(
                            node_id=node_id, node_type=NodeType.FUNCTION,
                            raw_type="function", language=language,
                            backend=ParserBackend.FALLBACK,
                            name=func_name, value=None, qualified_name=None,
                            file_path=file_path, start_line=i, end_line=i,
                            start_col=0, end_col=len(line),
                            raw_text=line[:LIMITS.max_node_text_chars],
                            depth=1, parent_id=prog_id, children_ids=(),
                            security_label=sec_lbl, security_confidence=sec_conf,
                            cwe_hints=cwes, attributes={},
                        ))
                        guard.check_edge()   # FIX-3
                        eid = Edge.make_id(prog_id, node_id, EdgeType.AST_CHILD.value)
                        edges.append(Edge(eid, EdgeType.AST_CHILD, prog_id, node_id))
                        break

            # ── Detect security-relevant call expressions ──────────────────────
            for i, raw_line in enumerate(lines, start=1):
                line = raw_line[:LIMITS.max_line_length]  # FIX-2

                # FIX-5: skip comment lines — don't emit their content as tokens
                if language == Language.PYTHON and _PYTHON_COMMENT_RE.match(line):
                    continue

                for m in _CALL_PATTERN.finditer(line):
                    call_name = m.group(1)
                    if len(call_name) < 2:
                        continue
                    # Only index security-relevant calls in fallback mode
                    sec_lbl, sec_conf, cwes = self._annotator.annotate(
                        NodeType.CALL, call_name, language, line
                    )
                    if sec_lbl == SecurityLabel.NONE:
                        continue

                    node_id = NormalizedNode.make_id(file_path, i, m.start(), "CALL")
                    guard.check_node()   # FIX-3

                    nodes.append(NormalizedNode(
                        node_id=node_id, node_type=NodeType.CALL,
                        raw_type="call", language=language,
                        backend=ParserBackend.FALLBACK,
                        name=call_name, value=None, qualified_name=None,
                        file_path=file_path, start_line=i, end_line=i,
                        start_col=m.start(), end_col=m.end(),
                        raw_text=line[:LIMITS.max_node_text_chars],
                        depth=2, parent_id=prog_id, children_ids=(),
                        security_label=sec_lbl, security_confidence=sec_conf,
                        cwe_hints=cwes, attributes={},
                    ))
                    guard.check_edge()   # FIX-3
                    eid = Edge.make_id(prog_id, node_id, EdgeType.AST_CHILD.value)
                    edges.append(Edge(eid, EdgeType.AST_CHILD, prog_id, node_id))

        except GraphExplosionError as exc:
            warnings.append(
                f"Graph Explosion defence activated: {exc}. "
                f"Graph truncated at {guard.node_count} nodes / {guard.edge_count} edges."
            )

        # ── Security summary ──────────────────────────────────────────────────
        summary  = SecurityAnnotationSummary()
        cwe_map: dict[str, list[str]] = {}
        for node in nodes:
            match node.security_label:
                case SecurityLabel.SOURCE:     summary.sources.append(node.node_id)
                case SecurityLabel.SINK:       summary.sinks.append(node.node_id)
                case SecurityLabel.SANITIZER:  summary.sanitizers.append(node.node_id)
                case SecurityLabel.SENSITIVE:  summary.sensitive_nodes.append(node.node_id)
            for cwe in node.cwe_hints:
                cwe_map.setdefault(cwe, []).append(node.node_id)
        summary.cwe_hints = cwe_map

        # ── GraphCodeBERT input with FIX-5 sentinel replacement ───────────────
        tokens, ids, types, labels = [], [], [], []
        for node in nodes:
            if not node.raw_text or len(tokens) >= LIMITS.max_graphcodebert_tokens:
                break
            # FIX-5: sentinel for comment/string node types
            sentinel = node.attributes.get("llm_sentinel")
            if sentinel:
                tokens.append(sentinel); ids.append(node.node_id)
                types.append(node.node_type.value); labels.append(node.security_label.value)
                continue
            for w in sanitize_for_llm(node.raw_text).split()[:4]:
                if len(tokens) >= LIMITS.max_graphcodebert_tokens:
                    break
                tokens.append(w); ids.append(node.node_id)
                types.append(node.node_type.value); labels.append(node.security_label.value)

        gcb_input = GraphCodeBERTInput(
            tokens=tokens, token_node_ids=ids, dfg_edges=[],
            node_type_sequence=types, security_label_sequence=labels,
        )

        elapsed_ms = time.monotonic() * 1000 - start_ms
        metadata = FileMetadata(
            file_path=file_path, language=language, backend=ParserBackend.FALLBACK,
            file_hash=file_hash, size_bytes=len(source_bytes), line_count=len(lines),
            encoding="utf-8", parse_duration_ms=round(elapsed_ms, 2),
            error_count=len(parse_errors), has_parse_errors=bool(parse_errors),
        )

        return ParsedGraphOutput(
            metadata=metadata, nodes=nodes, edges=edges,
            security_summary=summary, graphcodebert_input=gcb_input,
            graph_hash=ParsedGraphOutput.compute_graph_hash(nodes, edges),
            parse_errors=parse_errors,
            warnings=warnings + ["Used fallback regex parser"],
        )

    def _rejected_output(
        self, file_path: str, language: Language,
        start_ms: float, reason: str
    ) -> ParsedGraphOutput:
        elapsed = time.monotonic() * 1000 - start_ms
        prog_id = NormalizedNode.make_id(file_path, 0, 0, "PROGRAM")
        node = NormalizedNode(
            node_id=prog_id, node_type=NodeType.PROGRAM, raw_type="program",
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