"""
PRISM Parser Models
===================
Core data structures for the unified AST/CPG representation.
All downstream consumers (CFG builder, DFG builder, GraphCodeBERT,
Neo4j storage) depend on these immutable dataclasses.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Language(str, Enum):
    PYTHON         = "python"
    JAVA           = "java"
    JAVASCRIPT     = "javascript"
    TSX            = "tsx"
    TYPESCRIPT     = "typescript"
    C              = "c"
    CPP            = "cpp"
    RUST           = "rust"
    GO             = "go"
    TERRAFORM_HCL  = "terraform_hcl"
    YAML           = "yaml"
    UNKNOWN        = "unknown"


class ParserBackend(str, Enum):
    """Which backend produced this AST."""
    CODEQL      = "codeql"       # Primary: C/C++, Java, JS, Go, Python
    JOERN       = "joern"        # Cross-validation / fallback
    TREE_SITTER = "tree_sitter"  # Primary: Rust, HCL, YAML, TSX
    FALLBACK    = "fallback"     # Graceful degradation


class NodeType(str, Enum):
    # Structural
    PROGRAM              = "PROGRAM"
    FUNCTION             = "FUNCTION"
    CLASS                = "CLASS"
    MODULE               = "MODULE"
    BLOCK                = "BLOCK"
    NAMESPACE            = "NAMESPACE"
    # Statements
    ASSIGN               = "ASSIGN"
    AUGMENTED_ASSIGN     = "AUGMENTED_ASSIGN"
    RETURN               = "RETURN"
    IMPORT               = "IMPORT"
    DELETE               = "DELETE"
    RAISE                = "RAISE"
    ASSERT               = "ASSERT"
    EXPRESSION_STATEMENT = "EXPRESSION_STATEMENT"
    # Control flow
    IF                   = "IF"
    ELSE                 = "ELSE"
    ELIF                 = "ELIF"
    LOOP                 = "LOOP"
    BREAK                = "BREAK"
    CONTINUE             = "CONTINUE"
    SWITCH               = "SWITCH"
    CASE                 = "CASE"
    TRY                  = "TRY"
    CATCH                = "CATCH"
    FINALLY              = "FINALLY"
    # Expressions
    CALL                 = "CALL"
    BINARY_OP            = "BINARY_OP"
    UNARY_OP             = "UNARY_OP"
    COMPARISON           = "COMPARISON"
    LOGICAL_OP           = "LOGICAL_OP"
    TERNARY              = "TERNARY"
    AWAIT                = "AWAIT"
    YIELD                = "YIELD"
    LAMBDA               = "LAMBDA"
    # Primaries
    IDENTIFIER           = "IDENTIFIER"
    LITERAL              = "LITERAL"
    ATTRIBUTE            = "ATTRIBUTE"
    SUBSCRIPT            = "SUBSCRIPT"
    SPREAD               = "SPREAD"
    # Data structures
    ARRAY                = "ARRAY"
    DICT                 = "DICT"
    SET                  = "SET"
    TUPLE                = "TUPLE"
    PAIR                 = "PAIR"
    # Type system
    TYPE_ANNOTATION      = "TYPE_ANNOTATION"
    GENERIC              = "GENERIC"
    INTERFACE            = "INTERFACE"
    ENUM                 = "ENUM"
    # IaC / Config
    RESOURCE             = "RESOURCE"
    PROVIDER             = "PROVIDER"
    VARIABLE             = "VARIABLE"
    OUTPUT               = "OUTPUT"
    DATA_SOURCE          = "DATA_SOURCE"
    MODULE_CALL          = "MODULE_CALL"
    CONFIG_KEY           = "CONFIG_KEY"
    CONFIG_VALUE         = "CONFIG_VALUE"
    # Parameters / Arguments
    PARAMETER            = "PARAMETER"
    ARGUMENT             = "ARGUMENT"
    KEYWORD_ARGUMENT     = "KEYWORD_ARGUMENT"
    DEFAULT_VALUE        = "DEFAULT_VALUE"
    # Decorators
    DECORATOR            = "DECORATOR"
    ANNOTATION           = "ANNOTATION"
    # Comments
    COMMENT              = "COMMENT"
    DOCSTRING            = "DOCSTRING"
    # Fallback
    UNKNOWN              = "UNKNOWN"
    # Compatibility aliases used by token_extractor and joern_delegate
    DECL        = "IDENTIFIER"   # local variable declaration → IDENTIFIER
    PARAM       = "PARAMETER"    # parameter alias
    INDEX       = "SUBSCRIPT"    # index expression alias
    CONFIG      = "CONFIG_KEY"   # config block alias
    SECRET_REF  = "CONFIG_VALUE" # secret reference alias
    WITH        = "BLOCK"        # with-statement alias
    THROW       = "RAISE"        # throw/raise alias
    BREAK_      = "BREAK"        # BREAK alias (avoid clash with keyword)
    SWITCH_     = "SWITCH"       # SWITCH alias


class SecurityLabel(str, Enum):
    SOURCE      = "SOURCE"      # data enters system here
    SINK        = "SINK"        # dangerous operation
    SANITIZER   = "SANITIZER"   # validation / encoding
    PROPAGATOR  = "PROPAGATOR"  # passes tainted data through
    TAINTED     = "TAINTED"     # marked during DFG traversal
    SENSITIVE   = "SENSITIVE"   # handles secrets / PII
    NONE        = "NONE"


class EdgeType(str, Enum):
    # AST (produced by this parser)
    AST_CHILD        = "AST_CHILD"
    AST_NEXT_SIBLING = "AST_NEXT_SIBLING"
    # CFG (added by CFG builder)
    CFG_NEXT         = "CFG_NEXT"
    CFG_TRUE         = "CFG_TRUE"
    CFG_FALSE        = "CFG_FALSE"
    CFG_LOOP_BACK    = "CFG_LOOP_BACK"
    CFG_EXCEPTION    = "CFG_EXCEPTION"
    # DFG (added by DFG builder)
    DFG_FLOW         = "DFG_FLOW"
    DFG_DEPENDS      = "DFG_DEPENDS"
    DFG_ALIAS        = "DFG_ALIAS"
    # Call graph
    CALLS            = "CALLS"
    CALLED_BY        = "CALLED_BY"
    # Type / inheritance
    INHERITS         = "INHERITS"
    IMPLEMENTS       = "IMPLEMENTS"


# ---------------------------------------------------------------------------
# NormalizedNode
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class NormalizedNode:
    """
    Single node in the unified language-agnostic AST/CPG.
    node_id is a deterministic hash → reproducible for blockchain audit.
    """
    node_id:            str
    node_type:          NodeType
    raw_type:           str
    language:           Language
    backend:            ParserBackend
    name:               str | None
    value:              str | None
    qualified_name:     str | None
    file_path:          str
    start_line:         int
    end_line:           int
    start_col:          int
    end_col:            int
    raw_text:           str
    depth:              int
    parent_id:          str | None
    children_ids:       tuple[str, ...]
    security_label:     SecurityLabel
    security_confidence: float
    cwe_hints:          tuple[str, ...]
    attributes:         dict[str, Any] = field(default_factory=dict, compare=False, hash=False)

    @staticmethod
    def make_id(file_path: str, start_line: int, start_col: int, node_type: str) -> str:
        raw = f"{file_path}:{start_line}:{start_col}:{node_type}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type.value,
            "raw_type": self.raw_type,
            "language": self.language.value,
            "backend": self.backend.value,
            "name": self.name,
            "value": self.value,
            "qualified_name": self.qualified_name,
            "file_path": self.file_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "start_col": self.start_col,
            "end_col": self.end_col,
            "raw_text": self.raw_text,
            "depth": self.depth,
            "parent_id": self.parent_id,
            "children_ids": list(self.children_ids),
            "security_label": self.security_label.value,
            "security_confidence": self.security_confidence,
            "cwe_hints": list(self.cwe_hints),
            "attributes": self.attributes,
        }


# ---------------------------------------------------------------------------
# Edge
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Edge:
    edge_id:   str
    edge_type: EdgeType
    source_id: str
    target_id: str
    label:     str | None = None
    weight:    float = 1.0
    attributes: dict[str, Any] = field(default_factory=dict, compare=False, hash=False)

    @staticmethod
    def make_id(source_id: str, target_id: str, edge_type: str) -> str:
        raw = f"{source_id}->{target_id}:{edge_type}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "edge_type": self.edge_type.value,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "label": self.label,
            "weight": self.weight,
            "attributes": self.attributes,
        }


# ---------------------------------------------------------------------------
# FileMetadata
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FileMetadata:
    file_path:        str
    language:         Language
    backend:          ParserBackend
    file_hash:        str
    size_bytes:       int
    line_count:       int
    encoding:         str
    parse_duration_ms: float
    error_count:      int
    has_parse_errors: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "language": self.language.value,
            "backend": self.backend.value,
            "file_hash": self.file_hash,
            "size_bytes": self.size_bytes,
            "line_count": self.line_count,
            "encoding": self.encoding,
            "parse_duration_ms": self.parse_duration_ms,
            "error_count": self.error_count,
            "has_parse_errors": self.has_parse_errors,
        }


# ---------------------------------------------------------------------------
# SecurityAnnotationSummary
# ---------------------------------------------------------------------------

@dataclass
class SecurityAnnotationSummary:
    sources:         list[str] = field(default_factory=list)
    sinks:           list[str] = field(default_factory=list)
    sanitizers:      list[str] = field(default_factory=list)
    propagators:     list[str] = field(default_factory=list)
    sensitive_nodes: list[str] = field(default_factory=list)
    potential_paths: list[tuple[str, str, str]] = field(default_factory=list)
    cwe_hints:       dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sources": self.sources,
            "sinks": self.sinks,
            "sanitizers": self.sanitizers,
            "propagators": self.propagators,
            "sensitive_nodes": self.sensitive_nodes,
            "potential_paths": [
                {"source": s, "sink": t, "type": p}
                for s, t, p in self.potential_paths
            ],
            "cwe_hints": self.cwe_hints,
        }


# ---------------------------------------------------------------------------
# GraphCodeBERTInput
# ---------------------------------------------------------------------------

@dataclass
class GraphCodeBERTInput:
    """
    Prepared input for GraphCodeBERT.
    DFG edges are in token-index space; populated fully by the DFG builder.
    """
    tokens:                  list[str]
    token_node_ids:          list[str]
    dfg_edges:               list[tuple[int, int]]
    node_type_sequence:      list[str]
    security_label_sequence: list[str]
    max_token_length:        int = 512

    def to_dict(self) -> dict[str, Any]:
        return {
            "tokens": self.tokens,
            "token_node_ids": self.token_node_ids,
            "dfg_edges": self.dfg_edges,
            "node_type_sequence": self.node_type_sequence,
            "security_label_sequence": self.security_label_sequence,
        }


# ---------------------------------------------------------------------------
# ParsedGraphOutput  (top-level)
# ---------------------------------------------------------------------------

@dataclass
class ParsedGraphOutput:
    """
    Complete, self-contained output of the parser stage.
    Passed as-is to: CFG builder, DFG builder, Neo4j ingestion,
    GraphCodeBERT preparation, and blockchain audit logger.
    """
    metadata:             FileMetadata
    nodes:                list[NormalizedNode]
    edges:                list[Edge]
    security_summary:     SecurityAnnotationSummary
    graphcodebert_input:  GraphCodeBERTInput
    graph_hash:           str
    parse_errors:         list[str]
    warnings:             list[str]
    codeql_results:       dict[str, Any] | None = None

    @classmethod
    def compute_graph_hash(cls, nodes: list[NormalizedNode], edges: list[Edge]) -> str:
        node_ids = sorted(n.node_id for n in nodes)
        edge_ids = sorted(e.edge_id for e in edges)
        payload  = json.dumps({"nodes": node_ids, "edges": edge_ids}, sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata":            self.metadata.to_dict(),
            "graph_hash":          self.graph_hash,
            "node_count":          len(self.nodes),
            "edge_count":          len(self.edges),
            "nodes":               [n.to_dict() for n in self.nodes],
            "edges":               [e.to_dict() for e in self.edges],
            "security_summary":    self.security_summary.to_dict(),
            "graphcodebert_input": self.graphcodebert_input.to_dict(),
            "parse_errors":        self.parse_errors,
            "warnings":            self.warnings,
            "codeql_results":      self.codeql_results,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    # Convenience accessors
    def get_functions(self)  -> list[NormalizedNode]:
        return [n for n in self.nodes if n.node_type == NodeType.FUNCTION]

    def get_calls(self)      -> list[NormalizedNode]:
        return [n for n in self.nodes if n.node_type == NodeType.CALL]

    def get_sinks(self)      -> list[NormalizedNode]:
        return [n for n in self.nodes if n.security_label == SecurityLabel.SINK]

    def get_sources(self)    -> list[NormalizedNode]:
        return [n for n in self.nodes if n.security_label == SecurityLabel.SOURCE]

    def get_ast_edges(self)  -> list[Edge]:
        return [e for e in self.edges if e.edge_type == EdgeType.AST_CHILD]

    def get_children(self, node_id: str) -> list[NormalizedNode]:
        node_map = {n.node_id: n for n in self.nodes}
        node = node_map.get(node_id)
        if not node:
            return []
        return [node_map[cid] for cid in node.children_ids if cid in node_map]


# ---------------------------------------------------------------------------
# CodeToken — flat token emitted by token_extractor for GraphCodeBERT
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CodeToken:
    """
    Single token in the flat token sequence passed to GraphCodeBERT.

    Produced by TokenExtractor from the list of NormalizedNodes.
    The actual sub-word BPE tokenisation is done later at model-inference
    time; at this stage tokens are significant AST node names/values.
    """
    text:           str            # token string (identifier name, literal, etc.)
    node_id:        str            # back-reference to the NormalizedNode
    node_type:      str            # NodeType.value for quick filtering
    security_label: str            # SecurityLabel.value (SOURCE / SINK / NONE …)
    start_line:     int = 0
    start_col:      int = 0