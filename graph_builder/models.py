"""
PRISM Graph Builder — Data Models
===================================
Complete schema for CPG nodes, edges, and the GraphBuildResult
that flows into LangGraph agent state.

Node identity:
  node_id = SHA-256(file_path_relative + ":" + start_line + ":" +
                    start_col + ":" + normalized_type)[:16]

  This is stable across Tree-sitter, Joern, and CodeQL invocations
  on the same file. When Joern augmentation is added (Phase 2), Joern
  annotates the same node IDs — no schema migration required.

GraphCodeBERT input contract:
  The SecurityAnalysisAgent constructs GraphCodeBERT inputs via:
    tokens:     node.token_ids  (list of int)
    dfg_edges:  [(src_node_id, dst_node_id)] where edge.type == DFG_FLOW
    positions:  node.start_line (used as position embedding)
  These fields are populated during graph build, not during inference.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class NodeType(str, Enum):
    """
    Unified AST node types — language-agnostic.
    All language-specific node types are normalized to these values.

    Normalization examples:
      Python FunctionDef        → FUNCTION
      Java MethodDeclaration    → FUNCTION
      Rust FunctionItem         → FUNCTION
      JavaScript ArrowFunction  → FUNCTION
      Python AsyncFunctionDef   → FUNCTION  (is_async=True in properties)
      Python With               → BLOCK     (with_context=True in properties)
      HCL resource block        → RESOURCE  (IaC-specific)
      YAML mapping              → MAPPING   (IaC-specific)
    """
    # Core structural
    PROGRAM          = "PROGRAM"
    FUNCTION         = "FUNCTION"
    BLOCK            = "BLOCK"
    CLASS            = "CLASS"
    MODULE           = "MODULE"

    # Statements
    ASSIGN           = "ASSIGN"
    AUGMENTED_ASSIGN = "AUGMENTED_ASSIGN"
    RETURN           = "RETURN"
    IF               = "IF"
    LOOP             = "LOOP"
    BREAK            = "BREAK"
    CONTINUE         = "CONTINUE"
    IMPORT           = "IMPORT"
    DELETE           = "DELETE"
    ASSERT           = "ASSERT"
    RAISE            = "RAISE"
    TRY              = "TRY"
    CATCH            = "CATCH"
    FINALLY          = "FINALLY"
    WITH             = "WITH"
    YIELD            = "YIELD"
    AWAIT            = "AWAIT"

    # Expressions
    CALL             = "CALL"
    BINARY_OP        = "BINARY_OP"
    UNARY_OP         = "UNARY_OP"
    COMPARE          = "COMPARE"
    BOOL_OP          = "BOOL_OP"
    CONDITIONAL      = "CONDITIONAL"     # ternary
    LAMBDA           = "LAMBDA"
    COMPREHENSION    = "COMPREHENSION"   # list/dict/set/gen expr

    # Atoms
    IDENTIFIER       = "IDENTIFIER"
    LITERAL          = "LITERAL"
    PARAM            = "PARAM"
    MEMBER_ACCESS    = "MEMBER_ACCESS"   # obj.attr
    INDEX_ACCESS     = "INDEX_ACCESS"    # arr[i]
    SUBSCRIPT        = "SUBSCRIPT"
    SPREAD           = "SPREAD"          # *args, **kwargs

    # IaC-specific (Terraform HCL, YAML/K8s)
    RESOURCE         = "RESOURCE"        # Terraform resource block
    DATA_SOURCE      = "DATA_SOURCE"     # Terraform data block
    VARIABLE         = "VARIABLE"        # Terraform variable block
    OUTPUT           = "OUTPUT"          # Terraform output block
    PROVIDER         = "PROVIDER"        # Terraform provider block
    MAPPING          = "MAPPING"         # YAML mapping node
    SEQUENCE         = "SEQUENCE"        # YAML sequence node

    # Fallback
    UNKNOWN          = "UNKNOWN"


class EdgeType(str, Enum):
    """
    All edge types in the Code Property Graph.

    Three graph layers:
      AST_*     — syntactic containment / parent-child
      CFG_*     — execution order / control flow
      DFG_*     — data propagation / dependencies

    Security annotation edges (injected by CodeQL SARIF parser):
      TAINT_*   — taint tracking for vulnerability detection
      SANITIZER — taint elimination

    Call graph edges:
      CALLS / RETURNS_TO / PARAM_OF
    """
    # AST layer
    AST_CHILD        = "AST_CHILD"       # parent → child
    AST_SIBLING      = "AST_SIBLING"     # sequential siblings

    # CFG layer
    CFG_NEXT         = "CFG_NEXT"        # unconditional successor
    CFG_TRUE         = "CFG_TRUE"        # condition evaluated true
    CFG_FALSE        = "CFG_FALSE"       # condition evaluated false
    CFG_LOOP         = "CFG_LOOP"        # loop back-edge
    CFG_EXCEPTION    = "CFG_EXCEPTION"   # exception propagation
    CFG_FINALLY      = "CFG_FINALLY"     # finally block entry

    # DFG layer
    DFG_FLOW         = "DFG_FLOW"        # value flows from def to use
    DFG_DEPENDS      = "DFG_DEPENDS"     # node value depends on other
    DFG_KILLS        = "DFG_KILLS"       # definition kills previous def

    # Call graph
    CALLS            = "CALLS"           # call site → function def
    RETURNS_TO       = "RETURNS_TO"      # return → call site
    PARAM_OF         = "PARAM_OF"        # param → function
    ARG_OF           = "ARG_OF"          # argument → call

    # Security annotation (CodeQL SARIF injection)
    TAINT_SOURCE     = "TAINT_SOURCE"    # untrusted data entry point
    TAINT_SINK       = "TAINT_SINK"      # dangerous consumption point
    TAINT_PROPAGATES = "TAINT_PROPAGATES"# taint flows through this edge
    SANITIZER        = "SANITIZER"       # taint eliminated here

    # Member / structural
    MEMBER_OF        = "MEMBER_OF"       # field/method → class


class SecurityLabel(str, Enum):
    """
    Security classification labels on nodes.
    Populated by: SecurityAnnotator (Tree-sitter sinks/sources)
                  and SARIF injection (CodeQL).

    Used by SecurityAnalysisAgent to prioritize GraphCodeBERT inference.
    """
    NONE        = "NONE"
    SOURCE      = "SOURCE"        # taint source (user input)
    SINK        = "SINK"          # dangerous operation
    SANITIZER   = "SANITIZER"     # sanitization function
    TAINTED     = "TAINTED"       # confirmed tainted by DFG
    ENTRY_POINT = "ENTRY_POINT"   # API endpoint / entry point


class Language(str, Enum):
    """Supported languages in PRISM graph builder."""
    PYTHON      = "python"
    JAVA        = "java"
    JAVASCRIPT  = "javascript"
    TYPESCRIPT  = "typescript"
    TSX         = "tsx"
    RUST        = "rust"
    GO          = "go"
    C           = "c"
    CPP         = "cpp"
    TERRAFORM   = "terraform"
    YAML        = "yaml"
    UNKNOWN     = "unknown"


# ---------------------------------------------------------------------------
# Core graph objects
# ---------------------------------------------------------------------------

@dataclass
class CPGNode:
    """
    A single node in the Code Property Graph.

    node_id is the primary key in Neo4j and the stable cross-tool identity.
    All fields except node_id, node_type, language, file_path, start_line
    are optional — populated progressively as the pipeline stages run.

    LangGraph / Agent contract:
      SecurityAnalysisAgent reads: token_ids, normalized_text, security_label,
                                    cwe_hint, risk_score, confidence
      IaCGenerationAgent reads:     node_type (RESOURCE, PROVIDER),
                                    raw_text, file_path
    """
    # Identity (always set)
    node_id:          str
    node_type:        NodeType
    language:         Language
    file_path:        str           # relative to repo root
    start_line:       int
    end_line:         int
    start_col:        int
    end_col:          int

    # Content
    raw_text:         str = ""      # original source (stripped of leading whitespace)
    normalized_text:  str = ""      # prompt-injection-safe: strings→[STRING_LITERAL],
                                    # comments stripped, bidi markers removed
    token_ids:        list[int] = field(default_factory=list)
                                    # GraphCodeBERT token IDs (populated by tokenizer)

    # Security annotation (populated by SecurityAnnotator + SARIF injector)
    security_label:   SecurityLabel = SecurityLabel.NONE
    cwe_hint:         str = ""      # e.g. "CWE-89" from CodeQL match
    sarif_rule_id:    str = ""      # CodeQL rule ID that flagged this node

    # Classification (populated by SecurityAnalysisAgent after inference)
    risk_score:       float = 0.0   # GraphCodeBERT output ∈ [0, 1]
    is_vulnerable:    bool  = False
    confidence:       float = 0.0   # classification confidence ∈ [0, 1]
    finding_type:     str   = ""    # "VULNERABLE" | "MALICIOUS" | "UNCERTAIN" | ""

    # Structural metadata
    parent_function:  str = ""      # node_id of enclosing FUNCTION node
    parent_class:     str = ""      # node_id of enclosing CLASS node
    is_async:         bool = False
    properties:       dict[str, Any] = field(default_factory=dict)
                                    # language-specific extra properties

    @staticmethod
    def make_id(
        file_path:  str,
        start_line: int,
        start_col:  int,
        node_type:  str,
    ) -> str:
        """
        Compute the stable content-addressed node ID.

        This exact formula must be used by all tools (Tree-sitter builder,
        Joern augmentation, CodeQL SARIF injector) to guarantee that
        different tools annotate the same Neo4j node.
        """
        key = f"{file_path}:{start_line}:{start_col}:{node_type}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]

    def to_neo4j_dict(self) -> dict[str, Any]:
        """
        Serialize to a flat dict for Neo4j node properties.
        Lists are stored as JSON strings (Neo4j doesn't support list-of-int natively).
        """
        import json
        return {
            "node_id":         self.node_id,
            "node_type":       self.node_type.value,
            "language":        self.language.value,
            "file_path":       self.file_path,
            "start_line":      self.start_line,
            "end_line":        self.end_line,
            "start_col":       self.start_col,
            "end_col":         self.end_col,
            "raw_text":        self.raw_text[:2000],   # Neo4j string limit guard
            "normalized_text": self.normalized_text[:2000],
            "token_ids":       json.dumps(self.token_ids),
            "security_label":  self.security_label.value,
            "cwe_hint":        self.cwe_hint,
            "sarif_rule_id":   self.sarif_rule_id,
            "risk_score":      self.risk_score,
            "is_vulnerable":   self.is_vulnerable,
            "confidence":      self.confidence,
            "finding_type":    self.finding_type,
            "parent_function": self.parent_function,
            "parent_class":    self.parent_class,
            "is_async":        self.is_async,
        }


@dataclass
class CPGEdge:
    """
    A directed edge in the Code Property Graph.

    Edge identity: SHA-256(src_id + ":" + dst_id + ":" + type)[:16]
    Edges are idempotent — inserting the same edge twice is a no-op in Neo4j.
    """
    edge_id:    str
    src_id:     str
    dst_id:     str
    edge_type:  EdgeType
    properties: dict[str, Any] = field(default_factory=dict)
                                # e.g. {"condition": "x > 0"} for CFG_TRUE

    @staticmethod
    def make_id(src_id: str, dst_id: str, edge_type: str) -> str:
        key = f"{src_id}:{dst_id}:{edge_type}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]

    def to_neo4j_dict(self) -> dict[str, Any]:
        return {
            "edge_id":    self.edge_id,
            "src_id":     self.src_id,
            "dst_id":     self.dst_id,
            "edge_type":  self.edge_type.value,
            **self.properties,
        }


@dataclass
class CPGFile:
    """
    All nodes and edges for a single source file.
    Produced by the per-file graph builder, consumed by CPGAssembler.
    """
    file_path:   str
    language:    Language
    nodes:       list[CPGNode] = field(default_factory=list)
    edges:       list[CPGEdge] = field(default_factory=list)
    parse_errors: list[str]    = field(default_factory=list)
    warnings:    list[str]     = field(default_factory=list)

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    @property
    def has_errors(self) -> bool:
        return bool(self.parse_errors)


@dataclass
class GraphBuildResult:
    """
    Top-level result emitted by the graph builder.
    This object flows into LangGraph agent state as the output of
    the RepositoryAnalysisAgent's graph-build tool invocation.

    SecurityAnalysisAgent reads:
      - session_id (for Neo4j graph namespace)
      - total_nodes / total_edges (for progress tracking)
      - files_with_errors (for coverage reporting)
      - blind_spots (for audit log)
      - repo_hash (matches ingestion manifest — integrity check)

    IaCGenerationAgent reads:
      - session_id (to query Neo4j for RESOURCE/PROVIDER nodes)
    """
    session_id:         str
    repo_hash:          str         # from ingestion manifest (integrity)
    total_files:        int
    total_nodes:        int
    total_edges:        int
    files_processed:    int
    files_with_errors:  int
    files_skipped:      int
    languages_found:    list[str]
    blind_spots:        list[str]   # file paths that could not be analyzed
    warnings:           list[str]
    duration_ms:        float
    success:            bool
    error:              str = ""

    def to_langgraph_state(self) -> dict[str, Any]:
        """
        Serialize for LangGraph state node.
        Called by RepositoryAnalysisAgent after graph build completes.
        """
        return {
            "graph_build_result": {
                "session_id":        self.session_id,
                "repo_hash":         self.repo_hash,
                "total_nodes":       self.total_nodes,
                "total_edges":       self.total_edges,
                "files_processed":   self.files_processed,
                "files_with_errors": self.files_with_errors,
                "languages_found":   self.languages_found,
                "blind_spots":       self.blind_spots,
                "success":           self.success,
                "error":             self.error,
            }
        }