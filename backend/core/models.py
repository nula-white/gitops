"""
Core Pydantic models shared across the PRISM pipeline.
"""
from __future__ import annotations
from enum import Enum
from typing import Optional, List, Any
from pydantic import BaseModel, Field
import uuid


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class NodeType(str, Enum):
    FUNCTION = "FUNCTION"
    BLOCK = "BLOCK"
    CALL = "CALL"
    ASSIGN = "ASSIGN"
    IF = "IF"
    LOOP = "LOOP"
    RETURN = "RETURN"
    IDENTIFIER = "IDENTIFIER"
    LITERAL = "LITERAL"
    IMPORT = "IMPORT"
    PROGRAM = "PROGRAM"
    UNKNOWN = "UNKNOWN"


class EdgeKind(str, Enum):
    AST_CHILD = "AST_CHILD"
    CFG_NEXT = "CFG_NEXT"
    CFG_TRUE = "CFG_TRUE"
    CFG_FALSE = "CFG_FALSE"
    DFG_FLOW = "DFG_FLOW"
    DFG_DEPENDS = "DFG_DEPENDS"
    CALLS = "CALLS"


class PipelinePhase(str, Enum):
    IDLE = "IDLE"
    PARSE = "PARSE"
    AST = "AST"
    NORMALIZE = "NORMALIZE"
    CFG = "CFG"
    DFG = "DFG"
    CPG_MERGE = "CPG_MERGE"
    GRAPHCODEBERT = "GRAPHCODEBERT"
    ANNOTATE = "ANNOTATE"
    COMPLETE = "COMPLETE"
    ERROR = "ERROR"


# ---------------------------------------------------------------------------
# CPG node / edge models
# ---------------------------------------------------------------------------

class CPGNode(BaseModel):
    id: str
    session_id: str
    node_type: NodeType
    language: str = "unknown"
    file: str = ""
    line_start: int = 0
    line_end: int = 0
    col_start: int = 0
    col_end: int = 0
    name: str = ""
    code_snippet: str = ""          # the actual source text of this node
    phase: str = "ast"              # which phase introduced this node
    annotated: bool = False
    vuln_id: Optional[str] = None   # FK to VulnerabilityFinding.id


class CPGEdge(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    source_id: str
    target_id: str
    kind: EdgeKind
    label: str = ""


# ---------------------------------------------------------------------------
# Vulnerability finding
# ---------------------------------------------------------------------------

class VulnerabilityFinding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    node_id: str

    # Classification
    vuln_type: str                  # e.g. "SQL Injection"
    cwe: str                        # e.g. "CWE-89"
    severity: Severity
    confidence: float = 0.0         # 0.0 – 1.0 from GraphCodeBERT risk_score

    # Location
    file: str
    line_start: int
    line_end: int
    function_name: str = ""

    # Evidence
    description: str                # human-readable explanation
    code_snippet: str               # the raw source lines triggering this
    data_flow_path: List[str] = []  # ordered list of node names/ids

    # Remediation
    remediation: str = ""
    references: List[str] = []      # CVE / OWASP links


# ---------------------------------------------------------------------------
# WebSocket event envelope
# ---------------------------------------------------------------------------

class WSEventType(str, Enum):
    PHASE = "phase"
    NODE = "node"
    EDGE = "edge"
    ANNOTATION = "annotation"
    FINDING = "finding"
    COMPLETE = "complete"
    ERROR = "error"
    HEARTBEAT = "heartbeat"


class WSEvent(BaseModel):
    type: WSEventType
    session_id: str
    payload: Any = None


# ---------------------------------------------------------------------------
# Analysis request / response
# ---------------------------------------------------------------------------

class AnalysisRequest(BaseModel):
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    repository_url: Optional[str] = None
    inline_code: Optional[str] = None      # for quick single-file analysis
    language: str = "python"
    filename: str = "snippet.py"


class AnalysisStatus(BaseModel):
    session_id: str
    phase: PipelinePhase
    node_count: int = 0
    edge_count: int = 0
    finding_count: int = 0
    error: Optional[str] = None