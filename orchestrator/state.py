"""
PRISM Pipeline State
======================
Single TypedDict that flows through every LangGraph node.

New fields added in this version:
  Stage 0  tool_status, tool_warnings
  Stage 3.5  codeql_status, codeql_sarif_path, codeql_warnings
  Stage 4  sarif_edges  (taint edges written to Neo4j, was missing)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TypedDict


class PipelineStatus(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    HITL_WAIT = "hitl_wait"
    COMPLETE  = "complete"
    FAILED    = "failed"


@dataclass
class StageResult:
    stage:       str
    status:      str
    duration_ms: float
    summary:     str
    warnings:    list[str] = field(default_factory=list)
    error:       str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage":       self.stage,
            "status":      self.status,
            "duration_ms": self.duration_ms,
            "summary":     self.summary,
            "warnings":    self.warnings,
            "error":       self.error,
        }


class PipelineState(TypedDict, total=False):

    # ── Inputs ────────────────────────────────────────────────────────────────
    session_id:      str
    repo_url:        str
    branch:          str
    commit_sha:      str | None
    credential_ref:  str
    max_repo_mb:     int
    output_dir:      str

    # ── Stage 0: Tool health check ────────────────────────────────────────────
    # tool_status: {tool_name: ToolStatus.to_dict()}
    # Keys: "vault", "neo4j", "joern", "codeql"
    # Each value: {"available": bool, "required": bool, "version": str,
    #              "latency_ms": float, "reason": str, "metadata": dict}
    tool_status:     dict
    tool_warnings:   list[str]

    # ── Stage 1: Ingestion ────────────────────────────────────────────────────
    ingestion_status:   str
    repo_hash:          str
    fetched_commit:     str
    sandbox_path:       str
    total_files:        int
    ingestion_warnings: list[str]

    # ── Stage 2: Parsing ──────────────────────────────────────────────────────
    parsing_status:   str
    parse_outputs:    list[dict]
    backend_used:     dict
    parsing_warnings: list[str]

    # ── Stage 3: CPG Build ────────────────────────────────────────────────────
    cpg_status:     str
    cpg_node_count: int
    cpg_edge_count: int
    cpg_file_count: int
    neo4j_written:  bool
    cpg_warnings:   list[str]
    # cpg_sarif_path set here if a legacy SARIF file is found in the sandbox
    cpg_sarif_path: str | None

    # ── Stage 3.5: CodeQL Analysis ────────────────────────────────────────────
    # codeql_status: "ok" | "skipped" | "failed"
    codeql_status:     str
    # Path to the SARIF file written by CodeQL.
    # This is a file outside the ephemeral CodeQL temp dir so it survives
    # until node_sarif_annotation reads it.
    # Format: /tmp/prism_codeql_{session_id[:12]}.sarif
    codeql_sarif_path: str | None
    codeql_warnings:   list[str]

    # ── Stage 4: SARIF Annotation ─────────────────────────────────────────────
    sarif_status:      str
    sarif_annotations: int    # CPG nodes that received a security label
    sarif_edges:       int    # NEW: taint edges (TAINT_SOURCE, TAINT_SINK) written to Neo4j
    sarif_warnings:    list[str]

    # ── HITL-1 ────────────────────────────────────────────────────────────────
    hitl1_approved: bool | None
    hitl1_notes:    str

    # ── Cross-cutting ─────────────────────────────────────────────────────────
    status:        str           # PipelineStatus value
    stage_results: list[dict]    # StageResult.to_dict() entries — audit trail
    error:         str | None