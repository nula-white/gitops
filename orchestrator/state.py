"""
The single TypedDict that travels through every node in the LangGraph
pipeline graph.  Every stage reads from it and writes a slice of it back.

Design principles:
  - Immutable by convention between stages: each stage returns a *new*
    dict slice via the LangGraph reducer pattern (state is merged, not replaced).
  - All heavy objects (CPGFile, GraphBuildResult) are stored under string keys
    so the state can be serialized by LangGraph's checkpointer.
  - Sensitive data (tokens) is never stored here — credentials live only in
    the ingestion layer for the duration of Stage 2.
  - The `stage_results` list acts as the audit log within a single run;
    the blockchain audit logger consumes it at the end.

Extension contract:
  Future stages (SecurityAnalysisAgent, IaCGenerationAgent, RedTeamAgent)
  add new keys to PipelineState — they never remove existing ones.  This
  means any stage can read any earlier stage's output without coupling.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TypedDict


class PipelineStatus(str, Enum):
    """Coarse status of the whole pipeline run."""
    PENDING   = "pending"
    RUNNING   = "running"
    HITL_WAIT = "hitl_wait"   # paused at a human-in-the-loop checkpoint
    COMPLETE  = "complete"
    FAILED    = "failed"


@dataclass
class StageResult:
    """
    One entry in the audit log for a single stage execution.
    Serialisable to dict for LangGraph state persistence.
    """
    stage:     str
    status:    str              # "ok" | "skipped" | "failed"
    duration_ms: float
    summary:   str              # one-line human-readable summary
    warnings:  list[str] = field(default_factory=list)
    error:     str | None = None

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
    """
    Full pipeline state.  All fields are optional (total=False) because
    LangGraph merges partial updates — each node returns only the keys it
    modifies.

    - Inputs (set by the caller before graph.invoke())
    session_id      : str             unique session identifier
    repo_url        : str             repository URL
    branch          : str             Git branch name
    commit_sha      : str | None      specific commit to pin (None = HEAD)
    credential_ref  : str             Vault / env key for the GitHub token
    max_repo_mb     : int             size limit passed to ingestion
    output_dir      : str             sandbox delivery destination

    - Stage 1: Ingestion
    ingestion_status : str            "ok" | "failed"
    repo_hash        : str            Merkle hash of the ingested repo
    fetched_commit   : str            actual commit SHA that was fetched
    sandbox_path     : str            path to the delivered sandbox dir
    total_files      : int            total files in the manifest
    ingestion_warnings : list[str]

    - Stage 2: Parsing──
    parsing_status   : str
    parse_outputs    : list[dict]     serialised ParsedGraphOutput dicts
    backend_used     : dict           {"joern": N, "tree_sitter": M, ...}
    parsing_warnings : list[str]

    - Stage 3: CPG Build
    cpg_status       : str
    cpg_node_count   : int
    cpg_edge_count   : int
    cpg_file_count   : int
    neo4j_written    : bool
    cpg_warnings     : list[str]
    cpg_sarif_path   : str | None     path to CodeQL SARIF file (if available)

    - Stage 4: SARIF Annotation
    sarif_status     : str
    sarif_annotations : int           number of CPG nodes annotated
    sarif_warnings   : list[str]

    - HITL-1 checkpoint─
    hitl1_approved   : bool | None    None = waiting, True/False = decided
    hitl1_notes      : str

    - Future stages (reserved keys — not yet implemented)
    # vulnerability_findings : list[dict]
    # risk_scores            : dict[str, float]
    # iac_templates          : list[dict]
    # audit_tx_hash          : str

    - Cross-cutting
    status           : str            PipelineStatus value
    stage_results    : list[dict]     StageResult.to_dict() entries (audit log)
    error            : str | None     set on terminal failure
    """

    # - Inputs
    session_id:          str
    repo_url:            str
    branch:              str
    commit_sha:          str | None
    credential_ref:      str
    max_repo_mb:         int
    output_dir:          str

    # - Ingestion
    ingestion_status:    str
    repo_hash:           str
    fetched_commit:      str
    sandbox_path:        str
    total_files:         int
    ingestion_warnings:  list[str]

    # - Parsing
    parsing_status:      str
    parse_outputs:       list[dict]
    backend_used:        dict
    parsing_warnings:    list[str]

    # - CPG Build
    cpg_status:          str
    cpg_node_count:      int
    cpg_edge_count:      int
    cpg_file_count:      int
    neo4j_written:       bool
    cpg_warnings:        list[str]
    cpg_sarif_path:      str | None

    # - SARIF
    sarif_status:        str
    sarif_annotations:   int
    sarif_warnings:      list[str]

    # - HITL-1
    hitl1_approved:      bool | None
    hitl1_notes:         str

    # - Cross-cutting
    status:              str
    stage_results:       list[dict]
    error:               str | None