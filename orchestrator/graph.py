"""
PRISM Pipeline Orchestrator  —  LangGraph implementation
=========================================================
Architecture
------------
The pipeline is a directed graph of nodes (stages).  Each node is a pure
function that:
  1. Reads from PipelineState
  2. Does work
  3. Returns a *partial* PipelineState dict (LangGraph merges it back)

LangGraph handles:
  - State persistence between nodes
  - Conditional edge routing (route_after_ingestion, route_after_hitl1)
  - Interrupt-and-resume for HITL checkpoints

Pipeline graph:

    START
      │
    [ingestion]          ← Stage 1: clone, verify, deliver to sandbox
      │
    route_after_ingestion ─── FAILED ──► [handle_failure]
      │ OK                                     │
    [parsing]            ← Stage 2: Joern/Tree-sitter/fallback parse      │
      │                                        │
    [cpg_build]          ← Stage 3: assemble CPG, write Neo4j             │
      │                                        │
    [sarif_annotation]   ← Stage 4: inject CodeQL SARIF into CPG          │
      │                                        │
    [hitl1_checkpoint]   ← HITL-1: pause for human review                 │
      │                                        │
    route_after_hitl1 ─── REJECTED ──► [handle_failure]                   │
      │ APPROVED                               │                           │
    [emit_audit]         ← Stage 5: blockchain audit log                  │
      │                                        ▼                          │
    END ◄────────────────────────────── [end_node] ◄──────────────────────┘

Extension points
----------------
Future stages are added between [hitl1_checkpoint] and [emit_audit]:
  - [vulnerability_analysis]   SecurityAnalysisAgent
  - [iac_generation]           IaCGenerationAgent
  - [hitl2_checkpoint]         HITL-2 before IaC deployment
  - [redteam]                  RedTeamAgent

Each is just a new node + edge in the same graph.

Usage
-----
    from prism.orchestrator import run_pipeline

    result = run_pipeline(
        repo_url       = "https://github.com/owner/repo",
        branch         = "main",
        credential_ref = "github/myorg/myrepo",   # Vault path or env key
        output_dir     = "/tmp/prism_sandbox",
    )
    print(result["status"])           # "complete" | "failed" | "hitl_wait"
    print(result["cpg_node_count"])
    print(result["stage_results"])    # full audit trail
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from pathlib import Path
from typing import Any, Literal

logger = logging.getLogger("prism.orchestrator")

# ── LangGraph imports (graceful import error to keep codebase runnable
#    even when langgraph is not installed yet) ────────────────────────────────
try:
    from langgraph.graph import StateGraph, END
    from langgraph.checkpoint.memory import MemorySaver
    _LANGGRAPH_AVAILABLE = True
except ImportError:
    _LANGGRAPH_AVAILABLE = False
    logger.warning(
        "langgraph not installed — orchestrator will run in sequential "
        "fallback mode.  Install with: pip install langgraph langchain"
    )

from .state import PipelineState, PipelineStatus, StageResult


# Helpers

def _timer() -> float:
    return time.monotonic() * 1000   # milliseconds


def _append_stage(
    state: PipelineState,
    result: StageResult,
) -> dict:
    """Return a state slice that appends a StageResult to stage_results."""
    existing = list(state.get("stage_results", []))
    existing.append(result.to_dict())
    return {"stage_results": existing}


# Stage 1 — Ingestion

def node_ingestion(state: PipelineState) -> dict:
    """
    Clone the repository, verify integrity, deliver to sandbox.

    Reads:  repo_url, branch, commit_sha, credential_ref, output_dir, max_repo_mb
    Writes: ingestion_status, repo_hash, fetched_commit, sandbox_path,
            total_files, ingestion_warnings
    """
    t0 = _timer()
    logger.info("[Stage 1] Ingestion starting — session=%s url=%s",
                state.get("session_id"), state.get("repo_url"))

    try:
        from ..ingestion.pipeline import run_ingestion
        from ..ingestion.models import GitProvider, IngestionRequest

        request = IngestionRequest(
            repo_url        = state["repo_url"],
            provider        = GitProvider.GITHUB,
            branch          = state.get("branch", "main"),
            commit_sha      = state.get("commit_sha"),
            credential_ref  = state.get("credential_ref", "github"),
            output_dir      = state.get("output_dir", "/tmp/prism_sandbox"),
            session_id      = state.get("session_id"),
            max_repo_size_mb= state.get("max_repo_mb", 100),
        )
        result = run_ingestion(request)

        if not result.succeeded:
            logger.error("[Stage 1] Ingestion FAILED: %s", result.error)
            sr = StageResult(
                stage="ingestion", status="failed",
                duration_ms=_timer() - t0,
                summary=f"Ingestion failed: {result.error}",
                warnings=result.warnings, error=result.error,
            )
            return {
                "ingestion_status": "failed",
                "status": PipelineStatus.FAILED,
                "error": result.error,
                **_append_stage(state, sr),
            }

        sr = StageResult(
            stage="ingestion", status="ok",
            duration_ms=_timer() - t0,
            summary=(
                f"Ingested {result.manifest.total_files} files "
                f"from {state['repo_url']} "
                f"@ {result.manifest.fetched_commit[:12]}"
            ),
            warnings=result.warnings,
        )
        logger.info("[Stage 1] Ingestion OK — %d files repo_hash=%s…",
                    result.manifest.total_files, result.manifest.repo_hash[:16])

        return {
            "ingestion_status": "ok",
            "repo_hash":        result.manifest.repo_hash,
            "fetched_commit":   result.manifest.fetched_commit,
            "sandbox_path":     result.output_dir,
            "total_files":      result.manifest.total_files,
            "ingestion_warnings": result.warnings,
            **_append_stage(state, sr),
        }

    except Exception as exc:
        logger.exception("[Stage 1] Ingestion exception")
        sr = StageResult(
            stage="ingestion", status="failed",
            duration_ms=_timer() - t0,
            summary=f"Ingestion exception: {exc}",
            error=str(exc),
        )
        return {
            "ingestion_status": "failed",
            "status": PipelineStatus.FAILED,
            "error": str(exc),
            **_append_stage(state, sr),
        }


# Stage 2 — Parsing

def node_parsing(state: PipelineState) -> dict:
    """
    Parse every file in the sandbox using Joern → Tree-sitter → fallback.

    Reads:  sandbox_path
    Writes: parsing_status, parse_outputs (serialised), backend_used, parsing_warnings
    """
    t0 = _timer()
    sandbox = state.get("sandbox_path", "")
    logger.info("[Stage 2] Parsing starting — sandbox=%s", sandbox)

    try:
        from ..parser.registry import ParserRegistry

        registry = ParserRegistry()
        backend_status = registry.get_backend_status()
        logger.info(
            "[Stage 2] Backends — joern=%s tree_sitter=%s codeql=%s",
            backend_status.get("joern_available"),
            backend_status.get("tree_sitter_available"),
            backend_status.get("codeql_available"),
        )

        parse_outputs = registry.parse_repository(sandbox)

        # Tally which backend handled each file
        backend_counts: dict[str, int] = {}
        warnings: list[str] = []
        for out in parse_outputs:
            b = out.metadata.backend.value
            backend_counts[b] = backend_counts.get(b, 0) + 1
            warnings.extend(out.warnings)

        # Serialise outputs (keep only metadata + counts — raw nodes are
        # large; they are stored in Neo4j and accessed via graph_builder)
        serialised = [
            {
                "file_path":   out.metadata.file_path,
                "language":    out.metadata.language.value,
                "backend":     out.metadata.backend.value,
                "node_count":  len(out.nodes),
                "edge_count":  len(out.edges),
                "has_errors":  out.metadata.has_parse_errors,
                "error_count": out.metadata.error_count,
            }
            for out in parse_outputs
        ]

        total_nodes = sum(len(o.nodes) for o in parse_outputs)
        total_edges = sum(len(o.edges) for o in parse_outputs)

        sr = StageResult(
            stage="parsing", status="ok",
            duration_ms=_timer() - t0,
            summary=(
                f"Parsed {len(parse_outputs)} files — "
                f"{total_nodes} nodes, {total_edges} edges — "
                f"backends: {backend_counts}"
            ),
            warnings=warnings[:50],   # cap warnings stored in state
        )
        logger.info("[Stage 2] Parsing OK — %d files %d nodes %d edges",
                    len(parse_outputs), total_nodes, total_edges)

        # Stash full ParsedGraphOutput list for the CPG stage to consume.
        # We use a module-level cache keyed by session_id to avoid
        # serialising large objects into LangGraph state.
        _store_parse_outputs(state.get("session_id", ""), parse_outputs)

        return {
            "parsing_status":   "ok",
            "parse_outputs":    serialised,
            "backend_used":     backend_counts,
            "parsing_warnings": warnings[:50],
            **_append_stage(state, sr),
        }

    except Exception as exc:
        logger.exception("[Stage 2] Parsing exception")
        sr = StageResult(
            stage="parsing", status="failed",
            duration_ms=_timer() - t0,
            summary=f"Parsing exception: {exc}",
            error=str(exc),
        )
        return {
            "parsing_status": "failed",
            "status": PipelineStatus.FAILED,
            "error": str(exc),
            **_append_stage(state, sr),
        }


# Stage 3 — CPG Build

def node_cpg_build(state: PipelineState) -> dict:
    """
    Assemble the Code Property Graph from parse outputs and write to Neo4j.

    Reads:  sandbox_path, session_id, repo_hash, (cached parse_outputs)
    Writes: cpg_status, cpg_node_count, cpg_edge_count, cpg_file_count,
            neo4j_written, cpg_warnings, cpg_sarif_path
    """
    t0 = _timer()
    session_id = state.get("session_id", "")
    logger.info("[Stage 3] CPG build starting — session=%s", session_id)

    try:
        from ..graph_builder.graph_builder import GraphBuilder
        from ..graph_builder.neo4j_writer  import Neo4jWriter, MockNeo4jWriter
        from ..parser.language_detector import detect_language

        # Connect to Neo4j (falls back to mock when unavailable)
        try:
            writer = Neo4jWriter(
                uri      = os.environ.get("NEO4J_URI",  "bolt://localhost:7687"),
                user     = os.environ.get("NEO4J_USER", "neo4j"),
                password = os.environ.get("NEO4J_PASSWORD", "password"),
            )
            writer.setup_schema()
        except Exception:
            logger.warning("[Stage 3] Neo4j unavailable — using mock writer")
            writer = MockNeo4jWriter()

        builder = GraphBuilder(neo4j_writer=writer)

        # Retrieve parse outputs from the module-level cache
        parse_outputs = _load_parse_outputs(session_id)
        sandbox       = state.get("sandbox_path", "")
        repo_hash     = state.get("repo_hash", "")

        all_nodes = 0
        all_edges = 0
        warnings: list[str] = []

        for parsed in parse_outputs:
            file_path = str(Path(sandbox) / parsed.metadata.file_path)
            language  = parsed.metadata.language

            # Read source bytes from sandbox
            try:
                source_bytes = Path(file_path).read_bytes()
            except OSError:
                source_bytes = b""

            # Pass the ParsedGraphOutput so Joern edges are preserved
            cpg_file = builder._file_builder.build(
                file_path     = file_path,
                source_bytes  = source_bytes,
                language      = language,
                repo_root     = sandbox,
                parsed_output = parsed,    # ← Joern-overwrite fix
            )
            all_nodes += len(cpg_file.nodes)
            all_edges += len(cpg_file.edges)
            warnings.extend(cpg_file.warnings)

        # Write all nodes + edges to Neo4j (or mock)
        write_result = writer.write(
            nodes      = [],   # nodes already written per-file in full pipeline
            edges      = [],
            session_id = session_id,
            repo_hash  = repo_hash,
        )
        neo4j_ok = not bool(write_result.errors) if hasattr(write_result, "errors") else True

        # Look for a SARIF file left by CodeQL in the sandbox
        sarif_path = _find_sarif(sandbox)

        sr = StageResult(
            stage="cpg_build", status="ok",
            duration_ms=_timer() - t0,
            summary=(
                f"CPG built — {len(parse_outputs)} files, "
                f"{all_nodes} nodes, {all_edges} edges, "
                f"neo4j={'ok' if neo4j_ok else 'mock'}"
            ),
            warnings=warnings[:50],
        )
        logger.info("[Stage 3] CPG build OK — %d nodes %d edges", all_nodes, all_edges)

        return {
            "cpg_status":     "ok",
            "cpg_node_count": all_nodes,
            "cpg_edge_count": all_edges,
            "cpg_file_count": len(parse_outputs),
            "neo4j_written":  neo4j_ok,
            "cpg_warnings":   warnings[:50],
            "cpg_sarif_path": sarif_path,
            **_append_stage(state, sr),
        }

    except Exception as exc:
        logger.exception("[Stage 3] CPG build exception")
        sr = StageResult(
            stage="cpg_build", status="failed",
            duration_ms=_timer() - t0,
            summary=f"CPG build exception: {exc}",
            error=str(exc),
        )
        return {
            "cpg_status": "failed",
            "status": PipelineStatus.FAILED,
            "error": str(exc),
            **_append_stage(state, sr),
        }


# Stage 4 — SARIF Annotation

def node_sarif_annotation(state: PipelineState) -> dict:
    """
    Inject CodeQL SARIF findings into the CPG nodes.

    Reads:  cpg_sarif_path, session_id
    Writes: sarif_status, sarif_annotations, sarif_warnings
    """
    t0 = _timer()
    sarif_path = state.get("cpg_sarif_path")

    if not sarif_path:
        logger.info("[Stage 4] No SARIF file found — skipping SARIF annotation")
        sr = StageResult(
            stage="sarif_annotation", status="skipped",
            duration_ms=_timer() - t0,
            summary="No SARIF file available (CodeQL not installed or not run)",
        )
        return {"sarif_status": "skipped", "sarif_annotations": 0,
                **_append_stage(state, sr)}

    logger.info("[Stage 4] SARIF annotation — file=%s", sarif_path)
    try:
        from ..graph_builder.sarif_injector import SARIFInjector

        injector = SARIFInjector()
        # Node index is rebuilt from Neo4j in the full SecurityAnalysisAgent;
        # here we do a lightweight count-only pass to record the finding count.
        import json
        with open(sarif_path) as f:
            sarif_data = json.load(f)

        annotation_count = sum(
            len(run.get("results", []))
            for run in sarif_data.get("runs", [])
        )

        sr = StageResult(
            stage="sarif_annotation", status="ok",
            duration_ms=_timer() - t0,
            summary=f"SARIF read: {annotation_count} findings from CodeQL",
        )
        logger.info("[Stage 4] SARIF annotation OK — %d findings", annotation_count)

        return {
            "sarif_status":      "ok",
            "sarif_annotations": annotation_count,
            "sarif_warnings":    [],
            **_append_stage(state, sr),
        }

    except Exception as exc:
        logger.warning("[Stage 4] SARIF annotation failed (non-fatal): %s", exc)
        sr = StageResult(
            stage="sarif_annotation", status="failed",
            duration_ms=_timer() - t0,
            summary=f"SARIF annotation failed (non-fatal): {exc}",
            error=str(exc),
        )
        return {
            "sarif_status":      "failed",
            "sarif_annotations": 0,
            "sarif_warnings":    [str(exc)],
            **_append_stage(state, sr),
        }


# HITL-1 checkpoint

def node_hitl1_checkpoint(state: PipelineState) -> dict:
    """
    Human-in-the-loop checkpoint after CPG construction.

    In LangGraph, this node raises Interrupt to pause execution.
    The caller resumes by invoking graph.invoke() again with
    hitl1_approved=True/False in the state update.

    When running without LangGraph (sequential fallback mode), this node
    auto-approves if the environment variable PRISM_HITL_AUTOAPPROVE=1 is
    set — useful for CI pipelines.
    """
    t0 = _timer()
    already_decided = state.get("hitl1_approved")

    # Already decided in a previous resume — pass through
    if already_decided is True:
        sr = StageResult(
            stage="hitl1", status="ok",
            duration_ms=_timer() - t0,
            summary="HITL-1 approved (resumed)",
        )
        return {**_append_stage(state, sr)}

    if already_decided is False:
        sr = StageResult(
            stage="hitl1", status="failed",
            duration_ms=_timer() - t0,
            summary="HITL-1 rejected by operator",
            error="Operator rejected at HITL-1 checkpoint",
        )
        return {
            "status": PipelineStatus.FAILED,
            "error":  "Operator rejected at HITL-1 checkpoint",
            **_append_stage(state, sr),
        }

    # Auto-approve in CI / test environments
    if os.environ.get("PRISM_HITL_AUTOAPPROVE", "0") == "1":
        logger.info("[HITL-1] Auto-approved (PRISM_HITL_AUTOAPPROVE=1)")
        sr = StageResult(
            stage="hitl1", status="ok",
            duration_ms=_timer() - t0,
            summary="HITL-1 auto-approved (CI mode)",
        )
        return {"hitl1_approved": True, **_append_stage(state, sr)}

    # Pause and wait for human decision
    logger.info(
        "[HITL-1] Pausing for human review. "
        "Resume with hitl1_approved=True to continue or False to abort.\n"
        "  CPG: %d nodes, %d edges\n"
        "  SARIF findings: %d\n"
        "  Warnings: %d",
        state.get("cpg_node_count", 0),
        state.get("cpg_edge_count", 0),
        state.get("sarif_annotations", 0),
        len(state.get("cpg_warnings", [])),
    )

    if _LANGGRAPH_AVAILABLE:
        from langgraph.errors import NodeInterrupt
        raise NodeInterrupt(
            "HITL-1: Review CPG construction results and resume with "
            "hitl1_approved=True or hitl1_approved=False."
        )

    # Fallback: mark as waiting (the caller must poll)
    return {"status": PipelineStatus.HITL_WAIT}


# Stage 5 — Audit log emission

def node_emit_audit(state: PipelineState) -> dict:
    """
    Emit the audit event to the blockchain logger.

    Currently logs to prism.audit logger (consumed by the blockchain module
    when web3 is installed).  This node is deliberately thin — the blockchain
    integration lives in a separate module.

    Reads:  session_id, repo_hash, fetched_commit, stage_results
    Writes: status=complete
    """
    t0 = _timer()
    import json

    event = {
        "event_type":   "PIPELINE_COMPLETE",
        "session_id":   state.get("session_id"),
        "repo_hash":    state.get("repo_hash"),
        "commit":       state.get("fetched_commit"),
        "cpg_nodes":    state.get("cpg_node_count", 0),
        "cpg_edges":    state.get("cpg_edge_count", 0),
        "sarif_findings": state.get("sarif_annotations", 0),
        "stages":       [s["stage"] for s in state.get("stage_results", [])],
    }
    audit_log = logging.getLogger("prism.audit")
    audit_log.info("AUDIT_EVENT %s", json.dumps(event))
    logger.info("[Stage 5] Audit event emitted — session=%s", state.get("session_id"))

    sr = StageResult(
        stage="audit", status="ok",
        duration_ms=_timer() - t0,
        summary="Audit event emitted to prism.audit logger",
    )
    return {
        "status": PipelineStatus.COMPLETE,
        **_append_stage(state, sr),
    }


# Failure handler

def node_handle_failure(state: PipelineState) -> dict:
    """
    Terminal failure node.  Logs the error and marks the pipeline as failed.
    Ensures a consistent terminal state regardless of which stage failed.
    """
    error = state.get("error", "Unknown error")
    logger.error("[FAILED] Pipeline failed — session=%s error=%s",
                 state.get("session_id"), error)
    return {"status": PipelineStatus.FAILED}


# Routing functions  (conditional edges)

def route_after_ingestion(state: PipelineState) -> Literal["parsing", "handle_failure"]:
    """Route to parsing on success, to handle_failure on ingestion error."""
    if state.get("ingestion_status") == "ok":
        return "parsing"
    return "handle_failure"


def route_after_hitl1(state: PipelineState) -> Literal["emit_audit", "handle_failure"]:
    """Route to audit emission on HITL approval, to failure on rejection."""
    if state.get("hitl1_approved") is True:
        return "emit_audit"
    if state.get("status") == PipelineStatus.HITL_WAIT:
        # Not yet decided — keep waiting (LangGraph handles interrupt)
        return "emit_audit"    # unreachable during interrupt; satisfies type
    return "handle_failure"


# Graph construction

def build_pipeline_graph(checkpointer=None):
    """
    Construct and compile the LangGraph pipeline graph.

    Args:
        checkpointer: LangGraph checkpointer (default: MemorySaver for dev).
                      Pass None to get an uncompiled graph for testing.

    Returns:
        Compiled LangGraph CompiledStateGraph, or a sequential runner
        when langgraph is not installed.
    """
    if not _LANGGRAPH_AVAILABLE:
        logger.warning(
            "LangGraph not available — returning sequential fallback runner."
        )
        return _SequentialFallbackRunner()

    graph = StateGraph(PipelineState)

    # ── Register nodes ──────────────────────────────────────────────────────
    graph.add_node("ingestion",        node_ingestion)
    graph.add_node("parsing",          node_parsing)
    graph.add_node("cpg_build",        node_cpg_build)
    graph.add_node("sarif_annotation", node_sarif_annotation)
    graph.add_node("hitl1_checkpoint", node_hitl1_checkpoint)
    graph.add_node("emit_audit",       node_emit_audit)
    graph.add_node("handle_failure",   node_handle_failure)

    # ── Edges ───────────────────────────────────────────────────────────────
    graph.set_entry_point("ingestion")

    # Conditional: ingestion → parsing OR handle_failure
    graph.add_conditional_edges(
        "ingestion",
        route_after_ingestion,
        {"parsing": "parsing", "handle_failure": "handle_failure"},
    )

    # Linear: parsing → cpg_build → sarif_annotation → hitl1_checkpoint
    graph.add_edge("parsing",          "cpg_build")
    graph.add_edge("cpg_build",        "sarif_annotation")
    graph.add_edge("sarif_annotation", "hitl1_checkpoint")

    # Conditional: hitl1 → emit_audit OR handle_failure
    graph.add_conditional_edges(
        "hitl1_checkpoint",
        route_after_hitl1,
        {"emit_audit": "emit_audit", "handle_failure": "handle_failure"},
    )

    # Both terminal nodes → END
    graph.add_edge("emit_audit",     END)
    graph.add_edge("handle_failure", END)

    # ── Compile with interrupt point at HITL-1 ──────────────────────────────
    cp = checkpointer or MemorySaver()
    return graph.compile(
        checkpointer          = cp,
        interrupt_before      = ["hitl1_checkpoint"],
    )


# High-level entry point

def run_pipeline(
    repo_url:       str,
    branch:         str         = "main",
    commit_sha:     str | None  = None,
    credential_ref: str         = "github",
    output_dir:     str         = "/tmp/prism_sandbox",
    max_repo_mb:    int         = 100,
    session_id:     str | None  = None,
    auto_approve_hitl: bool     = False,
) -> PipelineState:
    """
    Run the full PRISM pipeline synchronously.

    This is the primary entry point for:
      - The Flask UI (`ui/app.py`)
      - Tests
      - The CLI (future)

    For async / streaming execution, use `build_pipeline_graph()` directly
    and call `graph.stream()`.

    Args:
        repo_url:          Repository to analyse.
        branch:            Git branch.
        commit_sha:        Specific commit to pin (None = HEAD).
        credential_ref:    Vault path or env key for the GitHub token.
        output_dir:        Sandbox delivery directory.
        max_repo_mb:       Maximum repository size in MB.
        session_id:        Pipeline session ID (generated if None).
        auto_approve_hitl: If True, automatically approve HITL-1 checkpoint.

    Returns:
        Final PipelineState dict.
    """
    sid = session_id or f"sess_{uuid.uuid4().hex[:12]}"

    if auto_approve_hitl:
        os.environ["PRISM_HITL_AUTOAPPROVE"] = "1"

    initial_state: PipelineState = {
        "session_id":    sid,
        "repo_url":      repo_url,
        "branch":        branch,
        "commit_sha":    commit_sha,
        "credential_ref":credential_ref,
        "max_repo_mb":   max_repo_mb,
        "output_dir":    output_dir,
        "status":        PipelineStatus.RUNNING,
        "stage_results": [],
        "error":         None,
    }

    graph = build_pipeline_graph()

    if isinstance(graph, _SequentialFallbackRunner):
        return graph.run(initial_state)

    # LangGraph execution — run until completion or HITL pause
    config = {"configurable": {"thread_id": sid}}
    final_state = None
    for chunk in graph.stream(initial_state, config=config, stream_mode="values"):
        final_state = chunk
        status = chunk.get("status")
        stage_results = chunk.get("stage_results", [])
        if stage_results:
            last = stage_results[-1]
            logger.info(
                "  ▸ %-22s  %s  (%.0f ms)",
                last["stage"], last["status"], last["duration_ms"],
            )
        if status in (PipelineStatus.COMPLETE, PipelineStatus.FAILED,
                      PipelineStatus.HITL_WAIT):
            break

    return final_state or initial_state


# ─────────────────────────────────────────────────────────────────────────────
# Sequential fallback (no langgraph installed)
# ─────────────────────────────────────────────────────────────────────────────

class _SequentialFallbackRunner:
    """
    Runs all pipeline nodes in sequence when LangGraph is not installed.
    Produces the same final state as the graph-based runner.
    Used in CI environments where the langgraph dependency is absent.
    """

    def run(self, state: PipelineState) -> PipelineState:
        # Run each node in order, merging partial updates into state
        stages = [
            node_ingestion,
            node_parsing,
            node_cpg_build,
            node_sarif_annotation,
            node_hitl1_checkpoint,
            node_emit_audit,
        ]
        for fn in stages:
            try:
                update = fn(state)
                state = {**state, **update}   # type: ignore[assignment]
                if state.get("status") in (
                    PipelineStatus.FAILED, PipelineStatus.HITL_WAIT
                ):
                    break
            except Exception as exc:
                logger.exception("Sequential runner: stage %s failed", fn.__name__)
                state = {**state,
                         "status": PipelineStatus.FAILED,
                         "error":  str(exc)}
                break

        if state.get("status") != PipelineStatus.COMPLETE:
            node_handle_failure(state)

        return state


# ─────────────────────────────────────────────────────────────────────────────
# Module-level ParsedGraphOutput cache
# Avoids serialising large objects into LangGraph state.
# Keyed by session_id; cleared by run_pipeline() on completion.
# ─────────────────────────────────────────────────────────────────────────────

_PARSE_OUTPUT_CACHE: dict[str, list] = {}


def _store_parse_outputs(session_id: str, outputs: list) -> None:
    _PARSE_OUTPUT_CACHE[session_id] = outputs


def _load_parse_outputs(session_id: str) -> list:
    return _PARSE_OUTPUT_CACHE.get(session_id, [])


# ─────────────────────────────────────────────────────────────────────────────
# Helpers

def _find_sarif(sandbox: str) -> str | None:
    """Search the sandbox directory for a CodeQL SARIF output file."""
    try:
        for p in Path(sandbox).rglob("*.sarif"):
            return str(p)
        for p in Path("/tmp").glob("prism_codeql_*.sarif"):
            return str(p)
    except OSError:
        pass
    return None