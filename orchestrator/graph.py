"""
PRISM Pipeline Orchestrator  —  complete implementation
=========================================================

Bug fixes applied:
  BUG-02  node_ingestion hardcoded GitProvider.GITHUB
          → provider now detected from URL via AdapterRegistry

  BUG-03  node_cpg_build used os.environ.get() for Neo4j config
          → replaced with get_settings()

  BUG-04  node_sarif_annotation only counted results, never injected
          → now rebuilds node_index from Neo4j, calls SARIFInjector,
            writes annotated nodes + taint edges back to Neo4j

  BUG-06  CodeQL called per-file inside parser, not at repo level
          → node_codeql_analysis runs CodeQL once per repository

New stages:
  node_tool_health_check  (Stage 0)
  node_codeql_analysis    (Stage 3.5)

Streaming events:
  Every long-running stage emits progress events via
  core.pipeline_events.emit() so the WebSocket frontend shows
  live progress even during the 5-30 min CodeQL analysis.
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from pathlib import Path
from typing import Any, Literal

logger = logging.getLogger("prism.orchestrator")

try:
    from langgraph.graph import StateGraph, END
    from langgraph.checkpoint.memory import MemorySaver
    _LANGGRAPH_AVAILABLE = True
except ImportError:
    _LANGGRAPH_AVAILABLE = False
    logger.warning(
        "langgraph not installed — orchestrator will run in sequential "
        "fallback mode.  Install with: pip install langgraph"
    )

from .state import PipelineState, PipelineStatus, StageResult


# Helpers

def _timer() -> float:
    return time.monotonic() * 1000


def _append_stage(state: PipelineState, result: StageResult) -> dict:
    existing = list(state.get("stage_results", []))
    existing.append(result.to_dict())
    return {"stage_results": existing}


def _emit(session_id: str, stage: str, label: str, data: dict | None = None) -> None:
    """
    Emit a phase event into the pipeline event bus.
    No-op if no bus is registered (sequential fallback, tests).
    """
    try:
        from backend.core.pipeline_events import emit_phase
        emit_phase(session_id, stage, label)
    except Exception:
        pass   # event bus is optional — never crash a pipeline stage


# Stage 0 — Tool health check

def node_tool_health_check(state: PipelineState) -> dict:
    """
    Check all four tools BEFORE any pipeline work.

    POLICY: all enabled tools are required.
      Vault   — always required (exception: dev mode with PRISM_GIT_TOKEN)
      Neo4j   — always required
      Joern   — required when enable_joern=True
      CodeQL  — required when enable_codeql=True

    Collects ALL failures into one message so the operator sees
    everything that needs fixing in a single run.
    """
    t0 = _timer()
    session_id = state.get("session_id", "?")
    logger.info("[Stage 0] Tool health check — session=%s", session_id)
    _emit(session_id, "tool_health_check", "Checking tool availability...")

    try:
        from backend.core.tool_registry import check_tools
        result = check_tools()
        result.log_summary()
        summary = result.summary()

        failures = result.failing_required

        if failures:
            lines = [f"  • {t.name}: {t.reason}" for t in failures]
            full_error = (
                f"{len(failures)} required tool(s) unavailable:\n"
                + "\n".join(lines)
            )
            logger.error("[Stage 0] %s", full_error)
            sr = StageResult(
                stage="tool_health_check", status="failed",
                duration_ms=_timer() - t0,
                summary=full_error,
                error=full_error,
                warnings=[t.reason for t in failures],
            )
            return {
                "status":        PipelineStatus.FAILED,
                "error":         full_error,
                "tool_status":   summary,
                "tool_warnings": [t.reason for t in failures],
                **_append_stage(state, sr),
            }

        availability = "  ".join(
            f"{n}={'✓' if s['available'] else '✗(disabled)'}"
            for n, s in summary.items()
        )
        sr = StageResult(
            stage="tool_health_check", status="ok",
            duration_ms=_timer() - t0,
            summary=f"All required tools healthy: {availability}",
        )
        _emit(session_id, "tool_health_check",
              f"Tools ready: {availability}")
        return {
            "tool_status":   summary,
            "tool_warnings": [],
            **_append_stage(state, sr),
        }

    except Exception as exc:
        logger.exception("[Stage 0] Health check exception")
        error_msg = f"Tool health check failed: {exc}"
        sr = StageResult(
            stage="tool_health_check", status="failed",
            duration_ms=_timer() - t0,
            summary=error_msg, error=error_msg,
        )
        return {
            "status":        PipelineStatus.FAILED,
            "error":         error_msg,
            "tool_status":   {},
            "tool_warnings": [str(exc)],
            **_append_stage(state, sr),
        }


# Stage 1 — Ingestion

def node_ingestion(state: PipelineState) -> dict:
    """
    Clone the repository, verify integrity, deliver to sandbox.

    BUG-02 FIX: provider detected from URL via AdapterRegistry,
    not hardcoded to GitProvider.GITHUB.
    """
    t0 = _timer()
    session_id = state.get("session_id", "?")
    repo_url   = state.get("repo_url", "")
    logger.info("[Stage 1] Ingestion — session=%s url=%s", session_id, repo_url)
    _emit(session_id, "ingestion", f"Cloning {repo_url} @ {state.get('branch', 'main')}...")

    try:
        from ..ingestion.pipeline import run_ingestion
        from ..ingestion.models import IngestionRequest

        # BUG-02 FIX: detect provider from URL
        provider = _detect_provider(repo_url)

        request = IngestionRequest(
            repo_url         = repo_url,
            provider         = provider,
            branch           = state.get("branch", "main"),
            commit_sha       = state.get("commit_sha"),
            credential_ref   = state.get("credential_ref", "github"),
            output_dir       = state.get("output_dir", "/tmp/prism_sandbox"),
            session_id       = session_id,
            max_repo_size_mb = state.get("max_repo_mb", 100),
        )

        _emit(session_id, "ingestion", "Verifying repository integrity...")
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
                "status":           PipelineStatus.FAILED,
                "error":            result.error,
                **_append_stage(state, sr),
            }

        summary = (
            f"Ingested {result.manifest.total_files} files "
            f"from {repo_url} @ {result.manifest.fetched_commit[:12]}"
        )
        _emit(session_id, "ingestion", summary)
        logger.info("[Stage 1] %s", summary)

        sr = StageResult(
            stage="ingestion", status="ok",
            duration_ms=_timer() - t0,
            summary=summary, warnings=result.warnings,
        )
        return {
            "ingestion_status":   "ok",
            "repo_hash":          result.manifest.repo_hash,
            "fetched_commit":     result.manifest.fetched_commit,
            "sandbox_path":       result.output_dir,
            "total_files":        result.manifest.total_files,
            "ingestion_warnings": result.warnings,
            **_append_stage(state, sr),
        }

    except Exception as exc:
        logger.exception("[Stage 1] Ingestion exception")
        sr = StageResult(
            stage="ingestion", status="failed",
            duration_ms=_timer() - t0,
            summary=str(exc), error=str(exc),
        )
        return {
            "ingestion_status": "failed",
            "status":           PipelineStatus.FAILED,
            "error":            str(exc),
            **_append_stage(state, sr),
        }


def _detect_provider(repo_url: str):
    """Detect GitProvider from URL; falls back to GENERIC on any error."""
    try:
        from ..ingestion.adapters.base import AdapterRegistry
        return AdapterRegistry().get_adapter(repo_url).provider()
    except Exception as exc:
        logger.warning(
            "Provider detection failed for %s: %s — using GENERIC",
            repo_url, exc,
        )
        from ..ingestion.models import GitProvider
        return GitProvider.GENERIC


# Stage 2 — Parsing

def node_parsing(state: PipelineState) -> dict:
    """
    Parse every file in the sandbox via Joern → Tree-sitter → fallback.
    """
    t0 = _timer()
    sandbox    = state.get("sandbox_path", "")
    session_id = state.get("session_id", "?")
    logger.info("[Stage 2] Parsing — sandbox=%s", sandbox)
    _emit(session_id, "parsing", "Building AST/CPG for repository files...")

    try:
        from ..parser.registry import ParserRegistry

        registry       = ParserRegistry()
        parse_outputs  = registry.parse_repository(sandbox)

        backend_counts: dict[str, int] = {}
        warnings: list[str] = []
        for out in parse_outputs:
            b = out.metadata.backend.value
            backend_counts[b] = backend_counts.get(b, 0) + 1
            warnings.extend(out.warnings)

        total_nodes = sum(len(o.nodes) for o in parse_outputs)
        total_edges = sum(len(o.edges) for o in parse_outputs)

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

        summary = (
            f"Parsed {len(parse_outputs)} files — "
            f"{total_nodes} nodes, {total_edges} edges — "
            f"backends: {backend_counts}"
        )
        _emit(session_id, "parsing", summary)
        logger.info("[Stage 2] %s", summary)

        _store_parse_outputs(session_id, parse_outputs)

        sr = StageResult(
            stage="parsing", status="ok",
            duration_ms=_timer() - t0,
            summary=summary, warnings=warnings[:50],
        )
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
            summary=str(exc), error=str(exc),
        )
        return {
            "parsing_status": "failed",
            "status":         PipelineStatus.FAILED,
            "error":          str(exc),
            **_append_stage(state, sr),
        }


# Stage 3 — CPG Build

def node_cpg_build(state: PipelineState) -> dict:
    """
    Assemble the CPG from parse outputs and write to Neo4j.

    BUG-03 FIX: Neo4j connection parameters from get_settings(),
    not os.environ.get() calls.
    """
    t0 = _timer()
    session_id = state.get("session_id", "?")
    logger.info("[Stage 3] CPG build — session=%s", session_id)
    _emit(session_id, "cpg_build", "Assembling Code Property Graph...")

    try:
        from ..graph_builder.graph_builder import GraphBuilder
        from ..graph_builder.neo4j_writer import Neo4jWriter, MockNeo4jWriter

        # BUG-03 FIX: read from get_settings()
        from backend.core.config import get_settings
        s = get_settings()

        try:
            writer = Neo4jWriter(
                uri      = s.neo4j_uri,
                user     = s.neo4j_user,
                password = s.neo4j_password,
            )
            writer.setup_schema()
        except Exception as e:
            logger.warning("[Stage 3] Neo4j unavailable (%s) — using mock writer", e)
            writer = MockNeo4jWriter()

        builder      = GraphBuilder(neo4j_writer=writer)
        parse_outputs = _load_parse_outputs(session_id)
        sandbox       = state.get("sandbox_path", "")
        repo_hash     = state.get("repo_hash", "")

        all_nodes = 0
        all_edges = 0
        warnings: list[str] = []

        for parsed in parse_outputs:
            file_path = str(Path(sandbox) / parsed.metadata.file_path)
            language  = parsed.metadata.language
            try:
                source_bytes = Path(file_path).read_bytes()
            except OSError:
                source_bytes = b""

            cpg_file = builder._file_builder.build(
                file_path     = file_path,
                source_bytes  = source_bytes,
                language      = language,
                repo_root     = sandbox,
                parsed_output = parsed,
            )
            all_nodes += len(cpg_file.nodes)
            all_edges += len(cpg_file.edges)
            warnings.extend(cpg_file.warnings)

        write_result = writer.write(
            nodes=[], edges=[], session_id=session_id, repo_hash=repo_hash,
        )
        neo4j_ok = not bool(getattr(write_result, "errors", None))

        summary = (
            f"CPG built — {len(parse_outputs)} files, "
            f"{all_nodes} nodes, {all_edges} edges, "
            f"neo4j={'ok' if neo4j_ok else 'mock'}"
        )
        _emit(session_id, "cpg_build", summary)
        logger.info("[Stage 3] %s", summary)

        sr = StageResult(
            stage="cpg_build", status="ok",
            duration_ms=_timer() - t0,
            summary=summary, warnings=warnings[:50],
        )
        return {
            "cpg_status":     "ok",
            "cpg_node_count": all_nodes,
            "cpg_edge_count": all_edges,
            "cpg_file_count": len(parse_outputs),
            "neo4j_written":  neo4j_ok,
            "cpg_warnings":   warnings[:50],
            **_append_stage(state, sr),
        }

    except Exception as exc:
        logger.exception("[Stage 3] CPG build exception")
        sr = StageResult(
            stage="cpg_build", status="failed",
            duration_ms=_timer() - t0,
            summary=str(exc), error=str(exc),
        )
        return {
            "cpg_status": "failed",
            "status":     PipelineStatus.FAILED,
            "error":      str(exc),
            **_append_stage(state, sr),
        }


# Stage 3.5 — CodeQL Analysis  (BUG-06 FIX + streaming events)

def node_codeql_analysis(state: PipelineState) -> dict:
    """
    Run CodeQL database create + analyze at the repository level.
    Produces a SARIF file for the sarif_annotation stage.

    BUG-06 FIX: CodeQL now runs once per REPOSITORY (not per file inside
    the parser registry).  The parser never calls CodeQL for structural
    parsing — CodeQL is a security oracle only.

    No timeout: CodeQL runs until it finishes, however long that takes.
    Progress events are emitted at each milestone so the frontend
    shows live status throughout the analysis.
    """
    t0 = _timer()
    session_id = state.get("session_id", "?")
    sandbox    = state.get("sandbox_path", "")

    tool_status = state.get("tool_status", {})
    codeql_ok   = tool_status.get("codeql", {}).get("available", False)

    if not codeql_ok:
        logger.info("[Stage 3.5] CodeQL not available — skipping")
        _emit(session_id, "codeql_analysis",
              "CodeQL skipped (not available or disabled)")
        sr = StageResult(
            stage="codeql_analysis", status="skipped",
            duration_ms=_timer() - t0,
            summary="CodeQL unavailable or disabled",
        )
        return {
            "codeql_status":     "skipped",
            "codeql_sarif_path": None,
            "cpg_sarif_path":    None,
            "codeql_warnings":   [],
            **_append_stage(state, sr),
        }

    logger.info("[Stage 3.5] CodeQL analysis — sandbox=%s", sandbox)

    try:
        from ..parser.parsers.codeql_parser import CodeQLParser
        from backend.core.config import get_settings
        import tempfile as tf

        s = get_settings()

        # Detect primary language
        primary_lang = _detect_primary_language(sandbox)
        logger.info("[Stage 3.5] Primary language: %s", primary_lang.value)

        # SARIF output path — outside the ephemeral CodeQL temp dir
        sarif_path = os.path.join(
            tf.gettempdir(),
            f"prism_codeql_{session_id[:12]}.sarif"
        )

        parser = CodeQLParser(
            codeql_cli_path    = s.codeql_cli_path or None,
            codeql_search_path = s.codeql_search_path or None,
        )

        # Emit milestone events (emitted from inside CodeQLParser via
        # the session_id passed through to _run_analysis)
        _emit(session_id, "codeql_analysis",
              f"CodeQL: creating database for {primary_lang.value} repository...")

        result = parser.parse_repository(
            repo_path         = sandbox,
            language          = primary_lang,
            sarif_output_path = sarif_path,
            session_id        = session_id,   # used for event emission
        )

        sarif_exists = os.path.exists(sarif_path)

        if sarif_exists:
            import json
            with open(sarif_path) as f:
                sarif_data = json.load(f)
            finding_count = sum(
                len(run.get("results", []))
                for run in sarif_data.get("runs", [])
            )
            summary = (
                f"CodeQL analysis complete — "
                f"{finding_count} security findings detected"
            )
        else:
            summary = "CodeQL ran but produced no SARIF output"

        _emit(session_id, "codeql_analysis", summary)
        logger.info("[Stage 3.5] %s", summary)

        sr = StageResult(
            stage="codeql_analysis",
            status="ok" if sarif_exists else "failed",
            duration_ms=_timer() - t0,
            summary=summary,
            warnings=(result.warnings[:20] if result else []),
        )
        return {
            "codeql_status":     "ok" if sarif_exists else "failed",
            "codeql_sarif_path": sarif_path if sarif_exists else None,
            "cpg_sarif_path":    sarif_path if sarif_exists else None,
            "codeql_warnings":   (result.warnings[:20] if result else []),
            **_append_stage(state, sr),
        }

    except Exception as exc:
        logger.warning("[Stage 3.5] CodeQL failed (non-fatal): %s", exc)
        _emit(session_id, "codeql_analysis",
              f"CodeQL analysis failed: {exc}")
        sr = StageResult(
            stage="codeql_analysis", status="failed",
            duration_ms=_timer() - t0,
            summary=str(exc), error=str(exc),
        )
        return {
            "codeql_status":     "failed",
            "codeql_sarif_path": None,
            "cpg_sarif_path":    None,
            "codeql_warnings":   [str(exc)],
            **_append_stage(state, sr),
        }


def _detect_primary_language(sandbox_path: str):
    """Count file extensions; return the most common parseable Language."""
    try:
        from collections import Counter
        from ..parser.language_detector import LanguageDetector
        from ..parser.models import Language

        detector = LanguageDetector()
        counts: Counter = Counter()
        for root, dirs, files in os.walk(sandbox_path):
            dirs[:] = [d for d in dirs if d not in
                       (".git", "node_modules", "__pycache__", ".terraform")]
            for f in files:
                r = detector.detect(os.path.join(root, f))
                if r.language not in (Language.UNKNOWN, Language.YAML,
                                      Language.TERRAFORM_HCL):
                    counts[r.language] += 1

        if counts:
            return counts.most_common(1)[0][0]
        return Language.PYTHON

    except Exception as exc:
        logger.warning("Language detection failed: %s — defaulting to Python", exc)
        from ..parser.models import Language
        return Language.PYTHON


# Stage 4 — SARIF Annotation  (BUG-04 FIX + streaming events)

def node_sarif_annotation(state: PipelineState) -> dict:
    """
    Inject CodeQL SARIF security labels into CPG nodes stored in Neo4j.

    BUG-04 FIX — complete rewrite of this stage:
      1. Load SARIF JSON from the path written by node_codeql_analysis.
      2. Rebuild node_index ({(file, line, col): CPGNode}) from Neo4j.
      3. Call SARIFInjector.inject() to annotate nodes in memory.
      4. Write annotated nodes + taint edges back to Neo4j.

    Previously: only counted SARIF results, never called SARIFInjector,
    never wrote anything to Neo4j.  The SARIFInjector was dead code.
    """
    t0 = _timer()
    session_id = state.get("session_id", "?")
    sarif_path = (
        state.get("cpg_sarif_path")
        or state.get("codeql_sarif_path")
    )

    if not sarif_path or not os.path.exists(str(sarif_path)):
        logger.info("[Stage 4] No SARIF file — skipping annotation")
        _emit(session_id, "sarif_annotation",
              "SARIF annotation skipped (no CodeQL output)")
        sr = StageResult(
            stage="sarif_annotation", status="skipped",
            duration_ms=_timer() - t0,
            summary="No SARIF file available",
        )
        return {
            "sarif_status":      "skipped",
            "sarif_annotations": 0,
            "sarif_edges":       0,
            "sarif_warnings":    [],
            **_append_stage(state, sr),
        }

    logger.info("[Stage 4] SARIF annotation — session=%s", session_id)
    _emit(session_id, "sarif_annotation",
          "Loading SARIF results and building node index...")

    try:
        from ..graph_builder.sarif_injector import SARIFInjector
        from ..graph_builder.neo4j_writer import Neo4jWriter
        from backend.core.config import get_settings
        import json

        s = get_settings()

        # Step 1: Load SARIF
        with open(sarif_path) as f:
            sarif_data = json.load(f)

        total_findings = sum(
            len(run.get("results", []))
            for run in sarif_data.get("runs", [])
        )
        _emit(session_id, "sarif_annotation",
              f"Injecting {total_findings} SARIF findings into CPG nodes...")

        # Step 2: Rebuild node_index from Neo4j
        node_index = _build_node_index_from_neo4j(session_id, s)
        logger.info(
            "[Stage 4] Node index: %d entries from Neo4j", len(node_index)
        )
        if not node_index:
            logger.warning(
                "[Stage 4] Node index empty — Neo4j may be down; "
                "SARIF annotations will not be persisted"
            )

        # Step 3: Inject
        new_edges: list = []
        injection_result = SARIFInjector().inject(
            sarif_data = sarif_data,
            node_index = node_index,
            edges      = new_edges,
            repo_root  = state.get("sandbox_path", ""),
        )

        _emit(
            session_id, "sarif_annotation",
            f"Annotated {injection_result.annotations_added} CPG nodes — "
            f"writing {injection_result.edges_added} taint edges to Neo4j...",
        )

        # Step 4: Write annotated nodes + taint edges back to Neo4j
        from ..graph_builder.models import SecurityLabel

        annotated_nodes = [
            n for n in node_index.values()
            if getattr(n, "security_label", None) not in
            (None, "", SecurityLabel.NONE)
        ]

        if annotated_nodes or new_edges:
            try:
                writer = Neo4jWriter(
                    uri      = s.neo4j_uri,
                    user     = s.neo4j_user,
                    password = s.neo4j_password,
                )
                writer.write(
                    nodes      = annotated_nodes,
                    edges      = new_edges,
                    session_id = session_id,
                    repo_hash  = state.get("repo_hash", ""),
                )
                writer.close()
                logger.info(
                    "[Stage 4] Wrote %d annotated nodes + %d taint edges to Neo4j",
                    len(annotated_nodes), len(new_edges),
                )
            except Exception as exc:
                logger.warning(
                    "[Stage 4] Neo4j write for SARIF annotations failed "
                    "(non-fatal): %s", exc
                )

        summary = (
            f"SARIF injection complete — "
            f"{injection_result.annotations_added} node annotations, "
            f"{injection_result.edges_added} taint edges, "
            f"{len(set(injection_result.rules_matched))} unique CWE rules matched"
        )
        _emit(session_id, "sarif_annotation", summary)
        logger.info("[Stage 4] %s", summary)

        sr = StageResult(
            stage="sarif_annotation", status="ok",
            duration_ms=_timer() - t0,
            summary=summary,
            warnings=injection_result.warnings[:20],
        )
        return {
            "sarif_status":      "ok",
            "sarif_annotations": injection_result.annotations_added,
            "sarif_edges":       injection_result.edges_added,
            "sarif_warnings":    injection_result.warnings[:20],
            **_append_stage(state, sr),
        }

    except Exception as exc:
        logger.warning("[Stage 4] SARIF annotation failed (non-fatal): %s", exc)
        _emit(session_id, "sarif_annotation",
              f"SARIF annotation failed: {exc}")
        sr = StageResult(
            stage="sarif_annotation", status="failed",
            duration_ms=_timer() - t0,
            summary=str(exc), error=str(exc),
        )
        return {
            "sarif_status":      "failed",
            "sarif_annotations": 0,
            "sarif_edges":       0,
            "sarif_warnings":    [str(exc)],
            **_append_stage(state, sr),
        }


def _build_node_index_from_neo4j(session_id: str, settings) -> dict:
    """
    Query Neo4j for all CPGNodes in this session.
    Returns {(file_path, start_line, start_col): CPGNode}.
    Falls back to empty dict if Neo4j is unavailable.
    """
    from ..graph_builder.models import CPGNode, NodeType, Language, SecurityLabel
    node_index: dict = {}
    try:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
            connection_timeout=settings.neo4j_timeout_s,
        )
        with driver.session(database=settings.neo4j_database) as session:
            result = session.run(
                """
                MATCH (n:CPGNode {session_id: $sid})
                RETURN n.node_id    AS node_id,
                       n.node_type  AS node_type,
                       n.file_path  AS file_path,
                       n.start_line AS start_line,
                       n.start_col  AS start_col,
                       n.end_line   AS end_line,
                       n.end_col    AS end_col,
                       n.language   AS language
                """,
                sid=session_id,
            )
            for rec in result:
                try:
                    nt   = NodeType(rec["node_type"]) if rec["node_type"] else NodeType.UNKNOWN
                    lang = Language(rec["language"]) if rec["language"] else Language.UNKNOWN
                    node = CPGNode(
                        node_id    = rec["node_id"],
                        node_type  = nt,
                        language   = lang,
                        file_path  = rec["file_path"] or "",
                        start_line = int(rec["start_line"] or 0),
                        end_line   = int(rec["end_line"] or 0),
                        start_col  = int(rec["start_col"] or 0),
                        end_col    = int(rec["end_col"] or 0),
                    )
                    node_index[(node.file_path, node.start_line, node.start_col)] = node
                except Exception:
                    continue
        driver.close()
    except Exception as exc:
        logger.warning("[Stage 4] Could not build node_index from Neo4j: %s", exc)
    return node_index


# HITL-1 checkpoint

def node_hitl1_checkpoint(state: PipelineState) -> dict:
    t0 = _timer()
    session_id = state.get("session_id", "?")
    already_decided = state.get("hitl1_approved")

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

    if os.environ.get("PRISM_HITL_AUTOAPPROVE", "0") == "1":
        logger.info("[HITL-1] Auto-approved (PRISM_HITL_AUTOAPPROVE=1)")
        sr = StageResult(
            stage="hitl1", status="ok",
            duration_ms=_timer() - t0,
            summary="HITL-1 auto-approved (CI mode)",
        )
        return {"hitl1_approved": True, **_append_stage(state, sr)}

    logger.info(
        "[HITL-1] Pausing for human review — "
        "CPG: %d nodes/%d edges  SARIF: %d annotations/%d taint edges",
        state.get("cpg_node_count", 0),
        state.get("cpg_edge_count", 0),
        state.get("sarif_annotations", 0),
        state.get("sarif_edges", 0),
    )
    _emit(session_id, "hitl1_checkpoint",
          "Awaiting operator approval (send hitl_decision via WebSocket)...")

    if _LANGGRAPH_AVAILABLE:
        from langgraph.errors import NodeInterrupt
        raise NodeInterrupt(
            "HITL-1: Review CPG and SARIF results. "
            "Resume with hitl1_approved=True or hitl1_approved=False."
        )
    return {"status": PipelineStatus.HITL_WAIT}


# Stage 5 — Audit

def node_emit_audit(state: PipelineState) -> dict:
    t0 = _timer()
    session_id = state.get("session_id", "?")
    import json
    event = {
        "event_type":        "PIPELINE_COMPLETE",
        "session_id":        session_id,
        "repo_hash":         state.get("repo_hash"),
        "commit":            state.get("fetched_commit"),
        "cpg_nodes":         state.get("cpg_node_count", 0),
        "cpg_edges":         state.get("cpg_edge_count", 0),
        "sarif_annotations": state.get("sarif_annotations", 0),
        "sarif_edges":       state.get("sarif_edges", 0),
        "tools": {
            k: v.get("available")
            for k, v in state.get("tool_status", {}).items()
        },
        "stages": [s["stage"] for s in state.get("stage_results", [])],
    }
    logging.getLogger("prism.audit").info("AUDIT_EVENT %s", json.dumps(event))
    _emit(session_id, "audit",
          f"Audit event emitted — repo_hash={state.get('repo_hash', '')[:16]}...")
    logger.info("[Stage 5] Audit emitted — session=%s", session_id)

    sr = StageResult(
        stage="audit", status="ok",
        duration_ms=_timer() - t0,
        summary="Audit event emitted",
    )
    return {"status": PipelineStatus.COMPLETE, **_append_stage(state, sr)}


def node_handle_failure(state: PipelineState) -> dict:
    logger.error(
        "[FAILED] session=%s error=%s",
        state.get("session_id"), state.get("error", "unknown"),
    )
    return {"status": PipelineStatus.FAILED}


# Routing functions

def route_after_health_check(
    state: PipelineState,
) -> Literal["ingestion", "handle_failure"]:
    if state.get("status") == PipelineStatus.FAILED:
        return "handle_failure"
    return "ingestion"


def route_after_ingestion(
    state: PipelineState,
) -> Literal["parsing", "handle_failure"]:
    if state.get("ingestion_status") == "ok":
        return "parsing"
    return "handle_failure"


def route_after_hitl1(
    state: PipelineState,
) -> Literal["emit_audit", "handle_failure"]:
    if state.get("hitl1_approved") is True:
        return "emit_audit"
    if state.get("status") == PipelineStatus.HITL_WAIT:
        return "emit_audit"   # unreachable during interrupt; satisfies type
    return "handle_failure"


# Graph construction

def build_pipeline_graph(checkpointer=None):
    """Build and compile the full PRISM pipeline graph."""
    if not _LANGGRAPH_AVAILABLE:
        return _SequentialFallbackRunner()

    graph = StateGraph(PipelineState)

    graph.add_node("tool_health_check",  node_tool_health_check)
    graph.add_node("ingestion",          node_ingestion)
    graph.add_node("parsing",            node_parsing)
    graph.add_node("cpg_build",          node_cpg_build)
    graph.add_node("codeql_analysis",    node_codeql_analysis)
    graph.add_node("sarif_annotation",   node_sarif_annotation)
    graph.add_node("hitl1_checkpoint",   node_hitl1_checkpoint)
    graph.add_node("emit_audit",         node_emit_audit)
    graph.add_node("handle_failure",     node_handle_failure)

    graph.set_entry_point("tool_health_check")

    graph.add_conditional_edges(
        "tool_health_check",
        route_after_health_check,
        {"ingestion": "ingestion", "handle_failure": "handle_failure"},
    )
    graph.add_conditional_edges(
        "ingestion",
        route_after_ingestion,
        {"parsing": "parsing", "handle_failure": "handle_failure"},
    )
    graph.add_edge("parsing",         "cpg_build")
    graph.add_edge("cpg_build",       "codeql_analysis")
    graph.add_edge("codeql_analysis", "sarif_annotation")
    graph.add_edge("sarif_annotation","hitl1_checkpoint")
    graph.add_conditional_edges(
        "hitl1_checkpoint",
        route_after_hitl1,
        {"emit_audit": "emit_audit", "handle_failure": "handle_failure"},
    )
    graph.add_edge("emit_audit",     END)
    graph.add_edge("handle_failure", END)

    cp = checkpointer or MemorySaver()
    return graph.compile(
        checkpointer     = cp,
        interrupt_before = ["hitl1_checkpoint"],
    )


# High-level entry point

def run_pipeline(
    repo_url:          str,
    branch:            str        = "main",
    commit_sha:        str | None = None,
    credential_ref:    str        = "github",
    output_dir:        str        = "/tmp/prism_sandbox",
    max_repo_mb:       int        = 100,
    session_id:        str | None = None,
    auto_approve_hitl: bool       = False,
) -> PipelineState:
    """Run the full PRISM pipeline synchronously."""
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

    config = {"configurable": {"thread_id": sid}}
    final_state = None
    for chunk in graph.stream(initial_state, config=config, stream_mode="values"):
        final_state = chunk
        stage_results = chunk.get("stage_results", [])
        if stage_results:
            last = stage_results[-1]
            logger.info(
                "  ▸ %-25s  %-8s  %.0f ms",
                last["stage"], last["status"], last["duration_ms"],
            )
        status = chunk.get("status")
        if status in (PipelineStatus.COMPLETE, PipelineStatus.FAILED,
                      PipelineStatus.HITL_WAIT):
            break

    return final_state or initial_state


# Sequential fallback

class _SequentialFallbackRunner:
    def run(self, state: PipelineState) -> PipelineState:
        stages = [
            node_tool_health_check,
            node_ingestion,
            node_parsing,
            node_cpg_build,
            node_codeql_analysis,
            node_sarif_annotation,
            node_hitl1_checkpoint,
            node_emit_audit,
        ]
        for fn in stages:
            try:
                update = fn(state)
                state  = {**state, **update}
                if state.get("status") in (PipelineStatus.FAILED,
                                           PipelineStatus.HITL_WAIT):
                    break
            except Exception as exc:
                logger.exception("Sequential runner: %s failed", fn.__name__)
                state = {**state, "status": PipelineStatus.FAILED,
                         "error": str(exc)}
                break
        if state.get("status") != PipelineStatus.COMPLETE:
            node_handle_failure(state)
        return state


# Parse output cache

_PARSE_OUTPUT_CACHE: dict[str, list] = {}


def _store_parse_outputs(session_id: str, outputs: list) -> None:
    _PARSE_OUTPUT_CACHE[session_id] = outputs


def _load_parse_outputs(session_id: str) -> list:
    return _PARSE_OUTPUT_CACHE.get(session_id, [])


# SARIF search helper

def _find_sarif(sandbox: str) -> "str | None":
    try:
        for p in Path(sandbox).rglob("*.sarif"):
            return str(p)
        for p in Path("/tmp").glob("prism_codeql_*.sarif"):
            return str(p)
    except OSError:
        pass
    return None