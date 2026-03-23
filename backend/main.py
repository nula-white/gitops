"""
PRISM FastAPI application

Changes from past version:
  1. Lifespan stores the running event loop in pipeline_events so
     synchronous LangGraph stages can push WebSocket progress events.

  2. New endpoint POST /api/analyze/repository starts a full repository
     analysis pipeline, returns session_id immediately, streams progress
     via the existing /ws/{session_id} WebSocket.

  3. New endpoint GET /api/session/{id}/pipeline returns current pipeline
     stage results for polling (complements WebSocket streaming).

  4. The existing inline-code WebSocket path is unchanged for backward
     compatibility.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from contextlib import asynccontextmanager
from typing import Any, Dict

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from core.config import get_settings
from core.models import (
    AnalysisRequest, AnalysisStatus,
    PipelinePhase, WSEventType,
)
from core.cpg_builder import build_cpg
from api.session_manager import manager
from api.pipeline_events import set_event_loop
from db import neo4j_client as db

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

_status:          Dict[str, AnalysisStatus] = {}
_pipeline_states: Dict[str, dict]           = {}


# App lifecycle

@asynccontextmanager
async def lifespan(app: FastAPI):
    s = get_settings()

    # Register the running event loop so synchronous LangGraph stages
    # (e.g. node_codeql_analysis) can push progress via WebSocket.
    set_event_loop(asyncio.get_running_loop())
    log.info("Event loop registered in pipeline_events.")

    ok = await db.verify_connectivity()
    if ok:
        await db.ensure_indexes()
        log.info("Neo4j connected and indexes verified.")
    else:
        log.warning("Neo4j not reachable — pipeline will run without persistence.")

    asyncio.create_task(manager.heartbeat_loop(s.ws_heartbeat_interval))
    yield
    await db.close_driver()


app = FastAPI(title="PRISM", version="1.2.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Health

@app.get("/health")
async def health() -> dict:
    neo4j_ok = await db.verify_connectivity()
    try:
        from core.tool_registry import check_tools
        tools = {n: s["available"] for n, s in check_tools().summary().items()}
    except Exception:
        tools = {}
    return {"status": "ok", "neo4j": neo4j_ok, "tools": tools}


# Inline code analysis 

@app.post("/api/analyze")
async def start_analysis(req: AnalysisRequest) -> Dict[str, Any]:
    if not req.inline_code and not req.repository_url:
        raise HTTPException(400, "Provide either inline_code or repository_url")
    session_id = req.session_id or str(uuid.uuid4())
    _status[session_id] = AnalysisStatus(session_id=session_id, phase=PipelinePhase.IDLE)
    return {"session_id": session_id, "ws_url": f"/ws/{session_id}"}


# Full repository analysis 

class RepositoryAnalysisRequest(BaseModel):
    repo_url:       str
    branch:         str        = "main"
    commit_sha:     str | None = None
    credential_ref: str        = "github"
    max_repo_mb:    int        = 100
    session_id:     str | None = None


@app.post("/api/analyze/repository")
async def start_repository_analysis(
    req: RepositoryAnalysisRequest,
    background_tasks: BackgroundTasks,
) -> Dict[str, Any]:
    """
    Start a full repository ingestion + CPG + CodeQL analysis pipeline.
    Returns immediately with a session_id; pipeline runs in background.
    Progress streams via WebSocket /ws/{session_id}.

    Stage sequence visible to frontend:
      tool_health_check → ingestion → parsing → cpg_build
      → codeql_analysis (streams per-query progress, no timeout)
      → sarif_annotation (streams per-finding annotation events)
      → hitl1_checkpoint → emit_audit
    """
    session_id = req.session_id or f"repo_{uuid.uuid4().hex[:12]}"
    _status[session_id] = AnalysisStatus(session_id=session_id, phase=PipelinePhase.IDLE)
    _pipeline_states[session_id] = {
        "session_id": session_id,
        "status": "pending",
        "stage_results": [],
    }

    import os
    os.makedirs(f"/tmp/prism_sessions/{session_id}", exist_ok=True)

    background_tasks.add_task(
        _run_pipeline_background,
        session_id     = session_id,
        repo_url       = req.repo_url,
        branch         = req.branch,
        commit_sha     = req.commit_sha,
        credential_ref = req.credential_ref,
        max_repo_mb    = req.max_repo_mb,
    )

    return {
        "session_id": session_id,
        "ws_url":     f"/ws/{session_id}",
        "status_url": f"/api/session/{session_id}/pipeline",
        "message":    "Pipeline started. Connect to ws_url for live progress.",
    }


def _run_pipeline_background(
    session_id:     str,
    repo_url:       str,
    branch:         str,
    commit_sha:     str | None,
    credential_ref: str,
    max_repo_mb:    int,
) -> None:
    """Runs in a BackgroundTasks thread. Calls the synchronous LangGraph orchestrator."""
    from orchestrator.graph import run_pipeline
    from api.pipeline_events import emit_progress

    log.info("Pipeline background starting — session=%s url=%s", session_id, repo_url)
    emit_progress(session_id, "pipeline_start", "Repository analysis starting…", 0.0)

    try:
        result = run_pipeline(
            repo_url       = repo_url,
            branch         = branch,
            commit_sha     = commit_sha,
            credential_ref = credential_ref,
            output_dir     = f"/tmp/prism_sessions/{session_id}/repo",
            max_repo_mb    = max_repo_mb,
            session_id     = session_id,
        )
        _pipeline_states[session_id] = dict(result)

        final_status = result.get("status", "unknown")
        if str(final_status) == "complete":
            emit_progress(session_id, "pipeline_complete",
                          "Analysis complete — results ready", 100.0)
        else:
            emit_progress(session_id, "pipeline_failed",
                          f"Pipeline ended: {final_status}", 100.0)

        log.info("Pipeline complete — session=%s status=%s", session_id, final_status)

    except Exception as exc:
        log.exception("Pipeline background task raised — session=%s", session_id)
        _pipeline_states[session_id] = {
            "session_id": session_id,
            "status": "failed",
            "error": str(exc),
        }
        emit_progress(session_id, "pipeline_failed", f"Pipeline failed: {exc}", 100.0)


# Status / data endpoints

@app.get("/api/session/{session_id}/status")
async def get_status(session_id: str) -> AnalysisStatus:
    if session_id not in _status:
        raise HTTPException(404, "Session not found")
    return _status[session_id]


@app.get("/api/session/{session_id}/pipeline")
async def get_pipeline_state(session_id: str) -> dict:
    """Current pipeline state for polling when WebSocket is unavailable."""
    if session_id not in _pipeline_states:
        raise HTTPException(404, "Session not found")
    s = _pipeline_states[session_id]
    return {
        "session_id":        s.get("session_id"),
        "status":            s.get("status"),
        "error":             s.get("error"),
        "repo_hash":         s.get("repo_hash"),
        "fetched_commit":    s.get("fetched_commit"),
        "tool_status":       s.get("tool_status", {}),
        "cpg_node_count":    s.get("cpg_node_count", 0),
        "cpg_edge_count":    s.get("cpg_edge_count", 0),
        "codeql_status":     s.get("codeql_status"),
        "sarif_annotations": s.get("sarif_annotations", 0),
        "sarif_edges":       s.get("sarif_edges", 0),
        "stage_results":     s.get("stage_results", []),
    }


@app.get("/api/session/{session_id}/graph")
async def get_graph(session_id: str) -> Dict[str, Any]:
    nodes = await db.get_nodes_for_session(session_id)
    edges = await db.get_edges_for_session(session_id)
    return {"nodes": nodes, "edges": edges}


@app.get("/api/session/{session_id}/findings")
async def get_findings(session_id: str):
    findings = await db.get_findings_for_session(session_id)
    return {"findings": findings}


# WebSocket (inline-code path unchanged; receives background task events too)

@app.websocket("/ws/{session_id}")
async def ws_analysis(websocket: WebSocket, session_id: str):
    """
    WebSocket for real-time event streaming.

    Two use cases:
      1. Inline code: client sends {action: "start", code: "..."}
      2. Repository pipeline: client connects; background task pushes events.
    """
    await manager.connect(session_id, websocket)
    try:
        # Wait up to 5 s for a start message.
        # If none arrives, stay connected for background-task events.
        try:
            raw = await asyncio.wait_for(websocket.receive_json(), timeout=5.0)
        except asyncio.TimeoutError:
            # Background pipeline mode — keep alive and relay events
            while True:
                try:
                    await asyncio.wait_for(websocket.receive_text(), timeout=60.0)
                except asyncio.TimeoutError:
                    await websocket.send_json({"type": "heartbeat"})
            return

        action = raw.get("action", "")
        if action != "start":
            await websocket.send_json({
                "type": "error",
                "payload": {"message": "Expected action=start for inline analysis"},
            })
            return

        code     = raw.get("code", "")
        language = raw.get("language", "python")
        filename = raw.get("filename", "snippet.py")

        if not code.strip():
            await websocket.send_json({
                "type": "error",
                "payload": {"message": "Empty code payload"},
            })
            return

        if session_id in _status:
            _status[session_id].phase = PipelinePhase.PARSE

        neo4j_ok = await db.verify_connectivity()

        async for event in build_cpg(code, language, filename, session_id):
            payload = event.model_dump()
            await manager.broadcast(session_id, payload)

            if session_id in _status:
                st = _status[session_id]
                if event.type == WSEventType.NODE:
                    st.node_count += 1
                elif event.type == WSEventType.EDGE:
                    st.edge_count += 1
                elif event.type == WSEventType.FINDING:
                    st.finding_count += 1
                elif event.type == WSEventType.PHASE and event.payload:
                    try:
                        st.phase = PipelinePhase(event.payload.get("stage", "IDLE"))
                    except ValueError:
                        pass

            if neo4j_ok:
                try:
                    if event.type == WSEventType.NODE:
                        from core.models import CPGNode
                        await db.upsert_node(CPGNode(**event.payload))
                    elif event.type == WSEventType.EDGE:
                        from core.models import CPGEdge
                        await db.upsert_edge(CPGEdge(**event.payload))
                    elif event.type == WSEventType.FINDING:
                        from core.models import VulnerabilityFinding
                        await db.upsert_finding(VulnerabilityFinding(**event.payload))
                except Exception as exc:
                    log.debug("Neo4j write skipped: %s", exc)

        if session_id in _status:
            _status[session_id].phase = PipelinePhase.COMPLETE

    except WebSocketDisconnect:
        log.info("Client disconnected session=%s", session_id)
    except Exception as exc:
        log.exception("Pipeline error session=%s: %s", session_id, exc)
        try:
            await websocket.send_json({
                "type": "error",
                "session_id": session_id,
                "payload": {"message": str(exc)},
            })
        except Exception:
            pass
    finally:
        manager.disconnect(session_id, websocket)