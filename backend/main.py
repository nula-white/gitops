"""
PRISM FastAPI application

Endpoints
---------
GET  /health                       – liveness check
POST /api/analyze                  – start analysis, returns session_id
GET  /api/session/{id}/status      – poll analysis status
GET  /api/session/{id}/graph       – fetch full CPG from Neo4j
GET  /api/session/{id}/findings    – fetch all findings
WS   /ws/{session_id}              – real-time CPG event stream
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from contextlib import asynccontextmanager
from typing import Any, Dict

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from core.config import get_settings
from core.models import (
    AnalysisRequest, AnalysisStatus,
    PipelinePhase, WSEventType,
)
from core.cpg_builder import build_cpg
from api.session_manager import manager
from db import neo4j_client as db

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# In-memory status store (replace with Redis for multi-node deployment)
_status: Dict[str, AnalysisStatus] = {}


# App lifecycle

@asynccontextmanager
async def lifespan(app: FastAPI):
    s = get_settings()
    # Try Neo4j; warn if unavailable (pipeline still works without persistence)
    ok = await db.verify_connectivity()
    if ok:
        await db.ensure_indexes()
        log.info("Neo4j connected and indexes verified.")
    else:
        log.warning("Neo4j not reachable — pipeline will run without persistence.")

    # Heartbeat task
    asyncio.create_task(manager.heartbeat_loop(s.ws_heartbeat_interval))
    yield
    await db.close_driver()


app = FastAPI(title="PRISM", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # tighten for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# REST endpoints
@app.get("/health")
async def health() -> dict:
    neo4j_ok = await db.verify_connectivity()
    return {"status": "ok", "neo4j": neo4j_ok}


@app.post("/api/analyze")
async def start_analysis(req: AnalysisRequest) -> Dict[str, Any]:
    """
    Accepts an inline code snippet or repository URL.
    Returns session_id immediately; client should connect to WS to receive events.
    """
    if not req.inline_code and not req.repository_url:
        raise HTTPException(400, "Provide either inline_code or repository_url")

    session_id = req.session_id or str(uuid.uuid4())
    _status[session_id] = AnalysisStatus(
        session_id=session_id,
        phase=PipelinePhase.IDLE,
    )
    return {"session_id": session_id, "ws_url": f"/ws/{session_id}"}


@app.get("/api/session/{session_id}/status")
async def get_status(session_id: str) -> AnalysisStatus:
    if session_id not in _status:
        raise HTTPException(404, "Session not found")
    return _status[session_id]


@app.get("/api/session/{session_id}/graph")
async def get_graph(session_id: str) -> Dict[str, Any]:
    """Return the full CPG stored in Neo4j for a completed session."""
    nodes = await db.get_nodes_for_session(session_id)
    edges = await db.get_edges_for_session(session_id)
    return {"nodes": nodes, "edges": edges}


@app.get("/api/session/{session_id}/findings")
async def get_findings(session_id: str):
    findings = await db.get_findings_for_session(session_id)
    return {"findings": findings}


# WebSocket endpoint

@app.websocket("/ws/{session_id}")
async def ws_analysis(websocket: WebSocket, session_id: str):
    """
    Full-duplex WebSocket for real-time CPG streaming.

    Client sends:
      {"action": "start", "code": "...", "language": "python", "filename": "app.py"}

    Server streams WSEvent JSON objects until COMPLETE or ERROR.
    """
    await manager.connect(session_id, websocket)
    try:
        # Wait for the start message
        raw = await websocket.receive_json()
        action = raw.get("action", "")

        if action != "start":
            await websocket.send_json({"type": "error", "payload": {"message": "Expected action=start"}})
            return

        code = raw.get("code", "")
        language = raw.get("language", "python")
        filename = raw.get("filename", "snippet.py")

        if not code.strip():
            await websocket.send_json({"type": "error", "payload": {"message": "Empty code payload"}})
            return

        # Update status
        if session_id in _status:
            _status[session_id].phase = PipelinePhase.PARSE

        neo4j_ok = await db.verify_connectivity()

        # Run CPG pipeline and stream events
        async for event in build_cpg(code, language, filename, session_id):
            payload = event.model_dump()
            await manager.broadcast(session_id, payload)

            # Update in-memory status
            if session_id in _status:
                st = _status[session_id]
                evt_type = event.type
                if evt_type == WSEventType.NODE:
                    st.node_count += 1
                elif evt_type == WSEventType.EDGE:
                    st.edge_count += 1
                elif evt_type == WSEventType.FINDING:
                    st.finding_count += 1
                elif evt_type == WSEventType.PHASE and event.payload:
                    try:
                        st.phase = PipelinePhase(event.payload.get("stage", "IDLE"))
                    except ValueError:
                        pass

            # Persist to Neo4j when available
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