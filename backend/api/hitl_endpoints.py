"""
PRISM HITL (Human-in-the-Loop) Endpoints
==========================================
FastAPI router for the operator approval checkpoint (hitl1_checkpoint).

Endpoints:
  POST /api/session/{session_id}/hitl/approve   — operator approves pipeline
  POST /api/session/{session_id}/hitl/reject    — operator rejects pipeline
  GET  /api/session/{session_id}/hitl/status    — current HITL gate state
  GET  /api/session/{session_id}/hitl/summary   — CPG + SARIF summary for review

The HITL gate works as follows:
  1.  LangGraph pauses at node_hitl1_checkpoint via NodeInterrupt.
  2.  The frontend polls /hitl/status and shows the approval UI.
  3.  The operator reviews the CPG summary and SARIF findings.
  4.  On approve: resumes the graph with hitl1_approved=True → emit_audit runs.
  5.  On reject:  resumes with hitl1_approved=False → handle_failure runs.

The endpoints also broadcast a WebSocket event so the live UI updates instantly.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel

log = logging.getLogger("prism.hitl")

router = APIRouter(prefix="/api/session", tags=["hitl"])


# ── Request / Response models ─────────────────────────────────────────────────

class HITLDecision(BaseModel):
    approved: bool
    notes:    str = ""
    operator: str = "anonymous"


class HITLStatus(BaseModel):
    session_id:   str
    state:        str          # "waiting" | "approved" | "rejected" | "not_reached"
    cpg_nodes:    int = 0
    cpg_edges:    int = 0
    sarif_alerts: int = 0
    taint_edges:  int = 0
    findings:     list  = []
    top_cwes:     dict  = {}
    notes:        str   = ""
    operator:     str   = ""


# ── In-memory state store for HITL decisions ──────────────────────────────────
# Keyed by session_id.  Replaced by LangGraph checkpoint in production.
_hitl_states:    Dict[str, dict] = {}
_pipeline_states: Dict[str, dict] = {}   # imported reference from main


def _get_pipeline_states() -> Dict[str, dict]:
    """Lazy import to avoid circular dependency with main.py."""
    try:
        from backend.main import _pipeline_states as ps
        return ps
    except ImportError:
        return _pipeline_states


# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_summary(session_id: str) -> dict[str, Any]:
    """Build a human-readable review summary from pipeline state."""
    ps = _get_pipeline_states()
    state = ps.get(session_id, {})

    findings_raw = state.get("_findings", [])
    top_cwes: dict[str, int] = {}
    for f in findings_raw:
        for cwe in (f.get("cwe_hints") or []):
            top_cwes[cwe] = top_cwes.get(cwe, 0) + 1

    # Sort by count descending
    top_cwes = dict(sorted(top_cwes.items(), key=lambda x: -x[1])[:10])

    return {
        "cpg_nodes":         state.get("cpg_node_count", 0),
        "cpg_edges":         state.get("cpg_edge_count", 0),
        "sarif_alerts":      state.get("sarif_annotations", 0),
        "taint_edges":       state.get("sarif_edges", 0),
        "total_files":       state.get("total_files", 0),
        "fetched_commit":    state.get("fetched_commit", "")[:16],
        "repo_hash":         state.get("repo_hash", "")[:16],
        "backend_used":      state.get("backend_used", {}),
        "codeql_status":     state.get("codeql_status", "unknown"),
        "tool_status":       {
            k: v.get("available") for k, v in state.get("tool_status", {}).items()
        },
        "top_cwes":          top_cwes,
        "high_severity":     sum(
            1 for f in findings_raw if f.get("severity") == "HIGH"
        ),
        "medium_severity":   sum(
            1 for f in findings_raw if f.get("severity") == "MEDIUM"
        ),
        "findings_preview":  findings_raw[:5],   # first 5 for the review panel
        "stage_results":     state.get("stage_results", []),
    }


async def _broadcast(session_id: str, event_type: str, payload: Any) -> None:
    """Non-blocking broadcast to WebSocket clients for this session."""
    try:
        from backend.api.session_manager import manager
        await manager.broadcast(session_id, {
            "type": event_type,
            "session_id": session_id,
            "payload": payload,
        })
    except Exception as exc:
        log.debug("WS broadcast skipped: %s", exc)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/{session_id}/hitl/status", response_model=HITLStatus)
async def get_hitl_status(session_id: str) -> HITLStatus:
    """
    Poll this endpoint to check whether the pipeline is waiting at the HITL gate.
    The frontend shows the approval UI when state == "waiting".
    """
    ps = _get_pipeline_states()
    if session_id not in ps:
        raise HTTPException(404, f"Session '{session_id}' not found")

    pipeline_status = ps[session_id].get("status", "")
    hitl_state = _hitl_states.get(session_id, {})

    if str(pipeline_status) == "hitl_wait":
        state = "waiting"
    elif hitl_state.get("approved") is True:
        state = "approved"
    elif hitl_state.get("approved") is False:
        state = "rejected"
    else:
        state = "not_reached"

    summary = _build_summary(session_id)

    return HITLStatus(
        session_id   = session_id,
        state        = state,
        cpg_nodes    = summary["cpg_nodes"],
        cpg_edges    = summary["cpg_edges"],
        sarif_alerts = summary["sarif_alerts"],
        taint_edges  = summary["taint_edges"],
        findings     = summary["findings_preview"],
        top_cwes     = summary["top_cwes"],
        notes        = hitl_state.get("notes", ""),
        operator     = hitl_state.get("operator", ""),
    )


@router.get("/{session_id}/hitl/summary")
async def get_hitl_summary(session_id: str) -> dict:
    """
    Full review summary for the HITL panel.
    Returns CPG stats, SARIF findings, tool status, stage results.
    """
    ps = _get_pipeline_states()
    if session_id not in ps:
        raise HTTPException(404, f"Session '{session_id}' not found")
    return _build_summary(session_id)


@router.post("/{session_id}/hitl/approve")
async def approve_hitl(
    session_id: str,
    decision: HITLDecision,
    background_tasks: BackgroundTasks,
) -> dict:
    """
    Operator approves the pipeline at the HITL gate.
    Resumes the LangGraph run with hitl1_approved=True.
    """
    ps = _get_pipeline_states()
    if session_id not in ps:
        raise HTTPException(404, f"Session '{session_id}' not found")

    log.info(
        "HITL APPROVED  session=%s  operator=%s  notes=%s",
        session_id, decision.operator, decision.notes[:100],
    )

    _hitl_states[session_id] = {
        "approved": True,
        "notes":    decision.notes,
        "operator": decision.operator,
    }

    # Broadcast immediately to all connected WebSocket clients
    await _broadcast(session_id, "phase", {
        "stage": "hitl1_checkpoint",
        "label": f"✅ HITL approved by {decision.operator or 'operator'}",
        "approved": True,
        "operator": decision.operator,
        "notes": decision.notes,
    })

    # Resume LangGraph in background
    background_tasks.add_task(
        _resume_pipeline, session_id, True, decision.notes, decision.operator
    )

    return {
        "session_id": session_id,
        "status": "approved",
        "message": "Pipeline resumed — proceeding to audit emission",
        "operator": decision.operator,
    }


@router.post("/{session_id}/hitl/reject")
async def reject_hitl(
    session_id: str,
    decision: HITLDecision,
    background_tasks: BackgroundTasks,
) -> dict:
    """
    Operator rejects the pipeline at the HITL gate.
    Terminates the run and records the rejection reason.
    """
    ps = _get_pipeline_states()
    if session_id not in ps:
        raise HTTPException(404, f"Session '{session_id}' not found")

    log.warning(
        "HITL REJECTED  session=%s  operator=%s  reason=%s",
        session_id, decision.operator, decision.notes[:200],
    )

    _hitl_states[session_id] = {
        "approved": False,
        "notes":    decision.notes,
        "operator": decision.operator,
    }

    await _broadcast(session_id, "phase", {
        "stage": "hitl1_checkpoint",
        "label": f"❌ HITL rejected by {decision.operator or 'operator'}: {decision.notes[:80]}",
        "approved": False,
        "operator": decision.operator,
        "notes": decision.notes,
    })

    background_tasks.add_task(
        _resume_pipeline, session_id, False, decision.notes, decision.operator
    )

    return {
        "session_id": session_id,
        "status": "rejected",
        "message": "Pipeline rejected and terminated",
        "operator": decision.operator,
    }


# ── Background pipeline resume ────────────────────────────────────────────────

def _resume_pipeline(
    session_id: str,
    approved:   bool,
    notes:      str,
    operator:   str,
) -> None:
    """
    Resume the LangGraph pipeline after HITL decision.
    Runs in BackgroundTasks thread so it doesn't block the HTTP response.
    """
    import asyncio

    ps = _get_pipeline_states()

    try:
        from orchestrator.graph import build_pipeline_graph
        from orchestrator.state import PipelineStatus

        graph  = build_pipeline_graph()
        config = {"configurable": {"thread_id": session_id}}

        # Resume with the operator decision injected into state
        resume_state = {
            "hitl1_approved": approved,
            "hitl1_notes":    notes,
            "status": PipelineStatus.RUNNING,
        }

        # LangGraph: update state then stream remaining nodes
        final = None
        for chunk in graph.stream(resume_state, config=config, stream_mode="values"):
            final = chunk
            status = chunk.get("status")
            if status in (PipelineStatus.COMPLETE, PipelineStatus.FAILED):
                break

        if final:
            ps[session_id] = {**ps.get(session_id, {}), **final}

        # Broadcast completion
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_broadcast_sync(session_id, approved, final))
        finally:
            loop.close()

    except Exception as exc:
        log.exception("Pipeline resume failed for session=%s", session_id)
        ps[session_id] = {
            **ps.get(session_id, {}),
            "status": "failed",
            "error": str(exc),
        }


async def _broadcast_sync(session_id: str, approved: bool, final_state: dict) -> None:
    if approved:
        await _broadcast(session_id, "complete", {
            "session_id":    session_id,
            "node_count":    final_state.get("cpg_node_count", 0) if final_state else 0,
            "edge_count":    final_state.get("cpg_edge_count", 0) if final_state else 0,
            "finding_count": 0,
            "repo_hash":     (final_state or {}).get("repo_hash", "")[:16],
            "audit_emitted": True,
        })
    else:
        await _broadcast(session_id, "error", {
            "message":  "Pipeline rejected at HITL checkpoint",
            "rejected": True,
        })