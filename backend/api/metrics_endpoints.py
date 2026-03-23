"""
PRISM Real-Time Performance Metrics
=====================================
Server-Sent Events (SSE) and REST endpoints for streaming pipeline
performance metrics to the UI in real time.

Metrics tracked:
  Detection:   precision, recall, F1, false positive rate per CWE
  Pipeline:    stage latencies, total duration, tool availability
  CPG:         node/edge counts, graph density, hotspot density
  IaC:         Terraform validation pass rate, misconfiguration count
  System:      memory, parse throughput (nodes/sec, files/sec)

All metrics update live via SSE → the frontend chart updates without polling.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field, asdict
from typing import Any, AsyncIterator, Dict, List, Optional

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

log = logging.getLogger("prism.metrics")

router = APIRouter(prefix="/api/metrics", tags=["metrics"])


# ── Metric data structures ────────────────────────────────────────────────────

@dataclass
class DetectionMetrics:
    """Per-CWE detection accuracy metrics."""
    cwe:              str
    true_positives:   int   = 0
    false_positives:  int   = 0
    false_negatives:  int   = 0
    true_negatives:   int   = 0

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def false_positive_rate(self) -> float:
        denom = self.false_positives + self.true_negatives
        return self.false_positives / denom if denom else 0.0

    def to_dict(self) -> dict:
        return {
            "cwe":               self.cwe,
            "true_positives":    self.true_positives,
            "false_positives":   self.false_positives,
            "false_negatives":   self.false_negatives,
            "precision":         round(self.precision, 4),
            "recall":            round(self.recall, 4),
            "f1":                round(self.f1, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
        }


@dataclass
class StageMetric:
    stage:        str
    status:       str   = "pending"   # pending | running | ok | skipped | failed
    duration_ms:  float = 0.0
    started_at:   float = 0.0
    finished_at:  float = 0.0


@dataclass
class PipelineMetrics:
    session_id:         str
    repo_url:           str         = ""
    started_at:         float       = field(default_factory=time.monotonic)
    total_duration_ms:  float       = 0.0
    total_files:        int         = 0
    files_per_second:   float       = 0.0
    nodes_per_second:   float       = 0.0
    total_nodes:        int         = 0
    total_edges:        int         = 0
    graph_density:      float       = 0.0      # edges / (nodes * (nodes-1))
    hotspot_count:      int         = 0        # nodes with degree > threshold
    finding_count:      int         = 0
    high_severity:      int         = 0
    medium_severity:    int         = 0
    low_severity:       int         = 0
    codeql_alerts:      int         = 0
    taint_paths:        int         = 0
    iac_pass_rate:      float       = 0.0
    stages:             List[dict]  = field(default_factory=list)
    detection_by_cwe:   List[dict]  = field(default_factory=list)
    tool_latencies:     dict        = field(default_factory=dict)
    memory_mb:          float       = 0.0
    backend_breakdown:  dict        = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


# ── Global metrics registry ───────────────────────────────────────────────────

_metrics_store: Dict[str, PipelineMetrics] = {}


def get_or_create(session_id: str, repo_url: str = "") -> PipelineMetrics:
    if session_id not in _metrics_store:
        _metrics_store[session_id] = PipelineMetrics(
            session_id=session_id, repo_url=repo_url
        )
    return _metrics_store[session_id]


def update_from_pipeline_state(session_id: str, state: dict) -> PipelineMetrics:
    """Sync metrics object from the LangGraph pipeline state dict."""
    m = get_or_create(session_id, state.get("repo_url", ""))

    # CPG metrics
    m.total_nodes = state.get("cpg_node_count", m.total_nodes)
    m.total_edges = state.get("cpg_edge_count", m.total_edges)
    m.total_files = state.get("total_files",    m.total_files)
    m.codeql_alerts = state.get("sarif_annotations", m.codeql_alerts)
    m.taint_paths   = state.get("sarif_edges",        m.taint_paths)

    # Stage latencies
    stage_results = state.get("stage_results", [])
    m.stages = stage_results

    tool_status = state.get("tool_status", {})
    m.tool_latencies = {
        name: info.get("latency_ms", 0)
        for name, info in tool_status.items()
    }

    # Graph density: E / (N*(N-1)/2) — normalized 0..1
    n = m.total_nodes
    if n > 1:
        m.graph_density = round(m.total_edges / (n * (n - 1) / 2), 6)

    # Findings breakdown
    findings = state.get("_findings", [])
    m.finding_count   = len(findings)
    m.high_severity   = sum(1 for f in findings if f.get("severity") == "HIGH")
    m.medium_severity = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    m.low_severity    = sum(1 for f in findings if f.get("severity") == "LOW")

    # CWE breakdown → detection metrics (estimated, no ground truth at runtime)
    cwe_counts: dict[str, int] = {}
    for f in findings:
        for cwe in (f.get("cwe_hints") or []):
            cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
    m.detection_by_cwe = [
        {"cwe": cwe, "count": cnt, "confidence_avg": _avg_confidence(cwe, findings)}
        for cwe, cnt in sorted(cwe_counts.items(), key=lambda x: -x[1])
    ]

    # Backend breakdown
    m.backend_breakdown = state.get("backend_used", {})

    # Throughput
    elapsed = (time.monotonic() - m.started_at)
    if elapsed > 0:
        m.files_per_second = round(m.total_files / elapsed, 2)
        m.nodes_per_second = round(m.total_nodes / elapsed, 2)
    m.total_duration_ms = round(elapsed * 1000, 1)

    # Memory (current process)
    try:
        import psutil, os
        proc = psutil.Process(os.getpid())
        m.memory_mb = round(proc.memory_info().rss / (1024 * 1024), 1)
    except Exception:
        pass

    return m


def _avg_confidence(cwe: str, findings: list) -> float:
    relevant = [f.get("confidence", 0.0) for f in findings
                if cwe in (f.get("cwe_hints") or [])]
    return round(sum(relevant) / len(relevant), 3) if relevant else 0.0


# ── SSE streaming endpoint ───────────────────────────────────────────────────

async def _metrics_event_stream(
    session_id: str, request: Request
) -> AsyncIterator[str]:
    """
    Yields Server-Sent Events with updated metrics every 500ms.
    Stops when the client disconnects or the session completes.
    """
    try:
        from backend.main import _pipeline_states
    except ImportError:
        _pipeline_states = {}

    last_hash = ""
    idle_ticks = 0

    while True:
        # Check client disconnect
        if await request.is_disconnected():
            break

        # Pull latest state
        state = _pipeline_states.get(session_id, {})
        if state:
            m = update_from_pipeline_state(session_id, state)
        else:
            m = get_or_create(session_id)

        payload = json.dumps(m.to_dict(), default=str)
        current_hash = str(hash(payload))

        if current_hash != last_hash:
            last_hash = current_hash
            yield f"data: {payload}\n\n"
            idle_ticks = 0
        else:
            idle_ticks += 1

        # Send heartbeat every 10 idle ticks (~5s) to keep connection alive
        if idle_ticks >= 10:
            yield f"data: {json.dumps({'heartbeat': True, 'session_id': session_id})}\n\n"
            idle_ticks = 0

        # Stop streaming when session is complete or failed
        status = str(state.get("status", ""))
        if status in ("complete", "failed") and idle_ticks > 4:
            yield f"data: {json.dumps({'stream_end': True, 'final_status': status})}\n\n"
            break

        await asyncio.sleep(0.5)


@router.get("/{session_id}/stream")
async def stream_metrics(session_id: str, request: Request) -> StreamingResponse:
    """
    Server-Sent Events stream of live pipeline metrics.
    Connect with: EventSource('/api/metrics/{session_id}/stream')
    """
    return StreamingResponse(
        _metrics_event_stream(session_id, request),
        media_type="text/event-stream",
        headers={
            "Cache-Control":               "no-cache",
            "X-Accel-Buffering":           "no",
            "Access-Control-Allow-Origin": "*",
        },
    )


@router.get("/{session_id}/snapshot")
async def get_metrics_snapshot(session_id: str) -> dict:
    """Single metrics snapshot (non-streaming, for polling fallback)."""
    try:
        from backend.main import _pipeline_states
        state = _pipeline_states.get(session_id, {})
    except ImportError:
        state = {}

    if state:
        m = update_from_pipeline_state(session_id, state)
    else:
        m = get_or_create(session_id)

    return m.to_dict()


@router.get("/summary/all")
async def get_all_sessions_summary() -> dict:
    """Summary across all active sessions — for operator dashboard."""
    return {
        "active_sessions": len(_metrics_store),
        "sessions": {
            sid: {
                "status":        "unknown",
                "total_files":   m.total_files,
                "finding_count": m.finding_count,
                "duration_ms":   m.total_duration_ms,
            }
            for sid, m in _metrics_store.items()
        },
    }