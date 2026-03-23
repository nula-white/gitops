"""
PRISM UI — Flask dashboard
===========================
Bridges the LangGraph/FastAPI pipeline to the legacy Flask frontend.

Routes:
  GET  /                         — main dashboard
  POST /api/analyze              — start analysis (inline code or repo URL)
  GET  /api/session/<id>/events  — SSE stream of pipeline events + metrics
  GET  /api/session/<id>/graph   — CPG graph JSON for vis.js
  GET  /api/session/<id>/findings — vulnerability findings JSON
  GET  /api/session/<id>/status  — pipeline status + stage results
  GET  /api/session/<id>/metrics — live performance metrics
  POST /api/session/<id>/hitl/approve  — HITL approval
  POST /api/session/<id>/hitl/reject   — HITL rejection
  GET  /api/session/<id>/hitl/status   — HITL gate state

Events streamed via SSE include:
  phase, node, edge, finding, annotation, hitl_waiting,
  metrics_update, complete, error, heartbeat
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import queue
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from flask import Flask, Response, jsonify, render_template, request, stream_with_context

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(name)-22s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("prism.ui")

# ── Add project root to path ──────────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET", "prism-dev-secret")

# ── Session store ─────────────────────────────────────────────────────────────
# Each session:  { log_queue, graph_queue, graph, findings, status, ... }
_sessions: dict[str, dict] = {}

# ── Pipeline availability ─────────────────────────────────────────────────────
_PIPELINE_AVAILABLE = False
_PARSER_AVAILABLE   = False
_METRICS_AVAILABLE  = False

try:
    from ingestion.pipeline import run_ingestion
    from ingestion.models   import GitProvider, IngestionRequest
    from ingestion.credential_provider import EnvCredentialProvider
    _PIPELINE_AVAILABLE = True
except ImportError as e:
    log.warning("Ingestion not importable (%s) — demo mode", e)

try:
    from parser.registry import ParserRegistry
    _PARSER_AVAILABLE = True
except ImportError as e:
    log.warning("Parser not importable (%s) — demo mode", e)

try:
    from backend.api.metrics_endpoints import update_from_pipeline_state
    _METRICS_AVAILABLE = True
except ImportError:
    pass


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def start_analysis():
    """
    Start a pipeline session.  Accepts JSON:
      { repo_url, branch, commit_sha, token, max_repo_mb }
      OR
      { code, language, filename }  (inline snippet mode)
    """
    data       = request.get_json(force=True, silent=True) or {}
    session_id = f"prism_{uuid.uuid4().hex[:12]}"

    log_q   = queue.Queue(maxsize=2000)
    graph_q = queue.Queue(maxsize=5000)

    session = {
        "session_id": session_id,
        "log_queue":   log_q,
        "graph_queue": graph_q,
        "graph":       {"nodes": [], "edges": [], "summary": {}},
        "findings":    [],
        "status":      "pending",
        "error":       None,
        "hitl_state":  "not_reached",  # waiting | approved | rejected | not_reached
        "hitl_notes":  "",
        "metrics":     {},
        "started_at":  time.time(),
    }
    _sessions[session_id] = session

    # Inline code mode (quick analysis)
    if data.get("code"):
        t = threading.Thread(
            target=_run_inline_pipeline,
            args=(session, data.get("code", ""),
                  data.get("language", "python"),
                  data.get("filename", "snippet.py")),
            daemon=True,
        )
        t.start()
        return jsonify({"session_id": session_id, "mode": "inline"})

    # Repository mode (full pipeline)
    repo_url = data.get("repo_url", "").strip()
    if not repo_url:
        return jsonify({"error": "repo_url or code is required"}), 400

    branch     = data.get("branch", "main")
    commit_sha = data.get("commit_sha") or None
    token      = data.get("token", "") or os.environ.get("PRISM_GIT_TOKEN", "")
    max_mb     = int(data.get("max_repo_mb", 100))

    session["repo_url"] = repo_url
    session["branch"]   = branch

    t = threading.Thread(
        target=_run_repo_pipeline,
        args=(session, repo_url, branch, commit_sha, token, max_mb),
        daemon=True,
    )
    t.start()

    return jsonify({"session_id": session_id, "mode": "repository", "repo_url": repo_url})


# ── HITL endpoints ────────────────────────────────────────────────────────────

@app.route("/api/session/<session_id>/hitl/status")
def hitl_status(session_id: str):
    s = _get_session(session_id)
    return jsonify({
        "session_id": session_id,
        "state":      s.get("hitl_state", "not_reached"),
        "notes":      s.get("hitl_notes", ""),
        "operator":   s.get("hitl_operator", ""),
        "summary":    _build_hitl_summary(s),
    })


@app.route("/api/session/<session_id>/hitl/approve", methods=["POST"])
def hitl_approve(session_id: str):
    s = _get_session(session_id)
    data = request.get_json(force=True, silent=True) or {}
    operator = data.get("operator", "anonymous")
    notes    = data.get("notes", "")

    log.info("HITL APPROVED  session=%s  operator=%s", session_id, operator)
    s["hitl_state"]    = "approved"
    s["hitl_notes"]    = notes
    s["hitl_operator"] = operator

    # Push a WebSocket-style event onto the graph queue
    s["graph_queue"].put_nowait({
        "type": "phase",
        "payload": {
            "stage":    "hitl1_checkpoint",
            "label":    f"✅ HITL approved by {operator}",
            "approved": True,
        },
    })

    # Resume the background pipeline thread if it's waiting
    event = s.get("_hitl_event")
    if event:
        event.set()

    return jsonify({"status": "approved", "session_id": session_id})


@app.route("/api/session/<session_id>/hitl/reject", methods=["POST"])
def hitl_reject(session_id: str):
    s = _get_session(session_id)
    data = request.get_json(force=True, silent=True) or {}
    operator = data.get("operator", "anonymous")
    notes    = data.get("notes", "")

    log.warning("HITL REJECTED  session=%s  operator=%s  reason=%s",
                session_id, operator, notes[:100])
    s["hitl_state"]    = "rejected"
    s["hitl_notes"]    = notes
    s["hitl_operator"] = operator

    s["graph_queue"].put_nowait({
        "type": "phase",
        "payload": {
            "stage":    "hitl1_checkpoint",
            "label":    f"❌ Rejected by {operator}: {notes[:60]}",
            "approved": False,
        },
    })

    event = s.get("_hitl_event")
    if event:
        event.set()

    return jsonify({"status": "rejected", "session_id": session_id})


# ── Data endpoints ────────────────────────────────────────────────────────────

@app.route("/api/session/<session_id>/graph")
def get_graph(session_id: str):
    s = _get_session(session_id)
    return jsonify(s.get("graph", {"nodes": [], "edges": [], "summary": {}}))


@app.route("/api/session/<session_id>/findings")
def get_findings(session_id: str):
    s = _get_session(session_id)
    return jsonify({"findings": s.get("findings", [])})


@app.route("/api/session/<session_id>/status")
def get_status(session_id: str):
    s = _get_session(session_id)
    return jsonify({
        "session_id":  session_id,
        "status":      s.get("status", "unknown"),
        "error":       s.get("error"),
        "hitl_state":  s.get("hitl_state", "not_reached"),
        "stage_results": s.get("stage_results", []),
        "total_files":   s.get("total_files", 0),
        "finding_count": len(s.get("findings", [])),
    })


@app.route("/api/session/<session_id>/metrics")
def get_metrics(session_id: str):
    s = _get_session(session_id)
    return jsonify(_compute_metrics(s))


@app.route("/api/sessions")
def list_sessions():
    return jsonify({
        "sessions": [
            {
                "session_id": sid,
                "status":     s.get("status"),
                "repo_url":   s.get("repo_url", ""),
                "started_at": s.get("started_at", 0),
                "findings":   len(s.get("findings", [])),
            }
            for sid, s in _sessions.items()
        ]
    })


# ── SSE event stream ──────────────────────────────────────────────────────────

@app.route("/api/session/<session_id>/events")
def event_stream(session_id: str):
    """
    Server-Sent Events stream.  Merges:
      - pipeline log events  (from log_queue)
      - graph events         (from graph_queue)
      - metrics snapshots    (every 1s)
      - HITL state changes
    """
    s = _sessions.get(session_id)
    if not s:
        def empty():
            yield f"data: {json.dumps({'type':'error','payload':{'message':'Session not found'}})}\n\n"
        return Response(stream_with_context(empty()), mimetype="text/event-stream")

    def generate():
        last_metrics_ts = 0.0
        heartbeat_ts    = 0.0
        last_hitl       = s.get("hitl_state", "not_reached")
        idle_count      = 0

        while True:
            emitted = False
            now = time.time()

            # Drain log queue
            while True:
                try:
                    evt = s["log_queue"].get_nowait()
                    yield f"data: {json.dumps(evt)}\n\n"
                    emitted = True
                except queue.Empty:
                    break

            # Drain graph event queue
            batch = 0
            while batch < 50:
                try:
                    evt = s["graph_queue"].get_nowait()
                    yield f"data: {json.dumps(evt)}\n\n"
                    emitted = True
                    batch += 1
                except queue.Empty:
                    break

            # Emit metrics every 1s
            if now - last_metrics_ts >= 1.0:
                metrics = _compute_metrics(s)
                yield f"data: {json.dumps({'type': 'metrics_update', 'payload': metrics})}\n\n"
                last_metrics_ts = now
                emitted = True

            # Emit HITL state change
            current_hitl = s.get("hitl_state", "not_reached")
            if current_hitl != last_hitl:
                last_hitl = current_hitl
                yield f"data: {json.dumps({'type': 'hitl_state', 'payload': {'state': current_hitl, 'summary': _build_hitl_summary(s)}})}\n\n"
                emitted = True

            # Heartbeat every 15s
            if now - heartbeat_ts >= 15.0:
                yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
                heartbeat_ts = now

            if not emitted:
                idle_count += 1
            else:
                idle_count = 0

            status = s.get("status", "")
            if status in ("complete", "failed") and idle_count > 10:
                yield f"data: {json.dumps({'type': 'stream_end', 'payload': {'status': status}})}\n\n"
                break

            time.sleep(0.1)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",
            "Connection":        "keep-alive",
        },
    )


# ── Pipeline runners ──────────────────────────────────────────────────────────

def _push_log(s: dict, msg: str, level: str = "info", stage: str = "") -> None:
    s["log_queue"].put_nowait({
        "type":    "log",
        "level":   level,
        "message": msg,
        "stage":   stage,
        "ts":      round(time.time() * 1000),
    })


def _push_phase(s: dict, stage: str, label: str) -> None:
    s["graph_queue"].put_nowait({
        "type":    "phase",
        "payload": {"stage": stage, "label": label},
    })


def _push_node(s: dict, node_data: dict) -> None:
    s["graph_queue"].put_nowait({"type": "node", "payload": node_data})


def _push_edge(s: dict, edge_data: dict) -> None:
    s["graph_queue"].put_nowait({"type": "edge", "payload": edge_data})


def _push_finding(s: dict, finding: dict) -> None:
    s["graph_queue"].put_nowait({"type": "finding", "payload": finding})


def _push_annotation(s: dict, node_id: str, severity: str) -> None:
    s["graph_queue"].put_nowait({
        "type": "annotation",
        "payload": {"node_id": node_id, "annotated": True, "severity": severity},
    })


def _run_repo_pipeline(
    session:     dict,
    repo_url:    str,
    branch:      str,
    commit_sha:  str | None,
    token:       str,
    max_repo_mb: int,
) -> None:
    """Full repository pipeline running in a daemon thread."""
    # Import the real pipeline runner
    try:
        from backend.core.cpg_builder import run_real_pipeline
        run_real_pipeline(session, repo_url, branch, commit_sha, token, max_repo_mb)
    except ImportError:
        _push_log(session, "cpg_builder not importable — running minimal demo", "warning")
        _run_demo_pipeline(session, repo_url)


def _run_inline_pipeline(
    session: dict, code: str, language: str, filename: str
) -> None:
    """Inline code snippet analysis."""
    try:
        from backend.core.cpg_builder import _serialise_node, _serialise_edge, _serialise_finding, _VIS_MAX_NODES, _VIS_MAX_EDGES
        _push_phase(session, "PARSE", "Parsing inline snippet...")
        session["status"] = "running"

        if not _PARSER_AVAILABLE:
            _run_demo_pipeline(session, f"inline:{filename}")
            return

        registry = ParserRegistry()
        result = registry.parse_file(filename, source_code=code)

        _push_phase(session, "AST", "Extracting AST nodes...")
        nodes_vis = []
        edges_vis = []
        findings  = []
        seen_n:  set[str] = set()
        seen_e:  set[str] = set()

        backend_val = result.metadata.backend.value if hasattr(result.metadata.backend, "value") else ""

        for n in result.nodes[:_VIS_MAX_NODES]:
            nid = getattr(n, "node_id", "")
            if nid in seen_n: continue
            seen_n.add(nid)
            vis = _serialise_node(n, backend_val)
            nodes_vis.append(vis)
            _push_node(session, vis)

            f = _serialise_finding(n, session["session_id"])
            if f:
                findings.append(f)
                _push_annotation(session, nid, f["severity"])
                _push_finding(session, f)

        _push_phase(session, "CFG", "Building control flow...")
        for e in result.edges[:_VIS_MAX_EDGES]:
            eid = getattr(e, "edge_id", "")
            if eid in seen_e: continue
            src = getattr(e, "src_id", "")
            dst = getattr(e, "dst_id", "")
            if src not in seen_n or dst not in seen_n: continue
            seen_e.add(eid)
            vis = _serialise_edge(e)
            edges_vis.append(vis)
            _push_edge(session, vis)

        _push_phase(session, "ANNOTATE", "Annotating security labels...")
        _push_phase(session, "COMPLETE", "Analysis complete")

        session["graph"] = {
            "nodes": nodes_vis, "edges": edges_vis,
            "summary": {
                "node_count": len(nodes_vis),
                "edge_count": len(edges_vis),
                "finding_count": len(findings),
            }
        }
        session["findings"] = findings
        session["status"]   = "complete"
        session["total_files"] = 1

        session["graph_queue"].put_nowait({
            "type": "complete",
            "payload": {
                "node_count":    len(nodes_vis),
                "edge_count":    len(edges_vis),
                "finding_count": len(findings),
            },
        })

    except Exception as exc:
        log.exception("Inline pipeline error")
        session["status"] = "failed"
        session["error"]  = str(exc)
        session["graph_queue"].put_nowait({"type": "error", "payload": {"message": str(exc)}})


def _run_demo_pipeline(session: dict, repo_url: str) -> None:
    """Minimal demo when real pipeline is not available."""
    import random
    session["status"] = "running"

    stages = [
        ("PARSE",      "Initialising..."),
        ("AST",        "Parsing source files..."),
        ("NORMALIZE",  "Normalizing AST..."),
        ("CFG",        "Building control flow graph..."),
        ("DFG",        "Building data flow graph..."),
        ("CPG_MERGE",  "Assembling Code Property Graph..."),
        ("GRAPHCODEBERT", "Running GraphCodeBERT inference..."),
        ("ANNOTATE",   "Annotating vulnerability findings..."),
        ("COMPLETE",   "Analysis complete"),
    ]

    demo_nodes = []
    demo_edges = []

    for stage, label in stages:
        _push_phase(session, stage, label)
        time.sleep(0.3)

        if stage == "AST":
            for i in range(15):
                node = {
                    "id": f"demo_n_{i}",
                    "label": f"func_{i}" if i % 3 == 0 else f"call_{i}",
                    "color": {"background": "#6b7280" if i % 3 else "#ef4444"},
                    "meta": {
                        "file_path": "demo.py",
                        "start_line": i * 5 + 1,
                        "node_type": "FUNCTION" if i % 3 == 0 else "CALL",
                        "security_label": "NONE" if i % 3 else "SINK",
                        "cwe_hints": ["CWE-89"] if i % 7 == 0 else [],
                    },
                }
                demo_nodes.append(node)
                _push_node(session, node)

        if stage == "CFG":
            for i in range(10):
                edge = {
                    "id": f"demo_e_{i}",
                    "from": f"demo_n_{i}",
                    "to":   f"demo_n_{i+1}",
                    "label": "CFG_NEXT",
                    "color": {"color": "#60a5fa"},
                }
                demo_edges.append(edge)
                _push_edge(session, edge)

        if stage == "ANNOTATE":
            findings = [
                {
                    "node_id":     "demo_n_0",
                    "session_id":  session["session_id"],
                    "file_path":   "demo.py",
                    "start_line":  12,
                    "node_type":   "CALL",
                    "name":        "cursor.execute",
                    "label":       "SINK",
                    "severity":    "HIGH",
                    "confidence":  0.91,
                    "cwe_hints":   ["CWE-89"],
                    "description": "User-controlled data flows into a SQL query without parameterisation.",
                    "remediation": "Use parameterised queries.",
                    "references":  ["https://cwe.mitre.org/data/definitions/89.html"],
                },
            ]
            for f in findings:
                _push_annotation(session, f["node_id"], f["severity"])
                _push_finding(session, f)
            session["findings"] = findings

    session["graph"] = {
        "nodes": demo_nodes,
        "edges": demo_edges,
        "summary": {"node_count": len(demo_nodes), "edge_count": len(demo_edges), "finding_count": 1},
    }
    session["status"] = "complete"
    session["total_files"] = 5
    session["graph_queue"].put_nowait({
        "type": "complete",
        "payload": {"node_count": len(demo_nodes), "edge_count": len(demo_edges), "finding_count": 1},
    })


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_session(session_id: str) -> dict:
    s = _sessions.get(session_id)
    if not s:
        from flask import abort
        abort(404, description=f"Session '{session_id}' not found")
    return s


def _build_hitl_summary(s: dict) -> dict:
    findings = s.get("findings", [])
    cwe_counts: dict[str, int] = {}
    for f in findings:
        for cwe in (f.get("cwe_hints") or []):
            cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1

    graph = s.get("graph", {})
    summary = graph.get("summary", {})

    return {
        "cpg_nodes":      summary.get("node_count", 0),
        "cpg_edges":      summary.get("edge_count", 0),
        "finding_count":  len(findings),
        "high_severity":  sum(1 for f in findings if f.get("severity") == "HIGH"),
        "medium_severity":sum(1 for f in findings if f.get("severity") == "MEDIUM"),
        "top_cwes":       dict(sorted(cwe_counts.items(), key=lambda x: -x[1])[:5]),
        "stage_results":  s.get("stage_results", []),
        "tool_status":    s.get("tool_status", {}),
    }


def _compute_metrics(s: dict) -> dict:
    """Compute real-time performance metrics from session data."""
    findings = s.get("findings", [])
    graph    = s.get("graph", {})
    summary  = graph.get("summary", {})
    elapsed  = time.time() - s.get("started_at", time.time())

    total_files = s.get("total_files", 0) or 0
    total_nodes = summary.get("node_count", 0)
    total_edges = summary.get("edge_count", 0)

    # Graph density
    density = 0.0
    if total_nodes > 1:
        density = round(total_edges / (total_nodes * (total_nodes - 1) / 2), 6)

    # CWE breakdown
    cwe_counts: dict[str, int] = {}
    severity_conf: dict[str, list[float]] = {}
    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        conf = float(f.get("confidence", 0.0))
        severity_conf.setdefault(sev, []).append(conf)
        for cwe in (f.get("cwe_hints") or []):
            cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1

    # Stage latencies
    stage_latencies = {}
    for sr in s.get("stage_results", []):
        if isinstance(sr, dict):
            stage_latencies[sr.get("stage", "?")] = sr.get("duration_ms", 0)

    # Memory usage
    memory_mb = 0.0
    try:
        import psutil, os as _os
        proc = psutil.Process(_os.getpid())
        memory_mb = round(proc.memory_info().rss / (1024 * 1024), 1)
    except Exception:
        pass

    return {
        "session_id":       s.get("session_id", ""),
        "status":           s.get("status", "unknown"),
        "elapsed_s":        round(elapsed, 1),
        "total_files":      total_files,
        "total_nodes":      total_nodes,
        "total_edges":      total_edges,
        "finding_count":    len(findings),
        "high_severity":    sum(1 for f in findings if f.get("severity") == "HIGH"),
        "medium_severity":  sum(1 for f in findings if f.get("severity") == "MEDIUM"),
        "low_severity":     sum(1 for f in findings if f.get("severity") == "LOW"),
        "graph_density":    density,
        "files_per_second": round(total_files / elapsed, 2) if elapsed > 0 else 0,
        "nodes_per_second": round(total_nodes / elapsed, 2) if elapsed > 0 else 0,
        "cwe_breakdown":    dict(sorted(cwe_counts.items(), key=lambda x: -x[1])[:10]),
        "stage_latencies":  stage_latencies,
        "memory_mb":        memory_mb,
        "hitl_state":       s.get("hitl_state", "not_reached"),
        "backend_breakdown":s.get("backend_breakdown", {}),
        "avg_confidence": {
            sev: round(sum(confs) / len(confs), 3)
            for sev, confs in severity_conf.items() if confs
        },
    }


# ── gVisor sandbox helper ─────────────────────────────────────────────────────

def run_in_gvisor_sandbox(repo_dir: str, session_id: str, push_fn, push_progress_fn) -> str:
    """
    Isolate the repo in a gVisor (runsc) Docker container.
    Falls back to standard Docker if gVisor is not available.
    Falls back to direct analysis if Docker is not available.
    """
    import shutil as _shutil
    output_dir = tempfile.mkdtemp(prefix=f"prism_out_{session_id[:8]}_")

    if not _shutil.which("docker"):
        push_fn("⚠️ Docker not found — running on host directly", "warning", "sandbox")
        return repo_dir

    try:
        result = subprocess.run(
            ["docker", "info", "--format", "{{json .Runtimes}}"],
            capture_output=True, text=True, timeout=5,
        )
        use_gvisor = "runsc" in result.stdout
    except Exception:
        use_gvisor = False

    runtime_flags = ["--runtime=runsc"] if use_gvisor else []
    runtime_label = "gVisor (runsc)" if use_gvisor else "standard Docker"
    push_fn(f"🔒 Sandbox: {runtime_label}", "info", "sandbox")

    container = f"prism-sandbox-{session_id[:12]}"
    cmd = [
        "docker", "run", "--name", container, "--rm",
        *runtime_flags,
        "--network=none", "--read-only",
        "--tmpfs", "/tmp:size=256m",
        f"--volume={repo_dir}:/workspace:ro",
        f"--volume={output_dir}:/output:rw",
        "--memory=512m", "--cpus=1", "--user=nobody",
        "python:3.11-slim", "python3", "-c",
        "import shutil; shutil.copytree('/workspace','/output/repo',dirs_exist_ok=True); print('ok')",
    ]

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if res.returncode == 0 and "ok" in res.stdout:
            push_progress_fn("sandbox", 35)
            return os.path.join(output_dir, "repo")
        push_fn(f"⚠️ Sandbox exit {res.returncode} — falling back", "warning", "sandbox")
        return repo_dir
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True)
        push_fn("⚠️ Sandbox timeout — falling back", "warning", "sandbox")
        return repo_dir
    except Exception as exc:
        push_fn(f"⚠️ Sandbox error ({exc}) — falling back", "warning", "sandbox")
        return repo_dir


if __name__ == "__main__":
    port  = int(os.environ.get("PORT", 5001))
    debug = os.environ.get("DEBUG", "false").lower() == "true"
    log.info("PRISM UI starting on http://0.0.0.0:%d  debug=%s", port, debug)
    app.run(host="0.0.0.0", port=port, debug=debug, threaded=True)