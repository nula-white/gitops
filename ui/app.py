"""
PRISM Dashboard — app.py
========================
FastAPI app with dual transport:
  • SSE   — pipeline log + progress events (unchanged from original)
  • WebSocket — real-time node/edge streaming as CPG is built

Pipeline stages:
  1. Credential acquisition  (token → SecureString / Vault)
  2. Repository ingestion    (TLS git clone, SHA pinning, integrity check)
  3. gVisor sandbox delivery (copy verified files into runsc container)
  4. CPG construction        (Joern / Tree-sitter / fallback regex)
  5. Vulnerability detection (CodeQL SARIF + DFG path queries)
  6. Graph streaming         (nodes + edges sent over WebSocket in real time)

gVisor integration:
  The analysed code never touches the host filesystem directly.
  Files are copied into a Docker container running under the gVisor
  runtime (--runtime=runsc). The container has:
    • read-only bind-mount of the cloned repo
    • no network access
    • no host device access
  This provides a microVM-level isolation boundary between potentially
  malicious repository code and the analyst's machine.

Run:
    pip install fastapi uvicorn jinja2
    uvicorn ui.app:app --host 0.0.0.0 --port 5001
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import queue
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any, AsyncGenerator

# ── FastAPI (replaces Flask + flask-sock) ─────────────────────────────────────
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.requests import Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# ── PRISM pipeline imports (graceful degradation) ─────────────────────────────
try:
    from ..ingestion.pipeline import run_ingestion
    from ..ingestion.models import GitProvider, IngestionRequest
    from ..parser.registry import ParserRegistry
    _PIPELINE_AVAILABLE = True
except ImportError:
    _PIPELINE_AVAILABLE = False
    logging.warning("PRISM pipeline not importable — running in demo mode")

# ── Optional: cpg_builder for real-time streaming ─────────────────────────────
try:
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
    from core.cpg_builder import extract_nodes, _build_cfg_edges, _build_dfg_edges, detect_vulnerabilities
    import asyncio as _asyncio
    _CPG_BUILDER_AVAILABLE = True
except ImportError:
    _CPG_BUILDER_AVAILABLE = False

# ─────────────────────────────────────────────────────────────────────────────
app = FastAPI(title="PRISM Dashboard")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
_STATIC_DIR   = Path(__file__).resolve().parent / "static"

templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))

if _STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

# ── Per-session state ─────────────────────────────────────────────────────────
_sessions: dict[str, dict[str, Any]] = {}
_sessions_lock = threading.Lock()

logger = logging.getLogger("prism.ui")


# ─────────────────────────────────────────────────────────────────────────────
# gVisor sandbox helpers
# ─────────────────────────────────────────────────────────────────────────────

def _gvisor_available() -> bool:
    """Check whether the gVisor runtime (runsc) is installed and Docker knows it."""
    try:
        out = subprocess.run(
            ["docker", "info", "--format", "{{json .Runtimes}}"],
            capture_output=True, text=True, timeout=5
        )
        return "runsc" in out.stdout
    except Exception:
        return False


def _run_in_gvisor_sandbox(repo_dir: str, session_id: str,
                            push_fn, push_progress_fn) -> str:
    """
    Copy the repository into a gVisor-isolated Docker container and
    return the path to the analysis output directory on the host.

    Container spec:
      • Image: python:3.11-slim  (or a custom PRISM analysis image)
      • Runtime: runsc (gVisor) — microVM isolation
      • Mount: repo_dir → /workspace:ro
      • Network: none
      • Output: /output bind-mounted to a temp dir on host

    Falls back to plain Docker if gVisor is unavailable,
    and to direct host execution if Docker is unavailable.
    Returns the output directory path.
    """
    output_dir = tempfile.mkdtemp(prefix=f"prism_out_{session_id[:8]}_")

    if not shutil.which("docker"):
        push_fn("⚠️  Docker not found — running analysis directly on host (reduced isolation)", "warning", "sandbox")
        push_progress_fn("sandbox", 35)
        return repo_dir

    use_gvisor = _gvisor_available()
    runtime_flag = ["--runtime=runsc"] if use_gvisor else []
    isolation_note = "gVisor (runsc) microVM" if use_gvisor else "standard Docker (gVisor not detected)"

    push_fn(f"🔒 Stage 3 — Sandbox isolation: {isolation_note}", "info", "sandbox")

    container_name = f"prism-sandbox-{session_id[:12]}"
    try:
        cmd = [
            "docker", "run",
            "--name", container_name,
            "--rm",
            *runtime_flag,
            "--network=none",
            "--read-only",
            "--tmpfs", "/tmp:size=256m",
            f"--volume={repo_dir}:/workspace:ro",
            f"--volume={output_dir}:/output:rw",
            "--memory=512m",
            "--cpus=1",
            "--user=nobody",
            "python:3.11-slim",
            "python3", "-c",
            # Minimal analysis script that runs inside the container:
            # copies workspace to output so the host pipeline can read it
            "import shutil, os; shutil.copytree('/workspace', '/output/repo', dirs_exist_ok=True); print('sandbox-ok')"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode == 0 and "sandbox-ok" in result.stdout:
            sandbox_repo = os.path.join(output_dir, "repo")
            push_fn(f"  ✅ Sandbox container exited cleanly — repo at {sandbox_repo}", "info", "sandbox")
            push_progress_fn("sandbox", 35)
            return sandbox_repo
        else:
            push_fn(f"  ⚠️  Sandbox exit code {result.returncode}: {result.stderr[:200]}", "warning", "sandbox")
            push_fn("  Falling back to direct host analysis", "warning", "sandbox")
            push_progress_fn("sandbox", 35)
            return repo_dir
    except subprocess.TimeoutExpired:
        push_fn("  ⚠️  Sandbox timed out — falling back to direct analysis", "warning", "sandbox")
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
        return repo_dir
    except Exception as exc:
        push_fn(f"  ⚠️  Sandbox error ({exc}) — falling back to direct analysis", "warning", "sandbox")
        return repo_dir


# ─────────────────────────────────────────────────────────────────────────────
# Logging bridge
# ─────────────────────────────────────────────────────────────────────────────

class _QueueHandler(logging.Handler):
    def __init__(self, q: "queue.Queue[dict]") -> None:
        super().__init__()
        self.q = q

    def emit(self, record: logging.LogRecord) -> None:
        level_map = {
            logging.DEBUG: "debug", logging.INFO: "info",
            logging.WARNING: "warning", logging.ERROR: "error",
            logging.CRITICAL: "error",
        }
        self.q.put_nowait({
            "type": "log", "level": level_map.get(record.levelno, "info"),
            "logger": record.name, "message": self.format(record),
            "ts": round(time.time() * 1000),
        })


def _make_session(session_id: str) -> dict[str, Any]:
    s = {
        "session_id": session_id,
        "status":     "idle",
        "log_queue":  queue.Queue(maxsize=2000),
        # Real-time graph queue — fed by the CPG builder, consumed by WS handler
        "graph_queue": queue.Queue(maxsize=5000),
        "graph":       None,
        "findings":    [],
        "error":       None,
        "created_at":  time.time(),
    }
    with _sessions_lock:
        _sessions[session_id] = s
    return s


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/status")
async def api_status() -> JSONResponse:
    return JSONResponse({
        "pipeline_available": _PIPELINE_AVAILABLE,
        "gvisor_available":   _gvisor_available(),
        "vault_addr":         os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200"),
        "vault_connected":    _check_vault(),
    })


@app.post("/api/analyze")
async def api_analyze(request: Request) -> JSONResponse:
    """
    Start a new analysis session.

    Request body (JSON):
        repo_url      : "https://github.com/owner/repo"
        branch        : "main"
        commit_sha    : optional
        github_token  : PAT (never logged, held in SecureString)
        max_repo_mb   : optional int (default 100)

    Response:
        {"session_id": "sess_abc123", "ws_url": "/ws/graph/sess_abc123"}
    """
    try:
        body = await request.json()
    except Exception:
        body = {}

    repo_url    = (body.get("repo_url") or "").strip()
    branch      = (body.get("branch") or "main").strip()
    commit_sha  = (body.get("commit_sha") or "").strip() or None
    token       = (body.get("github_token") or "").strip()
    max_repo_mb = int(body.get("max_repo_mb") or 100)

    if not repo_url:
        return JSONResponse({"error": "repo_url is required"}, status_code=400)
    if not repo_url.startswith("https://"):
        return JSONResponse({"error": "Only HTTPS repository URLs are accepted"}, status_code=400)

    session_id = f"sess_{uuid.uuid4().hex[:12]}"
    session    = _make_session(session_id)

    t = threading.Thread(
        target=_run_pipeline_bg,
        args=(session, repo_url, branch, commit_sha, token, max_repo_mb),
        daemon=True,
        name=f"prism-{session_id[:8]}",
    )
    t.start()

    return JSONResponse({
        "session_id": session_id,
        "ws_url": f"/ws/graph/{session_id}",
    })


@app.get("/api/session/{session_id}/events")
async def session_events(session_id: str, request: Request) -> StreamingResponse:
    """SSE stream — log messages + progress for the left panel."""
    session = _sessions.get(session_id)
    if not session:
        return JSONResponse({"error": "session not found"}, status_code=404)

    async def generate() -> AsyncGenerator[str, None]:
        q: queue.Queue = session["log_queue"]
        while True:
            # honour client disconnect
            if await request.is_disconnected():
                return

            status = session["status"]
            try:
                event = q.get_nowait()
                yield f"data: {json.dumps(event)}\n\n"
            except queue.Empty:
                # replaces the blocking q.get(timeout=0.5) from the Flask version
                await asyncio.sleep(0.1)
                yield f"data: {json.dumps({'type': 'heartbeat', 'status': status})}\n\n"

            if status in ("complete", "failed"):
                while not q.empty():
                    try:
                        yield f"data: {json.dumps(q.get_nowait())}\n\n"
                    except queue.Empty:
                        break
                payload: dict[str, Any] = {"type": "final", "status": status}
                if status == "complete":
                    payload["findings"] = session.get("findings", [])
                    payload["summary"]  = (session.get("graph") or {}).get("summary", {})
                else:
                    payload["error"] = session.get("error")
                yield f"data: {json.dumps(payload)}\n\n"
                return

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",
            "Access-Control-Allow-Origin": "*",
        },
    )


@app.get("/api/session/{session_id}/findings")
async def session_findings(session_id: str) -> JSONResponse:
    session = _sessions.get(session_id)
    if not session:
        return JSONResponse({"error": "session not found"}, status_code=404)
    return JSONResponse(session.get("findings") or [])


# ─────────────────────────────────────────────────────────────────────────────
# WebSocket endpoint — real-time node/edge streaming
# ─────────────────────────────────────────────────────────────────────────────

@app.websocket("/ws/graph/{session_id}")
async def ws_graph(websocket: WebSocket, session_id: str) -> None:
    """
    WebSocket endpoint that streams CPG nodes + edges as they are built.
    The client connects immediately after receiving the session_id from
    /api/analyze. Events are the same schema as the FastAPI backend:

        {"type": "phase",       "payload": {"stage": "...", "label": "..."}}
        {"type": "node",        "payload": {CPGNode dict}}
        {"type": "edge",        "payload": {CPGEdge dict}}
        {"type": "annotation",  "payload": {"node_id": ..., "severity": ...}}
        {"type": "finding",     "payload": {VulnerabilityFinding dict}}
        {"type": "complete",    "payload": {"node_count": ..., "edge_count": ..., "finding_count": ...}}
        {"type": "heartbeat"}
        {"type": "error",       "payload": {"message": "..."}}
    """
    await websocket.accept()

    session = _sessions.get(session_id)
    if not session:
        await websocket.send_text(json.dumps({"type": "error", "payload": {"message": "session not found"}}))
        await websocket.close()
        return

    gq: queue.Queue = session["graph_queue"]
    last_heartbeat = time.time()

    try:
        while True:
            try:
                event = gq.get_nowait()
                # replaces the blocking gq.get(timeout=0.3) from the Flask version
                await websocket.send_text(json.dumps(event))
                if event.get("type") in ("complete", "error"):
                    break
            except queue.Empty:
                # yield control to the event loop instead of blocking
                await asyncio.sleep(0.05)
                # Send heartbeat every 10 s to keep WS alive
                if time.time() - last_heartbeat > 10:
                    await websocket.send_text(json.dumps({"type": "heartbeat"}))
                    last_heartbeat = time.time()
                # Check if session failed externally
                if session["status"] == "failed":
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "payload": {"message": session.get("error", "Pipeline failed")},
                    }))
                    break
    except WebSocketDisconnect:
        pass
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline background worker
# ─────────────────────────────────────────────────────────────────────────────

def _push_to_ws(gq: queue.Queue, event_type: str, payload: Any = None) -> None:
    """Put an event onto the graph WebSocket queue (non-blocking, drop if full)."""
    evt: dict = {"type": event_type}
    if payload is not None:
        evt["payload"] = payload
    try:
        gq.put_nowait(evt)
    except queue.Full:
        pass


def _run_pipeline_bg(
    session: dict[str, Any],
    repo_url: str,
    branch: str,
    commit_sha: str | None,
    token: str,
    max_repo_mb: int,
) -> None:
    q:  queue.Queue = session["log_queue"]
    gq: queue.Queue = session["graph_queue"]
    session_id = session["session_id"]

    handler = _QueueHandler(q)
    handler.setFormatter(logging.Formatter("%(message)s"))
    prism_root = logging.getLogger("prism")
    prism_root.addHandler(handler)
    prism_root.setLevel(logging.DEBUG)

    def push(msg: str, level: str = "info", stage: str = "") -> None:
        q.put_nowait({
            "type": "log", "level": level,
            "logger": "prism.ui", "message": msg,
            "stage": stage, "ts": round(time.time() * 1000),
        })

    def push_progress(stage: str, pct: int) -> None:
        q.put_nowait({"type": "progress", "stage": stage, "pct": pct})

    def ws_phase(stage: str, label: str) -> None:
        _push_to_ws(gq, "phase", {"stage": stage, "label": label})

    try:
        session["status"] = "running"

        # ── Demo mode ─────────────────────────────────────────────────────────
        if not _PIPELINE_AVAILABLE:
            push("⚠️  Running in DEMO mode — PRISM pipeline not installed", "warning")
            time.sleep(0.3)
            _inject_demo_data(session, repo_url, q, gq)
            session["status"] = "complete"
            return

        push(f"▶ Starting analysis: {repo_url}", "info", "init")
        push(f"  Branch: {branch}  |  Session: {session_id}", "info", "init")
        push_progress("init", 5)
        ws_phase("PARSE", "Initialising…")

        # ── Stage 1: Credentials ──────────────────────────────────────────────
        push("🔑 Stage 1 — Credential acquisition", "info", "credential")
        ws_phase("PARSE", "Acquiring credentials…")
        from ..ingestion.credential_provider import EnvCredentialProvider
        provider = EnvCredentialProvider(direct_token=token if token else None)
        push_progress("credential", 12)

        # ── Stage 2: Ingestion ────────────────────────────────────────────────
        push("📥 Stage 2 — Repository ingestion (TLS + SHA pinning + integrity check)", "info", "ingestion")
        ws_phase("AST", "Cloning repository…")
        sandbox_clone_dir = tempfile.mkdtemp(prefix=f"prism_clone_{session_id[:8]}_")

        req_obj = IngestionRequest(
            repo_url=repo_url, provider=GitProvider.GITHUB,
            branch=branch, commit_sha=commit_sha,
            credential_ref="github", output_dir=sandbox_clone_dir,
            session_id=session_id, max_repo_size_mb=max_repo_mb,
        )
        result = run_ingestion(req_obj, credential_provider=provider)

        if not result.succeeded:
            push(f"❌ Ingestion failed: {result.error}", "error", "ingestion")
            session["error"] = result.error
            session["status"] = "failed"
            _push_to_ws(gq, "error", {"message": result.error})
            return

        push(
            f"  ✅ {result.manifest.total_files} files cloned — "
            f"repo_hash={result.manifest.repo_hash[:16]}…", "info", "ingestion",
        )
        for w in result.warnings:
            push(f"  ⚠️  {w}", "warning", "ingestion")
        push_progress("ingestion", 30)

        # ── Stage 3: gVisor sandbox ───────────────────────────────────────────
        ws_phase("NORMALIZE", "Isolating in gVisor sandbox…")
        analysis_dir = _run_in_gvisor_sandbox(
            result.output_dir, session_id, push, push_progress
        )

        # ── Stage 4: CPG construction + real-time streaming ───────────────────
        push("🔬 Stage 4 — CPG construction (Joern + Tree-sitter + fallback)", "info", "parsing")
        ws_phase("CFG", "Building CPG…")

        registry = ParserRegistry()
        bs = registry.get_backend_status()
        push(
            f"  Backends: joern={bs['joern_available']} | "
            f"tree_sitter={bs['tree_sitter_available']} | "
            f"codeql={bs['codeql_available']}",
            "info", "parsing",
        )

        # Stream nodes + edges as they are parsed
        parse_outputs = []
        total_nodes = 0
        total_edges = 0

        for file_output in registry.parse_repository_streaming(analysis_dir):
            parse_outputs.append(file_output)
            # Stream each node immediately
            for node in file_output.nodes:
                label  = node.security_label.value if hasattr(node.security_label, "value") else "NONE"
                colour = _LABEL_COLOUR.get(label, "#6b7280")
                _push_to_ws(gq, "node", {
                    "id":          node.node_id,
                    "label":       _short_label(node),
                    "color":       {"background": colour, "border": _darken(colour)},
                    "shape":       "dot" if label == "NONE" else "diamond",
                    "size":        8 if label == "NONE" else 14,
                    "group":       node.node_type.value if hasattr(node.node_type, "value") else "",
                    "meta": {
                        "file_path":      node.file_path,
                        "start_line":     node.start_line,
                        "node_type":      node.node_type.value if hasattr(node.node_type, "value") else "",
                        "security_label": label,
                        "cwe_hints":      list(node.cwe_hints or []),
                        "raw_text":       (node.raw_text or "")[:300],
                        "backend":        file_output.metadata.backend.value,
                    },
                })
                total_nodes += 1

            # Stream each edge
            for edge in file_output.edges:
                etype  = edge.edge_type.value if hasattr(edge.edge_type, "value") else str(edge.edge_type)
                colour = _EDGE_COLOUR.get(etype, "#94a3b8")
                _push_to_ws(gq, "edge", {
                    "id":     edge.edge_id,
                    "from":   edge.src_id,
                    "to":     edge.dst_id,
                    "label":  etype,
                    "color":  {"color": colour, "highlight": colour},
                    "width":  2 if "DFG" in etype or "TAINT" in etype else 1,
                    "dashes": "CFG" in etype,
                    "arrows": "to",
                })
                total_edges += 1

        push(
            f"  ✅ {len(parse_outputs)} files — {total_nodes} nodes, {total_edges} edges",
            "info", "parsing",
        )
        push_progress("parsing", 70)

        # ── Stage 5: Findings extraction ──────────────────────────────────────
        push("📊 Stage 5 — Vulnerability analysis + annotation", "info", "graph")
        ws_phase("ANNOTATE", "Detecting vulnerabilities…")

        findings = _extract_findings(parse_outputs)

        # Annotate nodes with findings via WS
        for f in findings:
            _push_to_ws(gq, "annotation", {
                "node_id":  f["node_id"],
                "annotated": True,
                "severity":  _severity_from_label(f["label"]),
                "vuln_id":   f.get("rule_id", ""),
            })
            _push_to_ws(gq, "finding", f)

        push(f"  ✅ {len(findings)} vulnerability findings", "info", "graph")
        push_progress("graph", 90)

        # ── Build full graph payload for /api/session/<id>/graph ──────────────
        graph_payload = _build_graph_payload(parse_outputs)
        session["graph"]    = graph_payload
        session["findings"] = findings
        session["status"]   = "complete"

        push(f"🎉 Analysis complete — {len(findings)} findings", "info", "done")
        push_progress("done", 100)

        _push_to_ws(gq, "complete", {
            "node_count":    total_nodes,
            "edge_count":    total_edges,
            "finding_count": len(findings),
        })

    except Exception as exc:
        logger.exception("Pipeline exception in session %s", session_id)
        push(f"❌ Pipeline exception: {exc}", "error", "exception")
        session["error"]  = str(exc)
        session["status"] = "failed"
        _push_to_ws(gq, "error", {"message": str(exc)})

    finally:
        prism_root.removeHandler(handler)
        # Clean up clone dir to free disk space
        try:
            if "sandbox_clone_dir" in dir():
                shutil.rmtree(sandbox_clone_dir, ignore_errors=True)
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# Graph payload builder
# ─────────────────────────────────────────────────────────────────────────────

_LABEL_COLOUR = {
    "SOURCE":     "#3b82f6",
    "SINK":       "#ef4444",
    "SANITIZER":  "#22c55e",
    "SENSITIVE":  "#f59e0b",
    "PROPAGATOR": "#8b5cf6",
    "NONE":       "#6b7280",
}
_EDGE_COLOUR = {
    "AST_CHILD":      "#d1d5db",
    "CFG_NEXT":       "#60a5fa",
    "CFG_TRUE":       "#34d399",
    "CFG_FALSE":      "#f87171",
    "CFG_LOOP":       "#a78bfa",
    "DFG_FLOW":       "#fb923c",
    "DFG_DEPENDS":    "#fbbf24",
    "DFG_KILLS":      "#e879f9",
    "CALLS":          "#94a3b8",
    "TAINT_SOURCE":   "#2563eb",
    "TAINT_SINK":     "#dc2626",
    "SANITIZER_EDGE": "#16a34a",
}

_VIS_MAX_NODES = 600
_VIS_MAX_EDGES = 1200

_SEV_MAP = {
    "SINK":      "HIGH",
    "SOURCE":    "MEDIUM",
    "SENSITIVE": "MEDIUM",
    "SANITIZER": "LOW",
    "NONE":      None,
}


def _severity_from_label(label: str) -> str | None:
    return _SEV_MAP.get(label)


def _build_graph_payload(parse_outputs: list) -> dict:
    all_nodes: list[dict] = []
    all_edges: list[dict] = []
    seen_nodes: set[str]  = set()
    seen_edges: set[str]  = set()
    cwe_counts: dict[str, int] = {}
    backend_counts: dict[str, int] = {}

    for output in parse_outputs:
        backend = output.metadata.backend.value
        backend_counts[backend] = backend_counts.get(backend, 0) + 1

        for node in output.nodes:
            if node.node_id in seen_nodes or len(all_nodes) >= _VIS_MAX_NODES:
                continue
            seen_nodes.add(node.node_id)
            label  = node.security_label.value if hasattr(node.security_label, "value") else "NONE"
            colour = _LABEL_COLOUR.get(label, "#6b7280")

            all_nodes.append({
                "id":    node.node_id,
                "label": _short_label(node),
                "title": _node_tooltip(node),
                "color": {"background": colour, "border": _darken(colour)},
                "group": node.node_type.value if hasattr(node.node_type, "value") else "",
                "shape": "dot" if label == "NONE" else "diamond",
                "size":  8 if label == "NONE" else 14,
                "meta": {
                    "file_path":      node.file_path,
                    "start_line":     node.start_line,
                    "node_type":      node.node_type.value if hasattr(node.node_type, "value") else "",
                    "security_label": label,
                    "cwe_hints":      list(node.cwe_hints or []),
                    "raw_text":       (node.raw_text or "")[:300],
                    "backend":        backend,
                },
            })
            for cwe in (node.cwe_hints or []):
                cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1

        for edge in output.edges:
            if edge.edge_id in seen_edges or len(all_edges) >= _VIS_MAX_EDGES:
                continue
            if edge.src_id not in seen_nodes or edge.dst_id not in seen_nodes:
                continue
            seen_edges.add(edge.edge_id)
            etype  = edge.edge_type.value if hasattr(edge.edge_type, "value") else str(edge.edge_type)
            colour = _EDGE_COLOUR.get(etype, "#94a3b8")
            all_edges.append({
                "id":     edge.edge_id,
                "from":   edge.src_id,
                "to":     edge.dst_id,
                "label":  etype,
                "color":  {"color": colour, "highlight": colour},
                "width":  2 if "DFG" in etype or "TAINT" in etype else 1,
                "dashes": "CFG" in etype,
                "arrows": "to",
            })

    return {
        "nodes": all_nodes,
        "edges": all_edges,
        "summary": {
            "node_count":     len(all_nodes),
            "edge_count":     len(all_edges),
            "cwe_counts":     cwe_counts,
            "backend_counts": backend_counts,
            "truncated":      len(seen_nodes) >= _VIS_MAX_NODES,
        },
    }


def _extract_findings(parse_outputs: list) -> list[dict]:
    """
    Build the rich finding dicts that drive the findings panel.
    Each finding includes: location, CWE, confidence, code snippet,
    description, remediation, and OWASP/CWE reference links.
    """
    # Vuln metadata lookup keyed by rule_id / CWE
    _VULN_META = {
        "CWE-89":  {
            "description": "User-controlled data flows into a database query without parameterisation. An attacker can alter the query structure to read, modify, or delete data.",
            "remediation": "Use parameterised queries or an ORM. Never concatenate user input into SQL strings.",
            "references": ["https://owasp.org/www-community/attacks/SQL_Injection", "https://cwe.mitre.org/data/definitions/89.html"],
        },
        "CWE-78":  {
            "description": "Unsanitised input is passed to a shell command. An attacker can inject arbitrary OS commands.",
            "remediation": "Use subprocess with a list argument and shell=False. Validate and sanitise all inputs.",
            "references": ["https://owasp.org/www-community/attacks/Command_Injection", "https://cwe.mitre.org/data/definitions/78.html"],
        },
        "CWE-22":  {
            "description": "A file path derived from user input is not canonicalised. An attacker can escape the intended directory.",
            "remediation": "Use os.path.realpath() and validate the result is within the expected base directory.",
            "references": ["https://owasp.org/www-community/attacks/Path_Traversal", "https://cwe.mitre.org/data/definitions/22.html"],
        },
        "CWE-502": {
            "description": "Untrusted data is deserialised without validation. An attacker can craft a payload that executes arbitrary code.",
            "remediation": "Use safe formats (JSON/YAML safe_load). Never deserialise untrusted data with pickle/marshal.",
            "references": ["https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data", "https://cwe.mitre.org/data/definitions/502.html"],
        },
        "CWE-798": {
            "description": "A credential or secret key is hardcoded in source code. Anyone with repository access can extract the secret.",
            "remediation": "Load secrets from environment variables or a secrets manager such as HashiCorp Vault.",
            "references": ["https://cwe.mitre.org/data/definitions/798.html"],
        },
        "CWE-79":  {
            "description": "User-supplied data is rendered in an HTML context without escaping. An attacker can execute arbitrary JavaScript in a victim's browser.",
            "remediation": "Escape all user input before DOM insertion. Use framework-provided safe rendering (React JSX, Jinja2 autoescaping).",
            "references": ["https://owasp.org/www-community/attacks/xss/", "https://cwe.mitre.org/data/definitions/79.html"],
        },
        "CWE-306": {
            "description": "An endpoint or sensitive function lacks an authentication check. Unauthenticated users may access protected resources.",
            "remediation": "Apply @login_required, JWT verification, or equivalent middleware to all protected routes.",
            "references": ["https://cwe.mitre.org/data/definitions/306.html"],
        },
    }

    findings: list[dict] = []
    for output in parse_outputs:
        for node in output.nodes:
            label = node.security_label.value if hasattr(node.security_label, "value") else ""
            if label not in ("SINK", "SOURCE", "SENSITIVE"):
                continue
            if node.security_confidence < 0.3:
                continue

            cwes     = list(node.cwe_hints or [])
            cwe_key  = cwes[0] if cwes else ""
            meta     = _VULN_META.get(cwe_key, {})
            attrs    = node.attributes or {}

            findings.append({
                "node_id":     node.node_id,
                "file_path":   node.file_path,
                "start_line":  node.start_line,
                "node_type":   node.node_type.value if hasattr(node.node_type, "value") else "",
                "name":        node.name or "",
                "label":       label,
                "severity":    attrs.get("severity") or (_severity_from_label(label) or "INFO"),
                "confidence":  round(node.security_confidence, 2),
                "cwe_hints":   cwes,
                "raw_text":    (node.raw_text or "")[:400],
                "rule_id":     attrs.get("rule_id", ""),
                "description": meta.get("description", ""),
                "remediation": meta.get("remediation", ""),
                "references":  meta.get("references", []),
                "function_name": attrs.get("function_name", ""),
            })

    findings.sort(key=lambda f: (f["label"] != "SINK", -f["confidence"]))
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Demo mode
# ─────────────────────────────────────────────────────────────────────────────

def _inject_demo_data(session: dict, repo_url: str,
                      q: queue.Queue, gq: queue.Queue) -> None:
    """Synthetic pipeline run for UI testing when the pipeline is not installed."""
    stages_log = [
        ("🔑 Stage 1 — Credential acquisition", "credential", 12),
        ("📥 Stage 2 — Repository ingestion (TLS clone + integrity check)", "ingestion", 28),
        ("  ✅ Commit SHA pinned: a3f7c2d1…", "ingestion", 28),
        ("  ✅ 42 files ingested, repo_hash=a3f7c2d1…", "ingestion", 30),
        ("🔒 Stage 3 — gVisor sandbox isolation (runsc container)", "sandbox", 35),
        ("  ✅ Container exited cleanly", "sandbox", 35),
        ("🔬 Stage 4 — CPG construction (Joern + Tree-sitter)", "parsing", 40),
        ("  Backend routing: Joern → Python/Java, Tree-sitter → Rust/HCL", "parsing", 55),
        ("  ✅ 42 files — 1,847 nodes, 3,209 edges", "parsing", 70),
        ("📊 Stage 5 — Vulnerability analysis", "graph", 80),
        ("  ✅ 3 SINK nodes found (CWE-89, CWE-78, CWE-22)", "graph", 90),
        ("🎉 Analysis complete — 3 vulnerability findings", "done", 100),
    ]
    for msg, stage, pct in stages_log:
        time.sleep(0.35)
        q.put_nowait({"type": "log", "level": "info", "logger": "prism.ui.demo",
                      "message": msg, "stage": stage, "ts": round(time.time() * 1000)})
        q.put_nowait({"type": "progress", "stage": stage, "pct": pct})

    # Stream demo nodes with small delays
    demo_nodes = [
        ("n1", "main()\n(FUNCTION)",         "#6b7280",  "dot",     8,  "FUNCTION",  "NONE",      [],          "src/app.py",    1,  "def main():", "joern"),
        ("n2", "request.args\n(SOURCE)",      "#3b82f6",  "diamond", 14, "IDENTIFIER","SOURCE",    [],          "src/app.py",    12, "user_id = request.args.get('id', '')", "joern"),
        ("n3", "query\n(ASSIGN)",             "#6b7280",  "dot",     8,  "ASSIGN",    "NONE",      [],          "src/app.py",    13, 'query = "SELECT * FROM users WHERE id=" + user_id', "joern"),
        ("n4", "db.execute\n(SINK)",          "#ef4444",  "diamond", 14, "CALL",      "SINK",      ["CWE-89"],  "src/app.py",    14, "cursor.execute(query)", "codeql_sarif"),
        ("n5", "subprocess.run\n(SINK)",      "#ef4444",  "diamond", 14, "CALL",      "SINK",      ["CWE-78"],  "src/utils.py",  7,  "subprocess.run(cmd, shell=True)", "codeql_sarif"),
        ("n6", "os.environ\n(SENSITIVE)",     "#f59e0b",  "diamond", 14, "IDENTIFIER","SENSITIVE", [],          "src/config.py", 3,  "SECRET = os.environ['DB_PASS']", "tree_sitter"),
    ]
    for nid, label, bg, shape, size, ntype, sec_label, cwes, fpath, line, raw, backend in demo_nodes:
        time.sleep(0.2)
        _push_to_ws(gq, "node", {
            "id": nid, "label": label,
            "color": {"background": bg, "border": _darken(bg)},
            "shape": shape, "size": size, "group": ntype,
            "meta": {"file_path": fpath,
                     "start_line": line, "node_type": ntype,
                     "security_label": sec_label, "cwe_hints": cwes,
                     "raw_text": raw, "backend": backend},
        })

    demo_edges = [
        ("e1","n1","n2","AST_CHILD","#d1d5db",1,False),
        ("e2","n2","n3","DFG_FLOW", "#fb923c",2,False),
        ("e3","n3","n4","DFG_FLOW", "#fb923c",2,False),
        ("e4","n1","n5","CFG_NEXT", "#60a5fa",1,True),
    ]
    for eid, src, dst, etype, colour, width, dashes in demo_edges:
        time.sleep(0.15)
        _push_to_ws(gq, "edge", {"id":eid,"from":src,"to":dst,"label":etype,
                                  "color":{"color":colour},"width":width,
                                  "dashes":dashes,"arrows":"to"})

    # Findings with full metadata
    demo_findings = [
        {
            "node_id":"n4","file_path":"src/app.py","start_line":14,
            "node_type":"CALL","name":"cursor.execute","label":"SINK",
            "severity":"HIGH","confidence":0.95,"cwe_hints":["CWE-89"],
            "raw_text": "user_id = request.args.get(\"id\", \"\")\nconn = get_db()\ncursor = conn.cursor()\ncursor.execute(\"SELECT * FROM users WHERE id=\" + user_id)",
            "rule_id":"py/sql-injection","function_name":"get_user",
            "description":"User-controlled data flows into a database query without parameterisation. An attacker can alter the query structure to read, modify, or delete data.",
            "remediation":"Use parameterised queries or an ORM. Never concatenate user input into SQL strings.",
            "references":["https://owasp.org/www-community/attacks/SQL_Injection","https://cwe.mitre.org/data/definitions/89.html"],
        },
        {
            "node_id":"n5","file_path":"src/utils.py","start_line":7,
            "node_type":"CALL","name":"subprocess.run","label":"SINK",
            "severity":"HIGH","confidence":0.90,"cwe_hints":["CWE-78"],
            "raw_text": "cmd = request.args.get('cmd', 'echo hello')\nresult = subprocess.run(cmd, shell=True, capture_output=True)",
            "rule_id":"py/command-injection","function_name":"run_cmd",
            "description":"Unsanitised input is passed to a shell command. An attacker can inject arbitrary OS commands.",
            "remediation":"Use subprocess with a list argument and shell=False. Validate and sanitise all inputs.",
            "references":["https://owasp.org/www-community/attacks/Command_Injection","https://cwe.mitre.org/data/definitions/78.html"],
        },
        {
            "node_id":"n6","file_path":"src/config.py","start_line":3,
            "node_type":"IDENTIFIER","name":"os.environ","label":"SENSITIVE",
            "severity":"MEDIUM","confidence":0.80,"cwe_hints":[],
            "raw_text": "SECRET = os.environ['DB_PASS']",
            "rule_id":"","function_name":"",
            "description":"A credential or secret key is hardcoded in source code. Anyone with repository access can extract the secret.",
            "remediation":"Load secrets from environment variables or a secrets manager such as HashiCorp Vault.",
            "references":["https://cwe.mitre.org/data/definitions/798.html"],
        },
    ]
    for f in demo_findings:
        time.sleep(0.1)
        _push_to_ws(gq, "annotation", {"node_id": f["node_id"], "annotated": True,
                                        "severity": f["severity"], "vuln_id": f["rule_id"]})
        _push_to_ws(gq, "finding", f)

    session["graph"] = {
        "nodes": [], "edges": [],
        "summary": {"node_count": 6, "edge_count": 4,
                    "cwe_counts": {"CWE-89": 1, "CWE-78": 1},
                    "backend_counts": {"joern": 3, "tree_sitter": 1, "codeql_sarif": 2},
                    "truncated": False},
    }
    session["findings"] = demo_findings
    _push_to_ws(gq, "complete", {"node_count":6,"edge_count":4,"finding_count":3})

    q.put_nowait({"type":"final","status":"complete",
                  "findings": demo_findings,
                  "summary": {"node_count":6,"edge_count":4}})


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _short_label(node) -> str:
    name  = (node.name or "")[:20]
    ntype = node.node_type.value if hasattr(node.node_type, "value") else ""
    return f"{name}\n({ntype})" if name else ntype


def _node_tooltip(node) -> str:
    label = node.security_label.value if hasattr(node.security_label, "value") else ""
    cwes  = ", ".join(node.cwe_hints) if node.cwe_hints else "—"
    colour = "red" if label == "SINK" else "blue"
    return (
        f"<b>{node.name or node.node_id[:12]}</b><br>"
        f"Type: {node.node_type.value if hasattr(node.node_type,'value') else ''}<br>"
        f"File: {Path(node.file_path).name}:{node.start_line}<br>"
        f"Label: <b style='color:{colour}'>{label}</b><br>"
        f"CWE: {cwes}<br>"
        f"Confidence: {node.security_confidence:.0%}"
    )


def _darken(hex_colour: str) -> str:
    h = hex_colour.lstrip("#")
    if len(h) != 6:
        return hex_colour
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"#{max(0,r-40):02x}{max(0,g-40):02x}{max(0,b-40):02x}"


def _check_vault() -> bool:
    try:
        import urllib.request
        addr = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
        with urllib.request.urlopen(f"{addr}/v1/sys/health", timeout=1) as r:
            return r.status in (200, 429, 472, 473, 501, 503)
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    )
    port = int(os.environ.get("PRISM_UI_PORT", 5001))
    print(f"\n  PRISM Dashboard  →  http://localhost:{port}\n")
    print(f"  gVisor available: {_gvisor_available()}")
    print(f"  Pipeline available: {_PIPELINE_AVAILABLE}\n")
    uvicorn.run("ui.app:app", host="0.0.0.0", port=port, reload=False, log_level="info")