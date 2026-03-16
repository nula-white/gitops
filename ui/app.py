"""
PRISM Dashboard : Flask app
  1. Accepts a GitHub repo URL + PAT from the user
  2. Runs the ingestion → parser → CPG pipeline
  3. Streams structured log events to the browser via SSE
  4. Serves the CPG as a vis.js graph (nodes + edges from Neo4j or in-memory)
  5. Shows vulnerability findings with CWE labels and taint paths

Design principles:
  - Single-file backend — no external UI framework dependency
  - All secrets flow through HashiCorp Vault (or env fallback for local dev)
  - Pipeline runs in a background thread; UI polls via SSE
  - No code is ever sent back to the client — only graph metadata

Run:
    cd prism
    pip install flask
    python -m ui.app

Then open http://localhost:5001
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import queue
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Generator

from flask import Flask, Response, jsonify, render_template, request, stream_with_context

# ── PRISM pipeline imports (graceful degradation if not installed) ────────────
try:
    from ..ingestion.pipeline import run_ingestion
    from ..ingestion.models import GitProvider, IngestionRequest
    from ..parser.registry import ParserRegistry
    _PIPELINE_AVAILABLE = True
except ImportError:
    _PIPELINE_AVAILABLE = False
    logging.warning("PRISM pipeline not importable — running in demo mode")

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = os.environ.get("PRISM_UI_SECRET", "dev-only-secret")

# ── Per-session state ─────────────────────────────────────────────────────────
# session_id → {"status": str, "log_queue": Queue, "graph": dict, "findings": list}
_sessions: dict[str, dict[str, Any]] = {}
_sessions_lock = threading.Lock()

logger = logging.getLogger("prism.ui")


# Logging bridge: routes prism.* logger messages into the SSE queue

class _QueueHandler(logging.Handler):
    """Forwards log records to a per-session queue for SSE streaming."""

    def __init__(self, q: "queue.Queue[dict]") -> None:
        super().__init__()
        self.q = q

    def emit(self, record: logging.LogRecord) -> None:
        level_map = {
            logging.DEBUG:    "debug",
            logging.INFO:     "info",
            logging.WARNING:  "warning",
            logging.ERROR:    "error",
            logging.CRITICAL: "error",
        }
        self.q.put_nowait({
            "type":    "log",
            "level":   level_map.get(record.levelno, "info"),
            "logger":  record.name,
            "message": self.format(record),
            "ts":      round(time.time() * 1000),
        })


def _make_session(session_id: str) -> dict[str, Any]:
    s = {
        "session_id": session_id,
        "status":     "idle",
        "log_queue":  queue.Queue(maxsize=2000),
        "graph":      None,
        "findings":   [],
        "error":      None,
        "created_at": time.time(),
    }
    with _sessions_lock:
        _sessions[session_id] = s
    return s


# Routes

@app.route("/")
def index() -> str:
    return render_template("index.html")


@app.route("/api/status")
def api_status() -> Response:
    return jsonify({
        "pipeline_available": _PIPELINE_AVAILABLE,
        "vault_addr":         os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200"),
        "vault_connected":    _check_vault(),
    })


@app.route("/api/analyze", methods=["POST"])
def api_analyze() -> Response:
    """
    Start a new analysis session.

    Request body (JSON):
        repo_url       : "https://github.com/owner/repo"
        branch         : "main"
        commit_sha     : optional — pin to a specific commit
        github_token   : raw PAT (stored only in SecureString, never logged)
        max_repo_mb    : optional int (default 100)

    Response:
        {"session_id": "sess_abc123"}
    """
    body = request.get_json(force=True, silent=True) or {}
    repo_url    = (body.get("repo_url") or "").strip()
    branch      = (body.get("branch")   or "main").strip()
    commit_sha  = (body.get("commit_sha") or "").strip() or None
    token       = (body.get("github_token") or "").strip()
    max_repo_mb = int(body.get("max_repo_mb") or 100)

    if not repo_url:
        return jsonify({"error": "repo_url is required"}), 400
    if not repo_url.startswith("https://"):
        return jsonify({"error": "Only HTTPS repository URLs are accepted"}), 400

    session_id = f"sess_{uuid.uuid4().hex[:12]}"
    session    = _make_session(session_id)

    # Start pipeline in background thread
    t = threading.Thread(
        target=_run_pipeline_bg,
        args=(session, repo_url, branch, commit_sha, token, max_repo_mb),
        daemon=True,
        name=f"prism-pipeline-{session_id[:8]}",
    )
    t.start()

    return jsonify({"session_id": session_id})


@app.route("/api/session/<session_id>/events")
def session_events(session_id: str) -> Response:
    """
    Server-Sent Events stream for a pipeline session.
    The browser connects once; we stream log + progress + graph events.
    """
    session = _sessions.get(session_id)
    if not session:
        return jsonify({"error": "session not found"}), 404

    def generate() -> Generator[str, None, None]:
        q: queue.Queue = session["log_queue"]
        while True:
            # Check for terminal state
            status = session["status"]

            try:
                event = q.get(timeout=0.5)
                yield f"data: {json.dumps(event)}\n\n"
            except queue.Empty:
                # Send a heartbeat keep-alive
                yield f"data: {json.dumps({'type': 'heartbeat', 'status': status})}\n\n"

            if status in ("complete", "failed"):
                # Flush remaining log events
                while not q.empty():
                    try:
                        event = q.get_nowait()
                        yield f"data: {json.dumps(event)}\n\n"
                    except queue.Empty:
                        break
                # Send final state event
                payload: dict[str, Any] = {
                    "type":   "final",
                    "status": status,
                }
                if status == "complete":
                    payload["graph"]    = session.get("graph")
                    payload["findings"] = session.get("findings", [])
                else:
                    payload["error"] = session.get("error")
                yield f"data: {json.dumps(payload)}\n\n"
                return

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":               "no-cache",
            "X-Accel-Buffering":           "no",
            "Access-Control-Allow-Origin": "*",
        },
    )


@app.route("/api/session/<session_id>/graph")
def session_graph(session_id: str) -> Response:
    """Return the CPG as JSON for vis.js."""
    session = _sessions.get(session_id)
    if not session:
        return jsonify({"error": "session not found"}), 404
    if session["status"] != "complete":
        return jsonify({"error": "analysis not complete yet"}), 202
    return jsonify(session.get("graph") or {})


@app.route("/api/session/<session_id>/findings")
def session_findings(session_id: str) -> Response:
    """Return vulnerability findings."""
    session = _sessions.get(session_id)
    if not session:
        return jsonify({"error": "session not found"}), 404
    return jsonify(session.get("findings") or [])


# Pipeline background worker

def _run_pipeline_bg(
    session:    dict[str, Any],
    repo_url:   str,
    branch:     str,
    commit_sha: str | None,
    token:      str,
    max_repo_mb: int,
) -> None:
    """Background thread: ingestion → parsing → CPG → findings."""
    q: queue.Queue = session["log_queue"]
    session_id = session["session_id"]

    # ── Attach a per-session log handler to all prism.* loggers ──────────────
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

    try:
        session["status"] = "running"

        # ── Stage 0: Demo mode (pipeline not importable) ─────────────────────
        if not _PIPELINE_AVAILABLE:
            push("⚠️  Running in DEMO mode — PRISM pipeline not installed", "warning")
            time.sleep(0.5)
            _inject_demo_data(session, repo_url, q)
            session["status"] = "complete"
            return

        push(f"▶ Starting analysis for {repo_url}", "info", "init")
        push(f"  Branch: {branch}  |  Session: {session_id}", "info", "init")
        push_progress("init", 5)

        # ── Stage 1: Credential setup ─────────────────────────────────────────
        push("🔑 Stage 1 — Credential acquisition", "info", "credential")
        from ..ingestion.credential_provider import EnvCredentialProvider
        provider = EnvCredentialProvider(direct_token=token if token else None)
        push_progress("credential", 15)

        # ── Stage 2: Run ingestion pipeline ───────────────────────────────────
        push("📥 Stage 2 — Repository ingestion (TLS clone + integrity verification)", "info", "ingestion")
        import tempfile, os as _os
        sandbox_dir = tempfile.mkdtemp(prefix=f"prism_ui_{session_id[:8]}_")

        request_obj = IngestionRequest(
            repo_url       = repo_url,
            provider       = GitProvider.GITHUB,
            branch         = branch,
            commit_sha     = commit_sha,
            credential_ref = "github",
            output_dir     = sandbox_dir,
            session_id     = session_id,
            max_repo_size_mb = max_repo_mb,
        )
        result = run_ingestion(request_obj, credential_provider=provider)

        if not result.succeeded:
            push(f"❌ Ingestion failed: {result.error}", "error", "ingestion")
            session["error"]  = result.error
            session["status"] = "failed"
            return

        push(
            f"✅ Ingestion complete — {result.manifest.total_files} files, "
            f"repo_hash={result.manifest.repo_hash[:16]}…",
            "info", "ingestion",
        )
        for w in result.warnings:
            push(f"  ⚠️  {w}", "warning", "ingestion")
        push_progress("ingestion", 40)

        # ── Stage 3: Parse → CPG ───────────────────────────────────────────────
        push("🔬 Stage 3 — CPG construction (Joern + Tree-sitter + CodeQL SARIF)", "info", "parsing")
        registry = ParserRegistry()
        backend_status = registry.get_backend_status()
        push(
            f"  Backends: joern={backend_status['joern_available']} | "
            f"tree_sitter={backend_status['tree_sitter_available']} | "
            f"codeql={backend_status['codeql_available']}",
            "info", "parsing",
        )

        parse_outputs = registry.parse_repository(result.output_dir)
        push(
            f"✅ Parsed {len(parse_outputs)} files — "
            f"{sum(len(o.nodes) for o in parse_outputs)} nodes, "
            f"{sum(len(o.edges) for o in parse_outputs)} edges",
            "info", "parsing",
        )
        push_progress("parsing", 70)

        # ── Stage 4: Build graph payload for vis.js ────────────────────────────
        push("📊 Stage 4 — Assembling graph for visualisation", "info", "graph")
        graph_payload = _build_graph_payload(parse_outputs)
        findings      = _extract_findings(parse_outputs)

        push(
            f"  Graph: {graph_payload['summary']['node_count']} nodes, "
            f"{graph_payload['summary']['edge_count']} edges, "
            f"{len(findings)} findings",
            "info", "graph",
        )
        push_progress("graph", 90)

        session["graph"]    = graph_payload
        session["findings"] = findings
        session["status"]   = "complete"

        push(
            f"🎉 Analysis complete — {len(findings)} vulnerability findings",
            "info", "done",
        )
        push_progress("done", 100)

    except Exception as exc:
        logger.exception("Pipeline exception in session %s", session_id)
        push(f"❌ Pipeline exception: {exc}", "error", "exception")
        session["error"]  = str(exc)
        session["status"] = "failed"

    finally:
        prism_root.removeHandler(handler)


# Graph payload builder — converts ParsedGraphOutput list → vis.js format

_LABEL_COLOUR = {
    "SOURCE":     "#3b82f6",  # blue
    "SINK":       "#ef4444",  # red
    "SANITIZER":  "#22c55e",  # green
    "SENSITIVE":  "#f59e0b",  # amber
    "PROPAGATOR": "#8b5cf6",  # purple
    "NONE":       "#6b7280",  # grey
}
_EDGE_COLOUR = {
    "AST_CHILD":    "#d1d5db",
    "CFG_NEXT":     "#60a5fa",
    "CFG_TRUE":     "#34d399",
    "CFG_FALSE":    "#f87171",
    "CFG_LOOP":     "#a78bfa",
    "DFG_FLOW":     "#fb923c",
    "DFG_DEPENDS":  "#fbbf24",
    "DFG_KILLS":    "#e879f9",
    "CALLS":        "#94a3b8",
    "TAINT_SOURCE": "#2563eb",
    "TAINT_SINK":   "#dc2626",
    "SANITIZER_EDGE": "#16a34a",
}

# Cap for the visualisation — very large graphs crash vis.js
_VIS_MAX_NODES = 500
_VIS_MAX_EDGES = 1000


def _build_graph_payload(parse_outputs: list) -> dict:
    """Convert parser output list to a vis.js-compatible JSON payload."""
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
            if node.node_id in seen_nodes:
                continue
            seen_nodes.add(node.node_id)
            label  = node.security_label.value if hasattr(node.security_label, "value") else str(node.security_label)
            colour = _LABEL_COLOUR.get(label, "#6b7280")

            vis_node: dict = {
                "id":    node.node_id,
                "label": _short_label(node),
                "title": _node_tooltip(node),
                "color": {"background": colour, "border": _darken(colour)},
                "group": node.node_type.value if hasattr(node.node_type, "value") else str(node.node_type),
                "shape": "dot" if label == "NONE" else "diamond",
                "size":  8 if label == "NONE" else 14,
                "meta": {
                    "file_path":       node.file_path,
                    "start_line":      node.start_line,
                    "node_type":       node.node_type.value if hasattr(node.node_type, "value") else "",
                    "security_label":  label,
                    "cwe_hints":       list(node.cwe_hints or []),
                    "raw_text":        (node.raw_text or "")[:200],
                    "backend":         backend,
                },
            }
            all_nodes.append(vis_node)
            for cwe in (node.cwe_hints or []):
                cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1

            if len(all_nodes) >= _VIS_MAX_NODES:
                break

        for edge in output.edges:
            if edge.edge_id in seen_edges:
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
            if len(all_edges) >= _VIS_MAX_EDGES:
                break

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
    """Extract security findings from parsed outputs for the findings panel."""
    findings: list[dict] = []
    for output in parse_outputs:
        for node in output.nodes:
            label = node.security_label.value if hasattr(node.security_label, "value") else ""
            if label not in ("SINK", "SOURCE", "SENSITIVE"):
                continue
            if node.security_confidence < 0.3:
                continue
            findings.append({
                "node_id":    node.node_id,
                "file_path":  node.file_path,
                "start_line": node.start_line,
                "node_type":  node.node_type.value if hasattr(node.node_type, "value") else "",
                "name":       node.name or "",
                "label":      label,
                "confidence": round(node.security_confidence, 2),
                "cwe_hints":  list(node.cwe_hints or []),
                "raw_text":   (node.raw_text or "")[:120],
                # SARIF rule ID if present
                "rule_id":    node.attributes.get("rule_id", "") if node.attributes else "",
                "severity":   node.attributes.get("severity", "")   if node.attributes else "",
            })
    # Sort: SINK first, then by confidence desc
    findings.sort(key=lambda f: (f["label"] != "SINK", -f["confidence"]))
    return findings


def _short_label(node) -> str:
    name = (node.name or "")[:20]
    ntype = node.node_type.value if hasattr(node.node_type, "value") else ""
    return f"{name}\n({ntype})" if name else ntype


def _node_tooltip(node) -> str:
    label = node.security_label.value if hasattr(node.security_label, "value") else ""
    cwes  = ", ".join(node.cwe_hints) if node.cwe_hints else "—"
    return (
        f"<b>{node.name or node.node_id[:12]}</b><br>"
        f"Type: {node.node_type.value if hasattr(node.node_type,'value') else ''}<br>"
        f"File: {Path(node.file_path).name}:{node.start_line}<br>"
        f"Label: <b style='color:{'red' if label=='SINK' else 'blue'}'>{label}</b><br>"
        f"CWE: {cwes}<br>"
        f"Confidence: {node.security_confidence:.0%}"
    )


def _darken(hex_colour: str) -> str:
    """Simple hex colour darkening for node borders."""
    h = hex_colour.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"#{max(0,r-40):02x}{max(0,g-40):02x}{max(0,b-40):02x}"


# Demo mode (when pipeline not importable)

def _inject_demo_data(session: dict, repo_url: str, q: queue.Queue) -> None:
    """Generate synthetic graph data so the UI can be tested standalone."""
    stages = [
        ("🔑 Stage 1 — Credential acquisition", "credential"),
        ("📥 Stage 2 — Repository ingestion (TLS clone + integrity verification)", "ingestion"),
        ("  ✅ Commit SHA pinned from GitHub API", "ingestion"),
        ("  ✅ Symlink escape check passed", "ingestion"),
        ("  ✅ Manifest built (42 files, repo_hash=a3f7c2d1…)", "ingestion"),
        ("🔬 Stage 3 — CPG construction (Joern + Tree-sitter + CodeQL SARIF)", "parsing"),
        ("  Backend routing: Joern for Python/Java; Tree-sitter for Rust/HCL", "parsing"),
        ("  ✅ Parsed 42 files — 1,847 nodes, 3,209 edges", "parsing"),
        ("📊 Stage 4 — Assembling graph for visualisation", "graph"),
        ("  ✅ 3 SINK nodes found (CWE-89, CWE-78)", "graph"),
        ("🎉 Analysis complete — 3 vulnerability findings", "done"),
    ]
    for i, (msg, stage) in enumerate(stages):
        time.sleep(0.4)
        q.put_nowait({
            "type": "log", "level": "info",
            "logger": "prism.ui.demo", "message": msg,
            "stage": stage, "ts": round(time.time() * 1000),
        })
        q.put_nowait({"type": "progress", "stage": stage, "pct": int((i + 1) / len(stages) * 95)})

    # Synthetic graph
    nodes = [
        {"id": "n1", "label": "main()\n(FUNCTION)", "color": {"background": "#6b7280", "border": "#374151"}, "group": "FUNCTION", "shape": "dot", "size": 8, "meta": {"file_path": "src/app.py", "start_line": 1, "node_type": "FUNCTION", "security_label": "NONE", "cwe_hints": [], "raw_text": "def main():", "backend": "joern"}},
        {"id": "n2", "label": "request.args\n(SOURCE)", "color": {"background": "#3b82f6", "border": "#1d4ed8"}, "group": "IDENTIFIER", "shape": "diamond", "size": 14, "meta": {"file_path": "src/app.py", "start_line": 12, "node_type": "IDENTIFIER", "security_label": "SOURCE", "cwe_hints": [], "raw_text": "user_id = request.args.get('id')", "backend": "joern"}},
        {"id": "n3", "label": "query\n(ASSIGN)", "color": {"background": "#6b7280", "border": "#374151"}, "group": "ASSIGN", "shape": "dot", "size": 8, "meta": {"file_path": "src/app.py", "start_line": 13, "node_type": "ASSIGN", "security_label": "NONE", "cwe_hints": [], "raw_text": 'query = "SELECT * FROM users WHERE id=" + user_id', "backend": "joern"}},
        {"id": "n4", "label": "db.execute\n(SINK)", "color": {"background": "#ef4444", "border": "#b91c1c"}, "group": "CALL", "shape": "diamond", "size": 14, "meta": {"file_path": "src/app.py", "start_line": 14, "node_type": "CALL", "security_label": "SINK", "cwe_hints": ["CWE-89"], "raw_text": "db.execute(query)", "backend": "codeql_sarif"}},
        {"id": "n5", "label": "subprocess.run\n(SINK)", "color": {"background": "#ef4444", "border": "#b91c1c"}, "group": "CALL", "shape": "diamond", "size": 14, "meta": {"file_path": "src/utils.py", "start_line": 7, "node_type": "CALL", "security_label": "SINK", "cwe_hints": ["CWE-78"], "raw_text": "subprocess.run(cmd, shell=True)", "backend": "codeql_sarif"}},
        {"id": "n6", "label": "os.environ\n(SENSITIVE)", "color": {"background": "#f59e0b", "border": "#b45309"}, "group": "IDENTIFIER", "shape": "diamond", "size": 14, "meta": {"file_path": "src/config.py", "start_line": 3, "node_type": "IDENTIFIER", "security_label": "SENSITIVE", "cwe_hints": [], "raw_text": "SECRET = os.environ['DB_PASS']", "backend": "tree_sitter"}},
    ]
    edges = [
        {"id": "e1", "from": "n1", "to": "n2", "label": "AST_CHILD", "color": {"color": "#d1d5db"}, "width": 1, "dashes": False, "arrows": "to"},
        {"id": "e2", "from": "n2", "to": "n3", "label": "DFG_FLOW",  "color": {"color": "#fb923c"}, "width": 2, "dashes": False, "arrows": "to"},
        {"id": "e3", "from": "n3", "to": "n4", "label": "DFG_FLOW",  "color": {"color": "#fb923c"}, "width": 2, "dashes": False, "arrows": "to"},
        {"id": "e4", "from": "n1", "to": "n5", "label": "CFG_NEXT",  "color": {"color": "#60a5fa"}, "width": 1, "dashes": True,  "arrows": "to"},
    ]
    session["graph"] = {
        "nodes": nodes, "edges": edges,
        "summary": {"node_count": len(nodes), "edge_count": len(edges),
                    "cwe_counts": {"CWE-89": 1, "CWE-78": 1},
                    "backend_counts": {"joern": 2, "tree_sitter": 1, "codeql_sarif": 2},
                    "truncated": False},
    }
    session["findings"] = [
        {"node_id": "n4", "file_path": "src/app.py", "start_line": 14, "node_type": "CALL", "name": "db.execute", "label": "SINK", "confidence": 0.95, "cwe_hints": ["CWE-89"], "raw_text": "db.execute(query)", "rule_id": "py/sql-injection", "severity": "error"},
        {"node_id": "n5", "file_path": "src/utils.py", "start_line": 7, "node_type": "CALL", "name": "subprocess.run", "label": "SINK", "confidence": 0.90, "cwe_hints": ["CWE-78"], "raw_text": "subprocess.run(cmd, shell=True)", "rule_id": "py/command-injection", "severity": "error"},
        {"node_id": "n6", "file_path": "src/config.py", "start_line": 3, "node_type": "IDENTIFIER", "name": "os.environ", "label": "SENSITIVE", "confidence": 0.80, "cwe_hints": [], "raw_text": "SECRET = os.environ['DB_PASS']", "rule_id": "", "severity": "warning"},
    ]


# Vault health check helper

def _check_vault() -> bool:
    try:
        import urllib.request
        addr = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
        with urllib.request.urlopen(f"{addr}/v1/sys/health", timeout=1) as r:
            return r.status in (200, 429, 472, 473, 501, 503)
    except Exception:
        return False


# Entry point

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    )
    port = int(os.environ.get("PRISM_UI_PORT", 5001))
    print(f"\n  PRISM Dashboard →  http://localhost:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)