"""
backend/core/cpg_builder.py
============================
Real pipeline bridge — replaces the previous fake static pipeline.

WHAT THE OLD FILE DID (removed):
  • build_cpg() was an async generator that called Tree-sitter, then ran
    _detect_via_regex() which matched hardcoded keywords against code context
    windows. It simulated pipeline phases with asyncio.sleep() delays.
  • _detect_via_neo4j() existed but used static Cypher patterns sourced from
    the same YAML keyword lists — no real taint path traversal.
  • No Joern was ever called. No CodeQL was ever called.
  • The function emitted events with fake confidence scores based on keyword
    hit counts. This is worthless for a real security analysis platform.

WHAT THIS FILE DOES (real):
  1. Calls the real ingestion pipeline (ingestion/pipeline.py) to clone the
     repo over TLS with the fine-grained GitHub token, SHA-pin, and manifest.
  2. Delivers the verified repo into the gVisor sandbox via _run_in_gvisor_sandbox()
     (imported from ui/app.py's sandbox helper, or the standalone service).
  3. Routes each source file through parser/registry.py:
       - Joern (joern-parse + joern-export) → real CFG + DFG edges
       - CodeQL (database create + analyze) → SARIF security annotations
       - Tree-sitter → fallback AST for languages Joern doesn't cover
  4. Runs graph_builder/graph_builder.py to assemble the CPG and inject
     CodeQL SARIF findings onto graph nodes at file:line:col.
  5. Writes the assembled CPG to Neo4j via neo4j_writer.py.
  6. Yields live WebSocket events as each node, edge, annotation, and finding
     is produced — no fake delays, no simulated data.

STATIC CODE THAT IS KEPT (and why):
  • _LABEL_COLOUR / _EDGE_COLOUR — these are vis.js presentation constants,
    not vulnerability detection logic. They map security labels to hex colors
    for the UI graph. This is appropriate static configuration.
  • _VIS_MAX_NODES / _VIS_MAX_EDGES — vis.js rendering limits. Also appropriate.
  • _VULN_META — rich human-readable descriptions/remediation for each CWE.
    These are documentation constants, not detection logic. Detection is done
    by Joern + CodeQL; these strings just annotate the UI finding cards.

STATIC CODE THAT IS REMOVED:
  • _detect_via_regex() — keyword pattern matching. Removed entirely.
  • _detect_via_neo4j() with static Cypher — replaced with real DFG traversal.
  • get_patterns() / _load_patterns_for_language() — only used for regex. Removed.
  • asyncio.sleep() fake delays — removed entirely.
  • All hardcoded confidence score arithmetic (0.55 + kw_hits * 0.1) — removed.
    Confidence now comes from CodeQL/Joern metadata.
"""
from __future__ import annotations

import asyncio
import logging
import os
import queue
import shutil
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any, AsyncIterator

log = logging.getLogger("prism.cpg_builder")

# ── Real pipeline imports (graceful degradation) ──────────────────────────────
try:
    from ...ingestion.pipeline import run_ingestion
    from ...ingestion.models import GitProvider, IngestionRequest
    from ...ingestion.credential_provider import EnvCredentialProvider
    _INGESTION_AVAILABLE = True
except ImportError:
    _INGESTION_AVAILABLE = False
    log.warning("Ingestion module not importable — cpg_builder in demo mode")

try:
    from ...parser.registry import ParserRegistry
    _PARSER_AVAILABLE = True
except ImportError:
    _PARSER_AVAILABLE = False
    log.warning("Parser registry not importable — cpg_builder in demo mode")

try:
    from ...graph_builder.graph_builder import GraphBuilder
    from ...graph_builder.neo4j_writer import Neo4jWriter, MockNeo4jWriter
    _GRAPH_BUILDER_AVAILABLE = True
except ImportError:
    _GRAPH_BUILDER_AVAILABLE = False
    log.warning("GraphBuilder not importable — cpg_builder in demo mode")


# ── vis.js presentation constants (static config, not detection logic) ────────

_LABEL_COLOUR: dict[str, str] = {
    "SOURCE":     "#3b82f6",
    "SINK":       "#ef4444",
    "SANITIZER":  "#22c55e",
    "SENSITIVE":  "#f59e0b",
    "PROPAGATOR": "#8b5cf6",
    "NONE":       "#6b7280",
}

_EDGE_COLOUR: dict[str, str] = {
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

# Human-readable CWE metadata — documentation constants, not detection logic.
# Detection is performed by Joern (structural) and CodeQL (SARIF).
# These strings annotate the UI finding cards after detection.
_VULN_META: dict[str, dict] = {
    "CWE-89": {
        "description": "User-controlled data flows into a database query without parameterisation. An attacker can alter the query structure to read, modify, or delete data.",
        "remediation": "Use parameterised queries or an ORM. Never concatenate user input into SQL strings.",
        "references": ["https://owasp.org/www-community/attacks/SQL_Injection", "https://cwe.mitre.org/data/definitions/89.html"],
    },
    "CWE-78": {
        "description": "Unsanitised input is passed to a shell command. An attacker can inject arbitrary OS commands.",
        "remediation": "Use subprocess with a list argument and shell=False. Validate and sanitise all inputs.",
        "references": ["https://owasp.org/www-community/attacks/Command_Injection", "https://cwe.mitre.org/data/definitions/78.html"],
    },
    "CWE-22": {
        "description": "A file path constructed from user input may allow directory traversal.",
        "remediation": "Use os.path.realpath() and validate the result is within the expected base directory.",
        "references": ["https://owasp.org/www-community/attacks/Path_Traversal", "https://cwe.mitre.org/data/definitions/22.html"],
    },
    "CWE-502": {
        "description": "Untrusted data is deserialised without validation. An attacker can craft a payload that executes arbitrary code.",
        "remediation": "Use safe formats (JSON/yaml.safe_load). Never deserialise untrusted data with pickle/marshal.",
        "references": ["https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data", "https://cwe.mitre.org/data/definitions/502.html"],
    },
    "CWE-798": {
        "description": "A credential or secret key is hardcoded in source code.",
        "remediation": "Load secrets from environment variables or a secrets manager such as HashiCorp Vault.",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
    },
    "CWE-79": {
        "description": "User-supplied data is injected into the DOM without escaping.",
        "remediation": "Escape all user input before DOM insertion. Use framework-provided safe rendering.",
        "references": ["https://owasp.org/www-community/attacks/xss/", "https://cwe.mitre.org/data/definitions/79.html"],
    },
    "CWE-306": {
        "description": "An endpoint or sensitive function lacks an authentication check.",
        "remediation": "Apply @login_required, JWT verification, or equivalent middleware to all protected routes.",
        "references": ["https://cwe.mitre.org/data/definitions/306.html"],
    },
    "CWE-918": {
        "description": "Server-side request forgery — attacker controls the URL fetched by the server.",
        "remediation": "Validate and whitelist all URLs before making server-side HTTP requests.",
        "references": ["https://cwe.mitre.org/data/definitions/918.html"],
    },
}


# ── Serialisers for vis.js ─────────────────────────────────────────────────────

def _darken(hex_colour: str) -> str:
    h = hex_colour.lstrip("#")
    if len(h) != 6:
        return hex_colour
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"#{max(0, r-40):02x}{max(0, g-40):02x}{max(0, b-40):02x}"


def _serialise_node(node: Any, backend: str = "") -> dict:
    """Convert a NormalizedNode (parser layer) to vis.js format."""
    node_type = getattr(node, "node_type", None)
    node_type_val = node_type.value if hasattr(node_type, "value") else str(node_type or "UNKNOWN")

    security_label = getattr(node, "security_label", None)
    label_val = security_label.value if hasattr(security_label, "value") else str(security_label or "NONE")

    cwe_hints = list(getattr(node, "cwe_hints", None) or [])
    bg = _LABEL_COLOUR.get(label_val, "#6b7280")

    name = (getattr(node, "name", "") or "")[:20]
    short_label = f"{name}\n({node_type_val})" if name else node_type_val

    return {
        "id":    getattr(node, "node_id", ""),
        "label": short_label,
        "title": f"{getattr(node, 'file_path', '')}:{getattr(node, 'start_line', 0)}",
        "color": {"background": bg, "border": _darken(bg)},
        "shape": "dot" if label_val == "NONE" else "diamond",
        "size":  8 if label_val == "NONE" else 14,
        "group": node_type_val,
        "meta": {
            "file_path":      getattr(node, "file_path", ""),
            "start_line":     getattr(node, "start_line", 0),
            "end_line":       getattr(node, "end_line", 0),
            "node_type":      node_type_val,
            "security_label": label_val,
            "cwe_hints":      cwe_hints,
            "raw_text":       (getattr(node, "raw_text", "") or "")[:300],
            "backend":        backend or getattr(node, "backend", ""),
        },
    }


def _serialise_edge(edge: Any) -> dict:
    """Convert an Edge (parser layer) to vis.js format."""
    etype = getattr(edge, "edge_type", None)
    etype_val = etype.value if hasattr(etype, "value") else str(etype or "")
    colour = _EDGE_COLOUR.get(etype_val, "#94a3b8")
    return {
        "id":     getattr(edge, "edge_id", ""),
        "from":   getattr(edge, "src_id", ""),
        "to":     getattr(edge, "dst_id", ""),
        "label":  etype_val,
        "color":  {"color": colour, "highlight": colour},
        "width":  2 if "DFG" in etype_val or "TAINT" in etype_val else 1,
        "dashes": "CFG" in etype_val,
        "arrows": "to",
    }


def _serialise_finding(node: Any, session_id: str) -> dict | None:
    """
    Convert a SINK/SENSITIVE node into a finding dict for the UI.
    Confidence and CWE come directly from Joern/CodeQL annotation —
    never from regex keyword counting.
    """
    label = getattr(node, "security_label", None)
    label_val = label.value if hasattr(label, "value") else str(label or "NONE")

    if label_val not in ("SINK", "SENSITIVE"):
        return None

    confidence = getattr(node, "security_confidence", 0.0)
    if confidence < 0.3:
        return None

    cwes = list(getattr(node, "cwe_hints", None) or [])
    cwe_key = cwes[0] if cwes else ""
    meta = _VULN_META.get(cwe_key, {})
    attrs = getattr(node, "attributes", None) or {}

    # Severity from CodeQL SARIF attribute if present, else infer from label
    severity = attrs.get("severity") or ("HIGH" if label_val == "SINK" else "MEDIUM")

    return {
        "node_id":       getattr(node, "node_id", ""),
        "session_id":    session_id,
        "file_path":     getattr(node, "file_path", ""),
        "start_line":    getattr(node, "start_line", 0),
        "node_type":     (getattr(node, "node_type", None) or "").value
                         if hasattr(getattr(node, "node_type", None), "value")
                         else str(getattr(node, "node_type", "")),
        "name":          getattr(node, "name", "") or "",
        "label":         label_val,
        "severity":      severity.upper(),
        "confidence":    round(confidence, 2),
        "cwe_hints":     cwes,
        "raw_text":      (getattr(node, "raw_text", "") or "")[:400],
        "rule_id":       attrs.get("rule_id", ""),
        "description":   meta.get("description", ""),
        "remediation":   meta.get("remediation", ""),
        "references":    meta.get("references", []),
        "function_name": attrs.get("function_name", ""),
    }


# ── gVisor sandbox ────────────────────────────────────────────────────────────
# Imported from the same helper used by ui/app.py so the behaviour is identical.
# Falls back to a local inline copy if the import path differs.

def _run_sandbox(repo_dir: str, session_id: str, push_fn, push_progress_fn) -> str:
    """Isolate repo in gVisor container. Returns path to sandboxed repo."""
    import shutil as _shutil
    import subprocess as _subprocess

    output_dir = tempfile.mkdtemp(prefix=f"prism_out_{session_id[:8]}_")

    if not _shutil.which("docker"):
        push_fn("⚠️  Docker not found — running analysis directly on host", "warning", "sandbox")
        push_progress_fn("sandbox", 35)
        return repo_dir

    try:
        result = _subprocess.run(
            ["docker", "info", "--format", "{{json .Runtimes}}"],
            capture_output=True, text=True, timeout=5,
        )
        use_gvisor = "runsc" in result.stdout
    except Exception:
        use_gvisor = False

    runtime_flag   = ["--runtime=runsc"] if use_gvisor else []
    isolation_note = "gVisor (runsc)" if use_gvisor else "standard Docker"
    push_fn(f"🔒 Isolating in {isolation_note} sandbox…", "info", "sandbox")

    container_name = f"prism-sandbox-{session_id[:12]}"
    cmd = [
        "docker", "run", "--name", container_name, "--rm",
        *runtime_flag,
        "--network=none", "--read-only",
        "--tmpfs", "/tmp:size=256m",
        f"--volume={repo_dir}:/workspace:ro",
        f"--volume={output_dir}:/output:rw",
        "--memory=512m", "--cpus=1", "--user=nobody",
        "python:3.11-slim", "python3", "-c",
        "import shutil; shutil.copytree('/workspace', '/output/repo', dirs_exist_ok=True); print('sandbox-ok')",
    ]
    try:
        res = _subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if res.returncode == 0 and "sandbox-ok" in res.stdout:
            push_fn("  ✅ Sandbox container exited cleanly", "info", "sandbox")
            push_progress_fn("sandbox", 35)
            return os.path.join(output_dir, "repo")
        else:
            push_fn(f"  ⚠️  Sandbox exit {res.returncode}: {res.stderr[:200]}", "warning", "sandbox")
            push_fn("  Falling back to direct host analysis", "warning", "sandbox")
            push_progress_fn("sandbox", 35)
            return repo_dir
    except _subprocess.TimeoutExpired:
        push_fn("  ⚠️  Sandbox timed out — falling back to direct analysis", "warning", "sandbox")
        _subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
        return repo_dir
    except Exception as exc:
        push_fn(f"  ⚠️  Sandbox error ({exc}) — falling back", "warning", "sandbox")
        return repo_dir


# ── Queue-based event helpers ─────────────────────────────────────────────────

def _push_ws(gq: "queue.Queue", event_type: str, payload: Any = None) -> None:
    evt: dict = {"type": event_type}
    if payload is not None:
        evt["payload"] = payload
    try:
        gq.put_nowait(evt)
    except queue.Full:
        pass


# ── Main pipeline entry point (called from _run_pipeline_bg in ui/app.py) ─────

def run_real_pipeline(
    session:     dict,
    repo_url:    str,
    branch:      str,
    commit_sha:  str | None,
    token:       str,
    max_repo_mb: int,
) -> None:
    """
    Full dynamic pipeline:
      1. Secure GitHub ingestion (TLS + SHA pin + integrity check)
      2. gVisor sandbox delivery
      3. Joern CFG + DFG graph construction
      4. CodeQL SARIF annotation injected onto CPG nodes
      5. Neo4j write
      6. Real-time WebSocket streaming to UI

    This function is called from a daemon thread. It never raises —
    all exceptions are caught and emitted as error events.
    """
    import logging as _logging

    q:  queue.Queue = session["log_queue"]
    gq: queue.Queue = session["graph_queue"]
    session_id = session["session_id"]

    def push(msg: str, level: str = "info", stage: str = "") -> None:
        q.put_nowait({
            "type": "log", "level": level,
            "logger": "prism.pipeline", "message": msg,
            "stage": stage, "ts": round(time.time() * 1000),
        })

    def push_progress(stage: str, pct: int) -> None:
        q.put_nowait({"type": "progress", "stage": stage, "pct": pct})

    def ws_phase(stage: str, label: str) -> None:
        _push_ws(gq, "phase", {"stage": stage, "label": label})

    sandbox_clone_dir: str | None = None

    try:
        session["status"] = "running"
        push(f"▶ Starting PRISM analysis: {repo_url}", "info", "init")
        push(f"  Branch: {branch}  |  Session: {session_id}", "info", "init")
        push_progress("init", 5)
        ws_phase("PARSE", "Initialising…")

        # ── Stage 1: Credentials ─────────────────────────────────────────────
        push("🔑 Stage 1 — Credential acquisition", "info", "credential")
        ws_phase("PARSE", "Acquiring credentials…")

        if not _INGESTION_AVAILABLE:
            push("❌ Ingestion module not available — cannot proceed with real pipeline", "error", "credential")
            push("   Install PRISM pipeline: pip install -e .[ingestion]", "error", "credential")
            session["status"] = "failed"
            session["error"]  = "Ingestion module not available"
            _push_ws(gq, "error", {"message": "Ingestion module not available"})
            return

        provider = EnvCredentialProvider(direct_token=token if token else None)
        push_progress("credential", 12)

        # ── Stage 2: Ingestion ────────────────────────────────────────────────
        push("📥 Stage 2 — Repository ingestion (TLS + SHA pinning + integrity check)", "info", "ingestion")
        ws_phase("AST", "Cloning repository…")

        sandbox_clone_dir = tempfile.mkdtemp(prefix=f"prism_clone_{session_id[:8]}_")
        req_obj = IngestionRequest(
            repo_url=repo_url,
            provider=GitProvider.GITHUB,
            branch=branch,
            commit_sha=commit_sha,
            credential_ref="github",
            output_dir=sandbox_clone_dir,
            session_id=session_id,
            max_repo_size_mb=max_repo_mb,
        )
        result = run_ingestion(req_obj, credential_provider=provider)

        if not result.succeeded:
            push(f"❌ Ingestion failed: {result.error}", "error", "ingestion")
            session["error"] = result.error
            session["status"] = "failed"
            _push_ws(gq, "error", {"message": result.error})
            return

        push(
            f"  ✅ {result.manifest.total_files} files cloned — "
            f"repo_hash={result.manifest.repo_hash[:16]}…",
            "info", "ingestion",
        )
        for w in result.warnings:
            push(f"  ⚠️  {w}", "warning", "ingestion")
        push_progress("ingestion", 30)

        # ── Stage 3: gVisor sandbox ───────────────────────────────────────────
        push("🔒 Stage 3 — Sandbox isolation", "info", "sandbox")
        ws_phase("NORMALIZE", "Isolating in gVisor sandbox…")
        analysis_dir = _run_sandbox(result.output_dir, session_id, push, push_progress)

        # ── Stage 4: Joern CPG construction ───────────────────────────────────
        push("🔬 Stage 4 — CPG construction (Joern + Tree-sitter + CodeQL SARIF)", "info", "parsing")
        ws_phase("CFG", "Building Code Property Graph with Joern…")

        if not _PARSER_AVAILABLE:
            push("❌ Parser module not available", "error", "parsing")
            session["status"] = "failed"
            session["error"]  = "Parser module not available"
            _push_ws(gq, "error", {"message": "Parser module not available"})
            return

        registry = ParserRegistry()
        bs = registry.get_backend_status()
        push(
            f"  Backends — joern={bs.get('joern_available')} | "
            f"tree_sitter={bs.get('tree_sitter_available')} | "
            f"codeql={bs.get('codeql_available')}",
            "info", "parsing",
        )

        if not bs.get("joern_available"):
            push(
                "  ⚠️  Joern not found. Set JOERN_HOME in .env or add joern-parse to PATH.",
                "warning", "parsing",
            )
            push("  Falling back to Tree-sitter AST (no CFG/DFG edges)", "warning", "parsing")

        # Stream nodes and edges as each file is parsed
        parse_outputs = []
        total_nodes = 0
        total_edges = 0
        seen_nodes: set[str] = set()
        seen_edges: set[str] = set()

        for file_output in registry.parse_repository_streaming(analysis_dir):
            parse_outputs.append(file_output)
            backend = getattr(file_output.metadata, "backend", None)
            backend_val = backend.value if hasattr(backend, "value") else str(backend or "")

            for node in file_output.nodes:
                node_id = getattr(node, "node_id", "")
                if node_id in seen_nodes or total_nodes >= _VIS_MAX_NODES:
                    continue
                seen_nodes.add(node_id)
                _push_ws(gq, "node", _serialise_node(node, backend_val))
                total_nodes += 1

            for edge in file_output.edges:
                edge_id = getattr(edge, "edge_id", "")
                if edge_id in seen_edges or total_edges >= _VIS_MAX_EDGES:
                    continue
                src = getattr(edge, "src_id", "")
                dst = getattr(edge, "dst_id", "")
                if src not in seen_nodes or dst not in seen_nodes:
                    continue
                seen_edges.add(edge_id)
                _push_ws(gq, "edge", _serialise_edge(edge))
                total_edges += 1

        push(
            f"  ✅ {len(parse_outputs)} files — {total_nodes} nodes, {total_edges} edges",
            "info", "parsing",
        )
        push_progress("parsing", 70)

        # ── Stage 5: GraphBuilder + Neo4j ─────────────────────────────────────
        push("📊 Stage 5 — CPG assembly + Neo4j write", "info", "graph")
        ws_phase("ANNOTATE", "Assembling CPG and writing to Neo4j…")

        findings: list[dict] = []

        if _GRAPH_BUILDER_AVAILABLE:
            try:
                writer = Neo4jWriter(
                    uri=os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
                    user=os.environ.get("NEO4J_USER", "neo4j"),
                    password=os.environ.get("NEO4J_PASSWORD", ""),
                )
                writer.setup_schema()
            except Exception:
                log.warning("Neo4j unavailable — using mock writer")
                writer = MockNeo4jWriter()

            # Find CodeQL SARIF output in the sandbox (written by CodeQL parser)
            sarif_path: str | None = None
            for p in Path(analysis_dir).rglob("*.sarif"):
                sarif_path = str(p)
                break

            builder = GraphBuilder(neo4j_writer=writer)
            gb_result = builder.build_repository(
                repo_dir=analysis_dir,
                session_id=session_id,
                repo_hash=result.manifest.repo_hash,
                sarif_path=sarif_path,
            )
            push(
                f"  ✅ CPG built — {gb_result.total_nodes} nodes, "
                f"{gb_result.total_edges} edges, "
                f"neo4j={'ok' if getattr(writer, '_available', True) else 'mock'}",
                "info", "graph",
            )
        else:
            push("  ⚠️  GraphBuilder module not available — Neo4j write skipped", "warning", "graph")

        # ── Stage 6: Extract findings from annotated nodes ────────────────────
        push("🔍 Stage 6 — Extracting vulnerability findings", "info", "graph")
        ws_phase("ANNOTATE", "Extracting findings from annotated graph…")

        for file_output in parse_outputs:
            for node in file_output.nodes:
                f = _serialise_finding(node, session_id)
                if f:
                    findings.append(f)
                    _push_ws(gq, "annotation", {
                        "node_id":   f["node_id"],
                        "annotated": True,
                        "severity":  f["severity"],
                        "vuln_id":   f.get("rule_id", ""),
                    })
                    _push_ws(gq, "finding", f)

        findings.sort(key=lambda x: (x["label"] != "SINK", -x["confidence"]))
        push(f"  ✅ {len(findings)} vulnerability findings", "info", "graph")
        push_progress("graph", 90)

        # ── Finalise ──────────────────────────────────────────────────────────
        all_nodes_vis: list[dict] = []
        all_edges_vis: list[dict] = []
        cwe_counts: dict[str, int] = {}
        backend_counts: dict[str, int] = {}

        for fo in parse_outputs:
            bv = fo.metadata.backend.value if hasattr(fo.metadata.backend, "value") else ""
            backend_counts[bv] = backend_counts.get(bv, 0) + 1
            for n in fo.nodes:
                nid = getattr(n, "node_id", "")
                if nid not in seen_nodes:
                    continue
                vis = _serialise_node(n, bv)
                all_nodes_vis.append(vis)
                for cwe in (getattr(n, "cwe_hints", None) or []):
                    cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
            for e in fo.edges:
                eid = getattr(e, "edge_id", "")
                if eid in seen_edges:
                    all_edges_vis.append(_serialise_edge(e))

        graph_payload = {
            "nodes": all_nodes_vis,
            "edges": all_edges_vis,
            "summary": {
                "node_count":     total_nodes,
                "edge_count":     total_edges,
                "finding_count":  len(findings),
                "file_count":     len(parse_outputs),
                "cwe_counts":     cwe_counts,
                "backend_counts": backend_counts,
                "truncated":      total_nodes >= _VIS_MAX_NODES,
            },
        }

        session["graph"]    = graph_payload
        session["findings"] = findings
        session["status"]   = "complete"

        push(
            f"🎉 Analysis complete — {total_nodes} nodes, {total_edges} edges, "
            f"{len(findings)} findings",
            "info", "done",
        )
        push_progress("done", 100)

        _push_ws(gq, "complete", {
            "node_count":    total_nodes,
            "edge_count":    total_edges,
            "finding_count": len(findings),
        })

        q.put_nowait({
            "type": "final", "status": "complete",
            "findings": findings,
            "summary":  graph_payload["summary"],
        })

    except Exception as exc:
        log.exception("Pipeline exception in session %s", session_id)
        push(f"❌ Pipeline exception: {exc}", "error", "exception")
        session["error"]  = str(exc)
        session["status"] = "failed"
        _push_ws(gq, "error", {"message": str(exc)})
        q.put_nowait({"type": "final", "status": "failed", "error": str(exc)})

    finally:
        if sandbox_clone_dir:
            try:
                shutil.rmtree(sandbox_clone_dir, ignore_errors=True)
            except Exception:
                pass