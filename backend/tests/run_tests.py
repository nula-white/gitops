#!/usr/bin/env python3
"""
PRISM backend test runner — zero external dependencies (pure stdlib).
assert_ is defined first so all test functions can reference it.
"""
import sys, os, re, uuid, asyncio, traceback, time, types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

# ── assert helper (must be first) ────────────────────────────────────────────
def assert_(condition, msg="Assertion failed"):
    if not condition:
        raise AssertionError(msg)

# ── Pydantic v2 stub ─────────────────────────────────────────────────────────
class _BaseModel:
    def __init__(self, **kwargs):
        ann = {}
        for cls in reversed(type(self).__mro__):
            ann.update(getattr(cls, '__annotations__', {}))
        for k, v in kwargs.items():
            setattr(self, k, v)
        for name in ann:
            if not hasattr(self, name):
                cls_val = getattr(type(self), name, None)
                if callable(cls_val) and hasattr(cls_val, 'default_factory') and cls_val.default_factory:
                    setattr(self, name, cls_val.default_factory())
                elif cls_val is not None and not callable(cls_val):
                    setattr(self, name, cls_val)
                else:
                    setattr(self, name, None)

    def model_dump(self):
        ann = {}
        for cls in reversed(type(self).__mro__):
            ann.update(getattr(cls, '__annotations__', {}))
        out = {}
        for k in ann:
            v = getattr(self, k, None)
            if hasattr(v, 'value'):
                out[k] = v.value
            elif isinstance(v, list):
                out[k] = [x.value if hasattr(x, 'value') else x for x in v]
            else:
                out[k] = v
        return out

def _field(*a, default_factory=None, **kw):
    class _F:
        pass
    f = _F(); f.default_factory = default_factory
    return f

pydantic_mod = types.ModuleType("pydantic")
pydantic_mod.BaseModel = _BaseModel
pydantic_mod.Field = _field
sys.modules["pydantic"] = pydantic_mod

pydantic_settings_mod = types.ModuleType("pydantic_settings")
class _BaseSettings(_BaseModel):
    class Config:
        env_file = ".env"
        case_sensitive = False
pydantic_settings_mod.BaseSettings = _BaseSettings
sys.modules["pydantic_settings"] = pydantic_settings_mod

neo4j_mod = types.ModuleType("neo4j")
neo4j_mod.AsyncGraphDatabase = None
sys.modules["neo4j"] = neo4j_mod

# ── Import core ───────────────────────────────────────────────────────────────
from core.models import (
    CPGNode, CPGEdge, VulnerabilityFinding,
    NodeType, EdgeKind, Severity,
    WSEvent, WSEventType, PipelinePhase,
    AnalysisRequest,
)
from core.cpg_builder import (
    _extract_nodes_regex, _build_cfg_edges, _build_dfg_edges,
    _detect_vulnerabilities, build_cpg, get_patterns, extract_nodes,
)

# ── Runner ────────────────────────────────────────────────────────────────────
PASS = 0; FAIL = 0; ERRORS = []

def test(name, fn):
    global PASS, FAIL
    try:
        r = fn()
        if asyncio.iscoroutine(r):
            asyncio.run(r)
        PASS += 1
        print(f"  \u2713  {name}")
    except Exception as e:
        FAIL += 1
        tb = traceback.format_exc().strip().split('\n')[-1]
        ERRORS.append((name, tb))
        print(f"  \u2717  {name}")
        print(f"       \u2192 {tb}")

def section(t):
    print(f"\n{'─'*60}\n  {t}\n{'─'*60}")

# ── Sample code fixtures ──────────────────────────────────────────────────────
SESSION = "test-session-001"

SAFE_CODE = """
def greet(name):
    return f"Hello, {name}"

def add(a, b):
    return a + b
"""

SQLI_CODE = """
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id=" + user_id)
    return cursor.fetchall()
"""

CMD_CODE = """
import os

def run_cmd(cmd):
    result = os.system(cmd)
    return result
"""

PATH_CODE = """
def read_config(path):
    with open(path) as f:
        return f.read()
"""

PICKLE_CODE = """
import pickle

def load_data(raw_bytes):
    obj = pickle.loads(raw_bytes)
    return obj
"""

SECRET_CODE = """
api_key = "sk-abcdefghijklmnop12345678"
password = "hunter2_super_secret"

def connect():
    return api_key
"""

MULTI_CODE = SQLI_CODE + "\n" + CMD_CODE + "\n" + SECRET_CODE

def do_detect(code, filename="test.py"):
    nodes = _extract_nodes_regex(code, "python", filename, SESSION)
    source_lines = {filename: code.splitlines()}
    return _detect_vulnerabilities(nodes, SESSION, source_lines, "python")

async def collect_events(code, filename="test.py"):
    events = []
    async for evt in build_cpg(code, "python", filename, SESSION):
        events.append(evt)
    return events

# ═══════════════════════════════════════════════════════════════════
# SECTION 1: Data models
# ═══════════════════════════════════════════════════════════════════
section("1. Data model construction")

def t_node_creates():
    n = CPGNode(id="n1", session_id=SESSION, node_type=NodeType.FUNCTION)
    assert_(n.id == "n1")
    assert_(n.session_id == SESSION)
test("CPGNode creates with required fields", t_node_creates)

def t_node_annotated_default():
    n = CPGNode(id="n1", session_id=SESSION, node_type=NodeType.CALL)
    assert_(n.annotated == False, f"annotated should be False, got {n.annotated}")
test("CPGNode annotated defaults to False", t_node_annotated_default)

def t_node_vuln_id_default():
    n = CPGNode(id="n1", session_id=SESSION, node_type=NodeType.CALL)
    assert_(n.vuln_id is None)
test("CPGNode vuln_id defaults to None", t_node_vuln_id_default)

def t_edge_id():
    e = CPGEdge(id="e1", session_id=SESSION, source_id="a", target_id="b", kind=EdgeKind.CFG_NEXT)
    assert_(e.id == "e1")
test("CPGEdge stores id", t_edge_id)

def t_finding_serialise():
    f = VulnerabilityFinding(
        id="f1", session_id=SESSION, node_id="n1",
        vuln_type="SQL Injection", cwe="CWE-89",
        severity=Severity.HIGH, confidence=0.87,
        file="app.py", line_start=5, line_end=5,
        description="desc", code_snippet="code", remediation="fix",
    )
    d = f.model_dump()
    assert_(d["cwe"] == "CWE-89")
    assert_(d["confidence"] == 0.87)
test("VulnerabilityFinding model_dump works", t_finding_serialise)

def t_ws_event():
    e = WSEvent(type=WSEventType.PHASE, session_id=SESSION, payload={"stage": "PARSE"})
    assert_(e.type == WSEventType.PHASE)
    assert_(e.session_id == SESSION)
test("WSEvent stores type and session_id", t_ws_event)

def t_analysis_request_default_lang():
    req = AnalysisRequest(inline_code="print('hello')")
    assert_(req.language == "python")
test("AnalysisRequest defaults language to python", t_analysis_request_default_lang)

# ═══════════════════════════════════════════════════════════════════
# SECTION 2: Node extraction
# ═══════════════════════════════════════════════════════════════════
section("2. Node extraction")

def t_extract_produces_nodes():
    nodes = _extract_nodes_regex(SQLI_CODE, "python", "sqli.py", SESSION)
    assert_(len(nodes) > 0, f"Expected nodes, got 0")
test("extracts nodes from Python code", t_extract_produces_nodes)

def t_extract_function():
    nodes = _extract_nodes_regex(SQLI_CODE, "python", "sqli.py", SESSION)
    types_ = [n.node_type for n in nodes]
    assert_(NodeType.FUNCTION in types_, f"No FUNCTION node found. Got: {types_}")
test("extracts FUNCTION node", t_extract_function)

def t_extract_import():
    nodes = _extract_nodes_regex(SQLI_CODE, "python", "sqli.py", SESSION)
    types_ = [n.node_type for n in nodes]
    assert_(NodeType.IMPORT in types_, f"No IMPORT node. Got: {types_}")
test("extracts IMPORT node", t_extract_import)

def t_extract_call():
    nodes = _extract_nodes_regex(SQLI_CODE, "python", "sqli.py", SESSION)
    types_ = [n.node_type for n in nodes]
    assert_(NodeType.CALL in types_, f"No CALL node. Got: {types_}")
test("extracts CALL node", t_extract_call)

def t_extract_session():
    nodes = _extract_nodes_regex(SQLI_CODE, "python", "sqli.py", SESSION)
    bad = [n for n in nodes if n.session_id != SESSION]
    assert_(not bad, f"Wrong session_id on nodes: {bad}")
test("all nodes have correct session_id", t_extract_session)

def t_extract_file():
    nodes = _extract_nodes_regex(SQLI_CODE, "python", "sqli.py", SESSION)
    bad = [n for n in nodes if n.file != "sqli.py"]
    assert_(not bad, f"Wrong file on {len(bad)} nodes")
test("all nodes have correct file", t_extract_file)

def t_extract_line_numbers():
    nodes = _extract_nodes_regex(SQLI_CODE, "python", "sqli.py", SESSION)
    bad = [n for n in nodes if n.line_start <= 0]
    assert_(not bad, f"{len(bad)} nodes have line_start <= 0")
test("all nodes have line_start > 0", t_extract_line_numbers)

def t_extract_snippet():
    nodes = _extract_nodes_regex(SQLI_CODE, "python", "sqli.py", SESSION)
    bad = [n for n in nodes if not n.code_snippet]
    assert_(not bad, f"{len(bad)} nodes have empty code_snippet")
test("all nodes have code_snippet", t_extract_snippet)

def t_extract_empty():
    nodes = _extract_nodes_regex("", "python", "e.py", SESSION)
    assert_(nodes == [], f"Expected empty list, got {nodes}")
test("empty code returns empty list", t_extract_empty)

def t_extract_comment_only():
    nodes = _extract_nodes_regex("# comment\n# more", "python", "c.py", SESSION)
    assert_(nodes == [], f"Comment-only code should yield no nodes, got {nodes}")
test("comment-only code returns empty list", t_extract_comment_only)

def t_extract_unique_ids():
    nodes = _extract_nodes_regex(MULTI_CODE, "python", "m.py", SESSION)
    ids = [n.id for n in nodes]
    assert_(len(ids) == len(set(ids)), "Duplicate node IDs detected")
test("node IDs are unique", t_extract_unique_ids)

def t_extract_sessions_disjoint():
    n1 = _extract_nodes_regex(SQLI_CODE, "python", "a.py", "sid-A")
    n2 = _extract_nodes_regex(SQLI_CODE, "python", "a.py", "sid-B")
    ids1 = {n.id for n in n1}
    ids2 = {n.id for n in n2}
    assert_(ids1.isdisjoint(ids2), "Different sessions must produce disjoint node IDs")
test("different sessions produce disjoint node IDs", t_extract_sessions_disjoint)

# ═══════════════════════════════════════════════════════════════════
# SECTION 3: CFG edges
# ═══════════════════════════════════════════════════════════════════
section("3. CFG edge construction")

def t_cfg_produces_edges():
    nodes = _extract_nodes_regex(SQLI_CODE, "python", "sqli.py", SESSION)
    edges = _build_cfg_edges(nodes, SESSION)
    assert_(len(edges) > 0, "Expected CFG edges, got 0")
test("CFG edges are produced", t_cfg_produces_edges)

def t_cfg_kinds():
    nodes = _extract_nodes_regex(SQLI_CODE, "python", "sqli.py", SESSION)
    edges = _build_cfg_edges(nodes, SESSION)
    valid = {EdgeKind.CFG_NEXT, EdgeKind.CFG_TRUE, EdgeKind.CFG_FALSE}
    bad = [e for e in edges if e.kind not in valid]
    assert_(not bad, f"Invalid CFG edge kinds: {[b.kind for b in bad]}")
test("CFG edges have valid kinds", t_cfg_kinds)

def t_cfg_source_valid():
    nodes = _extract_nodes_regex(SQLI_CODE, "python", "sqli.py", SESSION)
    node_ids = {n.id for n in nodes}
    edges = _build_cfg_edges(nodes, SESSION)
    bad = [e for e in edges if e.source_id not in node_ids]
    assert_(not bad, f"{len(bad)} edges have invalid source_id")
test("CFG edge source_ids exist in node set", t_cfg_source_valid)

def t_cfg_target_valid():
    nodes = _extract_nodes_regex(SQLI_CODE, "python", "sqli.py", SESSION)
    node_ids = {n.id for n in nodes}
    edges = _build_cfg_edges(nodes, SESSION)
    bad = [e for e in edges if e.target_id not in node_ids]
    assert_(not bad, f"{len(bad)} edges have invalid target_id")
test("CFG edge target_ids exist in node set", t_cfg_target_valid)

def t_cfg_no_self_loops():
    nodes = _extract_nodes_regex(SQLI_CODE, "python", "sqli.py", SESSION)
    edges = _build_cfg_edges(nodes, SESSION)
    loops = [e for e in edges if e.source_id == e.target_id]
    assert_(not loops, f"Found {len(loops)} self-loop CFG edges")
test("CFG edges have no self-loops", t_cfg_no_self_loops)

def t_cfg_empty():
    edges = _build_cfg_edges([], SESSION)
    assert_(edges == [], f"Empty nodes should yield empty edges, got {edges}")
test("empty nodes → empty CFG", t_cfg_empty)

def t_cfg_session():
    nodes = _extract_nodes_regex(SQLI_CODE, "python", "sqli.py", SESSION)
    edges = _build_cfg_edges(nodes, SESSION)
    bad = [e for e in edges if e.session_id != SESSION]
    assert_(not bad, f"{len(bad)} CFG edges have wrong session_id")
test("CFG edges have correct session_id", t_cfg_session)

# ═══════════════════════════════════════════════════════════════════
# SECTION 4: DFG edges
# ═══════════════════════════════════════════════════════════════════
section("4. DFG edge construction")

def t_dfg_kinds():
    nodes = _extract_nodes_regex(SQLI_CODE, "python", "sqli.py", SESSION)
    edges = _build_dfg_edges(nodes, SESSION)
    valid = {EdgeKind.DFG_FLOW, EdgeKind.DFG_DEPENDS}
    bad = [e for e in edges if e.kind not in valid]
    assert_(not bad, f"Invalid DFG edge kinds: {[b.kind for b in bad]}")
test("DFG edges have valid kinds", t_dfg_kinds)

def t_dfg_valid_refs():
    nodes = _extract_nodes_regex(SQLI_CODE, "python", "sqli.py", SESSION)
    node_ids = {n.id for n in nodes}
    edges = _build_dfg_edges(nodes, SESSION)
    for e in edges:
        assert_(e.source_id in node_ids, f"DFG source {e.source_id} not in graph")
        assert_(e.target_id in node_ids, f"DFG target {e.target_id} not in graph")
test("DFG source and target IDs valid", t_dfg_valid_refs)

def t_dfg_forward():
    nodes = _extract_nodes_regex(SQLI_CODE, "python", "sqli.py", SESSION)
    nmap = {n.id: n for n in nodes}
    edges = _build_dfg_edges(nodes, SESSION)
    for e in edges:
        src = nmap[e.source_id]; tgt = nmap[e.target_id]
        assert_(src.line_start <= tgt.line_start,
                f"DFG flows backward: line {src.line_start} → {tgt.line_start}")
test("DFG edges flow forward in source", t_dfg_forward)

# ═══════════════════════════════════════════════════════════════════
# SECTION 5: Vulnerability detection
# ═══════════════════════════════════════════════════════════════════
section("5. Vulnerability detection")

def t_sqli_detected():
    findings = do_detect(SQLI_CODE, "sqli.py")
    types_ = [f.vuln_type for f in findings]
    assert_("SQL Injection" in types_, f"Expected SQL Injection. Got: {types_}")
test("SQL injection detected", t_sqli_detected)

def t_sqli_cwe():
    findings = do_detect(SQLI_CODE, "sqli.py")
    f = next((x for x in findings if x.vuln_type == "SQL Injection"), None)
    assert_(f is not None, "No SQL Injection finding")
    assert_(f.cwe == "CWE-89", f"Wrong CWE: {f.cwe}")
test("SQL injection CWE is CWE-89", t_sqli_cwe)

def t_sqli_severity():
    findings = do_detect(SQLI_CODE, "sqli.py")
    f = next((x for x in findings if x.vuln_type == "SQL Injection"), None)
    assert_(f is not None)
    assert_(f.severity == Severity.HIGH, f"Expected HIGH, got {f.severity}")
test("SQL injection severity is HIGH", t_sqli_severity)

def t_cmd_detected():
    findings = do_detect(CMD_CODE, "cmd.py")
    types_ = [f.vuln_type for f in findings]
    assert_("Command Injection" in types_, f"Expected Command Injection. Got: {types_}")
test("Command injection detected", t_cmd_detected)

def t_cmd_severity():
    findings = do_detect(CMD_CODE, "cmd.py")
    f = next(x for x in findings if x.vuln_type == "Command Injection")
    assert_(f.severity == Severity.HIGH, f"Expected HIGH, got {f.severity}")
test("Command injection severity is HIGH", t_cmd_severity)

def t_path_detected():
    findings = do_detect(PATH_CODE, "path.py")
    types_ = [f.vuln_type for f in findings]
    assert_("Path Traversal" in types_, f"Expected Path Traversal. Got: {types_}")
test("Path traversal detected", t_path_detected)

def t_path_severity():
    findings = do_detect(PATH_CODE, "path.py")
    f = next(x for x in findings if x.vuln_type == "Path Traversal")
    assert_(f.severity == Severity.MEDIUM, f"Expected MEDIUM, got {f.severity}")
test("Path traversal severity is MEDIUM", t_path_severity)

def t_pickle_detected():
    findings = do_detect(PICKLE_CODE, "pkl.py")
    types_ = [f.vuln_type for f in findings]
    assert_("Insecure Deserialisation" in types_, f"Expected Insecure Deserialisation. Got: {types_}")
test("Insecure deserialisation detected", t_pickle_detected)

def t_secret_detected():
    findings = do_detect(SECRET_CODE, "sec.py")
    types_ = [f.vuln_type for f in findings]
    assert_("Hardcoded Secret" in types_, f"Expected Hardcoded Secret. Got: {types_}")
test("Hardcoded secret detected", t_secret_detected)

def t_safe_no_findings():
    findings = do_detect(SAFE_CODE, "safe.py")
    assert_(findings == [], f"Expected 0 findings for safe code, got: {[f.vuln_type for f in findings]}")
test("safe code has zero findings", t_safe_no_findings)

def t_findings_have_snippet():
    findings = do_detect(SQLI_CODE, "sqli.py")
    bad = [f for f in findings if not f.code_snippet]
    assert_(not bad, f"{len(bad)} findings missing code_snippet")
test("all findings have code_snippet", t_findings_have_snippet)

def t_findings_have_description():
    findings = do_detect(SQLI_CODE, "sqli.py")
    bad = [f for f in findings if len(f.description) < 20]
    assert_(not bad, f"{len(bad)} findings have short description")
test("all findings have description >20 chars", t_findings_have_description)

def t_findings_have_remediation():
    findings = do_detect(SQLI_CODE, "sqli.py")
    bad = [f for f in findings if not f.remediation]
    assert_(not bad, f"{len(bad)} findings missing remediation")
test("all findings have remediation", t_findings_have_remediation)

def t_findings_have_references():
    findings = do_detect(SQLI_CODE, "sqli.py")
    bad = [f for f in findings if not f.references]
    assert_(not bad, f"{len(bad)} findings have no references")
test("all findings have ≥1 reference", t_findings_have_references)

def t_confidence_range():
    findings = do_detect(MULTI_CODE, "multi.py")
    bad = [f for f in findings if not (0.0 <= f.confidence <= 1.0)]
    assert_(not bad, f"Confidence out of range: {[f.confidence for f in bad]}")
test("confidence values in [0.0, 1.0]", t_confidence_range)

def t_multi_vuln_types():
    findings = do_detect(MULTI_CODE, "multi.py")
    types_ = {f.vuln_type for f in findings}
    assert_(len(types_) >= 2, f"Expected ≥2 vuln types, got: {types_}")
test("multi-vuln file detects ≥2 distinct types", t_multi_vuln_types)

def t_finding_node_ids_valid():
    nodes = _extract_nodes_regex(SQLI_CODE, "python", "sqli.py", SESSION)
    source_lines = {"sqli.py": SQLI_CODE.splitlines()}
    findings = _detect_vulnerabilities(nodes, SESSION, source_lines)
    node_ids = {n.id for n in nodes}
    bad = [f for f in findings if f.node_id not in node_ids]
    assert_(not bad, f"{len(bad)} findings reference non-existent node IDs")
test("finding node_ids reference existing nodes", t_finding_node_ids_valid)

def t_finding_ids_unique():
    findings = do_detect(MULTI_CODE, "multi.py")
    ids = [f.id for f in findings]
    assert_(len(ids) == len(set(ids)), "Finding IDs must be unique")
test("finding IDs are unique", t_finding_ids_unique)

def t_vuln_pattern_catalogue():
    required = {"vuln_type","cwe","severity","node_types","keywords",
                "sink_pattern","description","remediation","references"}
    patterns = get_patterns("python")
    assert_(len(patterns) > 0, "get_patterns('python') returned empty list — check YAML file and PyYAML install")
    for pat in patterns:
        missing = required - set(pat.keys())
        assert_(not missing, f"Pattern '{pat.get('vuln_type')}' missing keys: {missing}")
test("YAML sink catalogue loads and is complete", t_vuln_pattern_catalogue)

def t_finding_has_file():
    findings = do_detect(SQLI_CODE, "sqli.py")
    bad = [f for f in findings if f.file != "sqli.py"]
    assert_(not bad, f"{len(bad)} findings have wrong file")
test("findings have correct file attribute", t_finding_has_file)

def t_finding_line_gt_0():
    findings = do_detect(SQLI_CODE, "sqli.py")
    bad = [f for f in findings if f.line_start <= 0]
    assert_(not bad, f"{len(bad)} findings have line_start <= 0")
test("findings have line_start > 0", t_finding_line_gt_0)

# ═══════════════════════════════════════════════════════════════════
# SECTION 6: Async pipeline event stream
# ═══════════════════════════════════════════════════════════════════
section("6. Pipeline event stream (async)")

def t_pipeline_produces():
    events = asyncio.run(collect_events(SQLI_CODE, "sqli.py"))
    assert_(len(events) > 0, "Pipeline produced no events")
test("pipeline produces events", t_pipeline_produces)

def t_pipeline_first_parse():
    events = asyncio.run(collect_events(SAFE_CODE))
    phase_events = [e for e in events if e.type == WSEventType.PHASE]
    assert_(phase_events, "No phase events")
    assert_(phase_events[0].payload["stage"] == PipelinePhase.PARSE,
            f"First phase should be PARSE, got {phase_events[0].payload['stage']}")
test("first phase event is PARSE", t_pipeline_first_parse)

def t_pipeline_ends_complete():
    events = asyncio.run(collect_events(SQLI_CODE, "sqli.py"))
    last = events[-1]
    assert_(last.type == WSEventType.COMPLETE,
            f"Last event should be COMPLETE, got {last.type}")
test("pipeline ends with COMPLETE event", t_pipeline_ends_complete)

def t_pipeline_node_events():
    events = asyncio.run(collect_events(SQLI_CODE, "sqli.py"))
    count = sum(1 for e in events if e.type == WSEventType.NODE)
    assert_(count > 0, "No NODE events emitted")
test("pipeline emits NODE events", t_pipeline_node_events)

def t_pipeline_edge_events():
    events = asyncio.run(collect_events(SQLI_CODE, "sqli.py"))
    count = sum(1 for e in events if e.type == WSEventType.EDGE)
    assert_(count > 0, "No EDGE events emitted")
test("pipeline emits EDGE events", t_pipeline_edge_events)

def t_pipeline_annotation_events():
    events = asyncio.run(collect_events(SQLI_CODE, "sqli.py"))
    count = sum(1 for e in events if e.type == WSEventType.ANNOTATION)
    assert_(count > 0, "No ANNOTATION events emitted")
test("pipeline emits ANNOTATION events", t_pipeline_annotation_events)

def t_pipeline_finding_for_vuln():
    events = asyncio.run(collect_events(SQLI_CODE, "sqli.py"))
    findings = [e for e in events if e.type == WSEventType.FINDING]
    assert_(len(findings) > 0, "No FINDING events for vulnerable code")
    types_ = [e.payload["vuln_type"] for e in findings]
    assert_("SQL Injection" in types_, f"Expected SQL Injection finding. Got: {types_}")
test("pipeline emits FINDING for SQL injection", t_pipeline_finding_for_vuln)

def t_pipeline_no_findings_safe():
    events = asyncio.run(collect_events(SAFE_CODE, "safe.py"))
    findings = [e for e in events if e.type == WSEventType.FINDING]
    assert_(findings == [], f"Expected no findings for safe code, got {len(findings)}")
test("pipeline emits no FINDINGs for safe code", t_pipeline_no_findings_safe)

def t_pipeline_all_session():
    events = asyncio.run(collect_events(SQLI_CODE, "sqli.py"))
    bad = [e for e in events if e.session_id != SESSION]
    assert_(not bad, f"{len(bad)} events have wrong session_id")
test("all events carry session_id", t_pipeline_all_session)

def t_pipeline_complete_counts():
    events = asyncio.run(collect_events(SQLI_CODE, "sqli.py"))
    node_count = sum(1 for e in events if e.type == WSEventType.NODE)
    edge_count = sum(1 for e in events if e.type == WSEventType.EDGE)
    find_count = sum(1 for e in events if e.type == WSEventType.FINDING)
    complete = next(e for e in events if e.type == WSEventType.COMPLETE)
    assert_(complete.payload["node_count"] == node_count,
            f"node_count mismatch: {complete.payload['node_count']} vs {node_count}")
    assert_(complete.payload["edge_count"] == edge_count,
            f"edge_count mismatch: {complete.payload['edge_count']} vs {edge_count}")
    assert_(complete.payload["finding_count"] == find_count,
            f"finding_count mismatch: {complete.payload['finding_count']} vs {find_count}")
test("COMPLETE payload counts match actual events", t_pipeline_complete_counts)

def t_pipeline_phase_order():
    events = asyncio.run(collect_events(SQLI_CODE, "sqli.py"))
    phases = [e.payload["stage"] for e in events if e.type == WSEventType.PHASE]
    expected = [
        PipelinePhase.PARSE, PipelinePhase.AST, PipelinePhase.NORMALIZE,
        PipelinePhase.CFG, PipelinePhase.DFG, PipelinePhase.CPG_MERGE,
        PipelinePhase.GRAPHCODEBERT, PipelinePhase.ANNOTATE, PipelinePhase.COMPLETE,
    ]
    assert_(phases == expected, f"Phase order wrong.\nExpected: {expected}\nGot:      {phases}")
test("phase order is correct", t_pipeline_phase_order)

def t_pipeline_annotation_refs_nodes():
    events = asyncio.run(collect_events(SQLI_CODE, "sqli.py"))
    node_ids = {e.payload["id"] for e in events if e.type == WSEventType.NODE}
    ann_events = [e for e in events if e.type == WSEventType.ANNOTATION]
    bad = [a for a in ann_events if a.payload["node_id"] not in node_ids]
    assert_(not bad, f"{len(bad)} annotations reference unknown node IDs")
test("annotation node_ids reference known nodes", t_pipeline_annotation_refs_nodes)

# ═══════════════════════════════════════════════════════════════════
# SECTION 7: Edge cases
# ═══════════════════════════════════════════════════════════════════
section("7. Edge cases and robustness")

def t_short_code():
    nodes = _extract_nodes_regex("x = 1", "python", "tiny.py", SESSION)
    assert_(isinstance(nodes, list))
test("very short code doesn't crash", t_short_code)

def t_unicode():
    code = "# Commentaire en français\ndef saluer(nom):\n    return f'Bonjour {nom}'\n"
    nodes = _extract_nodes_regex(code, "python", "unicode.py", SESSION)
    assert_(isinstance(nodes, list))
test("unicode code doesn't crash", t_unicode)

def t_large_file():
    big = (MULTI_CODE + "\n") * 10
    start = time.time()
    nodes = _extract_nodes_regex(big, "python", "big.py", SESSION)
    _build_cfg_edges(nodes, SESSION)
    elapsed = time.time() - start
    assert_(elapsed < 5.0, f"Took {elapsed:.1f}s — too slow for 500-line file")
test("large file (≈500 lines) processes in <5s", t_large_file)

def t_async_pipeline_short():
    events = asyncio.run(collect_events("x = 1\nreturn x", "tiny.py"))
    assert_(isinstance(events, list))
test("async pipeline handles minimal code", t_async_pipeline_short)

# ═══════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════
# SECTION 8: Sink loader and detection architecture
# ═══════════════════════════════════════════════════════════════════
section("8. Sink loader and detection architecture")

def t_yaml_loader_returns_patterns():
    patterns = get_patterns("python")
    assert_(len(patterns) >= 8, f"Expected >=8 patterns from python.yaml, got {len(patterns)}")
test("YAML loader returns patterns for python", t_yaml_loader_returns_patterns)

def t_yaml_loader_alias_js():
    patterns = get_patterns("javascript")
    assert_(len(patterns) > 0, "Expected patterns for javascript.yaml")
test("YAML loader resolves javascript language", t_yaml_loader_alias_js)

def t_yaml_loader_alias_ts():
    import core.cpg_builder as cb
    cb._PATTERN_CACHE.pop("typescript", None)
    cb._PATTERN_CACHE.pop("javascript", None)
    ts = get_patterns("typescript")
    js = get_patterns("javascript")
    assert_(len(ts) == len(js), "typescript should alias to javascript patterns")
test("YAML loader aliases typescript to javascript", t_yaml_loader_alias_ts)

def t_yaml_loader_terraform():
    patterns = get_patterns("terraform")
    assert_(len(patterns) > 0, "Expected IaC patterns from terraform.yaml")
test("YAML loader loads terraform/HCL patterns", t_yaml_loader_terraform)

def t_yaml_loader_hcl_alias():
    import core.cpg_builder as cb
    cb._PATTERN_CACHE.pop("hcl", None)
    cb._PATTERN_CACHE.pop("terraform", None)
    hcl = get_patterns("hcl")
    tf  = get_patterns("terraform")
    assert_(len(hcl) == len(tf), "hcl should alias to terraform patterns")
test("YAML loader aliases hcl to terraform", t_yaml_loader_hcl_alias)

def t_yaml_loader_unknown_fallback():
    import core.cpg_builder as cb
    cb._PATTERN_CACHE.pop("cobol", None)
    cobol   = get_patterns("cobol")
    python_ = get_patterns("python")
    assert_(len(cobol) == len(python_), "Unknown language should fall back to python.yaml")
test("YAML loader falls back to python for unknown language", t_yaml_loader_unknown_fallback)

def t_patterns_have_taint_defs():
    patterns = get_patterns("python")
    taint = [p for p in patterns if p.get("sources") and p.get("sinks")]
    assert_(len(taint) >= 5, f"Expected >=5 patterns with source/sink defs, got {len(taint)}")
test("python patterns have source/sink taint definitions", t_patterns_have_taint_defs)

def t_hardcoded_secret_no_sources():
    patterns = get_patterns("python")
    secret = next((p for p in patterns if p["vuln_type"] == "Hardcoded Secret"), None)
    assert_(secret is not None, "Hardcoded Secret pattern not found in python.yaml")
    assert_(secret.get("sources", []) == [], "Hardcoded Secret should have empty sources (regex-only)")
test("Hardcoded Secret has no sources (regex-only detection)", t_hardcoded_secret_no_sources)

def t_regex_respects_skip_node_ids():
    from core.cpg_builder import _detect_via_regex
    nodes = _extract_nodes_regex(SQLI_CODE, "python", "sqli.py", SESSION)
    source_lines = {"sqli.py": SQLI_CODE.splitlines()}
    all_findings = _detect_vulnerabilities(nodes, SESSION, source_lines, "python")
    skip_ids = {f.node_id for f in all_findings}
    skipped = _detect_via_regex(nodes, SESSION, source_lines, "python", skip_node_ids=skip_ids)
    assert_(skipped == [], f"Expected 0 after skipping known nodes, got {len(skipped)}")
test("_detect_via_regex respects skip_node_ids (deduplication)", t_regex_respects_skip_node_ids)

def t_pattern_cache_hit():
    import core.cpg_builder as cb
    # Warm cache then confirm a second call does NOT re-read disk
    # (if it re-read disk it would lose the sentinel we added to the cache)
    get_patterns("python")
    original_list = cb._PATTERN_CACHE["python"]
    sentinel = {"_sentinel": True, "vuln_type": "__test__"}
    original_list.append(sentinel)
    # If cache is working, get_patterns returns the same list object
    second_call = get_patterns("python")
    found = any(p.get("_sentinel") for p in second_call)
    original_list.remove(sentinel)  # clean up
    assert_(found, "Second call should return cached list (sentinel not found — cache miss)")
test("YAML patterns are cached after first load", t_pattern_cache_hit)

def t_javascript_has_prototype_pollution():
    patterns = get_patterns("javascript")
    types_ = [p["vuln_type"] for p in patterns]
    assert_("Prototype Pollution" in types_, f"Expected Prototype Pollution in JS patterns. Got: {types_}")
test("JavaScript patterns include Prototype Pollution (new pattern)", t_javascript_has_prototype_pollution)

def t_terraform_has_iac_patterns():
    patterns = get_patterns("terraform")
    types_ = [p["vuln_type"] for p in patterns]
    assert_("Public S3 Bucket" in types_, f"Expected IaC patterns. Got: {types_}")
    assert_("Hardcoded Secret in IaC" in types_, f"Missing IaC secret pattern. Got: {types_}")
test("Terraform patterns include IaC-specific vuln types", t_terraform_has_iac_patterns)

def t_all_loaded_patterns_have_required_keys():
    required = {"vuln_type","cwe","severity","node_types","keywords",
                "sink_pattern","description","remediation","references"}
    for lang in ["python", "javascript", "java", "go", "terraform"]:
        for pat in get_patterns(lang):
            missing = required - set(pat.keys())
            assert_(not missing, f"[{lang}] Pattern '{pat.get('vuln_type')}' missing: {missing}")
test("All language patterns have required keys", t_all_loaded_patterns_have_required_keys)


# ═══════════════════════════════════════════════════════════════════
# SECTION 9: Multi-language extraction
# ═══════════════════════════════════════════════════════════════════
section("9. Multi-language extraction")

JAVA_CODE = """
import java.sql.*;

public class UserDAO {
    public User getUser(String userId) throws SQLException {
        Connection conn = DriverManager.getConnection(DB_URL);
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(
            "SELECT * FROM users WHERE id=" + userId
        );
        return parseResult(rs);
    }
}
"""

JS_CODE = """
const express = require('express');
const db = require('./db');

async function getUser(req, res) {
    const userId = req.query.id;
    const result = await db.query('SELECT * FROM users WHERE id=' + userId);
    const html = '<div>' + req.query.q + '</div>';
    document.innerHTML = html;
    res.json(result);
}
"""

GO_CODE = """
import (
    "database/sql"
    "net/http"
    "os/exec"
)

func getUser(w http.ResponseWriter, r *http.Request) {
    userId := r.URL.Query().Get("id")
    row := db.Query("SELECT * FROM users WHERE id=" + userId)
    cmd := exec.Command("ls", userId)
    cmd.Run()
}
"""

RUST_CODE = """
use std::fs;
use std::process::Command;

fn read_config(path: &str) -> String {
    let content = fs::read_to_string(path).unwrap();
    content
}

fn run_cmd(input: &str) {
    let output = Command::new("sh").arg(input).output().unwrap();
}
"""

C_CODE = """
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vuln_strcpy(char *user_input) {
    char buf[10];
    strcpy(buf, user_input);
}

void vuln_system(char *user_input) {
    char cmd[256];
    sprintf(cmd, "ls %s", user_input);
    system(cmd);
}
"""

TERRAFORM_CODE = """
resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  acl    = "public-read"
}

variable "db_password" {
  default = "hardcoded_password_123"
}
"""

def t_java_extracts_function():
    nodes = _extract_nodes_regex(JAVA_CODE, "java", "UserDAO.java", SESSION)
    types_ = [n.node_type for n in nodes]
    assert_(NodeType.FUNCTION in types_, f"No FUNCTION node in Java. Got: {types_}")
test("Java: extracts FUNCTION nodes", t_java_extracts_function)

def t_java_extracts_import():
    nodes = _extract_nodes_regex(JAVA_CODE, "java", "UserDAO.java", SESSION)
    types_ = [n.node_type for n in nodes]
    assert_(NodeType.IMPORT in types_, f"No IMPORT node in Java. Got: {types_}")
test("Java: extracts IMPORT nodes", t_java_extracts_import)

def t_java_extracts_call():
    nodes = _extract_nodes_regex(JAVA_CODE, "java", "UserDAO.java", SESSION)
    types_ = [n.node_type for n in nodes]
    assert_(NodeType.CALL in types_, f"No CALL node in Java. Got: {types_}")
test("Java: extracts CALL nodes", t_java_extracts_call)

def t_js_extracts_function():
    nodes = _extract_nodes_regex(JS_CODE, "javascript", "app.js", SESSION)
    types_ = [n.node_type for n in nodes]
    assert_(NodeType.FUNCTION in types_, f"No FUNCTION node in JS. Got: {types_}")
test("JavaScript: extracts FUNCTION nodes", t_js_extracts_function)

def t_js_extracts_assign():
    nodes = _extract_nodes_regex(JS_CODE, "javascript", "app.js", SESSION)
    types_ = [n.node_type for n in nodes]
    assert_(NodeType.ASSIGN in types_, f"No ASSIGN node in JS. Got: {types_}")
test("JavaScript: extracts ASSIGN nodes", t_js_extracts_assign)

def t_ts_uses_js_patterns():
    ts_nodes = _extract_nodes_regex(JS_CODE, "typescript", "app.ts", SESSION)
    js_nodes = _extract_nodes_regex(JS_CODE, "javascript", "app.js", SESSION)
    assert_(len(ts_nodes) == len(js_nodes), "typescript and javascript should produce same node count")
test("TypeScript: uses javascript patterns (alias)", t_ts_uses_js_patterns)

def t_go_extracts_function():
    nodes = _extract_nodes_regex(GO_CODE, "go", "main.go", SESSION)
    types_ = [n.node_type for n in nodes]
    assert_(NodeType.FUNCTION in types_, f"No FUNCTION node in Go. Got: {types_}")
test("Go: extracts FUNCTION nodes", t_go_extracts_function)

def t_go_extracts_assign():
    nodes = _extract_nodes_regex(GO_CODE, "go", "main.go", SESSION)
    types_ = [n.node_type for n in nodes]
    assert_(NodeType.ASSIGN in types_, f"No ASSIGN node in Go. Got: {types_}")
test("Go: extracts ASSIGN nodes (:= and var)", t_go_extracts_assign)

def t_rust_extracts_function():
    nodes = _extract_nodes_regex(RUST_CODE, "rust", "main.rs", SESSION)
    types_ = [n.node_type for n in nodes]
    assert_(NodeType.FUNCTION in types_, f"No FUNCTION node in Rust. Got: {types_}")
test("Rust: extracts FUNCTION nodes (fn)", t_rust_extracts_function)

def t_c_extracts_function():
    nodes = _extract_nodes_regex(C_CODE, "c", "vuln.c", SESSION)
    types_ = [n.node_type for n in nodes]
    assert_(NodeType.FUNCTION in types_, f"No FUNCTION node in C. Got: {types_}")
test("C: extracts FUNCTION nodes", t_c_extracts_function)

def t_c_extracts_import():
    nodes = _extract_nodes_regex(C_CODE, "c", "vuln.c", SESSION)
    types_ = [n.node_type for n in nodes]
    assert_(NodeType.IMPORT in types_, f"No IMPORT node in C (#include). Got: {types_}")
test("C: extracts IMPORT nodes (#include)", t_c_extracts_import)

def t_cpp_uses_c_patterns():
    c_nodes   = _extract_nodes_regex(C_CODE, "c",   "vuln.c",   SESSION)
    cpp_nodes = _extract_nodes_regex(C_CODE, "cpp", "vuln.cpp", SESSION)
    assert_(len(cpp_nodes) == len(c_nodes), "cpp should alias to c patterns")
test("C++: uses c patterns (alias)", t_cpp_uses_c_patterns)

def t_terraform_extracts_block():
    nodes = _extract_nodes_regex(TERRAFORM_CODE, "terraform", "main.tf", SESSION)
    types_ = [n.node_type for n in nodes]
    assert_(NodeType.BLOCK in types_, f"No BLOCK node in Terraform. Got: {types_}")
test("Terraform: extracts resource BLOCK nodes", t_terraform_extracts_block)

def t_terraform_extracts_assign():
    nodes = _extract_nodes_regex(TERRAFORM_CODE, "terraform", "main.tf", SESSION)
    types_ = [n.node_type for n in nodes]
    assert_(NodeType.ASSIGN in types_, f"No ASSIGN node in Terraform. Got: {types_}")
test("Terraform: extracts attribute ASSIGN nodes", t_terraform_extracts_assign)

def t_hcl_alias():
    tf_nodes  = _extract_nodes_regex(TERRAFORM_CODE, "terraform", "main.tf",  SESSION)
    hcl_nodes = _extract_nodes_regex(TERRAFORM_CODE, "hcl",       "main.hcl", SESSION)
    assert_(len(tf_nodes) == len(hcl_nodes), "hcl should alias to terraform patterns")
test("HCL: uses terraform patterns (alias)", t_hcl_alias)

def t_all_languages_produce_nodes():
    cases = [
        (JAVA_CODE,      "java",       "UserDAO.java"),
        (JS_CODE,        "javascript", "app.js"),
        (JS_CODE,        "typescript", "app.ts"),
        (GO_CODE,        "go",         "main.go"),
        (RUST_CODE,      "rust",       "main.rs"),
        (C_CODE,         "c",          "vuln.c"),
        (C_CODE,         "cpp",        "vuln.cpp"),
        (TERRAFORM_CODE, "terraform",  "main.tf"),
        (TERRAFORM_CODE, "hcl",        "main.hcl"),
        (SAFE_CODE,      "python",     "safe.py"),
    ]
    for code, lang, fname in cases:
        nodes = _extract_nodes_regex(code, lang, fname, SESSION)
        assert_(len(nodes) > 0,
                f"Expected nodes for language '{lang}', got 0 from {fname}")
test("All languages produce at least 1 node", t_all_languages_produce_nodes)

def t_node_ids_unique_across_languages():
    all_nodes = []
    for code, lang, fname in [
        (JAVA_CODE, "java", "UserDAO.java"),
        (JS_CODE,   "javascript", "app.js"),
        (GO_CODE,   "go", "main.go"),
    ]:
        all_nodes += _extract_nodes_regex(code, lang, fname, SESSION)
    ids = [n.id for n in all_nodes]
    assert_(len(ids) == len(set(ids)), "Node IDs must be unique across different language files")
test("Node IDs are unique across different language files", t_node_ids_unique_across_languages)

def t_extract_nodes_returns_backend():
    nodes, backend = extract_nodes(SAFE_CODE, "python", "safe.py", SESSION)
    assert_(backend in ("treesitter", "regex"), f"Unexpected backend: {backend!r}")
    assert_(isinstance(nodes, list), "extract_nodes must return a list")
test("extract_nodes() returns (nodes, backend) tuple", t_extract_nodes_returns_backend)

def t_extract_nodes_fallback_still_works():
    # Even if tree-sitter is unavailable, regex backend must produce nodes
    nodes, backend = extract_nodes(SQLI_CODE, "python", "sqli.py", SESSION)
    assert_(len(nodes) > 0, "extract_nodes must produce nodes even in fallback mode")
test("extract_nodes() produces nodes regardless of backend", t_extract_nodes_fallback_still_works)

def t_java_sql_injection_detected():
    nodes = _extract_nodes_regex(JAVA_CODE, "java", "UserDAO.java", SESSION)
    source_lines = {"UserDAO.java": JAVA_CODE.splitlines()}
    findings = _detect_vulnerabilities(nodes, SESSION, source_lines, "java")
    types_ = [f.vuln_type for f in findings]
    assert_("SQL Injection" in types_,
            f"Expected SQL Injection in Java code. Got: {types_}")
test("Java: SQL injection detected via java.yaml patterns", t_java_sql_injection_detected)

def t_terraform_public_s3_detected():
    nodes = _extract_nodes_regex(TERRAFORM_CODE, "terraform", "main.tf", SESSION)
    source_lines = {"main.tf": TERRAFORM_CODE.splitlines()}
    findings = _detect_vulnerabilities(nodes, SESSION, source_lines, "terraform")
    types_ = [f.vuln_type for f in findings]
    assert_(len(findings) > 0,
            f"Expected IaC findings for Terraform code. Got nothing. Patterns: {[p['vuln_type'] for p in get_patterns('terraform')]}")
test("Terraform: IaC misconfiguration detected", t_terraform_public_s3_detected)

def t_comments_skipped_all_languages():
    for lang, comment in [
        ("python",     "# this is a comment"),
        ("java",       "// this is a comment"),
        ("javascript", "// this is a comment"),
        ("go",         "// this is a comment"),
        ("rust",       "// this is a comment"),
        ("c",          "// this is a comment"),
        ("terraform",  "# this is a comment"),
    ]:
        nodes = _extract_nodes_regex(comment, lang, f"test.{lang}", SESSION)
        assert_(nodes == [],
                f"Comment line should produce no nodes for {lang}, got: {nodes}")
test("Comments skipped for all languages", t_comments_skipped_all_languages)

# Final report
# ═══════════════════════════════════════════════════════════════════
print(f"\n{'═'*60}")
print(f"  Results:  {PASS} passed  |  {FAIL} failed  |  {PASS+FAIL} total")
print(f"{'═'*60}")
if ERRORS:
    print("\nFailed tests detail:")
    for name, err in ERRORS:
        print(f"  ✗ {name}")
        print(f"    {err}")
sys.exit(0 if FAIL == 0 else 1)