"""
PRISM Joern Delegate
====================
Delegates AST/CFG/DFG generation to Joern for the languages it natively
supports: C, C++, Java, JavaScript, TypeScript, Go, Python.

Joern produces a full Code Property Graph (CPG) out of the box for these
languages. PRISM uses Joern as a black-box CPG generator and then:
  1. Exports the CPG from Joern's embedded graph store via its REST API
     or cpg-query tool (joern-export)
  2. Normalizes the exported node/edge data into PRISM's unified schema
  3. Assembles a ParsedGraphOutput that is identical in shape to what
     the Tree-sitter parser produces — so all downstream stages are blind
     to which backend was used

Joern Integration Architecture:
  ┌──────────────┐     ┌─────────────────────┐    ┌──────────────────┐
  │ Source File  │────▶│  Joern CPG Generator │───▶│ joern-export     │
  └──────────────┘     │  (joern --script)    │    │ (GraphML / JSON) │
                        └─────────────────────┘    └────────┬─────────┘
                                                            │
                                                   ┌────────▼─────────┐
                                                   │  JoernDelegate   │
                                                   │  (normalize +    │
                                                   │   assemble CPG)  │
                                                   └────────┬─────────┘
                                                            │
                                                   ┌────────▼─────────┐
                                                   │ ParsedGraphOutput│
                                                   └──────────────────┘

Free / Local Setup (no Azure required):
  - Joern runs locally as a JVM process
  - Install: https://docs.joern.io/installation
  - This delegate invokes Joern via subprocess using joern-parse + joern-export
  - No cloud account needed — Joern is fully open source (Apache 2.0)

Joern commands used:
  joern-parse  <src_dir>  --output <cpg.bin>
  joern-export <cpg.bin>  --repr cpg14 --format graphml --out <export_dir>
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from .base import AbstractParser          # FIX-1: use parser/parsers/base.py (can_parse + parse)
from ..models import (
    Edge, EdgeType, FileMetadata, GraphCodeBERTInput, Language,
    NormalizedNode, NodeType, ParsedGraphOutput, ParserBackend,
    SecurityAnnotationSummary, SecurityLabel,
)
from ...graph_builder.normalizer import normalize_node_type
from ..security_annotator import SecurityAnnotator
from ..token_extractor import extract_tokens
from ..sandbox_config import get_minimal_subprocess_env, LIMITS

logger = logging.getLogger(__name__)

# Languages fully handled by Joern
JOERN_SUPPORTED: frozenset[Language] = frozenset({
    Language.PYTHON,
    Language.JAVA,
    Language.JAVASCRIPT,
    Language.TYPESCRIPT,
    Language.GO,
    Language.C,
    Language.CPP,
})

# Joern binary names (must be on PATH or configured via JOERN_HOME env var)
_JOERN_PARSE_BIN  = "joern-parse"
_JOERN_EXPORT_BIN = "joern-export"


class JoernDelegate(AbstractParser):
    """
    Parses source files using Joern and converts the CPG output to
    PRISM's unified ParsedGraphOutput format.

    Configuration (via environment variables or constructor args):
        JOERN_HOME       : Path to Joern installation directory
        JOERN_TIMEOUT    : Max seconds to wait for Joern (default: 300)
        JOERN_MAX_HEAP   : JVM heap size string, e.g. "4G" (default: "2G")
    """

    def __init__(
        self,
        joern_home: str | None = None,
        timeout: int | None = None,
        max_heap: str | None = None,
    ) -> None:
        self.joern_home = joern_home or os.environ.get("JOERN_HOME", "")
        self.timeout = timeout or int(os.environ.get("JOERN_TIMEOUT", "300"))
        self.max_heap = max_heap or os.environ.get("JOERN_MAX_HEAP", "2G")
        self._annotator = SecurityAnnotator()
        self._joern_available: bool | None = None  # cached availability check

    # -----------------------------------------------------------------------
    # AbstractParser interface  (parser/parsers/base.py contract)
    # -----------------------------------------------------------------------

    @property
    def backend_name(self) -> str:                          # FIX-1: required by base
        return "joern"

    def can_parse(self, language: Language) -> bool:        # FIX-1: was supports()
        return language in JOERN_SUPPORTED and self._is_joern_available()

    def parse(                                               # FIX-1: was parse_file()
        self,
        source_code: str,
        file_path: str,
        language: Language,
    ) -> ParsedGraphOutput:
        """Adapter: parse() → parse_file() for AbstractParser compliance."""
        return self.parse_file(file_path, source_code, language)

    def parse_file(
        self, file_path: str, content: str, language: Language
    ) -> ParsedGraphOutput:
        """
        Full pipeline:
          1. Write content to a temp directory
          2. Run joern-parse to produce a CPG binary
          3. Run joern-export to produce GraphML
          4. Parse GraphML into normalized nodes + edges
          5. Annotate security labels
          6. Extract tokens
        """
        start = time.monotonic()
        errors: list[str] = []

        metadata = FileMetadata(
            file_path=file_path,
            language=language,
            backend=ParserBackend.JOERN,
            file_hash="",
            size_bytes=len(content.encode("utf-8")),
            line_count=content.count("\n") + 1,
            encoding="utf-8",
            parse_duration_ms=0.0,
            error_count=0,
            has_parse_errors=False,
        )

        if not self._is_joern_available():
            logger.warning(
                "Joern not found on PATH (JOERN_HOME=%s). "
                "Returning minimal graph for %s. "
                "Install Joern: https://docs.joern.io/installation",
                self.joern_home, file_path,
            )
            errors = ["joern_not_available"]
            return self._make_output(
                metadata=FileMetadata(
                    file_path=file_path, language=language,
                    backend=ParserBackend.JOERN,
                    file_hash="", size_bytes=len(content.encode()),
                    line_count=content.count("\n") + 1, encoding="utf-8",
                    parse_duration_ms=0.0, error_count=1, has_parse_errors=True,
                ),
                nodes=self._minimal_nodes(content, language, file_path),
                edges=[],
                parse_errors=errors,
                warnings=["Joern unavailable — minimal AST only"],
            )

        with tempfile.TemporaryDirectory(prefix="prism_joern_") as tmpdir:
            tmp = Path(tmpdir)

            # Write source file preserving its name for Joern's language detection
            src_name = Path(file_path).name or "source"
            src_file = tmp / "src" / src_name
            src_file.parent.mkdir(exist_ok=True)
            src_file.write_text(content, encoding="utf-8")

            cpg_path    = tmp / "cpg.bin"
            export_dir  = tmp / "export"
            export_dir.mkdir()

            # ---- Step 1: joern-parse ----------------------------------------
            parse_ok, parse_err = self._run_joern_parse(
                src_dir=str(src_file.parent),
                cpg_output=str(cpg_path),
            )
            if not parse_ok:
                errors.append(f"joern_parse_error: {parse_err}")
                logger.error("joern-parse failed for %s: %s", file_path, parse_err)
                return self._make_output(
                    metadata=metadata, nodes=self._minimal_nodes(content, language, file_path),
                    edges=[], parse_errors=errors, warnings=["joern-parse failed — minimal AST only"],
                )

            # ---- Step 2: joern-export ----------------------------------------
            export_ok, export_err = self._run_joern_export(
                cpg_path=str(cpg_path),
                export_dir=str(export_dir),
            )
            if not export_ok:
                errors.append(f"joern_export_error: {export_err}")
                logger.error("joern-export failed for %s: %s", file_path, export_err)
                return self._make_output(
                    metadata=metadata, nodes=self._minimal_nodes(content, language, file_path),
                    edges=[], parse_errors=errors, warnings=["joern-export failed — minimal AST only"],
                )

            # ---- Step 3: Parse exported GraphML ------------------------------
            graphml_files = list(export_dir.rglob("*.xml")) + \
                            list(export_dir.rglob("*.graphml"))

            nodes: list[NormalizedNode] = []
            edges: list[Edge] = []

            for gml_file in graphml_files:
                try:
                    file_nodes, file_edges = self._parse_graphml(
                        gml_file, file_path, language, content
                    )
                    nodes.extend(file_nodes)
                    edges.extend(file_edges)
                except Exception as exc:
                    errors.append(f"graphml_parse_error: {gml_file.name}: {exc}")
                    logger.warning("Failed to parse %s: %s", gml_file, exc)

            # Also try JSON export if GraphML not found
            if not nodes:
                json_files = list(export_dir.rglob("*.json"))
                for jf in json_files:
                    try:
                        j_nodes, j_edges = self._parse_json_export(
                            jf, file_path, language, content
                        )
                        nodes.extend(j_nodes)
                        edges.extend(j_edges)
                    except Exception as exc:
                        errors.append(f"json_parse_error: {jf.name}: {exc}")

            # FIX-4: update metadata fields (FileMetadata is a plain dataclass)
            metadata.error_count      = len(errors)
            metadata.has_parse_errors = bool(errors)
            metadata.parse_duration_ms = round((time.monotonic() - start) * 1000, 2)

        elapsed = time.monotonic() - start
        logger.info(
            "Joern parsed %s in %.2fs: %d nodes, %d edges",
            file_path, elapsed, len(nodes), len(edges),
        )

        # ---- Step 4: Security annotation  (FIX-2: per-node, not graph) ------
        for node in nodes:
            lbl, conf, cwes = self._annotator.annotate(
                node.node_type, node.name, language, node.raw_text or ""
            )
            node.security_label      = lbl
            node.security_confidence = conf
            node.cwe_hints           = cwes

        # ---- Step 5: Token extraction  (FIX-3: use the return value) ---------
        code_tokens = extract_tokens(
            ParsedGraphOutput(
                metadata=metadata,
                nodes=nodes, edges=edges,
                security_summary=SecurityAnnotationSummary(),
                graphcodebert_input=GraphCodeBERTInput(
                    tokens=[], token_node_ids=[], dfg_edges=[],
                    node_type_sequence=[], security_label_sequence=[],
                ),
                graph_hash="",
                parse_errors=errors, warnings=[],
            )
        )

        return self._make_output(
            metadata=metadata, nodes=nodes, edges=edges,
            parse_errors=errors, warnings=[],
            code_tokens=code_tokens,
        )

    # -----------------------------------------------------------------------
    # Joern subprocess execution
    # -----------------------------------------------------------------------

    def _run_joern_parse(self, src_dir: str, cpg_output: str) -> tuple[bool, str]:
        """Run joern-parse to generate a CPG binary from source."""
        cmd = self._resolve_bin(_JOERN_PARSE_BIN)
        if not cmd:
            return False, "joern-parse binary not found"

        args = [
            cmd,
            src_dir,
            "--output", cpg_output,
            f"-J-Xmx{self.max_heap}",
        ]
        return self._run_subprocess(args, "joern-parse")

    def _run_joern_export(self, cpg_path: str, export_dir: str) -> tuple[bool, str]:
        """Export the CPG binary to GraphML format."""
        cmd = self._resolve_bin(_JOERN_EXPORT_BIN)
        if not cmd:
            return False, "joern-export binary not found"

        args = [
            cmd,
            "--input",  cpg_path,
            "--repr",   "cpg14",     # full CPG including CFG + DFG layers
            "--format", "graphml",
            "--out",    export_dir,
            f"-J-Xmx{self.max_heap}",
        ]
        return self._run_subprocess(args, "joern-export")

    def _run_subprocess(self, args: list[str], label: str) -> tuple[bool, str]:
        """Run a subprocess with timeout, capturing stderr on failure.
        FIX-5: pass minimal env — no parent secrets (VAULT_TOKEN etc.) inherited.
        """
        # Joern needs JAVA_HOME / PATH; everything else is stripped
        extra: dict[str, str] = {}
        for key in ("JAVA_HOME", "JOERN_HOME", "PATH"):
            import os as _os
            if key in _os.environ:
                extra[key] = _os.environ[key]
        safe_env = get_minimal_subprocess_env(extra)

        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env=safe_env,          # FIX-5: no parent env
            )
            if result.returncode != 0:
                return False, result.stderr[:1024]
            return True, ""
        except subprocess.TimeoutExpired:
            return False, f"{label} timed out after {self.timeout}s"
        except FileNotFoundError:
            return False, f"{label} binary not found: {args[0]}"
        except Exception as exc:
            return False, str(exc)

    def _resolve_bin(self, binary: str) -> str | None:
        """Resolve the path to a Joern binary, checking JOERN_HOME first."""
        if self.joern_home:
            candidate = Path(self.joern_home) / "bin" / binary
            if candidate.exists():
                return str(candidate)
        # Try PATH
        import shutil
        found = shutil.which(binary)
        return found

    def _is_joern_available(self) -> bool:
        """Cache-checked test for Joern availability."""
        if self._joern_available is not None:
            return self._joern_available
        self._joern_available = bool(self._resolve_bin(_JOERN_PARSE_BIN))
        if not self._joern_available:
            logger.warning(
                "joern-parse not found. Set JOERN_HOME or add Joern to PATH. "
                "Download from https://github.com/joernio/joern/releases"
            )
        return self._joern_available

    # -----------------------------------------------------------------------
    # GraphML parsing — converts Joern's exported CPG to PRISM schema
    # -----------------------------------------------------------------------

    def _parse_graphml(
        self,
        graphml_file: Path,
        file_path: str,
        language: Language,
        source_content: str,
    ) -> tuple[list[NormalizedNode], list[Edge]]:
        """
        Parse a Joern-exported GraphML file into normalized nodes and edges.

        Joern GraphML node properties of interest:
          - NAME           : function/variable name
          - CODE           : source code snippet
          - LINE_NUMBER    : start line
          - LINE_NUMBER_END: end line
          - COLUMN_NUMBER  : start column
          - NODE_TYPE      : Joern internal type (METHOD, CALL, IDENTIFIER, etc.)
          - TYPE_FULL_NAME : type annotation
          - FILENAME       : source file path

        Edge properties:
          - label: AST, CFG, CDG, DDG, PDG, CALL, REF, EVAL_TYPE, etc.
        """
        tree = ET.parse(graphml_file)
        root = tree.getroot()
        ns = {"gml": "http://graphml.graphdrawing.org/graphml"}

        # Extract key declarations: id → attr.name mapping
        key_map: dict[str, str] = {}
        for key_el in root.findall(".//gml:key", ns):
            kid  = key_el.get("id", "")
            kname = key_el.get("attr.name", "")
            if kid and kname:
                key_map[kid] = kname

        nodes: list[NormalizedNode] = []
        edges: list[Edge] = []

        # ---- Parse graph element ----
        for graph_el in root.findall(".//gml:graph", ns):
            # Nodes
            for node_el in graph_el.findall("gml:node", ns):
                node = self._parse_graphml_node(
                    node_el, ns, key_map, file_path, language
                )
                if node:
                    nodes.append(node)

            # Build node_id lookup for edge resolution
            node_lookup: dict[str, NormalizedNode] = {n.node_id: n for n in nodes}
            # Joern uses internal integer IDs in GraphML
            joern_id_to_prism: dict[str, str] = {}
            for node_el in graph_el.findall("gml:node", ns):
                jid = node_el.get("id", "")
                # We need to match back — store mapping from joern id
                props = self._extract_graphml_props(node_el, ns, key_map)
                prism_id = NormalizedNode.make_id(
                    file_path,
                    int(props.get("LINE_NUMBER", 0) or 0),
                    int(props.get("COLUMN_NUMBER", 0) or 0),
                    props.get("NODE_TYPE", ""),
                    props.get("CODE", ""),
                )
                joern_id_to_prism[jid] = prism_id

            # Edges
            for edge_el in graph_el.findall("gml:edge", ns):
                edge = self._parse_graphml_edge(
                    edge_el, ns, joern_id_to_prism
                )
                if edge:
                    edges.append(edge)

        return nodes, edges

    def _parse_graphml_node(
        self,
        node_el: ET.Element,
        ns: dict,
        key_map: dict[str, str],
        file_path: str,
        language: Language,
    ) -> NormalizedNode | None:
        props = self._extract_graphml_props(node_el, ns, key_map)

        raw_type   = props.get("NODE_TYPE", "UNKNOWN")
        name       = props.get("NAME") or props.get("FULL_NAME")
        code       = props.get("CODE", "")
        line_start = int(props.get("LINE_NUMBER", 0)     or 0)
        line_end   = int(props.get("LINE_NUMBER_END", line_start) or line_start)
        col_start  = int(props.get("COLUMN_NUMBER", 0)   or 0)

        # Skip meta/file nodes that don't correspond to real code
        if raw_type in ("FILE", "NAMESPACE_BLOCK", "META_DATA", "TYPE", "TYPE_DECL"):
            return None

        node_type = self._map_joern_type(raw_type, language)
        node_id   = NormalizedNode.make_id(
            file_path, line_start, col_start, raw_type, code
        )

        return NormalizedNode(
            node_id=node_id,
            node_type=node_type,
            raw_type=raw_type,
            language=language,
            name=name if name and name not in ("<empty>", "<global>") else None,
            value=code if node_type == NodeType.LITERAL else None,
            file_path=file_path,
            start_line=line_start,
            end_line=line_end,
            start_col=col_start,
            end_col=col_start + len(code),
            raw_text=code[:512],
            depth=0,  # depth computed in graph_builder if needed
            attributes={
                "joern_type": raw_type,
                "type_full_name": props.get("TYPE_FULL_NAME", ""),
                "order": props.get("ORDER", ""),
            },
        )

    def _parse_graphml_edge(
        self,
        edge_el: ET.Element,
        ns: dict,
        joern_id_to_prism: dict[str, str],
    ) -> Edge | None:
        src_jid = edge_el.get("source", "")
        dst_jid = edge_el.get("target", "")

        src_id = joern_id_to_prism.get(src_jid)
        dst_id = joern_id_to_prism.get(dst_jid)
        if not src_id or not dst_id:
            return None

        # Extract edge label from data elements
        label = ""
        for data in edge_el.findall("{http://graphml.graphdrawing.org/graphml}data"):
            label = data.text or ""
            break

        edge_type = self._map_joern_edge(label)
        edge_id   = Edge.make_id(src_id, dst_id, edge_type.value)

        return Edge(
            edge_id=edge_id,
            src_id=src_id,
            dst_id=dst_id,
            edge_type=edge_type,
            attributes={"joern_label": label},
        )

    @staticmethod
    def _extract_graphml_props(
        el: ET.Element, ns: dict, key_map: dict[str, str]
    ) -> dict[str, str]:
        """Extract all data properties from a GraphML node/edge element."""
        props: dict[str, str] = {}
        for data in el.findall("{http://graphml.graphdrawing.org/graphml}data"):
            key_id = data.get("key", "")
            attr   = key_map.get(key_id, key_id)
            props[attr] = data.text or ""
        return props

    # -----------------------------------------------------------------------
    # JSON export parsing (alternative to GraphML)
    # -----------------------------------------------------------------------

    def _parse_json_export(
        self,
        json_file: Path,
        file_path: str,
        language: Language,
        source_content: str,
    ) -> tuple[list[NormalizedNode], list[Edge]]:
        """
        Parse Joern's JSON export format.
        Joern can export to JSON using --format json flag.
        """
        data = json.loads(json_file.read_text(encoding="utf-8"))
        nodes: list[NormalizedNode] = []
        edges: list[Edge] = []

        if not isinstance(data, dict):
            return nodes, edges

        id_map: dict[str, str] = {}

        for n in data.get("nodes", []):
            raw_type  = n.get("_label", n.get("nodeType", "UNKNOWN"))
            name      = n.get("name") or n.get("fullName")
            code      = n.get("code", "")
            line_s    = int(n.get("lineNumber", 0) or 0)
            line_e    = int(n.get("lineNumberEnd", line_s) or line_s)
            col_s     = int(n.get("columnNumber", 0) or 0)

            if raw_type in ("FILE", "NAMESPACE_BLOCK", "META_DATA"):
                continue

            node_type = self._map_joern_type(raw_type, language)
            node_id   = NormalizedNode.make_id(
                file_path, line_s, col_s, raw_type, code
            )
            id_map[str(n.get("id", ""))] = node_id

            nodes.append(NormalizedNode(
                node_id=node_id,
                node_type=node_type,
                raw_type=raw_type,
                language=language,
                name=name if name and name not in ("<empty>", "<global>") else None,
                value=code if node_type == NodeType.LITERAL else None,
                file_path=file_path,
                start_line=line_s,
                end_line=line_e,
                start_col=col_s,
                end_col=col_s + len(code),
                raw_text=code[:512],
                depth=0,
                attributes={"joern_type": raw_type},
            ))

        for e in data.get("edges", []):
            src_id = id_map.get(str(e.get("outV", e.get("src", ""))))
            dst_id = id_map.get(str(e.get("inV",  e.get("dst", ""))))
            if not src_id or not dst_id:
                continue
            label     = e.get("_label", e.get("edgeType", "AST"))
            edge_type = self._map_joern_edge(label)
            edge_id   = Edge.make_id(src_id, dst_id, edge_type.value)
            edges.append(Edge(
                edge_id=edge_id,
                src_id=src_id,
                dst_id=dst_id,
                edge_type=edge_type,
                attributes={"joern_label": label},
            ))

        return nodes, edges

    # -----------------------------------------------------------------------
    # Type mapping — Joern internal types → PRISM NodeType
    # -----------------------------------------------------------------------

    _JOERN_NODE_MAP: dict[str, NodeType] = {
        # Joern CPG node types (cpg.proto spec)
        "METHOD":              NodeType.FUNCTION,
        "METHOD_RETURN":       NodeType.RETURN,
        "METHOD_PARAMETER_IN": NodeType.PARAMETER,
        "METHOD_PARAMETER_OUT":NodeType.PARAMETER,
        "CALL":                NodeType.CALL,
        "IDENTIFIER":          NodeType.IDENTIFIER,
        "LITERAL":             NodeType.LITERAL,
        "BLOCK":               NodeType.BLOCK,
        "LOCAL":               NodeType.IDENTIFIER,   # local var → IDENTIFIER
        "FIELD_IDENTIFIER":    NodeType.ATTRIBUTE,
        "RETURN":              NodeType.RETURN,
        "CONTROL_STRUCTURE":   NodeType.IF,            # refined below
        "JUMP_TARGET":         NodeType.BREAK,
        "UNKNOWN":             NodeType.UNKNOWN,
        "TYPE_REF":            NodeType.TYPE_ANNOTATION,
        "MODIFIER":            NodeType.UNKNOWN,
        # C / C++ specific
        "ARRAY_INITIALIZER":   NodeType.LITERAL,
    }

    _JOERN_CONTROL_MAP: dict[str, NodeType] = {
        "IF":       NodeType.IF,
        "ELSE":     NodeType.ELSE,
        "FOR":      NodeType.LOOP,
        "WHILE":    NodeType.LOOP,
        "DO":       NodeType.LOOP,
        "SWITCH":   NodeType.SWITCH,
        "BREAK":    NodeType.BREAK,
        "CONTINUE": NodeType.CONTINUE,
        "TRY":      NodeType.TRY,
        "CATCH":    NodeType.CATCH,
        "THROW":    NodeType.RAISE,
    }

    def _map_joern_type(self, raw: str, language: Language) -> NodeType:
        """Map a Joern node type string to PRISM NodeType."""
        upper = raw.upper()
        if upper in self._JOERN_NODE_MAP:
            nt = self._JOERN_NODE_MAP[upper]
            # Refine CONTROL_STRUCTURE using the raw string suffix
            if nt == NodeType.IF:
                for ctrl_key, ctrl_type in self._JOERN_CONTROL_MAP.items():
                    if ctrl_key in upper:
                        return ctrl_type
            return nt
        # Fall back to language-specific normalizer
        return normalize_node_type(raw.lower(), language)

    _JOERN_EDGE_MAP: dict[str, EdgeType] = {
        "AST":      EdgeType.AST_CHILD,
        "CFG":      EdgeType.CFG_NEXT,
        "CDG":      EdgeType.CFG_NEXT,    # control dependence graph
        "DDG":      EdgeType.DFG_FLOW,    # data dependence graph
        "PDG":      EdgeType.DFG_FLOW,    # program dependence graph
        "REACHING_DEF": EdgeType.DFG_FLOW,
        "CALL":     EdgeType.CALLS,
        "REF":      EdgeType.DFG_DEPENDS,
        "ARGUMENT": EdgeType.AST_CHILD,
        "RECEIVER": EdgeType.AST_CHILD,
        "CONDITION":EdgeType.CFG_TRUE,
        "DOMINATE": EdgeType.CFG_NEXT,
        "POST_DOMINATE": EdgeType.CFG_NEXT,
    }

    def _map_joern_edge(self, label: str) -> EdgeType:
        """Map a Joern edge label to PRISM EdgeType."""
        return self._JOERN_EDGE_MAP.get(label.upper(), EdgeType.AST_CHILD)

    # -----------------------------------------------------------------------
    # Minimal fallback when Joern is unavailable
    # -----------------------------------------------------------------------

    def _minimal_nodes(
        self, content: str, language: Language, file_path: str
    ) -> list[NormalizedNode]:
        """Return a single PROGRAM root node when Joern cannot run.
        The pipeline keeps functioning; the blind spot is recorded in parse_errors.
        """
        node_id = NormalizedNode.make_id(file_path, 0, 0, "PROGRAM", content[:64])
        root = NormalizedNode(
            node_id=node_id,
            node_type=NodeType.PROGRAM,
            raw_type="PROGRAM",
            language=language,
            name=Path(file_path).name,
            value=None,
            qualified_name=None,
            file_path=file_path,
            start_line=0,
            end_line=content.count("\n") + 1,
            start_col=0,
            end_col=0,
            raw_text=content[:256],
            depth=0,
            parent_id=None,
            children_ids=(),
            security_label=SecurityLabel.NONE,
            security_confidence=0.0,
            cwe_hints=(),
            attributes={"joern_fallback": True},
        )
        logger.warning(
            "Joern unavailable: minimal fallback node for %s. "
            "Install Joern: https://docs.joern.io/installation",
            file_path,
        )
        return [root]

    def _make_output(
        self,
        metadata:     FileMetadata,
        nodes:        list[NormalizedNode],
        edges:        list[Edge],
        parse_errors: list[str],
        warnings:     list[str],
        code_tokens=None,
    ) -> ParsedGraphOutput:
        """FIX-4: single factory so every return path produces a valid object."""
        # Build security summary from annotated nodes
        sec = SecurityAnnotationSummary()
        for n in nodes:
            if n.security_label == SecurityLabel.SOURCE:     sec.sources.append(n.node_id)
            elif n.security_label == SecurityLabel.SINK:     sec.sinks.append(n.node_id)
            elif n.security_label == SecurityLabel.SANITIZER: sec.sanitizers.append(n.node_id)
            elif n.security_label == SecurityLabel.SENSITIVE: sec.sensitive_nodes.append(n.node_id)
            for cwe in (n.cwe_hints or ()):
                sec.cwe_hints.setdefault(cwe, []).append(n.node_id)

        # Build minimal GCB input from token list (FIX-3)
        tokens, ids, types, labels = [], [], [], []
        if code_tokens:
            for tok in code_tokens[:LIMITS.max_graphcodebert_tokens]:
                tokens.append(tok.text)
                ids.append(tok.node_id)
                types.append(tok.node_type)
                labels.append(tok.security_label)

        gcb = GraphCodeBERTInput(
            tokens=tokens, token_node_ids=ids,
            dfg_edges=[t for e in edges
                       if e.edge_type in (EdgeType.DFG_FLOW, EdgeType.DFG_DEPENDS)
                       for t in [(e.src_id, e.dst_id)]],
            node_type_sequence=types,
            security_label_sequence=labels,
        )

        graph_hash = ParsedGraphOutput.compute_graph_hash(nodes, edges)
        return ParsedGraphOutput(
            metadata=metadata,
            nodes=nodes,
            edges=edges,
            security_summary=sec,
            graphcodebert_input=gcb,
            graph_hash=graph_hash,
            parse_errors=parse_errors,
            warnings=warnings,
        )