"""
CodeQL Integration Layer  
===================================================================
Security hardening applied:

  FIX-1  Path whitelist + injection prevention
         repo_path is validated against PATH_POLICY before subprocess call.
         All subprocess calls use explicit minimal env (no secrets inherited).
         --no-run-unnecessary-builds prevents executing attacker build systems
         for scripted languages.

  FIX-4  No persistent database across sessions
         All CodeQL databases use tempfile.TemporaryDirectory() as context
         manager. Databases are created fresh every run and destroyed on exit
         or exception — enforcing the ephemeral execution guarantee.

  FIX-6  Minimal subprocess environment
         All subprocess.run() calls pass env=get_minimal_subprocess_env().
         No parent environment variables (tokens, keys, vault paths) are
         inherited by the CodeQL process.

  FIX-5  Raw text sanitization
         SARIF alert messages stored in node.value are capped and
         sanitized before storage to prevent downstream LLM injection.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from ..models import (
    Edge, EdgeType, FileMetadata, GraphCodeBERTInput,
    Language, NormalizedNode, NodeType, ParsedGraphOutput,
    ParserBackend, SecurityAnnotationSummary, SecurityLabel,
)
from ..security_annotator import SecurityAnnotator
from ..sandbox_config import (
    LIMITS, CODEQL_SAFE_BASE_FLAGS, CODEQL_COMPILED_LANGUAGES,
    CODEQL_MAX_THREADS, get_minimal_subprocess_env, sanitize_for_llm,
)
from ..input_validator import InputValidator, GraphSizeGuard, GraphExplosionError
from ..language_detector import CODEQL_SUPPORTED_LANGUAGES
from .base import AbstractParser

logger = logging.getLogger(__name__)

CODEQL_LANGUAGE_MAP: dict[Language, str] = {
    Language.PYTHON:     "python",
    Language.JAVA:       "java",
    Language.JAVASCRIPT: "javascript",
    Language.TYPESCRIPT: "javascript",
    Language.TSX:        "javascript",
    Language.C:          "cpp",
    Language.CPP:        "cpp",
    Language.GO:         "go",
}

_EXTRACT_FUNCTIONS_QUERY = """
import {lang}
from Callable c
select c, c.getFile().getRelativePath(), c.getLocation().getStartLine(),
       c.getLocation().getEndLine(), c.getName(), c.getQualifiedName()
"""

_EXTRACT_CALLS_QUERY = """
import {lang}
from Call c, Callable callee
where callee = c.getACallee()
select c, c.getFile().getRelativePath(), c.getLocation().getStartLine(),
       callee.getQualifiedName()
"""


class CodeQLParser(AbstractParser):
    """
    Repository-level CodeQL parser.
    Hardened: ephemeral DBs, path whitelist, minimal subprocess env.
    """

    def __init__(
        self,
        codeql_cli_path: str | None = None,
        codeql_search_path: str | None = None,
        timeout_seconds: int | None = None,
    ) -> None:
        # FIX-1/FIX-6: Resolve CLI path at init time — never re-read env during analysis
        self._cli = Path(
            codeql_cli_path
            or os.environ.get("CODEQL_CLI_PATH", "codeql")
        )
        self._search_path = Path(
            codeql_search_path
            or os.environ.get("CODEQL_SEARCH_PATH", "")
        )
        self._timeout    = timeout_seconds or LIMITS.codeql_create_timeout_s
        self._annotator  = SecurityAnnotator()
        self._validator  = InputValidator()
        self._available: bool | None = None

        # FIX-6: build the minimal env once at init
        extra: dict[str, str] = {}
        for key in ("JAVA_HOME", "CODEQL_JAVA_HOME", "GOROOT", "GOPATH"):
            if key in os.environ:
                extra[key] = os.environ[key]
        self._safe_env = get_minimal_subprocess_env(extra)

    @property
    def backend_name(self) -> str:
        return "codeql"

    def can_parse(self, language: Language) -> bool:
        return language in CODEQL_SUPPORTED_LANGUAGES and self._check_available()

    def _check_available(self) -> bool:
        if self._available is not None:
            return self._available
        try:
            result = subprocess.run(
                [str(self._cli), "version", "--format=json"],
                capture_output=True, text=True, timeout=10,
                env=self._safe_env,          # FIX-6
            )
            if result.returncode == 0:
                info = json.loads(result.stdout)
                logger.info(f"CodeQL available: {info.get('version', 'unknown')}")
                self._available = True
            else:
                self._available = False
        except Exception as exc:
            logger.warning(f"CodeQL not available: {exc}")
            self._available = False
        return self._available

    def parse(
        self,
        source_code: str,
        file_path: str,
        language: Language,
    ) -> ParsedGraphOutput:
        """Parse a single file by wrapping it in an ephemeral temp repo."""
        # FIX-2: Validate input before anything else
        val = self._validator.validate_string(source_code, file_path)
        if not val.is_parseable:
            return self._fallback_output(
                file_path, language, time.monotonic() * 1000,
                [f"REJECTED: {val.rejection_reason}"], [],
            )

        # FIX-4: Ephemeral temp dir — auto-cleaned on exit or exception
        with tempfile.TemporaryDirectory(prefix="prism_codeql_repo_") as tmpdir:
            tmp_file = Path(tmpdir) / Path(file_path).name
            tmp_file.write_text(val.sanitized_source, encoding="utf-8")
            return self.parse_repository(
                tmpdir, language, single_file_path=file_path,
                source_code=val.sanitized_source,
            )

    def parse_repository(
        self,
        repo_path: str,
        language: Language,
        single_file_path: str | None = None,
        source_code: str | None = None,
    ) -> ParsedGraphOutput:
        start_ms      = time.monotonic() * 1000
        parse_errors: list[str] = []
        warnings:     list[str] = []
        codeql_results: dict[str, Any] = {}

        # ── FIX-1: Validate repo_path against path whitelist ─────────────────
        try:
            from ..sandbox_config import PATH_POLICY
            safe_repo_path = PATH_POLICY.validate_repo_path(repo_path)
        except ValueError as exc:
            logger.error(f"Path validation failed: {exc}")
            return self._fallback_output(
                single_file_path or repo_path, language,
                start_ms, [str(exc)], [],
            )

        codeql_lang = CODEQL_LANGUAGE_MAP.get(language, "")
        file_path   = single_file_path or repo_path
        nodes: list[NormalizedNode] = []
        edges: list[Edge]           = []

        # ── FIX-4: All CodeQL work in a single ephemeral temp directory ───────
        with tempfile.TemporaryDirectory(prefix="prism_codeql_db_") as db_parent:
            db_path = Path(db_parent) / f"db_{codeql_lang}"

            # ── Step 1: Create database ───────────────────────────────────────
            db_ok = self._create_database(
                safe_repo_path, db_path, codeql_lang,
                language, parse_errors, warnings,
            )
            if not db_ok:
                return self._fallback_output(
                    file_path, language, start_ms, parse_errors, warnings
                )

            # ── Step 2: Run security analysis → SARIF ─────────────────────────
            sarif_path = Path(db_parent) / "results.sarif"
            sarif_data = self._run_analysis(
                db_path, codeql_lang, sarif_path, parse_errors, warnings
            )
            if sarif_data:
                codeql_results["sarif_alert_count"] = sum(
                    len(r.get("results", []))
                    for r in sarif_data.get("runs", [])
                )

            # ── Step 3: Extract structural info ───────────────────────────────
            structural = self._extract_structural_info(
                db_path, codeql_lang, parse_errors, warnings
            )

            # ── Step 4: Convert to unified graph ──────────────────────────────
            nodes, edges = self._convert_to_graph(
                structural, file_path, language
            )

            # ── Step 5: Enrich with SARIF alerts ──────────────────────────────
            if sarif_data:
                nodes, edges = self._enrich_with_sarif(
                    nodes, edges, sarif_data, file_path, language
                )

        # ── Assemble output (db_parent cleaned up by context manager) ─────────
        elapsed_ms = time.monotonic() * 1000 - start_ms

        raw_bytes  = (source_code or "").encode("utf-8", errors="replace")
        file_hash  = hashlib.sha256(raw_bytes).hexdigest()
        line_count = (source_code or "").count("\n") + 1

        metadata = FileMetadata(
            file_path=file_path, language=language, backend=ParserBackend.CODEQL,
            file_hash=file_hash, size_bytes=len(raw_bytes), line_count=line_count,
            encoding="utf-8", parse_duration_ms=round(elapsed_ms, 2),
            error_count=len(parse_errors), has_parse_errors=bool(parse_errors),
        )

        sec_summary = self._build_security_summary(nodes)
        gcb_input   = self._build_graphcodebert_input(nodes)
        graph_hash  = ParsedGraphOutput.compute_graph_hash(nodes, edges)

        return ParsedGraphOutput(
            metadata=metadata, nodes=nodes, edges=edges,
            security_summary=sec_summary, graphcodebert_input=gcb_input,
            graph_hash=graph_hash, parse_errors=parse_errors, warnings=warnings,
            codeql_results=codeql_results,
        )

    # -------------------------------------------------------------------------
    # CodeQL CLI invocations — all use minimal env (FIX-6)
    # -------------------------------------------------------------------------

    def _create_database(
        self,
        repo_path: Path,
        db_path: Path,
        codeql_lang: str,
        language: Language,
        parse_errors: list[str],
        warnings: list[str],
    ) -> bool:
        """
        FIX-1: repo_path already validated by PATH_POLICY.
        FIX-6: env=self._safe_env — no parent env inherited.
        FIX-1: --no-run-unnecessary-builds prevents attacker build execution
               for scripted languages (Python, JS, Go).
               For compiled langs (Java, C/C++) the flag is omitted but
               a sandboxed build environment is required by the operator.
        """
        cmd = [
            str(self._cli), "database", "create",
            str(db_path),
            f"--language={codeql_lang}",
            f"--source-root={repo_path}",  # already path-validated
            f"--threads={CODEQL_MAX_THREADS}",
            "--overwrite",
        ]

        # FIX-1: For scripted languages, prevent build execution
        if codeql_lang not in CODEQL_COMPILED_LANGUAGES:
            cmd.append("--no-run-unnecessary-builds")

        if self._search_path.exists():
            cmd += [f"--search-path={self._search_path}"]

        logger.info(f"Creating CodeQL DB (lang={codeql_lang})")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                env=self._safe_env,          # FIX-6: minimal env
                cwd="/tmp",                  # FIX-1: neutral working dir
            )
            if result.returncode != 0:
                parse_errors.append(f"codeql database create failed: {result.stderr[:500]}")
                return False
            return True
        except subprocess.TimeoutExpired:
            parse_errors.append(f"codeql database create timed out after {self._timeout}s")
            return False
        except Exception as exc:
            parse_errors.append(f"codeql database create error: {exc}")
            return False

    def _run_analysis(
        self,
        db_path: Path,
        codeql_lang: str,
        sarif_path: Path,
        parse_errors: list[str],
        warnings: list[str],
    ) -> dict[str, Any] | None:
        query_suite = (
            f"codeql/{codeql_lang}-queries:"
            f"codeql-suites/{codeql_lang}-security-and-quality.qls"
        )
        cmd = [
            str(self._cli), "database", "analyze",
            str(db_path), query_suite,
            "--format=sarif-latest",
            f"--output={sarif_path}",
            f"--threads={CODEQL_MAX_THREADS}",
            "--no-print-diagnostics-summary",
        ]
        if self._search_path.exists():
            cmd += [f"--search-path={self._search_path}"]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=LIMITS.codeql_analyze_timeout_s,
                env=self._safe_env,          # FIX-6
                cwd="/tmp",
            )
            if result.returncode != 0:
                warnings.append(f"codeql analyze warning: {result.stderr[:300]}")
            if sarif_path.exists():
                with open(sarif_path) as f:
                    return json.load(f)
        except subprocess.TimeoutExpired:
            warnings.append(f"codeql analyze timed out after {LIMITS.codeql_analyze_timeout_s}s")
        except Exception as exc:
            warnings.append(f"codeql analyze error: {exc}")
        return None

    def _extract_structural_info(
        self,
        db_path: Path,
        codeql_lang: str,
        parse_errors: list[str],
        warnings: list[str],
    ) -> dict[str, Any]:
        results: dict[str, Any] = {}
        for name, tmpl in [
            ("functions", _EXTRACT_FUNCTIONS_QUERY),
            ("calls",     _EXTRACT_CALLS_QUERY),
        ]:
            csv = self._run_inline_query(
                db_path, name, tmpl.format(lang=codeql_lang), warnings
            )
            if csv:
                results[name] = csv
        return results

    def _run_inline_query(
        self,
        db_path: Path,
        query_name: str,
        query_src: str,
        warnings: list[str],
    ) -> list[list[str]] | None:
        # FIX-4: temp files inside the already-ephemeral db_parent context
        with tempfile.NamedTemporaryFile(
            suffix=".ql", mode="w", delete=False, dir="/tmp",
            prefix=f"prism_{query_name}_"
        ) as qf:
            qf.write(query_src)
            ql_path = qf.name

        bqrs_path = ql_path.replace(".ql", ".bqrs")
        csv_path  = ql_path.replace(".ql", ".csv")

        try:
            run_cmd = [
                str(self._cli), "query", "run", ql_path,
                f"--database={db_path}",
                f"--output={bqrs_path}",
                f"--threads={CODEQL_MAX_THREADS}",
            ]
            result = subprocess.run(
                run_cmd,
                capture_output=True,
                text=True,
                timeout=LIMITS.codeql_query_timeout_s,
                env=self._safe_env,      # FIX-6
                cwd="/tmp",
            )
            if result.returncode != 0:
                warnings.append(f"QL query '{query_name}' failed: {result.stderr[:200]}")
                return None

            decode_cmd = [
                str(self._cli), "bqrs", "decode",
                bqrs_path, "--format=csv", f"--output={csv_path}",
            ]
            subprocess.run(
                decode_cmd,
                capture_output=True, text=True, timeout=60,
                env=self._safe_env,      # FIX-6
                cwd="/tmp",
            )
            if Path(csv_path).exists():
                import csv as csv_mod
                with open(csv_path) as f:
                    return list(csv_mod.reader(f))
        except Exception as exc:
            warnings.append(f"QL query '{query_name}' exception: {exc}")
        finally:
            for p in [ql_path, bqrs_path, csv_path]:
                try:
                    Path(p).unlink(missing_ok=True)
                except Exception:
                    pass
        return None

    # -------------------------------------------------------------------------
    # Graph conversion
    # -------------------------------------------------------------------------

    def _convert_to_graph(
        self,
        structural: dict[str, Any],
        file_path: str,
        language: Language,
    ) -> tuple[list[NormalizedNode], list[Edge]]:
        guard = GraphSizeGuard(file_path)
        nodes: list[NormalizedNode] = []
        edges: list[Edge]           = []

        prog_id = NormalizedNode.make_id(file_path, 0, 0, "PROGRAM")
        nodes.append(NormalizedNode(
            node_id=prog_id, node_type=NodeType.PROGRAM, raw_type="program",
            language=language, backend=ParserBackend.CODEQL,
            name=file_path, value=None, qualified_name=None,
            file_path=file_path, start_line=0, end_line=0,
            start_col=0, end_col=0, raw_text="",
            depth=0, parent_id=None, children_ids=(),
            security_label=SecurityLabel.NONE, security_confidence=0.0,
            cwe_hints=(), attributes={"source": "codeql"},
        ))

        try:
            for row in (structural.get("functions", []))[1:]:
                if len(row) < 6:
                    continue
                _, rel_path, start_s, end_s, name, qualified = row
                try:
                    start_line = int(start_s); end_line = int(end_s)
                except ValueError:
                    continue

                guard.check_node()
                fp      = rel_path or file_path
                node_id = NormalizedNode.make_id(fp, start_line, 0, "FUNCTION")
                sec_lbl, sec_conf, cwes = self._annotator.annotate(
                    NodeType.FUNCTION, name, language
                )
                nodes.append(NormalizedNode(
                    node_id=node_id, node_type=NodeType.FUNCTION, raw_type="function",
                    language=language, backend=ParserBackend.CODEQL,
                    name=name, value=None, qualified_name=qualified or None,
                    file_path=fp, start_line=start_line, end_line=end_line,
                    start_col=0, end_col=0,
                    raw_text=sanitize_for_llm(f"function {name}"),
                    depth=1, parent_id=prog_id, children_ids=(),
                    security_label=sec_lbl, security_confidence=sec_conf,
                    cwe_hints=cwes, attributes={"source": "codeql"},
                ))
                guard.check_edge()
                eid = Edge.make_id(prog_id, node_id, EdgeType.AST_CHILD.value)
                edges.append(Edge(eid, EdgeType.AST_CHILD, prog_id, node_id))

            for row in (structural.get("calls", []))[1:]:
                if len(row) < 4:
                    continue
                _, rel_path, start_s, callee = row
                try:
                    start_line = int(start_s)
                except ValueError:
                    continue
                guard.check_node()
                fp      = rel_path or file_path
                node_id = NormalizedNode.make_id(fp, start_line, 0, "CALL")
                sec_lbl, sec_conf, cwes = self._annotator.annotate(
                    NodeType.CALL, callee, language
                )
                nodes.append(NormalizedNode(
                    node_id=node_id, node_type=NodeType.CALL, raw_type="call",
                    language=language, backend=ParserBackend.CODEQL,
                    name=callee, value=None, qualified_name=callee,
                    file_path=fp, start_line=start_line, end_line=start_line,
                    start_col=0, end_col=0,
                    raw_text=sanitize_for_llm(f"call {callee}"),
                    depth=2, parent_id=prog_id, children_ids=(),
                    security_label=sec_lbl, security_confidence=sec_conf,
                    cwe_hints=cwes, attributes={"source": "codeql"},
                ))
        except GraphExplosionError as exc:
            logger.warning(f"Graph explosion during CodeQL conversion: {exc}")

        return nodes, edges

    def _enrich_with_sarif(
        self,
        nodes: list[NormalizedNode],
        edges: list[Edge],
        sarif_data: dict[str, Any],
        file_path: str,
        language: Language,
    ) -> tuple[list[NormalizedNode], list[Edge]]:
        guard = GraphSizeGuard(file_path)
        guard._node_count = len(nodes)   # pre-seed counter
        guard._edge_count = len(edges)

        enriched_nodes = list(nodes)
        try:
            for run in sarif_data.get("runs", []):
                rules = {
                    r["id"]: r
                    for r in run.get("tool", {}).get("driver", {}).get("rules", [])
                }
                for alert in run.get("results", []):
                    rule_id   = alert.get("ruleId", "")
                    rule_info = rules.get(rule_id, {})
                    # FIX-5: sanitize SARIF message before storing in node
                    message = sanitize_for_llm(
                        alert.get("message", {}).get("text", "")
                    )

                    cwe_hints: tuple[str, ...] = tuple(
                        f"CWE-{tag.replace('external/cwe/cwe-', '')}"
                        for tag in rule_info.get("properties", {}).get("tags", [])
                        if tag.startswith("external/cwe/cwe-")
                    )

                    for location in alert.get("locations", []):
                        region     = location.get("physicalLocation", {}).get("region", {})
                        start_line = region.get("startLine", 0)
                        start_col  = region.get("startColumn", 0)

                        guard.check_node()
                        node_id = NormalizedNode.make_id(
                            file_path, start_line, start_col, f"SARIF_{rule_id}"
                        )
                        enriched_nodes.append(NormalizedNode(
                            node_id=node_id,
                            node_type=NodeType.CALL,
                            raw_type=f"sarif_alert:{rule_id}",
                            language=language,
                            backend=ParserBackend.CODEQL,
                            name=rule_id,
                            value=message[:LIMITS.max_node_text_chars],
                            qualified_name=rule_id,
                            file_path=file_path,
                            start_line=start_line, end_line=start_line,
                            start_col=start_col, end_col=start_col,
                            raw_text=message[:LIMITS.max_node_text_chars],
                            depth=2, parent_id=None, children_ids=(),
                            security_label=SecurityLabel.SINK,
                            security_confidence=0.95,
                            cwe_hints=cwe_hints,
                            attributes={
                                "rule_id":   rule_id,
                                "rule_name": rule_info.get("name", ""),
                                "severity":  alert.get("level", "warning"),
                                "source":    "codeql_sarif",
                            },
                        ))
        except (GraphExplosionError, Exception) as exc:
            logger.warning(f"SARIF enrichment stopped: {exc}")

        return enriched_nodes, edges

    # -------------------------------------------------------------------------
    # Shared helpers
    # -------------------------------------------------------------------------

    def _build_security_summary(self, nodes: list[NormalizedNode]) -> SecurityAnnotationSummary:
        summary  = SecurityAnnotationSummary()
        cwe_map: dict[str, list[str]] = {}
        for node in nodes:
            match node.security_label:
                case SecurityLabel.SOURCE:     summary.sources.append(node.node_id)
                case SecurityLabel.SINK:       summary.sinks.append(node.node_id)
                case SecurityLabel.SANITIZER:  summary.sanitizers.append(node.node_id)
                case SecurityLabel.PROPAGATOR: summary.propagators.append(node.node_id)
                case SecurityLabel.SENSITIVE:  summary.sensitive_nodes.append(node.node_id)
            for cwe in node.cwe_hints:
                cwe_map.setdefault(cwe, []).append(node.node_id)
        summary.cwe_hints = cwe_map
        return summary

    def _build_graphcodebert_input(self, nodes: list[NormalizedNode]) -> GraphCodeBERTInput:
        tokens, ids, types, labels = [], [], [], []
        for node in nodes:
            if not node.raw_text or len(tokens) >= LIMITS.max_graphcodebert_tokens:
                break
            # FIX-5: use sentinel for comment/string nodes
            sentinel = node.attributes.get("llm_sentinel")
            if sentinel:
                tokens.append(sentinel); ids.append(node.node_id)
                types.append(node.node_type.value); labels.append(node.security_label.value)
                continue
            for w in sanitize_for_llm(node.raw_text).split()[:4]:
                if len(tokens) >= LIMITS.max_graphcodebert_tokens:
                    break
                tokens.append(w); ids.append(node.node_id)
                types.append(node.node_type.value); labels.append(node.security_label.value)
        return GraphCodeBERTInput(
            tokens=tokens, token_node_ids=ids, dfg_edges=[],
            node_type_sequence=types, security_label_sequence=labels,
        )

    def _fallback_output(
        self,
        file_path: str,
        language: Language,
        start_ms: float,
        parse_errors: list[str],
        warnings: list[str],
    ) -> ParsedGraphOutput:
        elapsed = time.monotonic() * 1000 - start_ms
        prog_id = NormalizedNode.make_id(file_path, 0, 0, "PROGRAM")
        node = NormalizedNode(
            node_id=prog_id, node_type=NodeType.PROGRAM, raw_type="program",
            language=language, backend=ParserBackend.FALLBACK,
            name=file_path, value=None, qualified_name=None,
            file_path=file_path, start_line=0, end_line=0,
            start_col=0, end_col=0, raw_text="",
            depth=0, parent_id=None, children_ids=(),
            security_label=SecurityLabel.NONE, security_confidence=0.0,
            cwe_hints=(), attributes={"error": "codeql_unavailable"},
        )
        metadata = FileMetadata(
            file_path=file_path, language=language, backend=ParserBackend.FALLBACK,
            file_hash="", size_bytes=0, line_count=0, encoding="utf-8",
            parse_duration_ms=round(elapsed, 2),
            error_count=len(parse_errors), has_parse_errors=True,
        )
        return ParsedGraphOutput(
            metadata=metadata, nodes=[node], edges=[],
            security_summary=SecurityAnnotationSummary(),
            graphcodebert_input=GraphCodeBERTInput(
                tokens=[], token_node_ids=[], dfg_edges=[],
                node_type_sequence=[], security_label_sequence=[],
            ),
            graph_hash=ParsedGraphOutput.compute_graph_hash([node], []),
            parse_errors=parse_errors, warnings=warnings,
        )