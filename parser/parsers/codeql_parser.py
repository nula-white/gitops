"""
CodeQL Integration Layer
===================================================================
  • parse_repository() gains sarif_output_path: str | None
    so the SARIF file survives the ephemeral TemporaryDirectory and
    the orchestrator's node_sarif_annotation stage can read it.

  • parse_repository() gains session_id: str | None
    so CodeQL milestones stream to the WebSocket in real time via
    core.pipeline_events.emit_phase().

  • _run_analysis() passes sarif_output_path as --output when provided,
    otherwise falls back to a path inside the temp dir.

  • _analyze_timeout is None when codeql_timeout_analyze == 0
    (operator confirmed: wait indefinitely; frontend streams events).
    subprocess.TimeoutExpired handler remains for the create step.
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
    LIMITS, CODEQL_COMPILED_LANGUAGES,
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


def _emit(session_id: str | None, stage: str, label: str) -> None:
    if not session_id:
        return
    try:
        from backend.core.pipeline_events import emit_phase
        emit_phase(session_id, stage, label)
    except Exception:
        pass


def _get_analyze_timeout() -> int:
    """0 means no timeout (default)."""
    try:
        from backend.core.config import get_settings
        return get_settings().codeql_timeout_analyze
    except Exception:
        return int(os.environ.get("PRISM_CODEQL_ANALYZE_TIMEOUT", "0"))


def _get_create_timeout() -> int:
    try:
        from backend.core.config import get_settings
        return get_settings().codeql_timeout_create
    except Exception:
        return int(os.environ.get("PRISM_CODEQL_CREATE_TIMEOUT", "600"))


class CodeQLParser(AbstractParser):
    """Repository-level CodeQL parser. Ephemeral DBs, path whitelist, minimal env."""

    def __init__(
        self,
        codeql_cli_path:    str | None = None,
        codeql_search_path: str | None = None,
        timeout_seconds:    int | None = None,
    ) -> None:
        self._cli = Path(
            codeql_cli_path or os.environ.get("CODEQL_CLI_PATH", "codeql")
        )
        self._search_path = Path(
            codeql_search_path or os.environ.get("CODEQL_SEARCH_PATH", "")
        )
        raw = (
            timeout_seconds if timeout_seconds is not None
            else _get_analyze_timeout()
        )
        self._analyze_timeout: int | None = raw if raw > 0 else None
        self._create_timeout: int = _get_create_timeout()

        self._annotator = SecurityAnnotator()
        self._validator = InputValidator()
        self._available: bool | None = None

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
            r = subprocess.run(
                [str(self._cli), "version", "--format=json"],
                capture_output=True, text=True, timeout=10, env=self._safe_env,
            )
            if r.returncode == 0:
                info = json.loads(r.stdout)
                logger.info("CodeQL available: %s", info.get("version", "?"))
                self._available = True
            else:
                self._available = False
        except Exception as exc:
            logger.warning("CodeQL not available: %s", exc)
            self._available = False
        return self._available

    def parse(
        self,
        source_code: str,
        file_path:   str,
        language:    Language,
    ) -> ParsedGraphOutput:
        val = self._validator.validate_string(source_code, file_path)
        if not val.is_parseable:
            return self._fallback_output(
                file_path, language, time.monotonic() * 1000,
                [f"REJECTED: {val.rejection_reason}"], [],
            )
        with tempfile.TemporaryDirectory(prefix="prism_codeql_repo_") as tmpdir:
            tmp_file = Path(tmpdir) / Path(file_path).name
            tmp_file.write_text(val.sanitized_source, encoding="utf-8")
            return self.parse_repository(
                tmpdir, language,
                single_file_path=file_path,
                source_code=val.sanitized_source,
            )

    def parse_repository(
        self,
        repo_path:         str,
        language:          Language,
        single_file_path:  str | None = None,
        source_code:       str | None = None,
        sarif_output_path: str | None = None,
        session_id:        str | None = None,
    ) -> ParsedGraphOutput:
        """
        sarif_output_path — if provided, the SARIF file is written here
          (outside the ephemeral TemporaryDirectory) so the orchestrator
          can read it after this method returns.

        session_id — if provided, milestone events are emitted to the
          WebSocket via core.pipeline_events so the frontend shows live
          progress during the (potentially 30-minute) analysis.
        """
        start_ms      = time.monotonic() * 1000
        parse_errors: list[str] = []
        warnings:     list[str] = []
        codeql_results: dict[str, Any] = {}

        try:
            from ..sandbox_config import PATH_POLICY
            safe_repo_path = PATH_POLICY.validate_repo_path(repo_path)
        except ValueError as exc:
            logger.error("Path validation failed: %s", exc)
            return self._fallback_output(
                single_file_path or repo_path, language, start_ms, [str(exc)], [],
            )

        codeql_lang = CODEQL_LANGUAGE_MAP.get(language, "")
        file_path   = single_file_path or repo_path
        nodes: list[NormalizedNode] = []
        edges: list[Edge]           = []

        with tempfile.TemporaryDirectory(prefix="prism_codeql_db_") as db_parent:
            db_path = Path(db_parent) / f"db_{codeql_lang}"

            _emit(session_id, "codeql_analysis",
                  f"CodeQL: creating {codeql_lang} database "
                  f"(~1-3 min for small repos, up to 10 min for large)...")

            db_ok = self._create_database(
                safe_repo_path, db_path, codeql_lang,
                language, parse_errors, warnings,
            )
            if not db_ok:
                return self._fallback_output(
                    file_path, language, start_ms, parse_errors, warnings,
                )

            _emit(session_id, "codeql_analysis",
                  "CodeQL: database created — running security query suite "
                  "(5-30 min depending on repo size; streaming annotations when done)...")

            effective_sarif = (
                sarif_output_path
                if sarif_output_path
                else str(Path(db_parent) / "results.sarif")
            )

            sarif_data = self._run_analysis(
                db_path, codeql_lang, Path(effective_sarif),
                parse_errors, warnings, session_id=session_id,
            )
            if sarif_data:
                fc = sum(
                    len(r.get("results", []))
                    for r in sarif_data.get("runs", [])
                )
                codeql_results["sarif_alert_count"] = fc
                _emit(session_id, "codeql_analysis",
                      f"CodeQL: {fc} findings — extracting structural information...")

            structural = self._extract_structural_info(
                db_path, codeql_lang, parse_errors, warnings,
            )
            nodes, edges = self._convert_to_graph(structural, file_path, language)
            if sarif_data:
                nodes, edges = self._enrich_with_sarif(
                    nodes, edges, sarif_data, file_path, language,
                )

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
        return ParsedGraphOutput(
            metadata=metadata, nodes=nodes, edges=edges,
            security_summary=sec_summary, graphcodebert_input=gcb_input,
            graph_hash=ParsedGraphOutput.compute_graph_hash(nodes, edges),
            parse_errors=parse_errors, warnings=warnings,
            codeql_results=codeql_results,
        )

    # Subprocess calls                                                    

    def _create_database(self, repo_path, db_path, codeql_lang, language, parse_errors, warnings,) -> bool:
        cmd = [
            str(self._cli), "database", "create", str(db_path),
            f"--language={codeql_lang}",
            f"--source-root={repo_path}",
            f"--threads={CODEQL_MAX_THREADS}",
            "--overwrite",
        ]
        if codeql_lang not in CODEQL_COMPILED_LANGUAGES:
            cmd.append("--no-run-unnecessary-builds")
        if self._search_path.exists():
            cmd += [f"--search-path={self._search_path}"]
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self._create_timeout, env=self._safe_env, cwd="/tmp",
            )
            if r.returncode != 0:
                parse_errors.append(f"codeql database create failed: {r.stderr[:500]}")
                return False
            return True
        except subprocess.TimeoutExpired:
            parse_errors.append(
                f"codeql database create timed out after {self._create_timeout}s"
            )
            return False
        except Exception as exc:
            parse_errors.append(f"codeql database create error: {exc}")
            return False

    def _run_analysis(
        self,
        db_path:     Path,
        codeql_lang: str,
        sarif_path:  Path,
        parse_errors: list[str],
        warnings:     list[str],
        session_id:   str | None = None,
    ) -> dict[str, Any] | None:
        """
        timeout=self._analyze_timeout:
          None → no limit; subprocess blocks until CodeQL finishes.
                 Operator confirmed: always wait; frontend streams events.
          int  → hard limit in seconds (only if operator explicitly sets
                 codeql_timeout_analyze to a positive value).
        """
        query_suite = (
            f"codeql/{codeql_lang}-queries:"
            f"codeql-suites/{codeql_lang}-security-and-quality.qls"
        )
        cmd = [
            str(self._cli), "database", "analyze", str(db_path), query_suite,
            "--format=sarif-latest",
            f"--output={sarif_path}",
            f"--threads={CODEQL_MAX_THREADS}",
            "--no-print-diagnostics-summary",
        ]
        if self._search_path.exists():
            cmd += [f"--search-path={self._search_path}"]

        limit_label = (
            "no timeout" if self._analyze_timeout is None
            else f"{self._analyze_timeout}s timeout"
        )
        logger.info("CodeQL analyze starting (lang=%s, %s)", codeql_lang, limit_label)

        try:
            r = subprocess.run(
                cmd,
                capture_output=True, text=True,
                timeout=self._analyze_timeout,   # None = wait forever
                env=self._safe_env, cwd="/tmp",
            )
            if r.returncode != 0:
                warnings.append(
                    f"codeql analyze returned {r.returncode}: {r.stderr[:300]}"
                )
            if sarif_path.exists():
                with open(sarif_path) as f:
                    return json.load(f)
        except subprocess.TimeoutExpired:
            warnings.append(
                f"codeql analyze timed out after {self._analyze_timeout}s"
            )
            _emit(session_id, "codeql_analysis",
                  f"CodeQL timed out after {self._analyze_timeout}s — "
                  f"continuing without full SARIF results.")
        except Exception as exc:
            warnings.append(f"codeql analyze error: {exc}")
        return None

    def _extract_structural_info(
        self, db_path, codeql_lang, parse_errors, warnings,
    ) -> dict[str, Any]:
        results: dict[str, Any] = {}
        for name, tmpl in [
            ("functions", _EXTRACT_FUNCTIONS_QUERY),
            ("calls",     _EXTRACT_CALLS_QUERY),
        ]:
            csv = self._run_inline_query(db_path, name, tmpl.format(lang=codeql_lang), warnings)
            if csv:
                results[name] = csv
        return results

    def _run_inline_query(self, db_path, query_name, query_src, warnings):
        with tempfile.NamedTemporaryFile(
            suffix=".ql", mode="w", delete=False, dir="/tmp",
            prefix=f"prism_{query_name}_",
        ) as qf:
            qf.write(query_src)
            ql_path = qf.name

        bqrs_path = ql_path.replace(".ql", ".bqrs")
        csv_path  = ql_path.replace(".ql", ".csv")
        try:
            r = subprocess.run(
                [str(self._cli), "query", "run", ql_path,
                 f"--database={db_path}",
                 f"--output={bqrs_path}",
                 f"--threads={CODEQL_MAX_THREADS}"],
                capture_output=True, text=True,
                timeout=LIMITS.codeql_query_timeout_s,
                env=self._safe_env, cwd="/tmp",
            )
            if r.returncode != 0:
                warnings.append(f"QL '{query_name}' failed: {r.stderr[:200]}")
                return None
            subprocess.run(
                [str(self._cli), "bqrs", "decode", bqrs_path,
                 "--format=csv", f"--output={csv_path}"],
                capture_output=True, text=True, timeout=60,
                env=self._safe_env, cwd="/tmp",
            )
            if Path(csv_path).exists():
                import csv as csv_mod
                with open(csv_path) as f:
                    return list(csv_mod.reader(f))
        except Exception as exc:
            warnings.append(f"QL '{query_name}' exception: {exc}")
        finally:
            for p in [ql_path, bqrs_path, csv_path]:
                try:
                    Path(p).unlink(missing_ok=True)
                except Exception:
                    pass
        return None





    # Graph conversion + SARIF enrichment 

    def _convert_to_graph(self, structural, file_path, language):
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
                lbl, conf, cwes = self._annotator.annotate(
                    NodeType.FUNCTION, name, language,
                )
                nodes.append(NormalizedNode(
                    node_id=node_id, node_type=NodeType.FUNCTION, raw_type="function",
                    language=language, backend=ParserBackend.CODEQL,
                    name=name, value=None, qualified_name=qualified or None,
                    file_path=fp, start_line=start_line, end_line=end_line,
                    start_col=0, end_col=0,
                    raw_text=sanitize_for_llm(f"function {name}"),
                    depth=1, parent_id=prog_id, children_ids=(),
                    security_label=lbl, security_confidence=conf,
                    cwe_hints=cwes, attributes={"source": "codeql"},
                ))
                guard.check_edge()
                edges.append(Edge(
                    Edge.make_id(prog_id, node_id, EdgeType.AST_CHILD.value),
                    EdgeType.AST_CHILD, prog_id, node_id,
                ))

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
                lbl, conf, cwes = self._annotator.annotate(
                    NodeType.CALL, callee, language,
                )
                nodes.append(NormalizedNode(
                    node_id=node_id, node_type=NodeType.CALL, raw_type="call",
                    language=language, backend=ParserBackend.CODEQL,
                    name=callee, value=None, qualified_name=callee,
                    file_path=fp, start_line=start_line, end_line=start_line,
                    start_col=0, end_col=0,
                    raw_text=sanitize_for_llm(f"call {callee}"),
                    depth=2, parent_id=prog_id, children_ids=(),
                    security_label=lbl, security_confidence=conf,
                    cwe_hints=cwes, attributes={"source": "codeql"},
                ))
        except GraphExplosionError as exc:
            logger.warning("Graph explosion in CodeQL conversion: %s", exc)
        return nodes, edges

    def _enrich_with_sarif(self, nodes, edges, sarif_data, file_path, language):
        guard = GraphSizeGuard(file_path)
        guard._node_count = len(nodes)
        guard._edge_count = len(edges)
        enriched = list(nodes)
        try:
            for run in sarif_data.get("runs", []):
                rules = {
                    r["id"]: r
                    for r in run.get("tool", {}).get("driver", {}).get("rules", [])
                }
                for alert in run.get("results", []):
                    rule_id   = alert.get("ruleId", "")
                    rule_info = rules.get(rule_id, {})
                    message   = sanitize_for_llm(
                        alert.get("message", {}).get("text", "")
                    )
                    cwe_hints: tuple[str, ...] = tuple(
                        f"CWE-{t.replace('external/cwe/cwe-', '')}"
                        for t in rule_info.get("properties", {}).get("tags", [])
                        if t.startswith("external/cwe/cwe-")
                    )
                    for loc in alert.get("locations", []):
                        region = loc.get("physicalLocation", {}).get("region", {})
                        sl     = region.get("startLine", 0)
                        sc     = region.get("startColumn", 0)
                        guard.check_node()
                        node_id = NormalizedNode.make_id(
                            file_path, sl, sc, f"SARIF_{rule_id}"
                        )
                        enriched.append(NormalizedNode(
                            node_id=node_id, node_type=NodeType.CALL,
                            raw_type=f"sarif_alert:{rule_id}",
                            language=language, backend=ParserBackend.CODEQL,
                            name=rule_id,
                            value=message[:LIMITS.max_node_text_chars],
                            qualified_name=rule_id,
                            file_path=file_path,
                            start_line=sl, end_line=sl, start_col=sc, end_col=sc,
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
            logger.warning("SARIF enrichment stopped: %s", exc)
        return enriched, edges

    def _build_security_summary(self, nodes):
        s = SecurityAnnotationSummary()
        cwe: dict[str, list[str]] = {}
        for n in nodes:
            match n.security_label:
                case SecurityLabel.SOURCE:     s.sources.append(n.node_id)
                case SecurityLabel.SINK:       s.sinks.append(n.node_id)
                case SecurityLabel.SANITIZER:  s.sanitizers.append(n.node_id)
                case SecurityLabel.PROPAGATOR: s.propagators.append(n.node_id)
                case SecurityLabel.SENSITIVE:  s.sensitive_nodes.append(n.node_id)
            for c in n.cwe_hints:
                cwe.setdefault(c, []).append(n.node_id)
        s.cwe_hints = cwe
        return s

    def _build_graphcodebert_input(self, nodes):
        tokens, ids, types, labels = [], [], [], []
        for n in nodes:
            if not n.raw_text or len(tokens) >= LIMITS.max_graphcodebert_tokens:
                break
            sentinel = n.attributes.get("llm_sentinel")
            if sentinel:
                tokens.append(sentinel); ids.append(n.node_id)
                types.append(n.node_type.value); labels.append(n.security_label.value)
                continue
            for w in sanitize_for_llm(n.raw_text).split()[:4]:
                if len(tokens) >= LIMITS.max_graphcodebert_tokens:
                    break
                tokens.append(w); ids.append(n.node_id)
                types.append(n.node_type.value); labels.append(n.security_label.value)
        return GraphCodeBERTInput(
            tokens=tokens, token_node_ids=ids, dfg_edges=[],
            node_type_sequence=types, security_label_sequence=labels,
        )

    def _fallback_output(self, file_path, language, start_ms, parse_errors, warnings):
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
        meta = FileMetadata(
            file_path=file_path, language=language, backend=ParserBackend.FALLBACK,
            file_hash="", size_bytes=0, line_count=0, encoding="utf-8",
            parse_duration_ms=round(elapsed, 2),
            error_count=len(parse_errors), has_parse_errors=True,
        )
        return ParsedGraphOutput(
            metadata=meta, nodes=[node], edges=[],
            security_summary=SecurityAnnotationSummary(),
            graphcodebert_input=GraphCodeBERTInput(
                tokens=[], token_node_ids=[], dfg_edges=[],
                node_type_sequence=[], security_label_sequence=[],
            ),
            graph_hash=ParsedGraphOutput.compute_graph_hash([node], []),
            parse_errors=parse_errors, warnings=warnings,
        )