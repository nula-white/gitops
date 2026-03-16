"""
PRISM Parser Registry
=====================
Strategy-pattern dispatcher that routes each file to the appropriate
parser backend based on language and availability.

Routing logic:
  1. Detect language from file path + content
  2. Check if CodeQL is available AND language is CodeQL-supported
       → use CodeQLParser (primary for Python, Java, JS, C/C++, Go)
  3. Else if Tree-sitter grammar is available for the language
       → use TreeSitterParser (primary for Rust, HCL, YAML, TSX)
  4. Else → use FallbackParser (always available)

The registry is designed so that:
  - CodeQL and Tree-sitter can both run on the SAME file (cross-validation)
  - Results are merged when both are available (CodeQL for vulnerability
    alerts + Tree-sitter for fine-grained AST structure)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from .language_detector import LanguageDetector, CODEQL_SUPPORTED_LANGUAGES
from .models            import Language, ParsedGraphOutput, ParserBackend
from .parsers.treesitter_parser import TreeSitterParser
from .parsers.codeql_parser     import CodeQLParser
from .parsers.fallback_parser   import FallbackParser
from .parsers.joern_delegate    import JoernDelegate, JOERN_SUPPORTED   # FIX-6
from .parsers.base              import AbstractParser

logger = logging.getLogger(__name__)


class ParserRegistry:
    """
    Central dispatcher for all parser backends.

    Instantiate once per PRISM pipeline session and reuse.
    All parsers are lazy-initialized on first use.

    Args:
        codeql_cli_path:    path to the `codeql` binary (or set CODEQL_CLI_PATH env var)
        codeql_search_path: path to codeql libraries repo (or set CODEQL_SEARCH_PATH)
        prefer_codeql:      if True, use CodeQL for supported languages even if
                            tree-sitter is available (default: True)
        cross_validate:     if True, run BOTH CodeQL and Tree-sitter on supported
                            languages and merge results (default: False, expensive)
    """

    def __init__(
        self,
        codeql_cli_path: str | None = None,
        codeql_search_path: str | None = None,
        prefer_codeql: bool = True,
        cross_validate: bool = False,
    ) -> None:
        self._detector       = LanguageDetector()
        self._prefer_codeql  = prefer_codeql
        self._cross_validate = cross_validate

        # Lazy-initialized backends
        self._tree_sitter: TreeSitterParser | None = None
        self._codeql:      CodeQLParser | None     = None
        self._joern:       JoernDelegate | None    = None   # FIX-6: add Joern
        self._fallback:    FallbackParser          = FallbackParser()

        self._codeql_cli_path    = codeql_cli_path
        self._codeql_search_path = codeql_search_path

        logger.info(
            f"ParserRegistry initialized. "
            f"prefer_codeql={prefer_codeql}, cross_validate={cross_validate}"
        )

    # ── Backend accessors (lazy init) ─────────────────────────────────────────

    @property
    def tree_sitter(self) -> TreeSitterParser:
        if self._tree_sitter is None:
            self._tree_sitter = TreeSitterParser()
        return self._tree_sitter

    @property
    def joern(self) -> JoernDelegate:                       # FIX-6
        if self._joern is None:
            self._joern = JoernDelegate()
        return self._joern

    @property
    def codeql(self) -> CodeQLParser:
        if self._codeql is None:
            self._codeql = CodeQLParser(
                codeql_cli_path=self._codeql_cli_path,
                codeql_search_path=self._codeql_search_path,
            )
        return self._codeql

    # ── Main entry point ──────────────────────────────────────────────────────

    def parse_file(
        self,
        file_path: str | Path,
        source_code: str | None = None,
    ) -> ParsedGraphOutput:
        """
        Parse a single source file and return a ParsedGraphOutput.

        Args:
            file_path:   path to the source file
            source_code: if provided, uses this text instead of reading the file
                         (useful for in-memory analysis / sandbox environments)
        """
        file_path = str(file_path)

        # Load source if not provided
        if source_code is None:
            try:
                with open(file_path, encoding="utf-8", errors="replace") as f:
                    source_code = f.read()
            except OSError as exc:
                logger.error(f"Cannot read file {file_path}: {exc}")
                return self._fallback.parse("", file_path, Language.UNKNOWN)

        # Detect language
        detection = self._detector.detect(file_path, source_code)
        language  = detection.language

        if language == Language.UNKNOWN:
            logger.info(f"Unknown language for {file_path}, using fallback parser")
            return self._fallback.parse(source_code, file_path, Language.UNKNOWN)

        logger.debug(
            f"Detected {language.value} in {file_path} "
            f"(confidence={detection.confidence:.2f}, method={detection.method})"
        )

        # Select backend(s)
        primary_result   = self._dispatch(source_code, file_path, language)
        secondary_result = None

        if self._cross_validate and detection.primary_backend != detection.fallback_backend:
            secondary_result = self._dispatch_secondary(source_code, file_path, language)

        if secondary_result:
            return self._merge_results(primary_result, secondary_result)

        return primary_result

    def parse_repository(
        self,
        repo_path: str | Path,
        language_override: Language | None = None,
    ) -> list[ParsedGraphOutput]:
        """
        Parse all source files in a repository directory.
        Returns a list of ParsedGraphOutput, one per file.

        Uses CodeQL at repo level for supported languages (most accurate),
        then Tree-sitter / fallback for remaining files.
        """
        repo_path = Path(repo_path)
        outputs: list[ParsedGraphOutput] = []

        # Collect all source files
        all_files = [
            f for f in repo_path.rglob("*")
            if f.is_file() and not _should_skip(f)
        ]

        logger.info(f"Parsing repository: {repo_path} ({len(all_files)} files)")

        for file_path in all_files:
            try:
                result = self.parse_file(file_path)
                outputs.append(result)
                logger.debug(
                    f"  [{result.metadata.backend.value}] {file_path.name} "
                    f"→ {len(result.nodes)} nodes, {len(result.edges)} edges"
                )
            except Exception as exc:
                logger.error(f"Failed to parse {file_path}: {exc}", exc_info=True)

        logger.info(
            f"Repository parse complete: {len(outputs)} files, "
            f"{sum(len(o.nodes) for o in outputs)} total nodes"
        )
        return outputs

    # ── Internal dispatch ─────────────────────────────────────────────────────

    def _dispatch(
        self,
        source_code: str,
        file_path: str,
        language: Language,
    ) -> ParsedGraphOutput:
        """
        FIX-6: Three-role routing matching the architecture document.

        Architecture (from graph_generation_PRISM.docx):
          - Joern       → CPG topology (AST + CFG + DFG edges) for GraphCodeBERT
                          Primary for: C, C++, Java, JS, TS, Go, Python
          - Tree-sitter → AST for languages Joern doesn't cover
                          Primary for: Rust, HCL, YAML, TSX
          - CodeQL      → SARIF security oracle only (run in parallel via
                          parse_repository; SARIF injected by sarif_injector)
          - Fallback    → when nothing else is available

        CodeQL is NOT used here for structural parsing. The CodeQL SARIF
        results are merged at the CPG assembly stage (graph_builder layer),
        not at the parser routing stage.
        """
        # ── Joern: primary for its supported languages ────────────────────────
        if language in JOERN_SUPPORTED and self.joern.can_parse(language):
            logger.debug("Using Joern backend for %s (language=%s)", file_path, language.value)
            try:
                return self.joern.parse(source_code, file_path, language)
            except Exception as exc:
                logger.warning(
                    "Joern failed for %s (%s): %s — falling back to Tree-sitter",
                    file_path, language.value, exc,
                )

        # ── Tree-sitter: primary for Rust/HCL/YAML/TSX; fallback for Joern failures ──
        if self.tree_sitter.can_parse(language):
            logger.debug("Using Tree-sitter backend for %s", file_path)
            try:
                return self.tree_sitter.parse(source_code, file_path, language)
            except Exception as exc:
                logger.warning("Tree-sitter failed for %s: %s — using fallback", file_path, exc)

        # ── Fallback: always available, regex-based, no CFG/DFG ──────────────
        logger.debug("Using fallback backend for %s", file_path)
        return self._fallback.parse(source_code, file_path, language)

    def _dispatch_secondary(
        self,
        source_code: str,
        file_path: str,
        language: Language,
    ) -> ParsedGraphOutput | None:
        """Run the secondary backend for cross-validation."""
        if language in CODEQL_SUPPORTED_LANGUAGES and self.tree_sitter.can_parse(language):
            try:
                return self.tree_sitter.parse(source_code, file_path, language)
            except Exception as exc:
                logger.debug(f"Secondary Tree-sitter parse failed: {exc}")
        return None

    # ── Result merger ─────────────────────────────────────────────────────────

    def _merge_results(
        self,
        primary: ParsedGraphOutput,
        secondary: ParsedGraphOutput,
    ) -> ParsedGraphOutput:
        """
        Merge two ParsedGraphOutputs (e.g. CodeQL + Tree-sitter).
        Strategy:
          - Nodes: union by node_id; CodeQL nodes take precedence for conflicts
          - Edges: union by edge_id
          - Security summary: union of all lists
          - SARIF results: preserved from CodeQL (primary)
          - Graph hash: recomputed over merged nodes + edges
        """
        # Merge nodes (primary takes precedence)
        node_map = {n.node_id: n for n in secondary.nodes}
        node_map.update({n.node_id: n for n in primary.nodes})
        merged_nodes = list(node_map.values())

        # Merge edges
        edge_map = {e.edge_id: e for e in secondary.edges}
        edge_map.update({e.edge_id: e for e in primary.edges})
        merged_edges = list(edge_map.values())

        # Merge security summaries
        from .models import SecurityAnnotationSummary
        merged_sec = SecurityAnnotationSummary(
            sources=list(set(primary.security_summary.sources + secondary.security_summary.sources)),
            sinks=list(set(primary.security_summary.sinks + secondary.security_summary.sinks)),
            sanitizers=list(set(primary.security_summary.sanitizers + secondary.security_summary.sanitizers)),
            propagators=list(set(primary.security_summary.propagators + secondary.security_summary.propagators)),
            sensitive_nodes=list(set(primary.security_summary.sensitive_nodes + secondary.security_summary.sensitive_nodes)),
        )
        merged_cwe: dict[str, list[str]] = {}
        for cwe, ids in {**secondary.security_summary.cwe_hints, **primary.security_summary.cwe_hints}.items():
            merged_cwe[cwe] = list(set(ids))
        merged_sec.cwe_hints = merged_cwe

        new_hash = ParsedGraphOutput.compute_graph_hash(merged_nodes, merged_edges)

        return ParsedGraphOutput(
            metadata=primary.metadata,   # primary metadata wins
            nodes=merged_nodes,
            edges=merged_edges,
            security_summary=merged_sec,
            graphcodebert_input=primary.graphcodebert_input,
            graph_hash=new_hash,
            parse_errors=primary.parse_errors + secondary.parse_errors,
            warnings=primary.warnings + secondary.warnings + ["Cross-validated: CodeQL + Tree-sitter merged"],
            codeql_results=primary.codeql_results,
        )

    # ── Status / introspection ────────────────────────────────────────────────

    def get_backend_status(self) -> dict[str, Any]:
        return {
            "joern_available":       self.joern.can_parse(Language.PYTHON),
            "tree_sitter_available": self.tree_sitter.can_parse(Language.PYTHON),
            "codeql_available":      self.codeql.can_parse(Language.PYTHON),
            "fallback_available":    True,
            "prefer_codeql":         self._prefer_codeql,
            "cross_validate":        self._cross_validate,
            "routing_note": (
                "Joern=CPG topology (GraphCodeBERT); "
                "CodeQL=SARIF oracle (security annotations only); "
                "Tree-sitter=Rust/HCL/YAML/TSX primary"
            ),
        }


# ── Helpers ───────────────────────────────────────────────────────────────────

_SKIP_DIRS: frozenset[str] = frozenset({
    ".git", "__pycache__", "node_modules", ".tox", "venv", ".venv",
    "dist", "build", "target", ".terraform",
})

_SKIP_EXTENSIONS: frozenset[str] = frozenset({
    ".pyc", ".pyo", ".class", ".o", ".obj", ".exe", ".dll", ".so", ".dylib",
    ".jar", ".war", ".zip", ".gz", ".tar", ".lock", ".sum", ".png", ".jpg",
    ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot",
    ".min.js", ".min.css", ".map",
})

def _should_skip(file_path: Path) -> bool:
    """Return True if this file should be skipped during repo parsing."""
    # Skip files in ignored directories
    for part in file_path.parts:
        if part in _SKIP_DIRS:
            return True
    # Skip by extension
    name = file_path.name
    return any(name.endswith(ext) for ext in _SKIP_EXTENSIONS)