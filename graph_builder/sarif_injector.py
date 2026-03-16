"""
PRISM CodeQL SARIF Injector

Parses CodeQL SARIF output and injects security annotations into existing CPG nodes. This is the bridge between CodeQL's rule-based
taint analysis and the graph builder's structural representation.

SARIF structure (CodeQL output):
  {
    "runs": [{
      "results": [{
        "ruleId": "py/sql-injection",
        "message": {"text": "..."},
        "locations": [{
          "physicalLocation": {
            "artifactLocation": {"uri": "src/app.py"},
            "region": {
              "startLine": 42, "startColumn": 8,
              "endLine": 42,   "endColumn": 35
            }
          }
        }],
        "relatedLocations": [...]   // taint flow path
      }]
    }]
  }

Injection process:
  1. Parse SARIF JSON
  2. For each result, find the CPG node at that file:line:col
  3. Set node.security_label, node.cwe_hint, node.sarif_rule_id
  4. Emit TAINT_SOURCE / TAINT_SINK / SANITIZER edges

Node lookup:
  Nodes are indexed by (file_path, start_line, start_col) during
  graph assembly. The injector uses this index — O(1) per result.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import CPGNode, CPGEdge, EdgeType, SecurityLabel
from ..ingestion.exceptions import SARIFParseError

logger = logging.getLogger(__name__)

# CodeQL rule ID → (SecurityLabel for primary location, CWE hint)
"""
a security rule annotation map used in a static analysis / vulnerability detection pipeline. 
This tells teh system : When a specific security rule is triggered, 
how should it be interpreted in the code graph and which vulnerability type (CWE) does it correspond to?
"""

_RULE_ANNOTATIONS: dict[str, tuple[SecurityLabel, str]] = {
    # Python
    "py/sql-injection":               (SecurityLabel.SINK,   "CWE-89"),
    "py/command-injection":           (SecurityLabel.SINK,   "CWE-78"),
    "py/path-injection":              (SecurityLabel.SINK,   "CWE-22"),
    "py/code-injection":              (SecurityLabel.SINK,   "CWE-94"),
    "py/ssrf":                        (SecurityLabel.SINK,   "CWE-918"),
    "py/xml-bomb":                    (SecurityLabel.SINK,   "CWE-776"),
    "py/unsafe-deserialization":      (SecurityLabel.SINK,   "CWE-502"),
    "py/uncontrolled-format-string":  (SecurityLabel.SINK,   "CWE-134"),
    "py/reflected-xss":               (SecurityLabel.SINK,   "CWE-79"),
    "py/user-controlled-bypass":      (SecurityLabel.SOURCE, "CWE-807"),
    # Java
    "java/sql-injection":             (SecurityLabel.SINK,   "CWE-89"),
    "java/command-injection":         (SecurityLabel.SINK,   "CWE-78"),
    "java/path-injection":            (SecurityLabel.SINK,   "CWE-22"),
    "java/xss":                       (SecurityLabel.SINK,   "CWE-79"),
    "java/ssrf":                      (SecurityLabel.SINK,   "CWE-918"),
    "java/unsafe-deserialization":    (SecurityLabel.SINK,   "CWE-502"),
    # JavaScript
    "js/sql-injection":               (SecurityLabel.SINK,   "CWE-89"),
    "js/command-injection":           (SecurityLabel.SINK,   "CWE-78"),
    "js/path-injection":              (SecurityLabel.SINK,   "CWE-22"),
    "js/xss":                         (SecurityLabel.SINK,   "CWE-79"),
    "js/code-injection":              (SecurityLabel.SINK,   "CWE-94"),
    "js/prototype-polluting-assignment": (SecurityLabel.SINK, "CWE-1321"),
    # C/C++
    "cpp/path-injection":             (SecurityLabel.SINK,   "CWE-22"),
    "cpp/command-injection":          (SecurityLabel.SINK,   "CWE-78"),
    "cpp/overflow-buffer":            (SecurityLabel.SINK,   "CWE-120"),
    "cpp/unsafe-use-of-this":         (SecurityLabel.SINK,   "CWE-362"),
    # Go
    "go/sql-injection":               (SecurityLabel.SINK,   "CWE-89"),
    "go/command-injection":           (SecurityLabel.SINK,   "CWE-78"),
    "go/path-injection":              (SecurityLabel.SINK,   "CWE-22"),
    # Terraform (Checkov-compatible rule IDs)
    "CKV_AWS_57":                     (SecurityLabel.SINK,   "CWE-732"),  # S3 public
    "CKV_AWS_19":                     (SecurityLabel.SINK,   "CWE-311"),  # S3 encryption
    "CKV_AWS_18":                     (SecurityLabel.SINK,   "CWE-778"),  # S3 logging
    "CKV_AZURE_3":                    (SecurityLabel.SINK,   "CWE-732"),  # Storage public
}


@dataclass
class SARIFInjectionResult:
    annotations_added: int = 0
    edges_added:       int = 0
    warnings:          list[str] = field(default_factory=list)
    rules_matched:     list[str] = field(default_factory=list)


class SARIFInjector:
    """
    Injects CodeQL SARIF security annotations into CPG nodes.

    Usage:
        injector = SARIFInjector()
        result = injector.inject(
            sarif_path="/tmp/codeql_results.sarif",
            node_index=graph.node_index,   # {(file, line, col): CPGNode}
            edges=graph.edges,             # list to append new edges to
        )
    """

    def inject(
        self,
        sarif_data:   dict[str, Any] | str,
        node_index:   dict[tuple[str, int, int], CPGNode],
        edges:        list[CPGEdge],
        repo_root:    str = "",
    ) -> SARIFInjectionResult:
        """
        Parse SARIF and annotate matching CPG nodes.

        Args:
            sarif_data:  SARIF dict or JSON string
            node_index:  {(file_path, start_line, start_col): CPGNode}
            edges:       edge list to append TAINT_* edges to
            repo_root:   repository root path (for path normalization)

        Returns:
            SARIFInjectionResult with counts and warnings
        """
        result = SARIFInjectionResult()

        # Parse SARIF input
        if isinstance(sarif_data, str):
            try:
                sarif = json.loads(sarif_data)
            except json.JSONDecodeError as exc:
                raise SARIFParseError(
                    f"SARIF JSON parse failed: {exc}",
                    details={"parse_error": str(exc)},
                ) from exc
        else:
            sarif = sarif_data

        runs = sarif.get("runs", [])
        if not runs:
            result.warnings.append("SARIF has no 'runs' — empty results")
            return result

        for run in runs:
            sarif_results = run.get("results", [])
            for finding in sarif_results:
                self._process_finding(
                    finding, node_index, edges, result, repo_root
                )

        logger.info(
            "SARIF injection complete: %d annotations, %d edges, %d rules matched",
            result.annotations_added, result.edges_added,
            len(set(result.rules_matched)),
        )
        return result

    def inject_from_file(
        self,
        sarif_path:  str,
        node_index:  dict[tuple[str, int, int], CPGNode],
        edges:       list[CPGEdge],
        repo_root:   str = "",
    ) -> SARIFInjectionResult:
        """Load SARIF from file and inject."""
        try:
            with open(sarif_path, "r", encoding="utf-8") as f:
                sarif = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            raise SARIFParseError(
                f"Failed to load SARIF file {sarif_path!r}: {exc}",
                details={"sarif_path": sarif_path, "parse_error": str(exc)},
            ) from exc
        return self.inject(sarif, node_index, edges, repo_root)

    def _process_finding(
        self,
        finding:    dict[str, Any],
        node_index: dict[tuple[str, int, int], CPGNode],
        edges:      list[CPGEdge],
        result:     SARIFInjectionResult,
        repo_root:  str,
    ) -> None:
        rule_id   = finding.get("ruleId", "")
        locations = finding.get("locations", [])
        if not locations:
            return

        # Primary location (the sink — where the vulnerability manifests)
        primary = locations[0]
        node = self._find_node(primary, node_index, repo_root)
        if not node:
            return

        # Determine annotation from rule ID
        label, cwe = _RULE_ANNOTATIONS.get(rule_id, (SecurityLabel.SINK, ""))

        # Annotate the primary node
        node.security_label = label
        node.cwe_hint        = cwe
        node.sarif_rule_id   = rule_id
        result.annotations_added += 1
        result.rules_matched.append(rule_id)

        # Process related locations (taint flow path)
        # First related location is typically the SOURCE
        related = finding.get("relatedLocations", [])
        source_node = None
        if related:
            source_location = related[0]
            source_node = self._find_node(source_location, node_index, repo_root)
            if source_node:
                source_node.security_label = SecurityLabel.SOURCE
                if not source_node.cwe_hint:
                    source_node.cwe_hint = cwe
                result.annotations_added += 1

                # Emit TAINT_SOURCE edge: source → sink
                eid = CPGEdge.make_id(
                    source_node.node_id, node.node_id, EdgeType.TAINT_SOURCE.value
                )
                edges.append(CPGEdge(
                    edge_id    = eid,
                    src_id     = source_node.node_id,
                    dst_id     = node.node_id,
                    edge_type  = EdgeType.TAINT_SOURCE,
                    properties = {"rule_id": rule_id, "cwe": cwe},
                ))
                result.edges_added += 1

        # Emit TAINT_SINK edge on the primary node (self-loop for now —
        # signals to SecurityAnalysisAgent that this is a confirmed sink)
        eid = CPGEdge.make_id(node.node_id, node.node_id, EdgeType.TAINT_SINK.value)
        edges.append(CPGEdge(
            edge_id    = eid,
            src_id     = node.node_id,
            dst_id     = node.node_id,
            edge_type  = EdgeType.TAINT_SINK,
            properties = {"rule_id": rule_id, "cwe": cwe},
        ))
        result.edges_added += 1

    def _find_node(
        self,
        location:   dict[str, Any],
        node_index: dict[tuple[str, int, int], CPGNode],
        repo_root:  str,
    ) -> CPGNode | None:
        """Look up a CPG node by SARIF location."""
        try:
            phys = location.get("physicalLocation", {})
            uri  = phys.get("artifactLocation", {}).get("uri", "")
            region = phys.get("region", {})
            line = region.get("startLine", 0)
            col  = region.get("startColumn", 1) - 1  # SARIF is 1-based, CPG is 0-based

            # Normalize the file path
            file_path = _normalize_path(uri, repo_root)

            # Try exact match first
            node = node_index.get((file_path, line, col))
            if node:
                return node

            # Fallback: match by file and line only (col may differ slightly)
            for (fp, ln, _), n in node_index.items():
                if fp == file_path and ln == line:
                    return n

        except Exception as exc:
            logger.debug("SARIF node lookup failed: %s", exc)
        return None


def _normalize_path(uri: str, repo_root: str) -> str:
    """
    Normalize a SARIF URI to a relative file path matching CPG node paths.
    SARIF URIs may be absolute or relative; CPG stores relative paths.
    """
    import re
    # Remove file:// scheme
    path = re.sub(r"^file://", "", uri)
    # Remove repo_root prefix to get relative path
    if repo_root and path.startswith(repo_root):
        path = path[len(repo_root):].lstrip("/")
    # Normalize path separators
    path = path.replace("\\", "/").lstrip("./")
    return path