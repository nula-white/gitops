"""
Writes CPG nodes and edges to Neo4j using batched Cypher transactions.

Schema design:
  Nodes:  Label=CPGNode, primary key=node_id (unique constraint)
  Edges:  Relationship type = edge_type value (e.g. :DFG_FLOW, :CFG_NEXT)
          Primary key = edge_id (to prevent duplicates on re-run)

Idempotency:
  All writes use MERGE on node_id / edge_id.
  Re-running the graph builder on the same repo produces the same graph.
  This is critical for the audit trail: repo_hash → same graph every time.

Session namespacing:
  All nodes carry a session_id property.
  This allows querying "show me all nodes from analysis session X"
  and enables cleanup of old sessions without full DB wipe.

Batching:
  Nodes and edges are written in batches of BATCH_SIZE (default 500).
  This keeps transaction size manageable for large repositories.
  On failure, the batch is retried once with a smaller size (250).

Cypher queries:
  MERGE with ON CREATE SET / ON MATCH SET to handle both insert and update.
  ON MATCH SET updates risk_score and security_label (these are set later
  by SecurityAnalysisAgent — graph build only sets structural properties).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from .models import CPGNode, CPGEdge, GraphBuildResult
from ..ingestion.exceptions import Neo4jWriteError

logger = logging.getLogger(__name__)

BATCH_SIZE      = 500
RETRY_BATCH     = 250


# Cypher queries

_MERGE_NODE_CYPHER = """
        UNWIND $batch AS props
        MERGE (n:CPGNode {node_id: props.node_id})
        ON CREATE SET
        n.node_type       = props.node_type,
        n.language        = props.language,
        n.file_path       = props.file_path,
        n.start_line      = props.start_line,
        n.end_line        = props.end_line,
        n.start_col       = props.start_col,
        n.end_col         = props.end_col,
        n.raw_text        = props.raw_text,
        n.normalized_text = props.normalized_text,
        n.token_ids       = props.token_ids,
        n.security_label  = props.security_label,
        n.cwe_hint        = props.cwe_hint,
        n.sarif_rule_id   = props.sarif_rule_id,
        n.risk_score      = props.risk_score,
        n.is_vulnerable   = props.is_vulnerable,
        n.confidence      = props.confidence,
        n.finding_type    = props.finding_type,
        n.parent_function = props.parent_function,
        n.parent_class    = props.parent_class,
        n.is_async        = props.is_async,
        n.session_id      = props.session_id,
        n.repo_hash       = props.repo_hash
        ON MATCH SET
        n.security_label  = props.security_label,
        n.cwe_hint        = props.cwe_hint,
        n.sarif_rule_id   = props.sarif_rule_id,
        n.risk_score      = props.risk_score,
        n.is_vulnerable   = props.is_vulnerable,
        n.confidence      = props.confidence,
        n.finding_type    = props.finding_type
    """

# Dynamic edge query — edge type is part of the relationship type in Neo4j.
# We build one query per edge type to use the correct relationship label.

def _edge_cypher(edge_type: str) -> str:
    return f"""
        UNWIND $batch AS props
        MATCH (a:CPGNode {{node_id: props.src_id}})
        MATCH (b:CPGNode {{node_id: props.dst_id}})
        MERGE (a)-[r:{edge_type} {{edge_id: props.edge_id}}]->(b)
        ON CREATE SET r += props
    """

# Index creation queries (run once at startup)
_SETUP_QUERIES = [
    "CREATE CONSTRAINT cpg_node_id IF NOT EXISTS FOR (n:CPGNode) REQUIRE n.node_id IS UNIQUE",
    "CREATE INDEX cpg_file_path IF NOT EXISTS FOR (n:CPGNode) ON (n.file_path)",
    "CREATE INDEX cpg_security_label IF NOT EXISTS FOR (n:CPGNode) ON (n.security_label)",
    "CREATE INDEX cpg_session IF NOT EXISTS FOR (n:CPGNode) ON (n.session_id)",
    "CREATE INDEX cpg_language IF NOT EXISTS FOR (n:CPGNode) ON (n.language)",
    "CREATE INDEX cpg_is_vulnerable IF NOT EXISTS FOR (n:CPGNode) ON (n.is_vulnerable)",
]


# Writer

@dataclass
class WriteResult:
    nodes_written: int       = 0
    edges_written: int       = 0
    warnings:      list[str] = field(default_factory=list)
    success:       bool      = True
    error:         str       = ""


class Neo4jWriter:
    """
    Writes CPG nodes and edges to Neo4j.

    Usage:
        writer = Neo4jWriter(uri="neo4j://127.0.0.1:7687",
                             user="neo4j", password="password")
        result = writer.write(nodes, edges, session_id, repo_hash)
        writer.close()

    When neo4j is unavailable, use MockNeo4jWriter for testing.
    """
    import os
    from dotenv import load_dotenv
    password= os.getenv("NEO4J_PASSWORD", "password")
    def __init__(
        self,
        uri:      str = "bolt://localhost:7687",
        user:     str = "neo4j",
        password: str = "password",
    ) -> None:
        self._uri      = uri
        self._user     = user
        self._password = password
        self._driver   = None
        self._available = self._try_connect()

    def _try_connect(self) -> bool:
        """Attempt to connect to Neo4j. Returns False if unavailable."""
        try:
            from neo4j import GraphDatabase
            self._driver = GraphDatabase.driver(
                self._uri,
                auth=(self._user, self._password),
            )
            # Verify connectivity
            self._driver.verify_connectivity()
            logger.info("Neo4j connected: %s", self._uri)
            return True
        except ImportError:
            logger.warning(
                "neo4j Python driver not installed. "
                "Install with: pip install neo4j. "
                "Graph writes will be skipped."
            )
            return False
        except Exception as exc:
            logger.warning(
                "Neo4j unavailable at %s: %s. "
                "Graph writes will be skipped.",
                self._uri, exc,
            )
            return False

    def setup_schema(self) -> None:
        """Create indexes and constraints. Safe to call multiple times."""
        if not self._available:
            return
        with self._driver.session() as session:
            for query in _SETUP_QUERIES:
                try:
                    session.run(query)
                except Exception as exc:
                    logger.warning("Schema setup query failed (non-fatal): %s", exc)

    def write(
        self,
        nodes:      list[CPGNode],
        edges:      list[CPGEdge],
        session_id: str,
        repo_hash:  str,
    ) -> WriteResult:
        """
        Write all nodes and edges to Neo4j.

        Nodes are written first (required for edge MATCH to succeed).
        Edges are grouped by type and written with type-specific Cypher.
        """
        result = WriteResult()

        if not self._available:
            result.warnings.append(
                "Neo4j unavailable — graph not persisted. "
                "Start Neo4j with: docker run -p 7687:7687 neo4j"
            )
            result.success = True   # non-fatal for MVP
            return result

        try:
            # ── Write nodes ──────────────────────────────────────────────
            node_props = []
            for node in nodes:
                d = node.to_neo4j_dict()
                d["session_id"] = session_id
                d["repo_hash"]  = repo_hash
                node_props.append(d)

            self._write_batches(node_props, _MERGE_NODE_CYPHER)
            result.nodes_written = len(nodes)

            # ── Write edges grouped by type ───────────────────────────────
            edges_by_type: dict[str, list[dict]] = {}
            for edge in edges:
                et = edge.edge_type.value
                edges_by_type.setdefault(et, []).append(edge.to_neo4j_dict())

            for edge_type, edge_batch in edges_by_type.items():
                cypher = _edge_cypher(edge_type)
                self._write_batches(edge_batch, cypher)
                result.edges_written += len(edge_batch)

            logger.info(
                "Neo4j write complete: %d nodes, %d edges (session=%s)",
                result.nodes_written, result.edges_written, session_id,
            )

        except Exception as exc:
            raise Neo4jWriteError(
                f"Neo4j write failed: {exc}",
                details={
                    "session_id":     session_id,
                    "nodes_attempted": len(nodes),
                    "edges_attempted": len(edges),
                    "neo4j_error":    str(exc),
                },
            ) from exc

        return result

    def _write_batches(
        self,
        items:  list[dict],
        cypher: str,
    ) -> None:
        """Write items in batches with one retry on failure."""
        for i in range(0, len(items), BATCH_SIZE):
            batch = items[i : i + BATCH_SIZE]
            try:
                with self._driver.session() as session:
                    session.run(cypher, batch=batch)
            except Exception as exc:
                # Retry with smaller batch
                logger.warning(
                    "Batch write failed (size=%d), retrying with size=%d: %s",
                    len(batch), RETRY_BATCH, exc,
                )
                for j in range(0, len(batch), RETRY_BATCH):
                    sub = batch[j : j + RETRY_BATCH]
                    with self._driver.session() as session:
                        session.run(cypher, batch=sub)

    def delete_session(self, session_id: str) -> int:
        """Delete all CPG nodes (and their edges) for a session. Returns deleted count."""
        if not self._available:
            return 0
        with self._driver.session() as session:
            result = session.run(
                "MATCH (n:CPGNode {session_id: $sid}) DETACH DELETE n RETURN count(n) AS cnt",
                sid=session_id,
            )
            record = result.single()
            return record["cnt"] if record else 0

    def close(self) -> None:
        if self._driver:
            self._driver.close()

    def __enter__(self) -> "Neo4jWriter":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


# Mock writer for testing (no Neo4j required)

class MockNeo4jWriter:
    """
    In-memory Neo4j writer for testing and offline development.
    Stores nodes and edges in lists — no database required.
    """

    def __init__(self) -> None:
        self.written_nodes: list[dict] = []
        self.written_edges: list[dict] = []
        self._available = True

    def setup_schema(self) -> None:
        pass

    def write(
        self,
        nodes:      list[CPGNode],
        edges:      list[CPGEdge],
        session_id: str,
        repo_hash:  str,
    ) -> WriteResult:
        for node in nodes:
            d = node.to_neo4j_dict()
            d["session_id"] = session_id
            d["repo_hash"]  = repo_hash
            self.written_nodes.append(d)
        for edge in edges:
            self.written_edges.append(edge.to_neo4j_dict())
        return WriteResult(
            nodes_written = len(nodes),
            edges_written = len(edges),
        )

    def delete_session(self, session_id: str) -> int:
        before = len(self.written_nodes)
        self.written_nodes = [
            n for n in self.written_nodes if n.get("session_id") != session_id
        ]
        return before - len(self.written_nodes)

    def close(self) -> None:
        pass

    def __enter__(self) -> "MockNeo4jWriter":
        return self

    def __exit__(self, *args: object) -> None:
        pass