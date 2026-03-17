"""
Neo4j async client for PRISM CPG storage.

Connection: bolt://  (default port 7687)
Database  : configured via NEO4J_DATABASE env var (default "neo4j")

Schema
------
(:Node {id, session_id, node_type, language, file, line_start, line_end,
        col_start, col_end, name, code_snippet, phase, annotated, vuln_id})

(:Edge {id, session_id, source_id, target_id, kind, label})
  – edges are stored as both relationships AND nodes for easy querying

(:Finding {id, session_id, node_id, vuln_type, cwe, severity, confidence,
           file, line_start, line_end, function_name, description,
           code_snippet, data_flow_path, remediation, references})
"""
from __future__ import annotations

import logging
from typing import List, Optional

from neo4j import AsyncGraphDatabase, AsyncDriver
from core.config import get_settings
from core.models import CPGNode, CPGEdge, VulnerabilityFinding

log = logging.getLogger(__name__)
_driver: Optional[AsyncDriver] = None


# Driver lifecycle

async def get_driver() -> AsyncDriver:
    global _driver
    if _driver is None:
        s = get_settings()
        _driver = AsyncGraphDatabase.driver(s.neo4j_uri, auth=(s.neo4j_user, s.neo4j_password),
        )
        log.info("Neo4j driver initialised → %s", s.neo4j_uri)
    return _driver


async def close_driver() -> None:
    global _driver
    if _driver:
        await _driver.close()
        _driver = None


async def verify_connectivity() -> bool:
    """Return True if Neo4j is reachable, False otherwise."""
    try:
        d = await get_driver()
        await d.verify_connectivity()
        return True
    except Exception as exc:
        log.warning("Neo4j not reachable: %s", exc)
        return False


# Schema / indexes

async def ensure_indexes() -> None:
    """Create uniqueness constraints and indexes on first run."""
    d = await get_driver()
    s = get_settings()
    async with d.session(database=s.neo4j_database) as session:
        stmts = [
            "CREATE CONSTRAINT prism_node_id IF NOT EXISTS "
            "FOR (n:CPGNode) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT prism_finding_id IF NOT EXISTS "
            "FOR (f:Finding) REQUIRE f.id IS UNIQUE",
            "CREATE INDEX prism_node_session IF NOT EXISTS "
            "FOR (n:CPGNode) ON (n.session_id)",
            "CREATE INDEX prism_finding_session IF NOT EXISTS "
            "FOR (f:Finding) ON (f.session_id)",
        ]
        for stmt in stmts:
            try:
                await session.run(stmt)
            except Exception as exc:
                log.debug("Index stmt skipped (%s): %s", exc, stmt[:60])


# CPGNode

async def upsert_node(node: CPGNode) -> None:
    d = await get_driver()
    s = get_settings()
    async with d.session(database=s.neo4j_database) as session:
        await session.run(
            """
            MERGE (n:CPGNode {id: $id})
            SET n += {
                session_id:   $session_id,
                node_type:    $node_type,
                language:     $language,
                file:         $file,
                line_start:   $line_start,
                line_end:     $line_end,
                col_start:    $col_start,
                col_end:      $col_end,
                name:         $name,
                code_snippet: $code_snippet,
                phase:        $phase,
                annotated:    $annotated,
                vuln_id:      $vuln_id
            }
            """,
            **node.model_dump(),
        )


async def bulk_upsert_nodes(nodes: List[CPGNode]) -> None:
    if not nodes:
        return
    d = await get_driver()
    s = get_settings()
    rows = [n.model_dump() for n in nodes]
    async with d.session(database=s.neo4j_database) as session:
        await session.run(
            """
            UNWIND $rows AS row
            MERGE (n:CPGNode {id: row.id})
            SET n += row
            """,
            rows=rows,
        )


async def get_nodes_for_session(session_id: str) -> List[dict]:
    d = await get_driver()
    s = get_settings()
    async with d.session(database=s.neo4j_database) as session:
        result = await session.run(
            "MATCH (n:CPGNode {session_id: $sid}) RETURN n",
            sid=session_id,
        )
        records = await result.data()
        return [r["n"] for r in records]


async def mark_node_annotated(node_id: str, vuln_id: Optional[str] = None) -> None:
    d = await get_driver()
    s = get_settings()
    async with d.session(database=s.neo4j_database) as session:
        await session.run(
            "MATCH (n:CPGNode {id: $id}) SET n.annotated = true, n.vuln_id = $vuln_id",
            id=node_id,
            vuln_id=vuln_id,
        )


# CPGEdge

async def upsert_edge(edge: CPGEdge) -> None:
    d = await get_driver()
    s = get_settings()
    async with d.session(database=s.neo4j_database) as session:
        await session.run(
            """
            MERGE (e:CPGEdge {id: $id})
            SET e += {
                session_id: $session_id,
                source_id:  $source_id,
                target_id:  $target_id,
                kind:       $kind,
                label:      $label
            }
            WITH e
            MATCH (a:CPGNode {id: $source_id}), (b:CPGNode {id: $target_id})
            MERGE (a)-[r:CPG_EDGE {kind: $kind}]->(b)
            SET r.edge_id = $id
            """,
            **edge.model_dump(),
        )


async def bulk_upsert_edges(edges: List[CPGEdge]) -> None:
    if not edges:
        return
    d = await get_driver()
    s = get_settings()
    rows = [e.model_dump() for e in edges]
    async with d.session(database=s.neo4j_database) as session:
        await session.run(
            """
            UNWIND $rows AS row
            MERGE (e:CPGEdge {id: row.id})
            SET e += row
            """,
            rows=rows,
        )


async def get_edges_for_session(session_id: str) -> List[dict]:
    d = await get_driver()
    s = get_settings()
    async with d.session(database=s.neo4j_database) as session:
        result = await session.run(
            "MATCH (e:CPGEdge {session_id: $sid}) RETURN e",
            sid=session_id,
        )
        records = await result.data()
        return [r["e"] for r in records]


# VulnerabilityFinding

async def upsert_finding(finding: VulnerabilityFinding) -> None:
    d = await get_driver()
    s = get_settings()
    async with d.session(database=s.neo4j_database) as session:
        await session.run(
            """
            MERGE (f:Finding {id: $id})
            SET f += {
                session_id:    $session_id,
                node_id:       $node_id,
                vuln_type:     $vuln_type,
                cwe:           $cwe,
                severity:      $severity,
                confidence:    $confidence,
                file:          $file,
                line_start:    $line_start,
                line_end:      $line_end,
                function_name: $function_name,
                description:   $description,
                code_snippet:  $code_snippet,
                data_flow_path: $data_flow_path,
                remediation:   $remediation,
                references:    $references
            }
            """,
            **{**finding.model_dump(), "data_flow_path": finding.data_flow_path,
               "references": finding.references},
        )


async def get_findings_for_session(session_id: str) -> List[dict]:
    d = await get_driver()
    s = get_settings()
    async with d.session(database=s.neo4j_database) as session:
        result = await session.run(
            "MATCH (f:Finding {session_id: $sid}) RETURN f ORDER BY f.severity",
            sid=session_id,
        )
        records = await result.data()
        return [r["f"] for r in records]


# Session cleanup

async def delete_session(session_id: str) -> None:
    """Remove all CPG data for a session (ephemeral execution model)."""
    d = await get_driver()
    s = get_settings()
    async with d.session(database=s.neo4j_database) as session:
        await session.run(
            "MATCH (n:CPGNode {session_id: $sid}) DETACH DELETE n",
            sid=session_id,
        )
        await session.run(
            "MATCH (e:CPGEdge {session_id: $sid}) DETACH DELETE e",
            sid=session_id,
        )
        await session.run(
            "MATCH (f:Finding {session_id: $sid}) DETACH DELETE f",
            sid=session_id,
        )


async def get_session_stats(session_id: str) -> dict:
    d = await get_driver()
    s = get_settings()
    async with d.session(database=s.neo4j_database) as session:
        r1 = await (await session.run(
            "MATCH (n:CPGNode {session_id:$sid}) RETURN count(n) AS c", sid=session_id
        )).single()
        r2 = await (await session.run(
            "MATCH (e:CPGEdge {session_id:$sid}) RETURN count(e) AS c", sid=session_id
        )).single()
        r3 = await (await session.run(
            "MATCH (f:Finding {session_id:$sid}) RETURN count(f) AS c", sid=session_id
        )).single()
        return {
            "node_count": r1["c"] if r1 else 0,
            "edge_count": r2["c"] if r2 else 0,
            "finding_count": r3["c"] if r3 else 0,
        }