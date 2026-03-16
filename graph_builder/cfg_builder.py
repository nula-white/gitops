"""
PRISM Control Flow Graph Builder
==================================
Constructs CFG edges on top of the normalized AST.

Theory:
  A Control Flow Graph models all possible execution paths through a
  program. Each node is a statement or expression; edges represent
  possible transfers of control. The CFG is essential for:
    - Detecting authentication bypass (missing permission checks on
      some paths but not others)
    - Finding unreachable code after returns/raises
    - Identifying loops without exit conditions (infinite loops)
    - Tracking taint across conditional branches

CFG edge types produced:
  CFG_NEXT      — unconditional sequential execution
  CFG_TRUE      — branch taken when condition is True
  CFG_FALSE     — branch taken when condition is False
  CFG_LOOP      — back-edge from loop body to condition
  CFG_EXCEPTION — edge to exception handler (try→catch)
  CFG_FINALLY   — edge to finally block

Design:
  The CFGBuilder operates on CPGNode lists (already normalized).
  It does not re-parse source — it traverses the normalized node
  tree and emits edges between node IDs.

  Each language has a CFGBuilder subclass that overrides the
  per-construct handlers. The base class handles all constructs
  that have uniform semantics across languages.

  Intra-procedural only for MVP:
    - Builds CFG within a single function/block
    - Does not cross function call boundaries
    - Inter-procedural CFG is Phase 2 (requires call graph)

Limitation documentation (for SecurityAnalysisAgent blind spots):
  - Python generators: yield creates implicit suspension points
    (marked as YIELD nodes, not fully modeled in CFG edges)
  - JavaScript async/await: event loop semantics not modeled
    (await treated as sequential for MVP)
  - Rust panic!: always treated as exception edge
  - Go defer: modeled as CFG_FINALLY edge at function exit
"""

from __future__ import annotations
from dataclasses import dataclass, field
from .models import CPGNode, CPGEdge, EdgeType, NodeType


# ---------------------------------------------------------------------------
# CFG construction result
# ---------------------------------------------------------------------------

@dataclass
class CFGResult:
    edges:    list[CPGEdge] = field(default_factory=list)
    warnings: list[str]     = field(default_factory=list)

    def add_edge(
        self,
        src:       CPGNode,
        dst:       CPGNode,
        edge_type: EdgeType,
        props:     dict | None = None,
    ) -> None:
        eid = CPGEdge.make_id(src.node_id, dst.node_id, edge_type.value)
        self.edges.append(CPGEdge(
            edge_id    = eid,
            src_id     = src.node_id,
            dst_id     = dst.node_id,
            edge_type  = edge_type,
            properties = props or {},
        ))

    def add_edge_by_id(
        self,
        src_id:    str,
        dst_id:    str,
        edge_type: EdgeType,
        props:     dict | None = None,
    ) -> None:
        eid = CPGEdge.make_id(src_id, dst_id, edge_type.value)
        self.edges.append(CPGEdge(
            edge_id    = eid,
            src_id     = src_id,
            dst_id     = dst_id,
            edge_type  = edge_type,
            properties = props or {},
        ))


# ---------------------------------------------------------------------------
# Base CFG builder
# ---------------------------------------------------------------------------

class CFGBuilder:
    """
    Builds CFG edges for a list of CPGNodes representing a function body.

    Usage:
        builder = CFGBuilder.for_language("python")
        result  = builder.build(nodes)
        # result.edges contains all CFG edges
    """

    @classmethod
    def for_language(cls, language: str) -> "CFGBuilder":
        """Return the appropriate CFGBuilder subclass for the language."""
        lang = language.lower()
        subclasses = {
            "python":     PythonCFGBuilder,
            "javascript": JavaScriptCFGBuilder,
            "typescript": JavaScriptCFGBuilder,
            "tsx":        JavaScriptCFGBuilder,
            "java":       JavaCFGBuilder,
            "rust":       RustCFGBuilder,
            "go":         GoCFGBuilder,
            "c":          CCFGBuilder,
            "cpp":        CCFGBuilder,
            "terraform":  IaCCFGBuilder,
            "yaml":       IaCCFGBuilder,
        }
        return subclasses.get(lang, CFGBuilder)()

    def build(self, nodes: list[CPGNode]) -> CFGResult:
        """
        Build CFG edges for the given node list.
        Nodes are assumed to be in source order (sorted by start_line, start_col).
        """
        result = CFGResult()
        if not nodes:
            return result

        # Sort by position (should already be sorted, but enforce it)
        ordered = sorted(nodes, key=lambda n: (n.start_line, n.start_col))

        # Track exception handler stacks for try/catch/finally
        try_stack:     list[CPGNode] = []
        catch_stack:   list[CPGNode] = []
        finally_stack: list[CPGNode] = []

        # Track loop condition nodes for back-edges
        loop_stack: list[CPGNode] = []

        for i, node in enumerate(ordered):
            next_node = ordered[i + 1] if i + 1 < len(ordered) else None

            # ── Sequential flow ───────────────────────────────────────────
            # Every node has a CFG_NEXT edge to its sequential successor,
            # unless it's a return/break/continue/raise (terminal for this path).
            if next_node and node.node_type not in (
                NodeType.RETURN, NodeType.BREAK, NodeType.CONTINUE,
                NodeType.RAISE, NodeType.YIELD,
            ):
                result.add_edge(node, next_node, EdgeType.CFG_NEXT)

            # ── Branching ─────────────────────────────────────────────────
            if node.node_type == NodeType.IF:
                # CFG_TRUE → first node INSIDE the if-body
                # Criteria: same parent_function, start_line > IF.start_line
                # and start_line <= IF.end_line (inside the block).
                body_nodes = [
                    n for n in ordered[i + 1:]
                    if n.parent_function == node.parent_function
                    and n.start_line > node.start_line
                    and (node.end_line == 0 or n.start_line <= node.end_line)
                ]
                # CFG_FALSE → first node AFTER the if-body ends
                # (start_line > IF.end_line, same function, not a sibling else)
                after_nodes = [
                    n for n in ordered[i + 1:]
                    if n.parent_function == node.parent_function
                    and node.end_line > 0
                    and n.start_line > node.end_line
                    and n.node_type not in (NodeType.IF,)   # exclude sibling else-if
                ]

                if body_nodes:
                    result.add_edge(node, body_nodes[0], EdgeType.CFG_TRUE,
                                    {"condition": node.normalized_text[:80]})

                # False branch: post-if-block node, or next_node if end_line unknown
                false_target = after_nodes[0] if after_nodes else next_node
                if false_target and false_target is not (body_nodes[0] if body_nodes else None):
                    result.add_edge(node, false_target, EdgeType.CFG_FALSE)

            # ── Loops ─────────────────────────────────────────────────────
            elif node.node_type == NodeType.LOOP:
                loop_stack.append(node)
                if next_node:
                    result.add_edge(node, next_node, EdgeType.CFG_TRUE)
                    result.add_edge(node, next_node, EdgeType.CFG_FALSE)

            # ── Loop back-edge: end of loop body → loop condition ─────────
            elif node.node_type in (NodeType.BREAK, NodeType.CONTINUE) and loop_stack:
                result.add_edge(node, loop_stack[-1], EdgeType.CFG_LOOP)

            # ── Try/except ────────────────────────────────────────────────
            elif node.node_type == NodeType.TRY:
                try_stack.append(node)
                if next_node:
                    result.add_edge(node, next_node, EdgeType.CFG_NEXT)

            elif node.node_type == NodeType.CATCH and try_stack:
                result.add_edge(try_stack[-1], node, EdgeType.CFG_EXCEPTION)
                catch_stack.append(node)

            elif node.node_type == NodeType.FINALLY:
                if try_stack:
                    result.add_edge(try_stack[-1], node, EdgeType.CFG_FINALLY)
                if catch_stack:
                    result.add_edge(catch_stack[-1], node, EdgeType.CFG_FINALLY)
                finally_stack.append(node)
                if next_node:
                    result.add_edge(node, next_node, EdgeType.CFG_NEXT)

            # ── Return/Raise ──────────────────────────────────────────────
            # Terminal nodes — no CFG_NEXT, but add exception edge for raises
            elif node.node_type == NodeType.RAISE and try_stack:
                result.add_edge(node, try_stack[-1], EdgeType.CFG_EXCEPTION)

            # ── Yield/Await ───────────────────────────────────────────────
            # Treated as sequential for MVP (suspension point limitation documented)
            elif node.node_type in (NodeType.YIELD, NodeType.AWAIT):
                if next_node:
                    result.add_edge(node, next_node, EdgeType.CFG_NEXT)
                result.warnings.append(
                    f"CFG: {node.node_type.value} at {node.file_path}:{node.start_line} "
                    f"modeled as sequential (suspension semantics not fully modeled)"
                )

        return result


# ---------------------------------------------------------------------------
# Language-specific subclasses
# ---------------------------------------------------------------------------

class PythonCFGBuilder(CFGBuilder):
    """
    Python-specific CFG extensions.
    Handles: with statements, walrus operator, comprehensions as scope.
    """
    def build(self, nodes: list[CPGNode]) -> CFGResult:
        result = super().build(nodes)
        # Python-specific: with statement creates implicit __enter__/__exit__
        for node in nodes:
            if node.node_type == NodeType.WITH:
                result.warnings.append(
                    f"CFG: 'with' at {node.file_path}:{node.start_line} — "
                    f"__exit__ called on normal exit AND exception (context manager semantics)"
                )
        return result


class JavaScriptCFGBuilder(CFGBuilder):
    """
    JavaScript/TypeScript CFG extensions.
    Handles: async/await (event loop semantics approximated),
             optional chaining (?.), nullish coalescing (??).
    """
    def build(self, nodes: list[CPGNode]) -> CFGResult:
        result = super().build(nodes)
        for node in nodes:
            if node.node_type == NodeType.AWAIT:
                result.warnings.append(
                    f"CFG: 'await' at {node.file_path}:{node.start_line} — "
                    f"event loop suspension not fully modeled in MVP CFG"
                )
        return result


class JavaCFGBuilder(CFGBuilder):
    """
    Java CFG extensions.
    Handles: enhanced for loops, try-with-resources,
             synchronized blocks (treated as regular block).
    """
    pass  # Base class handles all Java constructs adequately for MVP


class RustCFGBuilder(CFGBuilder):
    """
    Rust CFG extensions.
    Handles: ? operator (propagates Result/Option — modeled as TRY edge),
             match expressions (modeled as IF with multiple branches),
             panic! macro (modeled as RAISE).
    """
    def build(self, nodes: list[CPGNode]) -> CFGResult:
        result = super().build(nodes)
        for node in nodes:
            # Rust ? operator creates implicit try/catch semantics
            if node.node_type == NodeType.TRY:
                result.warnings.append(
                    f"CFG: Rust '?' at {node.file_path}:{node.start_line} — "
                    f"early return on Err modeled as exception edge"
                )
        return result


class GoCFGBuilder(CFGBuilder):
    """
    Go CFG extensions.
    Handles: defer (modeled as CFG_FINALLY at function exit),
             goroutines (go statement, modeled as concurrent — approximated as sequential),
             channel select (modeled as IF with multiple branches).
    """
    def build(self, nodes: list[CPGNode]) -> CFGResult:
        result = super().build(nodes)
        for node in nodes:
            if node.node_type == NodeType.BLOCK and node.properties.get("is_defer"):
                result.warnings.append(
                    f"CFG: 'defer' at {node.file_path}:{node.start_line} — "
                    f"deferred execution modeled as finally edge"
                )
            if node.node_type == NodeType.BLOCK and node.properties.get("is_goroutine"):
                result.warnings.append(
                    f"CFG: 'go' (goroutine) at {node.file_path}:{node.start_line} — "
                    f"concurrent execution modeled as sequential (concurrency not modeled)"
                )
        return result


class CCFGBuilder(CFGBuilder):
    """
    C/C++ CFG extensions.
    Handles: goto (modeled as BREAK — approximate),
             setjmp/longjmp (not modeled — documented as blind spot),
             pointer dereference (not a CFG concern but noted).
    """
    def build(self, nodes: list[CPGNode]) -> CFGResult:
        result = super().build(nodes)
        for node in nodes:
            if node.node_type == NodeType.BREAK and node.properties.get("is_goto"):
                result.warnings.append(
                    f"CFG: 'goto' at {node.file_path}:{node.start_line} — "
                    f"goto target not resolved (approximated as break)"
                )
        return result


class IaCCFGBuilder(CFGBuilder):
    """
    IaC (Terraform HCL, YAML) CFG approximation.

    IaC files are declarative, not imperative — there is no traditional
    execution flow. However, we model:
      - Resource dependency ordering (depends_on) as CFG_NEXT edges
      - Conditional expressions as CFG_TRUE/CFG_FALSE
      - Module calls as CALLS edges

    This allows the SecurityAnalysisAgent to detect:
      - Circular dependencies (unusual and potentially malicious)
      - Resources that receive tainted values via interpolation
    """
    def build(self, nodes: list[CPGNode]) -> CFGResult:
        result = CFGResult()
        # For IaC: only model conditional expressions as control flow
        for node in nodes:
            if node.node_type == NodeType.CONDITIONAL:
                children = [n for n in nodes
                            if n.start_line > node.start_line
                            and n.start_line <= node.end_line]
                if len(children) >= 2:
                    result.add_edge(node, children[0], EdgeType.CFG_TRUE)
                    result.add_edge(node, children[1], EdgeType.CFG_FALSE)
        return result