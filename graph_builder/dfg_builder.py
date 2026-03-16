"""
PRISM Data Flow Graph Builder
================================
Constructs DFG edges by tracking variable definitions and uses
across the normalized AST nodes of a single function/block.

Theory:
  A Data Flow Graph tracks how values propagate through a program.
  For security analysis, the critical question is:
    "Does user-controlled data reach a dangerous operation
     without passing through a sanitizer?"

  The DFG answers this by modeling:
    DEF(x) at line N  →  USE(x) at line M  →  DFG_FLOW edge (N→M)

  This edge is the foundation for taint analysis:
    SOURCE node (user input)
    → DFG_FLOW chain
    → SINK node (SQL execute, subprocess.run, etc.)
    = SQL injection / command injection vulnerability

Scope:
  Intra-procedural only (MVP):
    - Tracks variable definitions and uses within a single function
    - Symbol table: maps variable name → most recent definition node
    - On redefinition: DFG_KILLS edge from old def to new def
    - On use: DFG_FLOW from definition to use
    - DFG_DEPENDS: nodes whose value depends on another node's value

  Inter-procedural (Phase 2, documented here for design continuity):
    - Requires call graph (CALLS edges) from the graph builder
    - Propagates taint from CALL arguments to PARAM nodes
    - Propagates return values from RETURN nodes to CALL sites
    - Implemented by DFGInterProceduralBuilder (not in MVP)

Key patterns detected via DFG:
  1. SQL injection:
     user_input → ASSIGN query → CALL db.execute  [DFG_FLOW chain]
  2. Command injection:
     request.args → ASSIGN cmd → CALL subprocess.run
  3. Path traversal:
     GET param → ASSIGN path → CALL open(path)
  4. Insecure deserialization:
     request.body → CALL pickle.loads
  5. SSRF:
     user_url → CALL requests.get
"""

from __future__ import annotations
from dataclasses import dataclass, field
from .models import CPGNode, CPGEdge, EdgeType, NodeType


@dataclass
class SymbolEntry:
    """Tracks a variable definition in the symbol table."""
    name:        str
    def_node_id: str    # node_id of the ASSIGN or PARAM that defines it
    scope_depth: int    # nesting depth (for scope resolution)
    line:        int    # definition line (for ordering)


@dataclass
class DFGResult:
    edges:    list[CPGEdge] = field(default_factory=list)
    warnings: list[str]     = field(default_factory=list)

    def add_flow(
        self,
        src_id:     str,
        dst_id:     str,
        edge_type:  EdgeType = EdgeType.DFG_FLOW,
        props:      dict | None = None,
    ) -> None:
        eid = CPGEdge.make_id(src_id, dst_id, edge_type.value)
        self.edges.append(CPGEdge(
            edge_id    = eid,
            src_id     = src_id,
            dst_id     = dst_id,
            edge_type  = edge_type,
            properties = props or {},
        ))


class DFGBuilder:
    """
    Intra-procedural data flow graph builder.

    Operates on a list of CPGNodes sorted by source position.
    Uses a symbol table to track variable definitions and emit
    DFG_FLOW edges from definitions to their uses.
    """

    def build(self, nodes: list[CPGNode]) -> DFGResult:
        """
        Build DFG edges for nodes within a single function/scope.

        Fixes applied:
          - Argument detection uses parent_id matching (was: same-line heuristic
            which silently dropped every multi-line call).
          - Assignment name extraction handles obj.attr = … correctly
            (was: returned "self" for `self.query = x`).
          - MEMBER_ACCESS nodes propagate taint from base object.
        """
        result = DFGResult()
        if not nodes:
            return result

        ordered = sorted(nodes, key=lambda n: (n.start_line, n.start_col))
        node_ids: set[str] = {n.node_id for n in ordered}

        symbol_table: dict[str, list[SymbolEntry]] = {}
        scope_depth = 0

        for node in ordered:
            # ── Scope depth tracking ──────────────────────────────────────
            if node.node_type in (NodeType.FUNCTION, NodeType.BLOCK,
                                   NodeType.WITH, NodeType.TRY):
                scope_depth += 1

            # ── Parameters: implicit definitions at function entry ─────────
            if node.node_type == NodeType.PARAM:
                var_name = _extract_identifier(node)
                if var_name:
                    _define(symbol_table, var_name, node.node_id,
                            scope_depth, node.start_line)

            # ── Assignments ───────────────────────────────────────────────
            elif node.node_type in (NodeType.ASSIGN, NodeType.AUGMENTED_ASSIGN):
                var_name = _extract_assigned_name(node)
                if var_name:
                    prev = _lookup(symbol_table, var_name)
                    if prev:
                        result.add_flow(
                            prev.def_node_id, node.node_id,
                            EdgeType.DFG_KILLS,
                            {"variable": var_name, "reason": "redefinition"},
                        )
                    _define(symbol_table, var_name, node.node_id,
                            scope_depth, node.start_line)

            # ── Identifier uses ───────────────────────────────────────────
            elif node.node_type == NodeType.IDENTIFIER:
                var_name = node.raw_text.strip()
                if var_name and not _is_builtin(var_name):
                    definition = _lookup(symbol_table, var_name)
                    if definition:
                        result.add_flow(
                            definition.def_node_id, node.node_id,
                            EdgeType.DFG_FLOW, {"variable": var_name},
                        )

            # ── Member access: taint propagates from base object ──────────
            elif node.node_type == NodeType.MEMBER_ACCESS:
                base_name = _extract_base_of_member(node)
                if base_name and not _is_builtin(base_name):
                    definition = _lookup(symbol_table, base_name)
                    if definition:
                        result.add_flow(
                            definition.def_node_id, node.node_id,
                            EdgeType.DFG_FLOW,
                            {"variable": base_name, "relationship": "member_access"},
                        )

            # ── Call nodes: depend on child argument nodes ────────────────
            # FIX: use parent_id to find children (handles multi-line calls).
            # Fallback: nodes within the call's line range when parent_id
            # is not set (Joern-produced nodes may lack parent_id).
            elif node.node_type == NodeType.CALL:
                call_end = node.end_line if node.end_line else node.start_line
                arg_types = frozenset({
                    NodeType.IDENTIFIER, NodeType.LITERAL,
                    NodeType.CALL, NodeType.MEMBER_ACCESS,
                })
                arg_nodes = [
                    n for n in ordered
                    if n.node_id != node.node_id
                    and n.node_type in arg_types
                    and (
                        n.parent_id == node.node_id          # preferred: explicit child
                        or (
                            n.parent_id not in node_ids      # fallback: range match
                            and n.start_line >= node.start_line
                            and n.start_line <= call_end
                        )
                    )
                ]
                for arg in arg_nodes:
                    result.add_flow(
                        arg.node_id, node.node_id,
                        EdgeType.DFG_DEPENDS, {"relationship": "argument"},
                    )

            # ── Return ────────────────────────────────────────────────────
            elif node.node_type == NodeType.RETURN:
                ret_deps = [
                    n for n in ordered
                    if n.start_line == node.start_line
                    and n.start_col > node.start_col
                    and n.node_type == NodeType.IDENTIFIER
                ]
                for dep in ret_deps:
                    definition = _lookup(symbol_table, dep.raw_text.strip())
                    if definition:
                        result.add_flow(
                            definition.def_node_id, node.node_id,
                            EdgeType.DFG_FLOW,
                            {"variable": dep.raw_text.strip(),
                             "reason": "return_value"},
                        )

        return result


# ---------------------------------------------------------------------------
# Symbol table helpers
# ---------------------------------------------------------------------------

def _define(
    table:       dict[str, list[SymbolEntry]],
    name:        str,
    node_id:     str,
    scope_depth: int,
    line:        int,
) -> None:
    entry = SymbolEntry(
        name        = name,
        def_node_id = node_id,
        scope_depth = scope_depth,
        line        = line,
    )
    if name not in table:
        table[name] = []
    # Most recent definition first
    table[name].insert(0, entry)


def _lookup(
    table: dict[str, list[SymbolEntry]],
    name:  str,
) -> SymbolEntry | None:
    """Return the most recent definition of a variable."""
    entries = table.get(name)
    return entries[0] if entries else None


def _extract_identifier(node: "CPGNode") -> str:
    """Extract variable name from a PARAM node.

    Handles:
      - Simple params:            "x"      → "x"
      - Annotated params:         "x: int" → "x"
      - Java-style typed params:  "int x"  → "x" (last identifier wins)
    """
    import re
    text = node.raw_text.strip()
    # Strip type annotation suffix: "x: int" → "x"
    text = re.sub(r"\s*:.*$", "", text).strip()
    # Strip Java-style leading type: "int x" → take last word
    parts = re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*", text)
    return parts[-1] if parts else ""


def _extract_assigned_name(node: "CPGNode") -> str:
    """Extract the variable being defined by an ASSIGN node.

    Handles:
      - Simple assignment:        "query = …"       → "query"
      - Annotated assignment:     "query: str = …"  → "query"
      - Attribute assignment:     "self.query = …"  → "query"
                                  (last component; base tracked separately)
      - Augmented assignment:     "counter += …"    → "counter"

    The old code called _extract_identifier() which returned the FIRST
    identifier — so "self.query = value" returned "self", losing taint
    on self.query entirely.
    """
    import re
    text = node.raw_text.strip()

    # Take the LHS of the first = (handles "a = b = c" → "a")
    lhs = text.split("=")[0].strip()
    # Remove type annotation:  "query: str" → "query"
    lhs = re.sub(r"\s*:.*$", "", lhs).strip()
    # Take the last dotted component: "self.query" → "query"
    parts = re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*", lhs)
    return parts[-1] if parts else ""


def _extract_base_of_member(node: "CPGNode") -> str:
    """Extract the object name from a MEMBER_ACCESS node.

    For "request.args" returns "request".
    For "self.db.execute" returns "self" (the root object).
    Returns "" if no base can be determined.
    """
    import re
    text = node.raw_text.strip()
    parts = re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*", text)
    return parts[0] if parts else ""


# Common builtins that don't have meaningful definitions in the CPG
_PYTHON_BUILTINS = frozenset([
    "print", "len", "range", "int", "str", "list", "dict", "set", "tuple",
    "open", "input", "type", "isinstance", "hasattr", "getattr", "setattr",
    "True", "False", "None", "self", "cls",
    "Exception", "ValueError", "TypeError", "KeyError", "AttributeError",
])
_JS_BUILTINS = frozenset([
    "console", "window", "document", "undefined", "null", "true", "false",
    "parseInt", "parseFloat", "JSON", "Object", "Array", "String", "Number",
    "Promise", "async", "await", "this",
])
_ALL_BUILTINS = _PYTHON_BUILTINS | _JS_BUILTINS


def _is_builtin(name: str) -> bool:
    return name in _ALL_BUILTINS or len(name) == 1  # single chars: i, j, x, etc.