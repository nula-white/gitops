"""
Applies SOURCE / SINK / SANITIZER labels to normalized AST nodes by consulting the language-specific sink registries.

Two-pass approach:
  Pass 1 — exact name lookup (fast, high confidence)
  Pass 2 — substring / suffix matching for method calls
            (e.g. "conn.execute" matches "execute")

Labels are attached during normalization and are used by:
  - The DFG builder (to trace tainted data flows)
  - The GraphCodeBERT input builder (security_label_sequence)
  - The vulnerability risk scorer
"""

from __future__ import annotations

import logging
from typing import Any

from .models import Language, NodeType, SecurityLabel, NormalizedNode
from .sinks  import SINK_REGISTRY

logger = logging.getLogger(__name__)


class SecurityAnnotator:
    """
    Stateless annotator; call annotate(node_type, name, language)
    to receive (SecurityLabel, confidence, cwe_hints).
    """

    def annotate(
        self,
        node_type: NodeType,
        name: str | None,
        language: Language,
        raw_text: str = "",
    ) -> tuple[SecurityLabel, float, tuple[str, ...]]:
        """
        Return the best security label for a given node.

        Args:
            node_type: normalized node type
            name:      resolved name (function/variable name, attribute chain)
            language:  source language
            raw_text:  raw source snippet for substring matching

        Returns:
            (SecurityLabel, confidence, cwe_hints)
        """
        # Only annotate nodes that can carry security meaning
        if node_type not in _ANNOTATABLE_TYPES:
            return SecurityLabel.NONE, 0.0, ()

        if not name:
            return SecurityLabel.NONE, 0.0, ()

        registry = SINK_REGISTRY.get(language, SINK_REGISTRY.get(Language.UNKNOWN, {}))
        sinks      = registry.get("sinks",      {})
        sources    = registry.get("sources",    {})
        sanitizers = registry.get("sanitizers", {})

        # --- Pass 1: exact lookup ---
        for lookup_name in _name_variants(name):
            if lookup_name in sinks:
                lbl, conf, cwes = sinks[lookup_name]
                return SecurityLabel(lbl), conf, cwes
            if lookup_name in sources:
                lbl, conf, cwes = sources[lookup_name]
                return SecurityLabel(lbl), conf, cwes
            if lookup_name in sanitizers:
                lbl, conf, cwes = sanitizers[lookup_name]
                return SecurityLabel(lbl), conf, cwes

        # --- Pass 2: suffix matching (handles method calls like conn.execute) ---
        name_lower = name.lower()
        for registry_dict, label_str in [
            (sinks,      "SINK"),
            (sources,    "SOURCE"),
            (sanitizers, "SANITIZER"),
        ]:
            for key, (lbl, conf, cwes) in registry_dict.items():
                key_lower = key.lower()
                if name_lower.endswith(key_lower) or name_lower == key_lower:
                    # Penalise partial matches slightly
                    adjusted_conf = conf * (1.0 if name_lower == key_lower else 0.75)
                    return SecurityLabel(lbl), adjusted_conf, cwes

        # --- Pass 3: keyword heuristics for names we've never seen ---
        heuristic = _heuristic_annotation(name, raw_text)
        if heuristic:
            return heuristic

        return SecurityLabel.NONE, 0.0, ()

    def build_summary_from_nodes(
        self,
        nodes: list[NormalizedNode],
    ) -> dict[str, Any]:
        """Build a SecurityAnnotationSummary-compatible dict from a node list."""
        from .models import SecurityAnnotationSummary
        summary = SecurityAnnotationSummary()
        cwe_map: dict[str, list[str]] = {}

        for node in nodes:
            nid = node.node_id
            match node.security_label:
                case SecurityLabel.SOURCE:
                    summary.sources.append(nid)
                case SecurityLabel.SINK:
                    summary.sinks.append(nid)
                case SecurityLabel.SANITIZER:
                    summary.sanitizers.append(nid)
                case SecurityLabel.PROPAGATOR:
                    summary.propagators.append(nid)
                case SecurityLabel.SENSITIVE:
                    summary.sensitive_nodes.append(nid)

            for cwe in node.cwe_hints:
                cwe_map.setdefault(cwe, []).append(nid)

        summary.cwe_hints = cwe_map
        return summary


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ANNOTATABLE_TYPES: frozenset[NodeType] = frozenset({
    NodeType.CALL,
    NodeType.IDENTIFIER,
    NodeType.ATTRIBUTE,
    NodeType.ASSIGN,
    NodeType.CONFIG_KEY,
    NodeType.RESOURCE,
})

_SENSITIVE_NAME_KEYWORDS: tuple[str, ...] = (
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "auth_key", "private_key", "credential", "access_key", "session_key",
)

_SOURCE_KEYWORDS: tuple[str, ...] = (
    "input", "request", "query", "param", "argv", "stdin",
    "form", "body", "header", "cookie", "env",
)

_SINK_KEYWORDS: tuple[str, ...] = (
    "execute", "exec", "eval", "system", "shell", "spawn",
    "render", "write", "send", "query", "deserializ",
)

_SANITIZER_KEYWORDS: tuple[str, ...] = (
    "sanitize", "sanitise", "validate", "escape", "encode",
    "clean", "strip", "filter", "purify",
)


def _name_variants(name: str) -> list[str]:
    """Return lookup variants for a name: full, last segment, lower-cased."""
    variants = [name, name.lower()]
    # "os.system" → also check "system"
    if "." in name:
        variants.append(name.split(".")[-1])
        variants.append(name.split(".")[-1].lower())
    return list(dict.fromkeys(variants))  # deduplicate preserving order


def _heuristic_annotation(
    name: str,
    raw_text: str,
) -> tuple[SecurityLabel, float, tuple[str, ...]] | None:
    """
    Keyword-based fallback annotation for unknown names.
    Returns None if no heuristic matches.
    """
    name_lower  = name.lower()
    text_lower  = raw_text.lower()

    for kw in _SENSITIVE_NAME_KEYWORDS:
        if kw in name_lower or kw in text_lower:
            return SecurityLabel.SENSITIVE, 0.55, ("CWE-798",)

    for kw in _SANITIZER_KEYWORDS:
        if name_lower.startswith(kw) or name_lower.endswith(kw):
            return SecurityLabel.SANITIZER, 0.45, ()

    for kw in _SINK_KEYWORDS:
        if name_lower.endswith(kw):
            return SecurityLabel.SINK, 0.40, ()

    for kw in _SOURCE_KEYWORDS:
        if name_lower.startswith(kw) or name_lower.endswith(kw):
            return SecurityLabel.SOURCE, 0.35, ()

    return None