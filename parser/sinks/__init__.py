"""
Security Sink / Source / Sanitizer Registries
====================================================
Each language module exposes:

  <LANG>_SINKS       : dict[str, tuple[str, float, tuple[str, ...]]]
  <LANG>_SOURCES     : same
  <LANG>_SANITIZERS  : same
  <LANG>_SINK_REGISTRY : {"sinks": ..., "sources": ..., "sanitizers": ...}

The SecurityAnnotator uses SINK_REGISTRY exclusively.
All per-language registries are slices of the same underlying dicts —
no data is duplicated.
"""

from .python_sinks     import PYTHON_SINKS,  PYTHON_SOURCES,  PYTHON_SANITIZERS,  PYTHON_SINK_REGISTRY
from .javascript_sinks import JS_SINKS,       JS_SOURCES,      JS_SANITIZERS,      JS_SINK_REGISTRY
from .java_sinks       import JAVA_SINKS,     JAVA_SOURCES,    JAVA_SANITIZERS,    JAVA_SINK_REGISTRY
from .rust_sinks       import RUST_SINKS,     RUST_SOURCES,    RUST_SANITIZERS,    RUST_SINK_REGISTRY
from .go_sinks         import GO_SINKS,       GO_SOURCES,      GO_SANITIZERS,      GO_SINK_REGISTRY
from .iac_sinks        import IAC_SINKS,      IAC_SOURCES,     IAC_SANITIZERS,     IAC_SINK_REGISTRY

from ..models import Language

# Master registry indexed by Language enum.
# Each value is a per-language registry dict with "sinks", "sources",
# "sanitizers" keys — identical structure to the per-language *_SINK_REGISTRY
# exports so callers work with either without code changes.
SINK_REGISTRY: dict[Language, dict] = {
    Language.PYTHON:        PYTHON_SINK_REGISTRY,
    Language.JAVA:          JAVA_SINK_REGISTRY,
    Language.JAVASCRIPT:    JS_SINK_REGISTRY,
    Language.TSX:           JS_SINK_REGISTRY,    # TSX shares JS sinks
    Language.TYPESCRIPT:    JS_SINK_REGISTRY,    # TS  shares JS sinks
    Language.RUST:          RUST_SINK_REGISTRY,
    Language.GO:            GO_SINK_REGISTRY,
    Language.C:             {"sinks": {}, "sources": {}, "sanitizers": {}},
    Language.CPP:           {"sinks": {}, "sources": {}, "sanitizers": {}},
    Language.TERRAFORM_HCL: IAC_SINK_REGISTRY,
    Language.YAML:          IAC_SINK_REGISTRY,
}

__all__ = [
    # Master registry (used by SecurityAnnotator)
    "SINK_REGISTRY",
    # Per-language registries (used by fine-tuning scripts, tests, plugins)
    "PYTHON_SINK_REGISTRY",
    "JAVA_SINK_REGISTRY",
    "JS_SINK_REGISTRY",
    "RUST_SINK_REGISTRY",
    "GO_SINK_REGISTRY",
    "IAC_SINK_REGISTRY",
    # Raw dicts (kept for backward compatibility)
    "PYTHON_SINKS",   "PYTHON_SOURCES",   "PYTHON_SANITIZERS",
    "JS_SINKS",       "JS_SOURCES",       "JS_SANITIZERS",
    "JAVA_SINKS",     "JAVA_SOURCES",     "JAVA_SANITIZERS",
    "RUST_SINKS",     "RUST_SOURCES",     "RUST_SANITIZERS",
    "GO_SINKS",       "GO_SOURCES",       "GO_SANITIZERS",
    "IAC_SINKS",      "IAC_SOURCES",      "IAC_SANITIZERS",
]