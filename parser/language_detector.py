"""
Determines the programming language of a source file using:
  1. File extension (fast, primary)
  2. Shebang line (for scripts without extension)
  3. Content heuristics (fallback)

Returns a (Language, confidence: float) pair so callers can decide
whether to attempt parsing or skip uncertain files.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import NamedTuple

from .models import Language, ParserBackend


# Backend routing table

# Maps each Language to its PRIMARY backend and an optional FALLBACK backend.
# CodeQL is primary for languages it supports natively.
# Tree-sitter is primary for the rest.

LANGUAGE_BACKEND_MAP: dict[Language, tuple[ParserBackend, ParserBackend | None]] = {
    Language.PYTHON:        (ParserBackend.CODEQL,       ParserBackend.TREE_SITTER),
    Language.JAVA:          (ParserBackend.CODEQL,       ParserBackend.TREE_SITTER),
    Language.JAVASCRIPT:    (ParserBackend.CODEQL,       ParserBackend.TREE_SITTER),
    Language.TYPESCRIPT:    (ParserBackend.CODEQL,       ParserBackend.TREE_SITTER),
    Language.C:             (ParserBackend.CODEQL,       ParserBackend.TREE_SITTER),
    Language.CPP:           (ParserBackend.CODEQL,       ParserBackend.TREE_SITTER),
    Language.GO:            (ParserBackend.CODEQL,       ParserBackend.TREE_SITTER),
    # Tree-sitter primary — CodeQL has no support
    Language.RUST:          (ParserBackend.TREE_SITTER,  None),
    Language.TSX:           (ParserBackend.TREE_SITTER,  ParserBackend.CODEQL),   # CodeQL handles TS/JS, close enough
    Language.TERRAFORM_HCL: (ParserBackend.TREE_SITTER,  None),
    Language.YAML:          (ParserBackend.TREE_SITTER,  None),
    Language.UNKNOWN:       (ParserBackend.FALLBACK,     None),
}

# CodeQL-supported languages (used by CodeQL integration layer)
CODEQL_SUPPORTED_LANGUAGES: frozenset[Language] = frozenset({
    Language.PYTHON,
    Language.JAVA,
    Language.JAVASCRIPT,
    Language.TYPESCRIPT,
    Language.C,
    Language.CPP,
    Language.GO,
})

# Tree-sitter grammar names (as required by tree-sitter-languages package)
TREE_SITTER_GRAMMAR_MAP: dict[Language, str] = {
    Language.PYTHON:        "python",
    Language.JAVA:          "java",
    Language.JAVASCRIPT:    "javascript",
    Language.TYPESCRIPT:    "typescript",
    Language.TSX:           "tsx",
    Language.C:             "c",
    Language.CPP:           "cpp",
    Language.RUST:          "rust",
    Language.GO:            "go",
    Language.TERRAFORM_HCL: "hcl",
    Language.YAML:          "yaml",
}


# Extension map

_EXTENSION_MAP: dict[str, Language] = {
    # Python
    ".py": Language.PYTHON, ".pyw": Language.PYTHON, ".pyi": Language.PYTHON,
    # Java
    ".java": Language.JAVA,
    # JavaScript
    ".js": Language.JAVASCRIPT, ".mjs": Language.JAVASCRIPT, ".cjs": Language.JAVASCRIPT,
    # TypeScript
    ".ts": Language.TYPESCRIPT,
    # TSX
    ".tsx": Language.TSX, ".jsx": Language.TSX,
    # C / C++
    ".c": Language.C, ".h": Language.C,
    ".cpp": Language.CPP, ".cc": Language.CPP, ".cxx": Language.CPP,
    ".hpp": Language.CPP, ".hxx": Language.CPP, ".hh": Language.CPP,
    # Rust
    ".rs": Language.RUST,
    # Go
    ".go": Language.GO,
    # Terraform / HCL
    ".tf": Language.TERRAFORM_HCL, ".tfvars": Language.TERRAFORM_HCL,
    ".hcl": Language.TERRAFORM_HCL,
    # YAML
    ".yaml": Language.YAML, ".yml": Language.YAML,
}

# Shebang patterns → language
_SHEBANG_PATTERNS: list[tuple[re.Pattern[str], Language]] = [
    (re.compile(r"python[23]?"),        Language.PYTHON),
    (re.compile(r"\bnode\b"),           Language.JAVASCRIPT),
    (re.compile(r"\bts-node\b"),        Language.TYPESCRIPT),
    (re.compile(r"\bbash\b|\bsh\b"),    Language.UNKNOWN),  # shell scripts — not analyzed
    (re.compile(r"\bperl\b"),           Language.UNKNOWN),  
    (re.compile(r"\benv\s+python[23]?"), Language.PYTHON),   # #!/usr/bin/env python3
]
# Content heuristics: (pattern, language, confidence_boost)
_CONTENT_HEURISTICS: list[tuple[re.Pattern[str], Language, float]] = [
    # Python
    (re.compile(r"^\s*def\s+\w+\s*\(", re.MULTILINE),      Language.PYTHON, 0.4),
    (re.compile(r"^\s*import\s+\w+", re.MULTILINE),        Language.PYTHON, 0.2),
    (re.compile(r"^\s*class\s+\w+\s*:", re.MULTILINE),     Language.PYTHON, 0.3),

    # Java
    (re.compile(r"^\s*public\s+class\s+\w+", re.MULTILINE), Language.JAVA, 0.6),
    (re.compile(r"^\s*package\s+[\w\.]+;", re.MULTILINE),  Language.JAVA, 0.5),
    (re.compile(r"^\s*import\s+[\w\.]+;", re.MULTILINE),   Language.JAVA, 0.2),

    # Rust
    (re.compile(r"^\s*fn\s+\w+\s*\(", re.MULTILINE),       Language.RUST, 0.5),
    (re.compile(r"^\s*use\s+std::", re.MULTILINE),         Language.RUST, 0.6),

    # Go
    (re.compile(r"^\s*func\s+\w+\s*\(", re.MULTILINE),     Language.GO, 0.5),
    (re.compile(r"^\s*package\s+\w+", re.MULTILINE),       Language.GO, 0.4),
    (re.compile(r"^\s*import\s+\(", re.MULTILINE),         Language.GO, 0.3),

    # C / C++
    (re.compile(r"^\s*#include\s+<\w+>", re.MULTILINE), Language.C, 0.5),
    (re.compile(r"^\s*int\s+main\s*\(", re.MULTILINE),  Language.C, 0.6),

    # TypeScript / JavaScript
    (re.compile(r"^\s*import\s+.*\s+from\s+['\"].*['\"];", re.MULTILINE), Language.JAVASCRIPT, 0.3),
    (re.compile(r"^\s*const\s+\w+\s*=\s*require\(", re.MULTILINE),           Language.JAVASCRIPT, 0.4),
    (re.compile(r"^\s*function\s+\w+\s*\(", re.MULTILINE),                   Language.JAVASCRIPT, 0.3),
    (re.compile(r"^\s*export\s+(default|const|function)\s+", re.MULTILINE),  Language.TYPESCRIPT, 0.4),

    # Terraform HCL
    (re.compile(r'^\s*resource\s+"[^"]+"\s+"[^"]+"\s*\{', re.MULTILINE),    Language.TERRAFORM_HCL, 0.8),
    (re.compile(r'^\s*provider\s+"[^"]+"\s*\{', re.MULTILINE),             Language.TERRAFORM_HCL, 0.8),
    (re.compile(r'^\s*variable\s+"[^"]+"\s*\{', re.MULTILINE),             Language.TERRAFORM_HCL, 0.6),

    # YAML
    (re.compile(r"^---\s*$", re.MULTILINE),                                Language.YAML, 0.3),
    (re.compile(r"^\w[\w\s]*:\s*$", re.MULTILINE),                          Language.YAML, 0.2),
]


class DetectionResult(NamedTuple):
    language:   Language
    confidence: float          # 0.0–1.0
    method:     str            # "extension" | "shebang" | "heuristic" | "fallback"
    primary_backend:  ParserBackend
    fallback_backend: ParserBackend | None


class LanguageDetector:
    """
    Stateless language detector.
    Call detect(path, content) to get a DetectionResult.
    """

    def detect(self, path: str | Path, content: str | None = None) -> DetectionResult:
        """
        Detect language from file path and (optionally) file content.

        Args:
            path:    path to source file (used for extension lookup)
            content: source text (used for shebang / heuristic detection)

        Returns:
            DetectionResult with language, confidence, method used, and backends.
        """
        file_path = Path(path)
        suffix = file_path.suffix.lower()

        # 1. Extension lookup (highest priority, highest confidence)
        if suffix in _EXTENSION_MAP:
            lang = _EXTENSION_MAP[suffix]
            primary, fallback = LANGUAGE_BACKEND_MAP[lang]
            return DetectionResult(lang, 1.0, "extension", primary, fallback)

        # Need content for remaining methods
        if content is None:
            primary, fallback = LANGUAGE_BACKEND_MAP[Language.UNKNOWN]
            return DetectionResult(Language.UNKNOWN, 0.0, "fallback", primary, fallback)

        # 2. Shebang line detection
        first_line = content.split("\n", 1)[0]
        if first_line.startswith("#!"):
            for pattern, lang in _SHEBANG_PATTERNS:
                if pattern.search(first_line):
                    primary, fallback = LANGUAGE_BACKEND_MAP[lang]
                    return DetectionResult(lang, 0.85, "shebang", primary, fallback)

        # 3. Content heuristics (score-based)
        scores: dict[Language, float] = {}
        for pattern, lang, boost in _CONTENT_HEURISTICS:
            matches = len(pattern.findall(content))
            if matches:
                scores[lang] = scores.get(lang, 0.0) + boost * min(matches, 3)

        if scores:
            best_lang = max(scores, key=lambda l: scores[l])
            confidence = min(scores[best_lang], 1.0)
            primary, fallback = LANGUAGE_BACKEND_MAP[best_lang]
            return DetectionResult(best_lang, confidence, "heuristic", primary, fallback)

        # 4. Fallback
        primary, fallback = LANGUAGE_BACKEND_MAP[Language.UNKNOWN]
        return DetectionResult(Language.UNKNOWN, 0.0, "fallback", primary, fallback)

    def detect_from_content(self, content: str, hint_path: str = "unknown") -> DetectionResult:
        """Convenience wrapper when we only have content."""
        return self.detect(hint_path, content)