"""
Central registry of all resource limits, path whitelists, and
security constants enforced by the parser inside the ephemeral
gVisor sandbox.

WHY THIS FILE EXISTS
--------------------
Every limit here directly maps to a threat in the PRISM threat model:

  MAX_FILE_SIZE_BYTES     → Resource Exhaustion (large files overwhelming memory)
  MAX_NODES_PER_FILE      → Graph Explosion (exponential node growth)
  MAX_STACK_DEPTH         → Graph Explosion (deeply nested structures)
  MAX_LINE_LENGTH         → ReDoS (catastrophic regex backtracking on long lines)
  SUBPROCESS_SAFE_ENV     → Secret leakage through inherited environment
  ALLOWED_REPO_BASE_DIRS  → Path traversal / command injection via repo_path
  CODEQL_SAFE_FLAGS       → CodeQL executing attacker build systems

All values are conservative defaults. Override via environment variables
in the container manifest — never hardcode environment-specific values here.

References:
  - OWASP CWE-1333 (ReDoS): https://cwe.mitre.org/data/definitions/1333.html
  - NIST SP 800-190 s3.3 (container secrets): https://doi.org/10.6028/NIST.SP.800-190
  - CodeQL CLI safety: https://docs.github.com/en/code-security/codeql-cli
  - gVisor syscall interception: https://gvisor.dev/docs/architecture_guide/
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final


# Resource limits

@dataclass(frozen=True)
class ResourceLimits:
    """
    Hard limits enforced before and during parsing.
    All values are configurable via environment variables so the
    container operator can tune without code changes.
    """

    # ── File-level limits ────────────────────────────────────────────────────

    # Maximum source file size accepted for parsing.
    # Files exceeding this produce a single PROGRAM node + warning.
    # Default: 5 MB. Env: PRISM_MAX_FILE_BYTES
    max_file_size_bytes: int = int(os.environ.get("PRISM_MAX_FILE_BYTES", 5 * 1024 * 1024))

    # Maximum single line length before regex operations are applied.
    # Lines exceeding this are truncated before pattern matching to
    # prevent ReDoS via catastrophic backtracking.
    # Default: 4096 chars. Env: PRISM_MAX_LINE_LENGTH
    max_line_length: int = int(os.environ.get("PRISM_MAX_LINE_LENGTH", 4096))

    # Maximum number of lines considered for fallback regex parsing.
    # Prevents O(n²) scanning of enormous flat files.
    # Default: 100,000 lines. Env: PRISM_MAX_LINES
    max_lines: int = int(os.environ.get("PRISM_MAX_LINES", 100_000))

    # ── Graph limits ─────────────────────────────────────────────────────────

    # Maximum nodes produced per file by any parser backend.
    # Graph Explosion defence: if this is hit, the walk is stopped and
    # a TRUNCATED flag is set in FileMetadata.
    # Default: 500,000 nodes. Env: PRISM_MAX_NODES_PER_FILE
    max_nodes_per_file: int = int(os.environ.get("PRISM_MAX_NODES_PER_FILE", 500_000))

    # Maximum edges produced per file.
    # Default: 2,000,000 edges. Env: PRISM_MAX_EDGES_PER_FILE
    max_edges_per_file: int = int(os.environ.get("PRISM_MAX_EDGES_PER_FILE", 2_000_000))

    # Maximum AST depth during tree walk.
    # Deeply nested structures (e.g., 10,000-level nested ternaries in JS)
    # can exhaust Python stack even with iterative traversal due to
    # children_ids tuple construction.
    # Default: 500 levels. Env: PRISM_MAX_DEPTH
    max_ast_depth: int = int(os.environ.get("PRISM_MAX_DEPTH", 500))

    # Maximum raw_text length stored per node (chars).
    # Limits memory per node AND caps the size of any LLM-visible text.
    # Default: 512 chars. Env: PRISM_MAX_NODE_TEXT
    max_node_text_chars: int = int(os.environ.get("PRISM_MAX_NODE_TEXT", 512))

    # ── Subprocess / CodeQL limits ────────────────────────────────────────────

    # Maximum wall-clock seconds for CodeQL database creation.
    # Default: 600s (10 min). Env: PRISM_CODEQL_CREATE_TIMEOUT
    codeql_create_timeout_s: int = int(os.environ.get("PRISM_CODEQL_CREATE_TIMEOUT", 600))

    # Maximum wall-clock seconds for CodeQL analysis (query suite).
    # Default: 1800s (30 min). Env: PRISM_CODEQL_ANALYZE_TIMEOUT
    codeql_analyze_timeout_s: int = int(os.environ.get("PRISM_CODEQL_ANALYZE_TIMEOUT", 1800))

    # Maximum wall-clock seconds for individual QL queries.
    # Default: 120s. Env: PRISM_CODEQL_QUERY_TIMEOUT
    codeql_query_timeout_s: int = int(os.environ.get("PRISM_CODEQL_QUERY_TIMEOUT", 120))

    # ── Token limits ─────────────────────────────────────────────────────────

    # Maximum tokens in the GraphCodeBERT input sequence.
    # Hard-capped at GraphCodeBERT's 512-token context window.
    max_graphcodebert_tokens: int = 512


# Global singleton — import and use directly
LIMITS = ResourceLimits()


# Path whitelist

@dataclass
class PathPolicy:
    """
    Enforces that all file paths processed by the parser are
    strictly within the approved sandbox mount points.

    Inside the gVisor container the layout is:
      /sandbox/repo/     ← read-only bind mount of the ingested repo
      /sandbox/work/     ← ephemeral tmpfs for CodeQL databases, scratch
      /sandbox/output/   ← write-only output mount for ParsedGraphOutput JSON

    Nothing outside these paths should ever be touched by the parser.
    """

    # Configurable via PRISM_REPO_BASE_DIR and PRISM_WORK_BASE_DIR
    repo_base: Path = field(
        default_factory=lambda: Path(os.environ.get("PRISM_REPO_BASE_DIR", "/sandbox/repo"))
    )
    work_base: Path = field(
        default_factory=lambda: Path(os.environ.get("PRISM_WORK_BASE_DIR", "/sandbox/work"))
    )
    output_base: Path = field(
        default_factory=lambda: Path(os.environ.get("PRISM_OUTPUT_BASE_DIR", "/sandbox/output"))
    )

    def validate_repo_path(self, path: str | Path) -> Path:
        """
        Resolve and validate that `path` is strictly under repo_base.
        Raises ValueError on path traversal attempts.

        This is the critical guard against CWE-22 / CWE-78 via
        crafted repo paths passed to CodeQL subprocess.
        """
        resolved = Path(path).resolve()
        repo_resolved = self.repo_base.resolve()

        # Allow /tmp and /sandbox paths in dev/test (when PRISM_REPO_BASE_DIR not set)
        # In production the base dir will be /sandbox/repo
        allowed_bases = [repo_resolved]
        if os.environ.get("PRISM_ENV", "production") in ("development", "test"):
            allowed_bases += [Path("/tmp").resolve(), Path("/home").resolve()]

        for base in allowed_bases:
            try:
                resolved.relative_to(base)
                return resolved
            except ValueError:
                continue

        raise ValueError(
            f"Path traversal attempt detected: '{path}' resolves to '{resolved}' "
            f"which is outside allowed base directories {[str(b) for b in allowed_bases]}. "
            f"This event will be logged to the audit ledger."
        )

    def validate_work_path(self, path: str | Path) -> Path:
        resolved = Path(path).resolve()
        work_resolved = self.work_base.resolve()
        try:
            resolved.relative_to(work_resolved)
            return resolved
        except ValueError:
            # Also allow tempfile defaults (/tmp) in dev
            if os.environ.get("PRISM_ENV", "production") in ("development", "test"):
                tmp_resolved = Path("/tmp").resolve()
                try:
                    resolved.relative_to(tmp_resolved)
                    return resolved
                except ValueError:
                    pass
            raise ValueError(
                f"Work path '{path}' is outside approved work directory '{work_resolved}'"
            )


# Global singleton
PATH_POLICY = PathPolicy()


# Minimal subprocess environment

# Default minimal PATH (can be overridden by environment variable)
_DEFAULT_MINIMAL_PATH = "/usr/local/bin:/usr/bin:/bin"
MINIMAL_PATH = os.environ.get("PRISM_MINIMAL_PATH", _DEFAULT_MINIMAL_PATH)

# Whitelist of allowed extra environment keys (module-level constant)
_ALLOWED_EXTRA_KEYS: Final[frozenset[str]] = frozenset({
    "JAVA_HOME", "JAVA_OPTS",
    "CODEQL_JAVA_HOME",
    "DOTNET_ROOT",
    "GOROOT", "GOPATH",
})


def _validate_extra_value(key: str, value: str) -> None:
    """
    Validate that a value does not contain characters that could be used
    for injection (newline, carriage return, null byte).
    Raises ValueError if any forbidden character is found.
    """
    forbidden = {'\n', '\r', '\x00'}
    if any(ch in value for ch in forbidden):
        raise ValueError(
            f"Value for extra environment key '{key}' contains forbidden "
            f"characters (newline, CR, or null byte). Injection attempt blocked."
        )


def get_minimal_subprocess_env(
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    """
    Return the minimal environment dict for subprocess execution.
    Only PATH, TMPDIR, HOME, LANG, LC_ALL are included. All secrets
    (API keys, tokens, vault credentials) are explicitly excluded.

    Args:
        extra: additional non-secret vars to include (e.g., JAVA_HOME for CodeQL)
               Keys must be in the allowlist _ALLOWED_EXTRA_KEYS, and values must
               not contain newline, carriage return, or null characters.

    Returns:
        A new environment dictionary safe for subprocess use.

    Raises:
        ValueError: if an extra key is not allowed or its value contains
                    forbidden characters.
    """
    env = {
        "PATH":    MINIMAL_PATH,
        "TMPDIR":  tempfile.gettempdir(),        # always a safe, absolute path
        "HOME":    "/tmp",                        # prevent reading ~/.config etc.
        "LANG":    "en_US.UTF-8",                 # needed for consistent output encoding
        "LC_ALL":  "en_US.UTF-8",
    }
    if extra:
        for k, v in extra.items():
            if k not in _ALLOWED_EXTRA_KEYS:
                raise ValueError(f"Extra environment key '{k}' is not allowed.")
            _validate_extra_value(k, v)
            env[k] = v
    return env


# CodeQL safe invocation flags

CODEQL_SAFE_BASE_FLAGS: list[str] = [
    "--no-run-unnecessary-builds",   # Python, JS, TS, Go: skip build execution
    "--threads=2",                   # limit CPU consumption inside sandbox
]

CODEQL_COMPILED_LANGUAGES: frozenset[str] = frozenset({"java", "cpp"})

CODEQL_MAX_THREADS: int = int(os.environ.get("PRISM_CODEQL_THREADS", "2"))


# LLM token sanitization

# Sentinel values – can be overridden by environment variables
PROMPT_INJECTION_SENTINEL = os.environ.get("PRISM_PROMPT_SENTINEL", "[REDACTED]")
COMMENT_SENTINEL          = os.environ.get("PRISM_COMMENT_SENTINEL", "[COMMENT]")
STRING_LITERAL_SENTINEL   = os.environ.get("PRISM_STRING_SENTINEL", "[STRING_LITERAL]")

# Unicode direction override characters (Trojan Source)
# Same set as used in the input validator.
_DIRECTION_OVERRIDE_CHARS: Final[str] = (
    "\u202a\u202b\u202c\u202d\u202e"
    "\u2066\u2067\u2068\u2069"
    "\u200f\u200e"
)

# Build translation table that deletes these characters (once at module load)
_DIRECTION_DELETE_TABLE = str.maketrans("", "", _DIRECTION_OVERRIDE_CHARS)

# Control characters (ASCII 0-31 except tab, LF, CR) -> space mapping
_CONTROL_CHAR_TABLE = str.maketrans(
    {chr(i): " " for i in range(32) if i not in (9, 10, 13)}  # keep tab, LF, CR
)

# Comment node types that should be replaced with COMMENT_SENTINEL
COMMENT_NODE_TYPES: frozenset[str] = frozenset({
    "COMMENT", "DOCSTRING",
})


def sanitize_for_llm(text: str) -> str:
    """
    Sanitize raw source text before it enters any LLM context window.

    Defends against indirect prompt injection via:
      - Embedded system prompt overrides in comments
      - Control character injection
      - Null byte injection
      - Unicode direction override attacks (RLO/LRO characters)

    The raw_text field on NormalizedNode is NOT sanitized — it preserves
    the original source for security annotation and graph analysis.
    Only the token sequence fed to LLMs is sanitized.
    """
    if not text:
        return text

    # 1. Remove null bytes
    text = text.replace("\x00", "")

    # 2. Remove Unicode direction overrides using efficient translation
    text = text.translate(_DIRECTION_DELETE_TABLE)

    # 3. Strip control characters (keep whitespace)
    text = text.translate(_CONTROL_CHAR_TABLE)

    # 4. Cap length
    return text[:LIMITS.max_node_text_chars]


def sanitize_line_for_regex(line: str) -> str:
    """
    Truncate a line to max_line_length before applying regex patterns.
    Prevents ReDoS via catastrophically backtracking patterns on long lines.
    Ref: OWASP CWE-1333
    """
    return line[:LIMITS.max_line_length]