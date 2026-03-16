"""
Zero-trust input validation layer that runs BEFORE any parser backend
is invoked. Every source file passes through this gate.

Threat model coverage:
  ┌─────────────────────────────────┬──────────────────────────────────────┐
  │ Threat                          │ Defence                              │
  ├─────────────────────────────────┼──────────────────────────────────────┤
  │ Resource Exhaustion (large      │ File size + line count hard caps     │
  │ files, recursive includes)      │ before any parsing begins            │
  ├─────────────────────────────────┼──────────────────────────────────────┤
  │ ReDoS (malformed syntax         │ Line length truncation before regex  │
  │ triggering backtracking)        │ + per-pattern timeout via signal     │
  ├─────────────────────────────────┼──────────────────────────────────────┤
  │ Path Traversal / Injection      │ Strict path whitelist via PathPolicy │
  │ via crafted file paths          │ + path component validation          │
  ├─────────────────────────────────┼──────────────────────────────────────┤
  │ Encoding attacks (polyglot      │ Explicit UTF-8 decode with error     │
  │ files, BOM injection)           │ handling + BOM stripping             │
  ├─────────────────────────────────┼──────────────────────────────────────┤
  │ Trojan Source (Unicode          │ Bidirectional override character      │
  │ direction overrides)            │ detection and rejection              │
  └─────────────────────────────────┴──────────────────────────────────────┘

References:
  - Trojan Source attack: https://trojansource.codes/ (CVE-2021-42574)
  - OWASP CWE-1333 ReDoS: https://cwe.mitre.org/data/definitions/1333.html
  - CWE-22 Path Traversal: https://cwe.mitre.org/data/definitions/22.html
"""

from __future__ import annotations

import logging
import re
import unicodedata
import signal
import time
from collections import Counter
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .sandbox_config import LIMITS, PATH_POLICY

logger = logging.getLogger(__name__)

# Validation result
class ValidationStatus(str, Enum):
    PASSED        = "passed"
    TRUNCATED     = "truncated"     # file accepted but content was trimmed
    REJECTED      = "rejected"      # file must not be parsed


@dataclass
class ValidationResult:
    status:         ValidationStatus
    sanitized_source: str                   # safe-to-parse content
    original_size_bytes: int
    original_line_count: int
    warnings:       list[str]
    rejection_reason: str | None = None     # set when status == REJECTED

    @property
    def is_parseable(self) -> bool:
        return self.status != ValidationStatus.REJECTED

# Bidirectional override character detection
# (Trojan Source — CVE-2021-42574)
# Unicode codepoints that can visually hide malicious code
_BIDI_OVERRIDE_CHARS: frozenset[str] = frozenset({
    "\u202a",  # LEFT-TO-RIGHT EMBEDDING
    "\u202b",  # RIGHT-TO-LEFT EMBEDDING
    "\u202c",  # POP DIRECTIONAL FORMATTING
    "\u202d",  # LEFT-TO-RIGHT OVERRIDE
    "\u202e",  # RIGHT-TO-LEFT OVERRIDE   ← primary Trojan Source vector
    "\u2066",  # LEFT-TO-RIGHT ISOLATE
    "\u2067",  # RIGHT-TO-LEFT ISOLATE
    "\u2068",  # FIRST STRONG ISOLATE
    "\u2069",  # POP DIRECTIONAL ISOLATE
    "\u200f",  # RIGHT-TO-LEFT MARK
    "\u200e",  # LEFT-TO-RIGHT MARK
    "\ufeff",  # BOM / ZERO WIDTH NO-BREAK SPACE (used as polyglot marker)
})

# Zero-width characters used to hide code from reviewers
_ZERO_WIDTH_CHARS: frozenset[str] = frozenset({
    "\u200b",  # ZERO WIDTH SPACE
    "\u200c",  # ZERO WIDTH NON-JOINER
    "\u200d",  # ZERO WIDTH JOINER
    "\u2060",  # WORD JOINER
    "\ufeff",  # ZERO WIDTH NO-BREAK SPACE
})

# Null byte — used in polyglot attacks and to terminate C strings
_NULL_BYTE = "\x00"

# New constants for additional gates (preserving existing ones above)

# Unicode characters that are "default ignorable" (invisible in rendering)
# Includes zero-width spaces, joiners, directional marks, etc.
# These are in addition to _ZERO_WIDTH_CHARS; we treat them separately.
_DEFAULT_IGNORABLE = frozenset(
    chr(c) for c in range(0xFFFF) if unicodedata.category(chr(c)) == 'Cf'
)

# Non-standard whitespace (all Unicode Zs category except ASCII space)
_WHITESPACE_ZS = frozenset(
    ch for ch in [chr(c) for c in range(0xFFFF) if unicodedata.category(chr(c)) == 'Zs']
)
_STANDARD_WHITESPACE = {' ', '\t', '\n', '\r'}
_NONSTANDARD_WHITESPACE = _WHITESPACE_ZS - _STANDARD_WHITESPACE

# Line/paragraph separators that can break comment boundaries
_LINE_SEPARATORS = {'\u2028', '\u2029'}

# Regex for detecting probable base64 strings (simplified)
_BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')

# Helper functions for new gates

def _count_replacement_chars(text: str) -> int:
    """Count Unicode replacement characters (U+FFFD) as proxy for malformed input."""
    
    """
    Why count it?
    In the validator, we decode the raw bytes with errors="replace" (Gate 2). This ensures we never fail on malformed input ;
    instead, every invalid byte is replaced with \ufffd. By counting these characters afterwards, 
    we can detect if the original file contained malformed UTF- 8 sequences, which might be a sign of an encoding attack or data corruption. 
    The warning in Gate 12 alerts the user to the presence of these malformed sequences."""
    return text.count('\ufffd')

def _entropy_warning(text: str, threshold: float = 0.9) -> tuple[bool, str]:
    """
    Detect low-entropy input (e.g., repeated single character) which may indicate a DoS attempt.
    Returns (triggered, warning_message).
    """
    if not text:
        return False, ""
    most_common_char, count = Counter(text).most_common(1)[0]
    ratio = count / len(text)
    if ratio > threshold:
        return True, f"Low-entropy input: {most_common_char!r} appears {ratio:.1%} of the time (possible DoS)."
    return False, ""

def _find_regex_vulnerabilities(source: str) -> list[str]:
    """
    Naive ReDoS pattern detection: look for nested quantifiers (e.g., (a+)+).
    Returns list of warnings (one per suspicious line).
    """
    warnings = []
    # Very basic: find strings that look like regex literals (simple heuristic)
    # In real code you'd need language-specific parsing; this is a placeholder.
    regex_literals = re.findall(r'[rR]?"([^"\\]*(?:\\.[^"\\]*)*)"', source)
    for lit in regex_literals:
        if re.search(r'\([^)]*[+*][^)]*\)\s*[+*]', lit):
            warnings.append(f"Possible ReDoS pattern in regex literal: {lit[:50]}...")
    return warnings

def _extract_line_context(source: str, line_number: int, context_lines: int = 2) -> str:
    """Get a few lines around a given line for contextual warnings."""
    lines = source.splitlines()
    start = max(0, line_number - context_lines - 1)
    end = min(len(lines), line_number + context_lines)
    context = lines[start:end]
    return "\n".join(f"{idx+1}: {line}" for idx, line in enumerate(context, start=start+1))

# Main validator

class InputValidator:
    """
    Stateless input validator. Thread-safe; instantiate once and reuse.

    Usage:
        validator = InputValidator()
        result = validator.validate(source_code, file_path)
        if not result.is_parseable:
            log_rejection(result.rejection_reason)
        else:
            parser.parse(result.sanitized_source, file_path, language)
    """

    def validate(
        self,
        raw_bytes: bytes,
        file_path: str | Path,
    ) -> ValidationResult:
        """
        Full validation pipeline for a raw source file.

        Args:
            raw_bytes:  raw file content as bytes (not yet decoded)
            file_path:  path for audit logging (already validated by PathPolicy)

        Returns:
            ValidationResult with sanitized source or rejection reason.
        """
        warnings: list[str]      = []
        file_path_str = str(file_path)
        original_size = len(raw_bytes)

        # ── Gate 1: File size ─────────────────────────────────────────────────
        if original_size > LIMITS.max_file_size_bytes:
            return ValidationResult(
                status=ValidationStatus.REJECTED,
                sanitized_source="",
                original_size_bytes=original_size,
                original_line_count=0,
                warnings=[],
                rejection_reason=(
                    f"File size {original_size:,} bytes exceeds limit "
                    f"{LIMITS.max_file_size_bytes:,} bytes. "
                    f"Resource exhaustion defence — file rejected."
                ),
            )

        # ── Timeout protection ────────────
        try:
            signal.signal(signal.SIGALRM, lambda signum, frame: (_ for _ in ()).throw(TimeoutError()))
            signal.alarm(2)  # 2-second timeout for the whole validation
        except (AttributeError, ValueError):
            # signal not available or not in main thread – skip timeout
            pass

        try:
            # ── Gate 2: UTF-8 decode ──────────────────────────────────────────────
            try:
                source = raw_bytes.decode("utf-8", errors="replace")
            except Exception as exc:
                return ValidationResult(
                    status=ValidationStatus.REJECTED,
                    sanitized_source="",
                    original_size_bytes=original_size,
                    original_line_count=0,
                    warnings=[],
                    rejection_reason=f"Encoding error during UTF-8 decode: {exc}",
                )

            # ── Gate 3: Null byte detection ───────────────────────────────────────
            if _NULL_BYTE in source:
                null_count = source.count(_NULL_BYTE)
                warnings.append(
                    f"Null bytes detected ({null_count} occurrences). "
                    f"Stripping before parse (polyglot attack defence)."
                )
                source = source.replace(_NULL_BYTE, "")

            # ── Gate 4: Trojan Source — bidirectional override detection ──────────
            bidi_found = [ch for ch in _BIDI_OVERRIDE_CHARS if ch in source]
            if bidi_found:
                codepoints = [f"U+{ord(c):04X}" for c in bidi_found]
                warnings.append(
                    f"Bidirectional override characters detected: {codepoints}. "
                    f"Potential Trojan Source attack (CVE-2021-42574). "
                    f"Characters stripped."
                )
                for ch in bidi_found:
                    source = source.replace(ch, "")

            # ── Gate 5: Zero-width character detection ────────────────────────────
            zw_found = [ch for ch in _ZERO_WIDTH_CHARS if ch in source]
            if zw_found:
                warnings.append(
                    f"Zero-width characters detected ({len(zw_found)} types). "
                    f"Stripping — may indicate hidden code."
                )
                for ch in zw_found:
                    source = source.replace(ch, "")

            # ── Gate 6: BOM stripping ─────────────────────────────────────────────
            if source.startswith("\ufeff"):
                source = source[1:]
                warnings.append("UTF-8 BOM stripped.")

            # ── Gate 7: Line count ────────────────────────────────────────────────
            lines = source.split("\n")
            original_line_count = len(lines)

            if original_line_count > LIMITS.max_lines:
                warnings.append(
                    f"File has {original_line_count:,} lines; "
                    f"truncating to {LIMITS.max_lines:,} "
                    f"(resource exhaustion defence)."
                )
                lines = lines[:LIMITS.max_lines]
                source = "\n".join(lines)
                status = ValidationStatus.TRUNCATED
            else:
                status = ValidationStatus.PASSED

            # ── Gate 8: Per-line length cap (ReDoS defence) ───────────────────────
            sanitized_lines: list[str] = []
            long_line_count = 0
            for line in lines:
                if len(line) > LIMITS.max_line_length:
                    long_line_count += 1
                    sanitized_lines.append(line[:LIMITS.max_line_length])
                else:
                    sanitized_lines.append(line)

            if long_line_count > 0:
                warnings.append(
                    f"{long_line_count} lines truncated to {LIMITS.max_line_length} chars "
                    f"(ReDoS defence — CWE-1333)."
                )
                source = "\n".join(sanitized_lines)
                status = ValidationStatus.TRUNCATED

            # ── Gate 9: Suspicious Unicode homoglyphs ─────────────────────────────
            homoglyph_count = _count_confusables(source)
            if homoglyph_count > 50:
                warnings.append(
                    f"High confusable Unicode character count ({homoglyph_count}). "
                    f"May indicate homoglyph attack. Flagged for review."
                )

            # ── Gate 10: Unicode normalization (NFKC) ─────────────────────────────
            normalized = unicodedata.normalize('NFKC', source)
            if normalized != source:
                warnings.append("Unicode normalized to NFKC (may affect identifiers).")
                source = normalized
                # After normalization, lines may have changed; re-split for subsequent gates
                lines = source.split("\n")

            # ── Gate 11: Dangerous Unicode categories (format, line separators) ───
            dangerous_chars = []
            for ch in source:
                cat = unicodedata.category(ch)
                if cat in {'Cf', 'Zl', 'Zp'} or ch in _LINE_SEPARATORS:
                    dangerous_chars.append(f"U+{ord(ch):04X}")
            if dangerous_chars:
                warnings.append(
                    f"Dangerous Unicode characters (format/line separators): {dangerous_chars}. "
                    f"These may break parsers – stripped."
                )
                for ch in set(dangerous_chars):
                    source = source.replace(ch, "")

            # ── Gate 12: Overlong UTF-8 / malformed input ─────────────────────────
            replacement_count = _count_replacement_chars(source)
            if replacement_count > 0:
                warnings.append(
                    f"{replacement_count} replacement character(s) inserted during UTF-8 decode "
                    f"(malformed byte sequences)."
                )

            # ── Gate 13: Non-standard whitespace replacement ───────────────────────
            nonstd_ws = [ch for ch in source if ch in _NONSTANDARD_WHITESPACE]
            if nonstd_ws:
                for ch in set(nonstd_ws):
                    source = source.replace(ch, ' ')
                warnings.append(
                    f"Non-standard whitespace replaced with space: {set(nonstd_ws)}"
                )

            # ── Gate 14: Expanded zero-width (default ignorable) detection ─────────
            # This is a superset of Gate 5, but we run it separately because Gate 5
            # only stripped a specific set. We now strip any remaining default ignorable.
            extra_zw = [ch for ch in _DEFAULT_IGNORABLE if ch in source]
            if extra_zw:
                codepoints = [f"U+{ord(c):04X}" for c in extra_zw]
                warnings.append(
                    f"Additional default-ignorable characters detected: {codepoints}. "
                    f"Stripping – may hide code."
                )
                for ch in extra_zw:
                    source = source.replace(ch, "")

            # ── Gate 15: Entropy / repetition detection ───────────────────────────
            low_entropy, entropy_msg = _entropy_warning(source)
            if low_entropy:
                warnings.append(entropy_msg)

            # ── Gate 16: ReDoS pattern detection ──────────────────────────────────
            redos_warnings = _find_regex_vulnerabilities(source)
            warnings.extend(redos_warnings)

            # ── Gate 17: Encoded payload detection (base64) ───────────────────────
            base64_matches = _BASE64_PATTERN.findall(source)
            if base64_matches:
                warnings.append(
                    f"Found {len(base64_matches)} potential base64 strings (length ≥40). "
                    f"May hide encoded payloads – review."
                )

            # ── Gate 18: Metadata warnings (shebang, encoding) ────────────────────
            shebang_lines = [i for i, line in enumerate(lines[:5]) if line.startswith('#!')]
            if len(shebang_lines) > 1:
                warnings.append(f"Multiple shebang lines found (lines {shebang_lines}).")
            encoding_lines = [i for i, line in enumerate(lines[:5]) if 'coding:' in line or 'encoding:' in line]
            if len(encoding_lines) > 1:
                warnings.append(f"Multiple encoding declarations found (lines {encoding_lines}).")

            # Cancel alarm before returning
            signal.alarm(0)

            return ValidationResult(
                status=status,
                sanitized_source=source,
                original_size_bytes=original_size,
                original_line_count=original_line_count,
                warnings=warnings,
            )

        except TimeoutError:
            signal.alarm(0)
            return ValidationResult(
                status=ValidationStatus.REJECTED,
                sanitized_source="",
                original_size_bytes=original_size,
                original_line_count=0,
                warnings=["Validation timed out (possible DoS attempt)."],
                rejection_reason="Validation timeout",
            )
        except Exception as e:
            signal.alarm(0)
            return ValidationResult(
                status=ValidationStatus.REJECTED,
                sanitized_source="",
                original_size_bytes=original_size,
                original_line_count=0,
                warnings=[f"Unexpected validation error: {e}"],
                rejection_reason="Internal validation error",
            )

    def validate_string(self, source: str, file_path: str) -> ValidationResult:
        """Convenience wrapper when source is already decoded."""
        return self.validate(source.encode("utf-8", errors="replace"), file_path)

# Existing helpers and GraphSizeGuard

def _count_confusables(text: str) -> int:
    """
    Count characters that are visually similar to ASCII but are not ASCII.
    High counts suggest homoglyph substitution attacks.
    We use Unicode category: Lo (Other Letter) and Ll/Lu that are
    outside Basic Latin range.
    """
    count = 0
    for ch in text:
        cp = ord(ch)
        if cp > 127:
            cat = unicodedata.category(ch)
            if cat in ("Ll", "Lu", "Lo", "Lm"):  # letter categories
                count += 1
    return count


class GraphSizeGuard:
    """
    Stateful circuit breaker used during the AST walk.
    Raise GraphExplosionError when limits are exceeded.

    Usage inside tree walk:
        guard = GraphSizeGuard(file_path)
        guard.check_node()      # raises on limit
        guard.check_edge()
        guard.check_depth(depth)
    """

    def __init__(self, file_path: str) -> None:
        self.file_path    = file_path
        self._node_count  = 0
        self._edge_count  = 0
        self._truncated   = False

    @property
    def truncated(self) -> bool:
        return self._truncated

    @property
    def node_count(self) -> int:
        return self._node_count

    @property
    def edge_count(self) -> int:
        return self._edge_count

    def check_node(self) -> None:
        self._node_count += 1
        if self._node_count > LIMITS.max_nodes_per_file:
            self._truncated = True
            raise GraphExplosionError(
                limit_type="nodes",
                limit_value=LIMITS.max_nodes_per_file,
                actual_value=self._node_count,
                file_path=self.file_path,
            )

    def check_edge(self) -> None:
        self._edge_count += 1
        if self._edge_count > LIMITS.max_edges_per_file:
            self._truncated = True
            raise GraphExplosionError(
                limit_type="edges",
                limit_value=LIMITS.max_edges_per_file,
                actual_value=self._edge_count,
                file_path=self.file_path,
            )

    def check_depth(self, depth: int) -> None:
        if depth > LIMITS.max_ast_depth:
            self._truncated = True
            raise GraphExplosionError(
                limit_type="depth",
                limit_value=LIMITS.max_ast_depth,
                actual_value=depth,
                file_path=self.file_path,
            )


class GraphExplosionError(Exception):
    """
    Raised when a graph size limit is exceeded during AST walking.
    Carries structured information about which limit was hit.
    """

    def __init__(
        self,
        limit_type: str,          # "nodes", "edges", or "depth"
        limit_value: int,
        actual_value: int | None,
        file_path: str,
        *,
        message: str | None = None,
    ) -> None:
        self.limit_type = limit_type
        self.limit_value = limit_value
        self.actual_value = actual_value
        self.file_path = file_path

        if message is None:
            if actual_value is not None:
                msg = (
                    f"{limit_type.capitalize()} count {actual_value:,} "
                    f"exceeded limit ({limit_value:,}) in {file_path}. "
                    f"Graph explosion defence activated."
                )
            else:
                msg = (
                    f"{limit_type.capitalize()} depth {limit_value} "
                    f"exceeded in {file_path}. Graph explosion defence activated."
                )
        else:
            msg = message

        super().__init__(msg)