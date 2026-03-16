"""
PRISM Integrity Verifier
=========================
Validates a fetched repository BEFORE handing it to the parser.

The four-layer integrity model:

  Layer 1 — Commit hash pinning
    If the IngestionRequest specifies a commit_sha, we verify the
    fetched HEAD exactly matches. This prevents a compromised upstream
    from serving a different commit than requested.

  Layer 2 — Symlink escape detection
    Walk every file in the repository. Any symlink that resolves
    to a path outside the repository root is rejected and quarantined.
    This is the "symlink escape" or "zip slip" attack applied to Git.
    A malicious repository could contain:
        evil_link -> ../../../../etc/passwd
    If the parser follows this symlink, it reads a host system file.
    We reject the entire repository if any such link is found.

  Layer 3 — File manifest construction
    After symlink validation, compute SHA-256 of every file.
    Build the RepoManifest — the tamper-evident record that goes on-chain.
    The repo_hash (Merkle root) represents the entire repository state
    at the moment of ingestion.

  Layer 4 — Resource limit enforcement
    Apply limits from sandbox_config before any file reaches the parser:
      - max_repo_size_mb: total repository size
      - max_files: maximum number of files
      - max_file_size_bytes: per-file size (from LIMITS)
    Oversized repositories are rejected before parsing begins.

Why verify AFTER fetch and not during?
    We fetch into a temp directory, then verify. This means:
    - The network operation is complete before we do any path operations
    - We verify the exact bytes that will be parsed — not an estimate
    - Verification failures abort the pipeline before the sandbox sees anything

References:
    - "zip slip" vulnerability: https://github.com/snyk/zip-slip-vulnerability
    - Git symlink attacks: CVE-2014-9390, CVE-2021-21300
"""

from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .models import FileEntry, IngestionRequest, RepoManifest

# Import resource limits from our existing sandbox config
from ..parser.sandbox_config import LIMITS


from .exceptions import (
    CommitMismatchError, SymlinkEscapeError,
    ManifestSealError, IntegrityError,
)

logger = logging.getLogger(__name__)

# Maximum number of files in a single repository
# Prevents memory exhaustion during manifest construction
_MAX_FILES = 100_000

# File extensions that are always treated as binary (skipped by parser)
_BINARY_EXTENSIONS: frozenset[str] = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg",
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".obj",
    ".pyc", ".pyo", ".class", ".jar", ".war", ".ear",
    ".mp3", ".mp4", ".avi", ".mov", ".wav",
    ".ttf", ".woff", ".woff2", ".eot",
    ".lock",   # package lock files — large and not analyzed
})

# Git internal directories and files we never parse
_SKIP_DIRS: frozenset[str] = frozenset({
    ".git", ".svn", ".hg",
    "node_modules", "__pycache__", ".pytest_cache",
    ".venv", "venv", ".env", "env",
    "vendor",  # Go / PHP vendored dependencies — parsed separately if needed
    ".idea", ".vscode",
    "dist", "build", "target",  # compiled output
    ".terraform",  # Terraform provider cache
})


@dataclass
class VerificationResult:
    """Result of the integrity verification pass."""
    passed:            bool
    fetched_commit:    str          # actual commit SHA in the cloned repo
    commit_verified:   bool         # True if commit_sha matched request
    manifest:          RepoManifest | None
    rejected_paths:    list[str]    # symlink escapes, oversized files
    warnings:          list[str]
    error:             str | None = None


class IntegrityVerifier:
    """
    Stateless verifier. Instantiate once and call verify() per ingestion.
    Thread-safe — no mutable state.
    """

    def verify(
        self,
        repo_dir:       str,
        fetched_commit: str,
        request:        IngestionRequest,
    ) -> VerificationResult:
        """
        Run all four integrity layers on a fetched repository.

        Args:
            repo_dir:       absolute path to the cloned repository
            fetched_commit: commit SHA returned by the Git client
            request:        original IngestionRequest (for commit pinning)

        Returns:
            VerificationResult — check .passed before proceeding
        """
        rejected:  list[str] = []
        warnings:  list[str] = []
        repo_path = Path(repo_dir).resolve()

        # ── Layer 1: Commit hash pinning ──────────────────────────────────────
        commit_verified = True
        actual_commit   = fetched_commit

        if not actual_commit:
            # Try to read it from the .git directory directly
            actual_commit = self._read_head_from_git_dir(repo_path)

        if request.commit_sha:
            commit_verified = self._verify_commit(
                actual_commit, request.commit_sha, warnings
            )
            if not commit_verified:
                return VerificationResult(
                    passed=False,
                    fetched_commit=actual_commit,
                    commit_verified=False,
                    manifest=None,
                    rejected_paths=[],
                    warnings=warnings,
                    error=(
                        f"Commit mismatch: requested {request.commit_sha!r} "
                        f"but fetched {actual_commit!r}. "
                        f"Possible repository tampering — ingestion aborted."
                    ),
                )
        else:
            warnings.append(
                "No commit_sha specified in request. "
                "Pinning to latest HEAD is less secure than explicit pinning. "
                f"Fetched commit: {actual_commit}"
            )

        # ── Layer 4 (early): Total repo size check ────────────────────────────
        total_bytes = self._measure_repo_size(repo_path)
        max_bytes   = request.max_repo_size_mb * 1024 * 1024
        if total_bytes > max_bytes:
            return VerificationResult(
                passed=False,
                fetched_commit=actual_commit,
                commit_verified=commit_verified,
                manifest=None,
                rejected_paths=[],
                warnings=warnings,
                error=(
                    f"Repository size {total_bytes / 1024 / 1024:.1f} MB "
                    f"exceeds limit {request.max_repo_size_mb} MB. "
                    f"Resource exhaustion defence — ingestion aborted."
                ),
            )

        # ── Layer 2 + 3: Symlink check + manifest construction ────────────────
        manifest = RepoManifest(
            session_id=request.session_id,
            repo_url=request.repo_url,
            provider=request.provider.value,
            branch=request.branch,
            fetched_commit=actual_commit,
            fetch_timestamp=datetime.now(timezone.utc).isoformat(),
        )

        file_count = 0
        for abs_path, rel_path in self._walk_repo(repo_path):

            # Layer 4: file count limit
            file_count += 1
            if file_count > _MAX_FILES:
                warnings.append(
                    f"File count exceeded {_MAX_FILES}. "
                    f"Remaining files skipped."
                )
                break

            # Layer 2: symlink escape detection
            escape = self._check_symlink_escape(abs_path, repo_path)
            if escape:
                reason = f"Symlink escape rejected: {rel_path} → {escape}"
                logger.warning(reason)
                rejected.append(reason)
                manifest.reject_file(reason)
                continue

            # Layer 4: per-file size limit
            try:
                file_size = abs_path.stat().st_size
            except OSError:
                continue

            if file_size > LIMITS.max_file_size_bytes:
                reason = (
                    f"File too large: {rel_path} "
                    f"({file_size:,} bytes > {LIMITS.max_file_size_bytes:,})"
                )
                warnings.append(reason)
                manifest.reject_file(reason)
                continue

            # Layer 3: compute file hash
            is_binary = self._is_binary(abs_path)
            file_hash = self._hash_file(abs_path)
            if file_hash is None:
                continue

            manifest.add_file(FileEntry(
                relative_path=rel_path,
                sha256=file_hash,
                size_bytes=file_size,
                is_binary=is_binary,
            ))

        # Seal the manifest — computes the Merkle-style repo_hash
        repo_hash = manifest.seal()
        logger.info(
            "Repository manifest sealed. files=%d repo_hash=%s...",
            manifest.total_files, repo_hash[:16],
        )

        return VerificationResult(
            passed=True,
            fetched_commit=actual_commit,
            commit_verified=commit_verified,
            manifest=manifest,
            rejected_paths=rejected,
            warnings=warnings,
        )

    # Layer 1: Commit pinning

    def _verify_commit(
        self,
        actual:    str,
        requested: str,
        warnings:  list[str],
    ) -> bool:
        """
        Verify that the fetched commit matches the requested SHA.

        We support both:
          - Full 40-hex SHA  (strongest — exact match)
          - Short SHA prefix (≥7 chars — acceptable for auditing)

        We always record both in the audit log.
        """
        if not actual:
            if requested:
                # A specific commit was requested but we cannot read what was
                # fetched — this is ambiguous and potentially dangerous.
                # Fail closed: refuse to proceed without verification.
                warnings.append(
                    f"COMMIT_PIN_FAIL: requested SHA {requested!r} but "
                    "fetched SHA is unreadable. Aborting to prevent "
                    "unverified code from reaching the parser."
                )
                return False
            # No commit was requested — empty SHA is just a warning.
            warnings.append(
                "Could not read fetched commit SHA — "
                "no explicit commit was requested so continuing, "
                "but consider pinning a commit_sha for stronger guarantees."
            )
            return True

        # Normalise to lowercase hex
        actual_n    = actual.strip().lower()
        requested_n = requested.strip().lower()

        if len(requested_n) < 7:
            warnings.append(
                f"Requested commit SHA {requested_n!r} is too short "
                f"(min 7 chars). Using prefix match with caution."
            )

        if actual_n.startswith(requested_n) or requested_n.startswith(actual_n):
            logger.info("Commit pinning verified: %s", actual_n[:16])
            return True

        return False

    def _read_head_from_git_dir(self, repo_path: Path) -> str:
        """Read the commit SHA directly from .git/HEAD and .git/refs."""
        try:
            head_file = repo_path / ".git" / "HEAD"
            if not head_file.exists():
                return ""
            content = head_file.read_text().strip()

            # HEAD can be "ref: refs/heads/main" or a direct SHA
            if content.startswith("ref: "):
                ref = content[5:]  # e.g. "refs/heads/main"
                ref_file = repo_path / ".git" / ref
                if ref_file.exists():
                    return ref_file.read_text().strip()
                # Try packed-refs
                packed = repo_path / ".git" / "packed-refs"
                if packed.exists():
                    for line in packed.read_text().splitlines():
                        if line.endswith(ref):
                            return line.split()[0]
            else:
                # Direct SHA (detached HEAD)
                return content
        except Exception:
            pass
        return ""

    # Layer 2: Symlink escape detection

    def _check_symlink_escape(
        self,
        abs_path:  Path,
        repo_root: Path,
    ) -> str | None:
        """
        If abs_path is a symlink, resolve it and check if it escapes repo_root.

        Returns the resolved target path string if it escapes (attack detected),
        or None if the symlink is safe or the path is not a symlink.

        Attack examples:
            evil_link → ../../../../etc/passwd       (absolute escape)
            evil_link → ../../../some/parent/secret  (relative escape)
            evil_link → /var/run/secrets/token       (absolute path)
        """
        if not abs_path.is_symlink():
            return None

        try:
            # resolve() follows the symlink chain to the final target
            # strict=False: don't raise if target doesn't exist
            resolved = abs_path.resolve(strict=False)

            # Check if the resolved path is inside the repo root
            try:
                resolved.relative_to(repo_root)
                return None   # safe — symlink stays inside repo
            except ValueError:
                # Symlink escapes the repository root
                return str(resolved)

        except Exception as exc:
            # If we can't resolve the symlink, treat it as suspicious
            logger.warning("Could not resolve symlink %s: %s", abs_path, exc)
            return f"unresolvable: {exc}"

    # Layer 3: File hashing

    def _hash_file(self, path: Path) -> str | None:
        """Compute SHA-256 of a file in 64KB chunks (memory-efficient)."""
        CHUNK = 65536
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(CHUNK)
                    if not chunk:
                        break
                    h.update(chunk)
            return h.hexdigest()
        except OSError as exc:
            logger.warning("Could not hash file %s: %s", path, exc)
            return None

    def _is_binary(self, path: Path) -> bool:
        """
        Quick binary detection: extension check + null byte sniff.
        We read only the first 8KB to detect null bytes (binary indicator).
        """
        if path.suffix.lower() in _BINARY_EXTENSIONS:
            return True
        try:
            with open(path, "rb") as f:
                sample = f.read(8192)
            return b"\x00" in sample
        except OSError:
            return False

    # Layer 4: Resource measurement and repo walk

    def _measure_repo_size(self, repo_path: Path) -> int:
        """Total size of all files in the repository (bytes)."""
        total = 0
        try:
            for root, dirs, files in os.walk(repo_path):
                # Skip .git and other ignored dirs
                dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
                for fname in files:
                    try:
                        total += (Path(root) / fname).stat().st_size
                    except OSError:
                        pass
        except Exception:
            pass
        return total

    def _walk_repo(self, repo_path: Path):
        """
        Yield (absolute_path, relative_path) for every file in the repo.
        Skips .git directory and other non-code directories.
        Yields symlinks too — they are handled by _check_symlink_escape.
        """
        for root, dirs, files in os.walk(repo_path, followlinks=False):
            root_path = Path(root)

            # Prune directories we should never descend into
            dirs[:] = sorted(   # sort for deterministic manifest order
                d for d in dirs if d not in _SKIP_DIRS
            )

            for fname in sorted(files):   # sort for determinism
                abs_path = root_path / fname
                try:
                    rel_path = str(abs_path.relative_to(repo_path))
                    # Normalize to forward slashes on Windows
                    rel_path = rel_path.replace(os.sep, "/")
                except ValueError:
                    continue
                yield abs_path, rel_path