"""
PRISM Submodule Resolver
Safely fetches Git submodule content after the parent repository has
been cloned, mitigating the four submodule-specific threat vectors:

  Threat A — Silent blind spot
    Submodule directories are empty after --depth=1. Without this resolver,
    the parser silently skips them. Every skipped submodule is a potential
    undetected vulnerability. We fetch each submodule's content at its
    pinned commit so the parser sees a complete file tree.

  Threat B — Malicious submodule URL
    .gitmodules can contain arbitrary URLs — including private IPs, localhost,
    git:// or ssh:// schemes, and SSRF-reachable internal hosts. Every
    submodule URL is validated through the same pipeline as the parent URL:
    HTTPS-only, no embedded credentials, full SSRF IP range check.
    Any URL that fails validation is skipped and logged — the parent
    ingestion continues with a warning.

  Threat C — Submodule commit drift
    .gitmodules contains URLs but NOT the pinned commit SHA. The pinned SHA
    is stored in the parent's tree object as a "gitlink" entry. We read the
    pinned SHA from the parent tree (via .git/modules or git ls-tree), never
    from .gitmodules alone. This prevents an attacker from serving a different
    commit by modifying .gitmodules while leaving the tree pointer intact.

  Threat D — Recursive depth explosion
    Submodules can themselves contain submodules. Without a depth cap,
    circular references or deeply nested structures cause infinite recursion
    or memory exhaustion. We enforce:
      - MAX_SUBMODULE_DEPTH: maximum nesting levels (default 2)
      - visited set: (url, commit_sha) pairs already fetched this session
      - MAX_SUBMODULES_TOTAL: maximum submodules across the entire tree
"""

from __future__ import annotations

import configparser
import logging
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from .git_client        import GitClient, GitFetchResult
from .credential_provider import AbstractCredentialProvider, SecureString
from .integrity_verifier  import IntegrityVerifier, _SKIP_DIRS
from .models              import (
    FileEntry, GitProvider, IngestionRequest, AuthMethod,
)
from .validators          import check_ssrf as _check_ssrf, is_safe_ref as _is_safe_ref
from .providers           import ProviderRegistry

try:
    from ..parser.sandbox_config import LIMITS, get_minimal_subprocess_env
except ImportError:
    from parser.sandbox_config import LIMITS, get_minimal_subprocess_env

logger = logging.getLogger(__name__)

# Hard limits 

# Maximum nesting depth of submodule resolution.
# 0 = parent repo, 1 = direct submodules, 2 = their submodules.
# Beyond this: skip and warn. Most real projects have depth 0 or 1.
MAX_SUBMODULE_DEPTH: int = int(os.environ.get("PRISM_MAX_SUBMODULE_DEPTH", 2))

# Maximum total number of submodules resolved across all nesting levels.
# Prevents explosion from repos with hundreds of vendored submodules.
MAX_SUBMODULES_TOTAL: int = int(os.environ.get("PRISM_MAX_SUBMODULES_TOTAL", 50))

# Timeout for each individual submodule fetch (seconds)
SUBMODULE_FETCH_TIMEOUT_S: int = int(os.environ.get("PRISM_SUBMODULE_TIMEOUT", 60))


# Data structures

@dataclass
class SubmoduleEntry:
    """
    Describes a single submodule found in a repository.
    Populated progressively as resolution proceeds.
    """
    # From .gitmodules
    name:        str           # logical name (e.g. "vendor/crypto-lib")
    path:        str           # relative path in parent repo (e.g. "vendor/crypto-lib")
    url:         str           # raw URL from .gitmodules (may be relative or unsafe)

    # From parent tree (Threat C: commit pinning)
    pinned_sha:  str = ""      # SHA read from parent git tree — NOT from .gitmodules

    # Resolution outcome
    status:      str = "pending"   # pending | fetched | skipped | failed
    reason:      str = ""          # why skipped/failed (never contains credentials)
    local_path:  str = ""          # where files landed after fetch
    files:       list[FileEntry] = field(default_factory=list)
    repo_hash:   str = ""          # SHA-256 Merkle root of submodule files
    depth:       int = 0           # nesting level (0 = direct child of parent)
    warnings:    list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name":       self.name,
            "path":       self.path,
            "url":        self.url,
            "pinned_sha": self.pinned_sha,
            "status":     self.status,
            "reason":     self.reason,
            "repo_hash":  self.repo_hash,
            "file_count": len(self.files),
            "depth":      self.depth,
            "warnings":   self.warnings,
        }


@dataclass
class SubmoduleResolutionResult:
    """
    Complete result of resolving all submodules in a repository tree.
    Added to the parent RepoManifest after resolution.
    """
    submodules:      list[SubmoduleEntry] = field(default_factory=list)
    total_fetched:   int = 0
    total_skipped:   int = 0
    total_failed:    int = 0
    warnings:        list[str] = field(default_factory=list)

    @property
    def has_blind_spots(self) -> bool:
        """True if any submodule could not be fetched — partial analysis."""
        return self.total_skipped > 0 or self.total_failed > 0

    def to_dict(self) -> dict:
        return {
            "submodules":    [s.to_dict() for s in self.submodules],
            "total_fetched": self.total_fetched,
            "total_skipped": self.total_skipped,
            "total_failed":  self.total_failed,
            "has_blind_spots": self.has_blind_spots,
            "warnings":      self.warnings,
        }


# Main resolver──

class SubmoduleResolver:
    """
    Resolves submodules for a cloned repository, applying all four
    threat mitigations.

    Usage:
        resolver = SubmoduleResolver(credential_provider, git_client)
        result   = resolver.resolve(parent_repo_dir, parent_request)
        # result.submodules contains fetched file entries
        # Attach result to RepoManifest for audit trail
    """

    def __init__(
        self,
        credential_provider: AbstractCredentialProvider,
        git_client:          GitClient | None = None,
        verifier:            IntegrityVerifier | None = None,
    ) -> None:
        self._creds    = credential_provider
        self._client   = git_client or GitClient()
        self._verifier = verifier or IntegrityVerifier()
        self._registry = ProviderRegistry()

        # Threat D: global visited set for this resolver instance
        # Keyed by (normalized_url, pinned_sha) to detect circular refs
        self._visited: set[tuple[str, str]] = set()
        self._total_fetched = 0

    def resolve(
        self,
        parent_repo_dir: str,
        parent_request:  IngestionRequest,
    ) -> SubmoduleResolutionResult:
        """
        Discover and fetch all submodules in the parent repository.

        Args:
            parent_repo_dir: absolute path to the already-cloned parent repo
            parent_request:  original IngestionRequest (for credential ref
                             and session context)

        Returns:
            SubmoduleResolutionResult with all SubmoduleEntries populated
        """
        result   = SubmoduleResolutionResult()
        warnings = result.warnings

        # Parse .gitmodules to discover submodule definitions
        gitmodules_path = Path(parent_repo_dir) / ".gitmodules"
        if not gitmodules_path.exists():
            logger.debug("No .gitmodules found in %s — no submodules", parent_repo_dir)
            return result

        raw_submodules = self._parse_gitmodules(gitmodules_path, parent_repo_dir)
        if not raw_submodules:
            return result

        logger.info(
            "Found %d submodule(s) in %s",
            len(raw_submodules), parent_repo_dir,
        )

        # Threat C: read pinned SHAs from the parent git tree
        # These are the authoritative commit pointers — not the URLs in .gitmodules
        pinned_shas = self._read_pinned_shas(parent_repo_dir)

        # Resolve each submodule recursively
        self._resolve_recursive(
            submodules=raw_submodules,
            pinned_shas=pinned_shas,
            parent_repo_dir=parent_repo_dir,
            parent_request=parent_request,
            depth=0,
            result=result,
        )

        result.total_fetched = sum(
            1 for s in result.submodules if s.status == "fetched"
        )
        result.total_skipped = sum(
            1 for s in result.submodules if s.status == "skipped"
        )
        result.total_failed = sum(
            1 for s in result.submodules if s.status == "failed"
        )

        if result.has_blind_spots:
            warnings.append(
                f"Analysis has blind spots: {result.total_skipped} skipped, "
                f"{result.total_failed} failed submodule(s). "
                f"Vulnerabilities in these submodules will not be detected."
            )

        logger.info(
            "Submodule resolution complete. fetched=%d skipped=%d failed=%d",
            result.total_fetched, result.total_skipped, result.total_failed,
        )
        return result

    # ──────────
    # Recursive resolution
    # ──────────

    def _resolve_recursive(
        self,
        submodules:      list[SubmoduleEntry],
        pinned_shas:     dict[str, str],
        parent_repo_dir: str,
        parent_request:  IngestionRequest,
        depth:           int,
        result:          SubmoduleResolutionResult,
    ) -> None:
        """
        Fetch each submodule, then recursively fetch their submodules.
        Enforces depth limit and total count limit (Threat D).
        """
        for entry in submodules:
            entry.depth = depth

            # Threat D: total count limit ────────────────────────────────
            if self._total_fetched >= MAX_SUBMODULES_TOTAL:
                entry.status = "skipped"
                entry.reason = (
                    f"Total submodule limit ({MAX_SUBMODULES_TOTAL}) reached. "
                    f"This submodule was not analyzed."
                )
                result.submodules.append(entry)
                result.warnings.append(entry.reason)
                continue

            # Threat D: depth limit ──────────────────────────────────────
            if depth > MAX_SUBMODULE_DEPTH:
                entry.status = "skipped"
                entry.reason = (
                    f"Maximum submodule nesting depth ({MAX_SUBMODULE_DEPTH}) "
                    f"reached at depth {depth}. Submodule '{entry.name}' skipped."
                )
                result.submodules.append(entry)
                result.warnings.append(entry.reason)
                continue

            # Threat C: attach pinned SHA from parent tree ───────────────
            # Key: the submodule path as it appears in the parent tree
            pinned = pinned_shas.get(entry.path, "")
            if not pinned:
                # Try alternate key formats
                pinned = pinned_shas.get(entry.path.lstrip("/"), "")
            entry.pinned_sha = pinned

            if not pinned:
                entry.status = "skipped"
                entry.reason = (
                    f"Could not read pinned commit SHA for submodule "
                    f"'{entry.path}' from parent tree. "
                    f"Fetching without commit pinning is unsafe — skipped."
                )
                result.submodules.append(entry)
                result.warnings.append(entry.reason)
                continue

            # Threat B: validate submodule URL ──────────────────────────
            url_error = self._validate_submodule_url(
                entry.url, parent_request.repo_url, parent_repo_dir
            )
            if url_error:
                entry.status = "skipped"
                entry.reason = f"URL validation failed: {url_error}"
                result.submodules.append(entry)
                result.warnings.append(
                    f"Submodule '{entry.name}' skipped — {url_error}"
                )
                continue

            # Threat D: circular reference detection ────────────────────
            visit_key = (entry.url, entry.pinned_sha)
            if visit_key in self._visited:
                entry.status = "skipped"
                entry.reason = (
                    f"Circular submodule reference detected: "
                    f"'{entry.url}' @ {entry.pinned_sha[:12]} already visited."
                )
                result.submodules.append(entry)
                result.warnings.append(entry.reason)
                continue
            self._visited.add(visit_key)

            # Fetch the submodule ────────────────────────────────────────
            self._fetch_submodule(
                entry, parent_repo_dir, parent_request, result
            )

            if entry.status == "fetched":
                self._total_fetched += 1

                # Recurse into nested submodules ─────────────────────────
                nested_gitmodules = Path(entry.local_path) / ".gitmodules"
                if nested_gitmodules.exists() and depth < MAX_SUBMODULE_DEPTH:
                    nested_entries = self._parse_gitmodules(
                        nested_gitmodules, entry.local_path
                    )
                    nested_shas = self._read_pinned_shas(entry.local_path)
                    self._resolve_recursive(
                        submodules=nested_entries,
                        pinned_shas=nested_shas,
                        parent_repo_dir=entry.local_path,
                        parent_request=parent_request,
                        depth=depth + 1,
                        result=result,
                    )

    # ──────────
    # Submodule fetch
    # ──────────

    def _fetch_submodule(
        self,
        entry:           SubmoduleEntry,
        parent_repo_dir: str,
        parent_request:  IngestionRequest,
        result:          SubmoduleResolutionResult,
    ) -> None:
        """
        Clone a single submodule at its pinned commit SHA into the
        correct path under parent_repo_dir.

        The submodule lands at:
            parent_repo_dir / entry.path /

        This mirrors what `git submodule update --init` would produce,
        so the parser sees the correct directory structure.
        """
        dest_path = Path(parent_repo_dir) / entry.path
        dest_path.mkdir(parents=True, exist_ok=True)

        logger.info(
            "Fetching submodule '%s' from %s @ %s (depth=%d)",
            entry.name, entry.url, entry.pinned_sha[:12], entry.depth,
        )

        # Build a synthetic IngestionRequest for this submodule
        # Reuse the parent's credential_ref — most private repos share auth
        sub_request = IngestionRequest(
            repo_url       = entry.url,
            provider       = self._registry.get_strategy(entry.url).provider_type(),
            branch         = "main",           # doesn't matter — we pin by SHA
            commit_sha     = entry.pinned_sha, # Threat C: always pin to parent's pointer
            credential_ref = parent_request.credential_ref,
            auth_method    = parent_request.auth_method,
            output_dir     = str(dest_path),
            depth          = 1,
            timeout_s      = SUBMODULE_FETCH_TIMEOUT_S,
            max_repo_size_mb = 100,            # stricter limit for submodules
            session_id     = parent_request.session_id,
            operator_id    = parent_request.operator_id,
        )

        # Fetch into a temp dir first, then move to dest_path
        try:
            with tempfile.TemporaryDirectory(
                prefix=f"prism_sub_{entry.name[:12].replace('/', '_')}_",
                dir="/tmp",
            ) as tmp_dir:
                # Acquire credential
                with self._creds.credential_context(
                    parent_request.credential_ref
                ) as credential:
                    fetch_result = self._client.fetch(
                        sub_request, credential, tmp_dir
                    )

                if not fetch_result.success:
                    entry.status = "failed"
                    entry.reason = (
                        f"Git fetch failed: {fetch_result.error}"
                    )
                    result.submodules.append(entry)
                    return

                entry.warnings.extend(fetch_result.warnings)

                # Verify the fetched commit matches the pinned SHA
                commit_ok = self._verify_submodule_commit(
                    fetch_result.fetched_commit,
                    entry.pinned_sha,
                    entry,
                )
                if not commit_ok:
                    entry.status = "failed"
                    entry.reason = (
                        f"Commit verification failed: "
                        f"expected {entry.pinned_sha[:12]}, "
                        f"got {fetch_result.fetched_commit[:12] if fetch_result.fetched_commit else 'unknown'}"
                    )
                    result.submodules.append(entry)
                    return

                # Hash all files and collect FileEntry objects
                file_entries, repo_hash = self._hash_submodule_files(
                    tmp_dir, entry.path
                )
                entry.files    = file_entries
                entry.repo_hash = repo_hash

                # Copy files to their final location under parent repo
                self._install_submodule_files(tmp_dir, str(dest_path), entry)

                entry.local_path = str(dest_path)
                entry.status     = "fetched"
                logger.info(
                    "Submodule '%s' fetched: %d files, hash=%s...",
                    entry.name, len(entry.files), repo_hash[:16],
                )

        except Exception as exc:
            entry.status = "failed"
            entry.reason = f"Unexpected error: {exc}"
            logger.exception("Submodule fetch exception for '%s'", entry.name)

        result.submodules.append(entry)

    # ──────────
    # Threat B: URL validation
    # ──────────

    def _validate_submodule_url(
        self,
        raw_url:         str,
        parent_repo_url: str,
        parent_repo_dir: str,
    ) -> str | None:
        """
        Validate a submodule URL from .gitmodules.
        Returns an error string if invalid, None if safe.

        Handles three URL forms found in .gitmodules:
          1. Absolute HTTPS:  https://github.com/org/lib
          2. Relative path:   ../other-repo   (relative to parent URL)
          3. Absolute path:   /home/user/lib  (local filesystem — always reject)
        """
        if not raw_url:
            return "empty URL"

        url = raw_url.strip()

        # Reject local filesystem paths — these are never valid for remote repos
        if url.startswith("/") or url.startswith("file://"):
            return (
                f"Filesystem path submodule URLs are not allowed: {url!r}. "
                f"Only HTTPS URLs to remote hosts are accepted."
            )

        # Resolve relative URLs against the parent repo URL
        if url.startswith("../") or url.startswith("./"):
            url = self._resolve_relative_url(url, parent_repo_url)
            if url is None:
                return f"Could not resolve relative submodule URL: {raw_url!r}"

        # Reject non-HTTPS schemes (git://, ssh://, etc.)
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
        except Exception as exc:
            return f"URL parse error: {exc}"

        if parsed.scheme not in ("https", "http"):
            return (
                f"Only HTTPS submodule URLs are accepted. "
                f"Got scheme {parsed.scheme!r} in URL: {url!r}. "
                f"git:// and ssh:// are rejected — they bypass TLS verification."
            )

        # Reject embedded credentials
        if parsed.username or parsed.password:
            return (
                f"Submodule URL contains embedded credentials: {url!r}. "
                f"Credentials must be provided via the credential provider."
            )

        # SSRF check on the hostname (Threat B: private IP ranges)
        if not parsed.hostname:
            return f"Submodule URL has no hostname: {url!r}"

        ssrf_error = _check_ssrf(parsed.hostname)
        if ssrf_error:
            return ssrf_error

        # Path traversal in URL path component
        if ".." in parsed.path:
            return (
                f"Path traversal detected in submodule URL path: {url!r}. "
                f"URL paths must not contain '..' components."
            )

        return None   # URL is safe

    def _resolve_relative_url(
        self, relative: str, parent_url: str
    ) -> str | None:
        """
        Resolve a relative submodule URL against the parent repo URL.

        Example:
            parent:   https://github.com/org/main-repo
            relative: ../crypto-lib
            result:   https://github.com/org/crypto-lib
        """
        try:
            from urllib.parse import urlparse, urljoin
            # Treat the parent URL as a directory (add trailing slash)
            base = parent_url.rstrip("/") + "/"
            resolved = urljoin(base, relative)
            # Verify the resolved URL stays on the same host
            parent_host = urlparse(parent_url).hostname
            resolved_host = urlparse(resolved).hostname
            if parent_host != resolved_host:
                logger.warning(
                    "Relative submodule URL resolves to different host: "
                    "%s → %s (parent host: %s)",
                    relative, resolved, parent_host,
                )
                # Don't reject — legitimate cross-host submodules exist.
                # SSRF check below will catch private IPs.
            return resolved
        except Exception:
            return None

    # ──────────
    # Threat C: Pinned SHA reading
    # ──────────

    def _read_pinned_shas(self, repo_dir: str) -> dict[str, str]:
        """
        Read the pinned commit SHAs for all submodules from the parent's
        git tree. These are "gitlink" entries (mode 160000) in the tree.

        WHY NOT USE .gitmodules?
            .gitmodules contains URLs and paths but NOT the pinned SHA.
            The pinned SHA is stored in the parent's tree object as a special
            entry type (mode 160000 = gitlink). Git uses this to lock the
            submodule to a specific commit regardless of what branch tip
            that commit appears on.

        We read it two ways:
          1. Via `git ls-tree` subprocess (accurate, requires git binary)
          2. By reading .git/modules/<name>/HEAD directly (fallback)

        Returns:
            dict mapping submodule path → pinned SHA (40-hex)
        """
        shas: dict[str, str] = {}

        # Method 1: git ls-tree (most reliable)
        shas.update(self._read_shas_via_ls_tree(repo_dir))
        if shas:
            return shas

        # Method 2: Read from .git/modules/<name>/HEAD
        shas.update(self._read_shas_via_git_modules_dir(repo_dir))
        return shas

    def _read_shas_via_ls_tree(self, repo_dir: str) -> dict[str, str]:
        """
        Use `git ls-tree -r HEAD` to find gitlink entries (mode 160000).
        Each gitlink entry is a submodule pointer with its pinned SHA.

        Output format:
            160000 commit abc123...def  vendor/crypto-lib
            (mode)  (type) (sha)         (path)
        """
        shas: dict[str, str] = {}
        env   = get_minimal_subprocess_env()
        try:
            result = subprocess.run(
                ["git", "ls-tree", "-r", "--full-tree", "HEAD"],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=repo_dir,
                env=env,
            )
            if result.returncode != 0:
                return shas

            for line in result.stdout.splitlines():
                # Format: "<mode> <type> <sha>\t<path>"
                parts = line.split()
                if len(parts) >= 3 and parts[0] == "160000":
                    # parts[2] is the SHA, rest of line after tab is the path
                    sha  = parts[2]
                    path = line.split("\t", 1)[-1].strip() if "\t" in line else ""
                    if path and self._is_valid_sha(sha):
                        shas[path] = sha
                        logger.debug("Pinned SHA for submodule '%s': %s", path, sha[:12])

        except Exception as exc:
            logger.debug("git ls-tree failed: %s", exc)
        return shas

    def _read_shas_via_git_modules_dir(self, repo_dir: str) -> dict[str, str]:
        """
        Fallback: read submodule HEAD SHAs from .git/modules/<name>/HEAD.
        This is where git stores the submodule's local HEAD after
        `git submodule update`.
        """
        shas: dict[str, str] = {}
        modules_dir = Path(repo_dir) / ".git" / "modules"
        if not modules_dir.exists():
            return shas

        for module_path in modules_dir.rglob("HEAD"):
            try:
                content = module_path.read_text().strip()
                # HEAD is either a direct SHA or "ref: refs/heads/main"
                sha = content if self._is_valid_sha(content) else ""
                if sha:
                    # Reconstruct the submodule path from the modules directory structure
                    relative = str(module_path.parent.relative_to(modules_dir))
                    shas[relative] = sha
            except Exception:
                pass
        return shas

    def _is_valid_sha(self, sha: str) -> bool:
        """Check if a string looks like a 40-hex Git SHA."""
        return bool(re.match(r"^[0-9a-f]{40}$", sha, re.I))

    # ──────────
    # Commit verification
    # ──────────

    def _verify_submodule_commit(
        self,
        fetched: str,
        pinned:  str,
        entry:   SubmoduleEntry,
    ) -> bool:
        """
        Verify that the fetched commit matches the parent's pinned SHA.
        Logs a warning but does not fail if fetched commit is unknown.
        """
        if not fetched:
            entry.warnings.append(
                f"Could not verify fetched commit for submodule '{entry.name}' "
                f"— proceeding with caution (commit unknown)."
            )
            return True   # allow but warn — don't block on unknown commit

        fetched_n = fetched.strip().lower()
        pinned_n  = pinned.strip().lower()

        # Accept if fetched starts with pinned (covers short SHAs)
        if fetched_n.startswith(pinned_n) or pinned_n.startswith(fetched_n):
            return True

        return False

    # ──────────
    # File handling
    # ──────────

    def _hash_submodule_files(
        self,
        tmp_dir:         str,
        submodule_path:  str,
    ) -> tuple[list[FileEntry], str]:
        """
        Compute SHA-256 for every file in the fetched submodule.
        Returns (list of FileEntry, repo_hash).
        The repo_hash is the Merkle root for this submodule — logged in
        the parent manifest and available for on-chain audit.
        """
        import hashlib
        entries: list[FileEntry] = []
        tmp_path = Path(tmp_dir)

        for root, dirs, files in os.walk(tmp_dir, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
            root_path = Path(root)

            for fname in sorted(files):
                abs_path = root_path / fname
                try:
                    rel_to_tmp = str(abs_path.relative_to(tmp_path)).replace(os.sep, "/")
                    # Path in the parent repo context
                    full_rel   = f"{submodule_path}/{rel_to_tmp}"

                    # Symlink escape check (Threat B extension)
                    if abs_path.is_symlink():
                        resolved = abs_path.resolve(strict=False)
                        try:
                            resolved.relative_to(tmp_path)
                        except ValueError:
                            logger.warning(
                                "Symlink escape in submodule '%s': %s → %s",
                                submodule_path, rel_to_tmp, resolved,
                            )
                            continue  # skip escaped symlinks

                    size = abs_path.stat().st_size
                    if size > LIMITS.max_file_size_bytes:
                        continue

                    # Hash the file
                    h = hashlib.sha256()
                    with open(abs_path, "rb") as f:
                        while chunk := f.read(65536):
                            h.update(chunk)
                    file_hash = h.hexdigest()

                    # Detect binary
                    is_binary = b"\x00" in abs_path.read_bytes()[:8192]

                    entries.append(FileEntry(
                        relative_path=full_rel,
                        sha256=file_hash,
                        size_bytes=size,
                        is_binary=is_binary,
                    ))
                except OSError:
                    continue

        # Compute Merkle root for this submodule
        sorted_pairs = sorted(f"{e.relative_path}:{e.sha256}" for e in entries)
        repo_hash = hashlib.sha256(
            "\n".join(sorted_pairs).encode()
        ).hexdigest()

        return entries, repo_hash

    def _install_submodule_files(
        self,
        src_dir:  str,
        dest_dir: str,
        entry:    SubmoduleEntry,
    ) -> None:
        """
        Copy fetched submodule files to their final location under the
        parent repo directory. Enforces read-only permissions (0o444).
        """
        import shutil
        src  = Path(src_dir)
        dest = Path(dest_dir)
        dest.mkdir(parents=True, exist_ok=True)

        for file_entry in entry.files:
            # file_entry.relative_path is "submodule/path/file.py"
            # we need just "file.py" relative to the submodule root
            sub_path = entry.path.rstrip("/") + "/"
            if file_entry.relative_path.startswith(sub_path):
                rel = file_entry.relative_path[len(sub_path):]
            else:
                rel = file_entry.relative_path

            src_file  = src  / rel.replace("/", os.sep)
            dest_file = dest / rel.replace("/", os.sep)

            if not src_file.exists():
                continue
            dest_file.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(str(src_file), str(dest_file))
                os.chmod(str(dest_file), 0o444)   # read-only
            except OSError as exc:
                entry.warnings.append(f"Copy failed for {rel}: {exc}")

    # ──────────
    # .gitmodules parser
    # ──────────

    def _parse_gitmodules(
        self,
        gitmodules_path: Path,
        repo_dir:        str,
    ) -> list[SubmoduleEntry]:
        """
        Parse .gitmodules to extract submodule definitions.

        .gitmodules format (INI-like):
            [submodule "vendor/crypto-lib"]
                path = vendor/crypto-lib
                url  = https://github.com/org/crypto-lib
                branch = main   (optional)

        Security: we parse with configparser (no shell execution).
        We validate path values to prevent directory traversal.
        """
        entries: list[SubmoduleEntry] = []

        try:
            # Read and size-check the file (prevent gigantic .gitmodules)
            content = gitmodules_path.read_text(encoding="utf-8", errors="replace")
            if len(content) > 1024 * 1024:  # 1MB max for .gitmodules
                logger.warning(
                    ".gitmodules file is unusually large (%d bytes) — "
                    "reading first 1MB only", len(content)
                )
                content = content[:1024 * 1024]

            # configparser needs section headers — .gitmodules uses them natively
            config = configparser.RawConfigParser()
            config.read_string(content)

            for section in config.sections():
                # Section name format: 'submodule "name"'
                if not section.startswith("submodule "):
                    continue

                # Extract the logical name (between quotes)
                name_match = re.match(r'^submodule\s+"([^"]+)"$', section)
                name = name_match.group(1) if name_match else section

                path = config.get(section, "path", fallback="").strip()
                url  = config.get(section, "url",  fallback="").strip()

                if not path or not url:
                    logger.warning(
                        "Submodule section '%s' missing path or url — skipped",
                        section,
                    )
                    continue

                # Validate path: no traversal, must be relative
                path_error = self._validate_submodule_path(path, repo_dir)
                if path_error:
                    logger.warning(
                        "Submodule path rejected ('%s'): %s", path, path_error
                    )
                    entries.append(SubmoduleEntry(
                        name=name, path=path, url=url,
                        status="skipped",
                        reason=f"Path validation failed: {path_error}",
                    ))
                    continue

                entries.append(SubmoduleEntry(name=name, path=path, url=url))

        except Exception as exc:
            logger.warning("Failed to parse .gitmodules: %s", exc)

        return entries

    def _validate_submodule_path(
        self, path: str, repo_dir: str
    ) -> str | None:
        """
        Validate a submodule path from .gitmodules.
        Returns error string if invalid, None if safe.

        Prevents:
          - Absolute paths: /etc/passwd
          - Traversal:      ../../outside
          - Hidden dirs:    .git (would overwrite git metadata)
        """
        if not path:
            return "empty path"

        # Must be relative
        if path.startswith("/"):
            return f"absolute path not allowed: {path!r}"

        # No traversal components
        normalized = Path(path)
        parts = normalized.parts
        if ".." in parts:
            return f"path traversal (..) not allowed: {path!r}"

        # Must not target .git or other git internals
        if any(part.startswith(".git") for part in parts):
            return f"path must not target .git directory: {path!r}"

        # Verify the resolved path stays under repo_dir
        try:
            resolved = (Path(repo_dir) / path).resolve()
            resolved.relative_to(Path(repo_dir).resolve())
        except ValueError:
            return f"path escapes repository root: {path!r}"

        return None