"""
Immutable data structures for the repository ingestion pipeline.

Design principles:
  - All models are frozen dataclasses (immutable after creation)
  - No credential material is ever stored in any model
  - Every model is JSON-serializable for audit logging
  - RepoManifest produces the Merkle root that goes on-chain
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


# Enumerations

class GitProvider(str, Enum):
    """Supported Git hosting providers."""
    GITHUB       = "github"
    GITLAB       = "gitlab"
    BITBUCKET    = "bitbucket"
    AZURE_DEVOPS = "azure_devops"
    GENERIC      = "generic"    # self-hosted Gitea, Forgejo, Gogs, plain Git


class IngestionStatus(str, Enum):
    SUCCESS   = "success"
    FAILED    = "failed"
    REJECTED  = "rejected"    # failed integrity check


class AuthMethod(str, Enum):
    """How the credential is delivered to the Git transport."""
    PAT         = "pat"           # Personal Access Token
    GITHUB_APP  = "github_app"    # GitHub App installation token (JWT-derived)
    OAUTH       = "oauth"         # OAuth2 Bearer token
    BASIC       = "basic"         # username:password (legacy, some self-hosted)
    SSH_KEY     = "ssh_key"       # SSH private key (future)


# Ingestion Request

@dataclass(frozen=True)
class IngestionRequest:
    """
    Everything the ingestion layer needs to fetch a repository.

    Security notes:
      - `credential_ref` is a reference KEY to a secret in the
        CredentialProvider — NOT the actual token. The token is
        fetched just-in-time during the Git callback and zeroed
        immediately after use.
      - `commit_sha` pins the exact commit to fetch. If None,
        the latest commit on `branch` is fetched AND its SHA is
        recorded for audit. Pinning is strongly preferred.
      - `output_dir` is validated against PATH_POLICY before use.
    """
    # Repository location
    repo_url:       str                  # e.g. https://github.com/org/repo
    provider:       GitProvider

    # What to fetch
    branch:         str        = "main"
    commit_sha:     str | None = None    # 40-hex SHA-1; None = HEAD of branch

    # Credential reference (not the credential itself)
    credential_ref: str        = ""      # key in CredentialProvider store
    auth_method:    AuthMethod = AuthMethod.PAT

    # Delivery target (will be validated against PATH_POLICY)
    output_dir:     str        = "/sandbox/repo"

    # Fetch behaviour
    depth:          int        = 1       # shallow clone depth (1 = HEAD only)
    timeout_s:      int        = 120     # max seconds for the entire fetch
    max_repo_size_mb: int      = 500     # reject repos larger than this

    # Pipeline correlation
    session_id:     str        = ""      # ties this fetch to a pipeline session
    operator_id:    str        = ""      # who triggered this ingestion

    def to_audit_dict(self) -> dict[str, Any]:
        """
        Produce an audit-safe dict — no credential material included.
        Used for blockchain event logging.
        """
        return {
            "repo_url":       self.repo_url,
            "provider":       self.provider.value,
            "branch":         self.branch,
            "commit_sha":     self.commit_sha,
            "auth_method":    self.auth_method.value,
            "output_dir":     self.output_dir,
            "depth":          self.depth,
            "session_id":     self.session_id,
            "operator_id":    self.operator_id,
            # credential_ref intentionally EXCLUDED
        }


# File entry in the repository manifest

@dataclass(frozen=True)
class FileEntry:
    """
    Single file in the repository, with its integrity hash.
    The hash is computed AFTER delivery to the sandbox — not during fetch.
    This ensures the hash reflects what the parser will actually see.
    """
    relative_path: str       # relative to repo root, forward slashes
    sha256:        str       # hex SHA-256 of file content
    size_bytes:    int
    is_binary:     bool      # binary files are recorded but not parsed

    def to_dict(self) -> dict[str, Any]:
        return {
            "path":       self.relative_path,
            "sha256":     self.sha256,
            "size_bytes": self.size_bytes,
            "is_binary":  self.is_binary,
        }


# Repository manifest

@dataclass
class RepoManifest:
    """
    Tamper-evident manifest of a fetched repository.

    The `repo_hash` is a Merkle-style root: SHA-256 of the
    sorted concatenation of all (path + sha256) pairs.
    This single hash represents the entire repository state
    and is what gets logged to the blockchain audit ledger.

    Immutable after `seal()` is called.
    """
    session_id:      str
    repo_url:        str
    provider:        str
    branch:          str
    fetched_commit:  str              # actual commit SHA fetched (may differ from request if None)
    fetch_timestamp: str              # ISO-8601 UTC
    files:           list[FileEntry]  = field(default_factory=list)
    repo_hash:       str              = ""       # populated by seal()
    total_files:     int              = 0
    total_bytes:     int              = 0
    rejected_files:  list[str]        = field(default_factory=list)  # symlink escapes etc.
    _sealed:         bool             = field(default=False, repr=False, compare=False)

    def add_file(self, entry: FileEntry) -> None:
        if self._sealed:
            raise RuntimeError("Cannot modify a sealed RepoManifest")
        self.files.append(entry)

    def reject_file(self, reason: str) -> None:
        if self._sealed:
            raise RuntimeError("Cannot modify a sealed RepoManifest")
        self.rejected_files.append(reason)

    def seal(self) -> str:
        """
        Compute and lock the repo_hash. Returns the hash.
        Called once all files have been added — after delivery to sandbox.

        Hash construction:
          For each file, sorted by relative_path (deterministic order):
            entry = f"{file.relative_path}:{file.sha256}"
          repo_hash = SHA-256( "\n".join(sorted_entries) )

        This means any single byte change in any file changes the repo_hash.
        """
        if self._sealed:
            return self.repo_hash

        self.total_files = len(self.files)
        self.total_bytes = sum(f.size_bytes for f in self.files)

        # Sort entries for determinism
        sorted_entries = sorted(
            f"{f.relative_path}:{f.sha256}"
            for f in self.files
        )
        payload = "\n".join(sorted_entries)
        self.repo_hash = hashlib.sha256(payload.encode()).hexdigest()
        self._sealed   = True
        return self.repo_hash

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id":      self.session_id,
            "repo_url":        self.repo_url,
            "provider":        self.provider,
            "branch":          self.branch,
            "fetched_commit":  self.fetched_commit,
            "fetch_timestamp": self.fetch_timestamp,
            "repo_hash":       self.repo_hash,
            "total_files":     self.total_files,
            "total_bytes":     self.total_bytes,
            "rejected_files":  self.rejected_files,
            "files":           [f.to_dict() for f in self.files],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


# Ingestion Result

@dataclass
class IngestionResult:
    """
    Final result of a repository ingestion attempt.
    Returned by IngestionPipeline.run() to the pipeline orchestrator.
    """
    status:          IngestionStatus
    request:         IngestionRequest
    manifest:        RepoManifest | None = None
    output_dir:      str                 = ""
    duration_ms:     float               = 0.0
    error:           str | None          = None
    warnings:        list[str]           = field(default_factory=list)

    @property
    def succeeded(self) -> bool:
        return self.status == IngestionStatus.SUCCESS

    def to_audit_dict(self) -> dict[str, Any]:
        """
        Audit-log-safe representation.
        The manifest's repo_hash is the on-chain entry.
        """
        return {
            "status":      self.status.value,
            "request":     self.request.to_audit_dict(),
            "repo_hash":   self.manifest.repo_hash if self.manifest else None,
            "output_dir":  self.output_dir,
            "duration_ms": self.duration_ms,
            "error":       self.error,
            "warnings":    self.warnings,
        }


# Extend RepoManifest with submodule tracking
# We extend via a separate field rather than modifying the frozen dataclass,
# since RepoManifest is mutable (sealed after construction).
# The submodule result is attached after seal() and serialized in to_dict().

def _attach_submodule_result(manifest: "RepoManifest", result: object) -> None:
    """
    Attach a SubmoduleResolutionResult to a RepoManifest.
    Called after manifest.seal() — does not affect the repo_hash.
    The submodule data is additional metadata for the audit log.
    """
    manifest.submodule_result = result  # type: ignore[attr-defined]

# Monkey-patch to_dict to include submodule data when present
_original_to_dict = RepoManifest.to_dict

def _to_dict_with_submodules(self) -> dict:
    d = _original_to_dict(self)
    sr = getattr(self, "submodule_result", None)
    if sr is not None:
        d["submodules"] = sr.to_dict()
    return d

RepoManifest.to_dict = _to_dict_with_submodules  # type: ignore[method-assign]