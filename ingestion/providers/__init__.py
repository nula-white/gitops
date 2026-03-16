"""
PRISM Ingestion Exception Hierarchy
=====================================
All exceptions are structured with:
  - A human-readable message (safe to log — never contains credentials)
  - An optional `code` for programmatic handling by the pipeline
  - An optional `details` dict for structured context (audit logging)
  - Proper __cause__ chaining so stack traces are always meaningful

Hierarchy:
  PRISMError                          (base)
  ├── IngestionError                  (anything in the ingestion layer)
  │   ├── CredentialError             (secret retrieval / zeroing)
  │   │   ├── CredentialNotFoundError
  │   │   ├── CredentialExpiredError
  │   │   └── CredentialZeroingError
  │   ├── TransportError              (network / TLS)
  │   │   ├── TLSVerificationError
  │   │   ├── SSRFBlockedError
  │   │   └── FetchTimeoutError
  │   ├── AuthenticationError         (token rejected by remote)
  │   │   └── TokenRevokedError
  │   ├── RepositoryError             (git object / ref issues)
  │   │   ├── CommitNotFoundError
  │   │   ├── BranchNotFoundError
  │   │   └── CommitMismatchError
  │   ├── IntegrityError              (manifest / hash verification)
  │   │   ├── SymlinkEscapeError
  │   │   ├── ManifestSealError
  │   │   └── CopyIntegrityError
  │   ├── ValidationError             (request / URL / input)
  │   │   ├── URLValidationError
  │   │   ├── BranchNameError
  │   │   └── CommitSHAError
  │   ├── SubmoduleError              (submodule resolution)
  │   │   ├── SubmoduleURLError
  │   │   ├── SubmoduleDepthError
  │   │   └── SubmoduleCommitError
  │   ├── SandboxError                (delivery / permissions)
  │   │   ├── PathPolicyViolation
  │   │   └── DeliveryError
  │   └── AdapterError                (VC platform adapter)
  │       ├── RateLimitError
  │       ├── PermissionDeniedError
  │       └── RepositoryNotFoundError
  └── VaultError                      (HashiCorp Vault integration)
      ├── VaultUnavailableError
      ├── VaultAuthError
      └── VaultSecretNotFoundError
"""

from __future__ import annotations
from typing import Any


# Base

class PRISMError(Exception):
    """
    Base class for all PRISM exceptions.
    Always safe to log — never contains credential material.
    """
    code: str = "PRISM_ERROR"

    def __init__(
        self,
        message:  str,
        code:     str | None       = None,
        details:  dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code    = code or self.__class__.code
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "error":   self.__class__.__name__,
            "code":    self.code,
            "message": self.message,
            "details": self.details,
        }

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(code={self.code!r}, message={self.message!r})"


# Ingestion layer

class IngestionError(PRISMError):
    """Base for all errors in the ingestion pipeline."""
    code = "INGESTION_ERROR"


# ── Credential errors ────────────────────────────────────────────────────────

class CredentialError(IngestionError):
    """Base for credential lifecycle errors."""
    code = "CREDENTIAL_ERROR"

class CredentialNotFoundError(CredentialError):
    """
    No credential exists for the given reference key.
    Raised by both VaultCredentialProvider and EnvCredentialProvider.
    """
    code = "CREDENTIAL_NOT_FOUND"

class CredentialExpiredError(CredentialError):
    """
    Token exists but has expired before use.
    The pipeline should request a fresh token and retry once.
    """
    code = "CREDENTIAL_EXPIRED"

class CredentialZeroingError(CredentialError):
    """
    Failed to zero credential memory after use.
    Non-fatal but must be logged — credential may persist in memory longer
    than intended. Does not abort the pipeline.
    """
    code = "CREDENTIAL_ZEROING_FAILED"


# ── Transport errors ─────────────────────────────────────────────────────────

class TransportError(IngestionError):
    """Base for network and TLS errors during Git fetch."""
    code = "TRANSPORT_ERROR"

class TLSVerificationError(TransportError):
    """
    TLS certificate validation failed.
    The connection is refused — we never accept invalid certificates.
    Details include: hostname, certificate subject, failure reason.
    """
    code = "TLS_VERIFICATION_FAILED"

class SSRFBlockedError(TransportError):
    """
    The target URL resolves to a private/reserved IP range.
    Server-Side Request Forgery (SSRF) defence activated.
    """
    code = "SSRF_BLOCKED"

class FetchTimeoutError(TransportError):
    """
    Git fetch exceeded the configured timeout.
    Details include: timeout_s, backend_used, bytes_received.
    """
    code = "FETCH_TIMEOUT"


# ── Authentication errors ────────────────────────────────────────────────────

class AuthenticationError(IngestionError):
    """
    Token was rejected by the remote Git host.
    Distinguishes from CredentialNotFoundError (secret exists but doesn't work).
    """
    code = "AUTHENTICATION_FAILED"

class TokenRevokedError(AuthenticationError):
    """
    Token existed in Vault but was revoked at the remote host.
    Pipeline should alert operator to rotate the token.
    """
    code = "TOKEN_REVOKED"


# ── Repository errors ────────────────────────────────────────────────────────

class RepositoryError(IngestionError):
    """Base for git object resolution errors."""
    code = "REPOSITORY_ERROR"

class CommitNotFoundError(RepositoryError):
    """
    The requested commit SHA does not exist in the fetched repository.
    Usually means the SHA was from a different repo or was force-pushed away.
    """
    code = "COMMIT_NOT_FOUND"

class BranchNotFoundError(RepositoryError):
    """The requested branch does not exist on the remote."""
    code = "BRANCH_NOT_FOUND"

class CommitMismatchError(RepositoryError):
    """
    The fetched HEAD commit does not match the pinned commit_sha.
    Possible repository tampering — pipeline aborts.
    Details include: expected_sha, actual_sha, repo_url.
    """
    code = "COMMIT_MISMATCH"


# ── Integrity errors ─────────────────────────────────────────────────────────

class IntegrityError(IngestionError):
    """Base for post-fetch integrity verification failures."""
    code = "INTEGRITY_ERROR"

class SymlinkEscapeError(IntegrityError):
    """
    A symlink in the repository resolves outside the repository root.
    Possible zip-slip / symlink escape attack. File rejected.
    Details include: symlink_path, resolved_target, repo_root.
    """
    code = "SYMLINK_ESCAPE"

class ManifestSealError(IntegrityError):
    """Failed to compute or seal the repository manifest."""
    code = "MANIFEST_SEAL_FAILED"

class CopyIntegrityError(IntegrityError):
    """
    SHA-256 of a delivered file does not match the manifest entry.
    Delivery of that file is aborted. Details include: path, expected, actual.
    """
    code = "COPY_INTEGRITY_MISMATCH"


# ── Validation errors ────────────────────────────────────────────────────────

class ValidationError(IngestionError):
    """Base for request / input validation failures."""
    code = "VALIDATION_ERROR"

class URLValidationError(ValidationError):
    """
    The repository URL failed validation.
    May indicate: wrong scheme, embedded credentials, SSRF target, malformed URL.
    """
    code = "URL_INVALID"

class BranchNameError(ValidationError):
    """Branch name contains shell metacharacters or unsafe patterns."""
    code = "BRANCH_NAME_INVALID"

class CommitSHAError(ValidationError):
    """Commit SHA is not a valid 7-40 hex string."""
    code = "COMMIT_SHA_INVALID"


# ── Submodule errors ─────────────────────────────────────────────────────────

class SubmoduleError(IngestionError):
    """Base for submodule resolution errors."""
    code = "SUBMODULE_ERROR"

class SubmoduleURLError(SubmoduleError):
    """
    A submodule URL in .gitmodules failed validation.
    Possible SSRF, non-HTTPS scheme, or embedded credentials.
    """
    code = "SUBMODULE_URL_INVALID"

class SubmoduleDepthError(SubmoduleError):
    """Maximum submodule nesting depth or count limit exceeded."""
    code = "SUBMODULE_DEPTH_EXCEEDED"

class SubmoduleCommitError(SubmoduleError):
    """
    Could not verify the fetched submodule commit against the parent's
    pinned SHA. Possible commit drift or tampering.
    """
    code = "SUBMODULE_COMMIT_MISMATCH"


# ── Sandbox errors ────────────────────────────────────────────────────────────

class SandboxError(IngestionError):
    """Base for sandbox delivery errors."""
    code = "SANDBOX_ERROR"

class PathPolicyViolation(SandboxError):
    """
    A path operation attempted to access a location outside the
    approved sandbox mount points. Possible path traversal attack.
    Details include: attempted_path, allowed_base.
    """
    code = "PATH_POLICY_VIOLATION"

class DeliveryError(SandboxError):
    """File copy to sandbox failed (permissions, disk space, etc.)."""
    code = "DELIVERY_FAILED"


# ── VC Adapter errors ────────────────────────────────────────────────────────

class AdapterError(IngestionError):
    """Base for VC platform adapter errors."""
    code = "ADAPTER_ERROR"

class RateLimitError(AdapterError):
    """
    Remote API rate limit exceeded.
    Details include: reset_at (epoch seconds), limit, remaining.
    The pipeline should back off until reset_at before retrying.
    """
    code = "RATE_LIMIT_EXCEEDED"

    def __init__(
        self,
        message:  str,
        reset_at: int   = 0,
        limit:    int   = 0,
        remaining: int  = 0,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            message,
            details={"reset_at": reset_at, "limit": limit, "remaining": remaining},
            **kwargs,
        )
        self.reset_at  = reset_at
        self.limit     = limit
        self.remaining = remaining

class PermissionDeniedError(AdapterError):
    """
    Token does not have the required scopes for this operation.
    Details include: required_scopes, token_scopes (if known).
    """
    code = "PERMISSION_DENIED"

class RepositoryNotFoundError(AdapterError):
    """
    Repository does not exist or is not accessible with the provided token.
    Could mean: repo is private, wrong URL, or repo was deleted.
    """
    code = "REPOSITORY_NOT_FOUND"


# Vault errors

class VaultError(PRISMError):
    """Base for HashiCorp Vault integration errors."""
    code = "VAULT_ERROR"

class VaultUnavailableError(VaultError):
    """
    Vault server is not reachable.
    Common causes: container not started, not unsealed, wrong VAULT_ADDR.
    """
    code = "VAULT_UNAVAILABLE"

class VaultAuthError(VaultError):
    """
    Vault authentication failed.
    Common causes: expired token, wrong AppRole credentials, policy mismatch.
    """
    code = "VAULT_AUTH_FAILED"

class VaultSecretNotFoundError(VaultError):
    """
    Secret path does not exist in Vault.
    Check that setup_prism_secrets.sh was run and the path is correct.
    """
    code = "VAULT_SECRET_NOT_FOUND"


# Re-export all for convenience

__all__ = [
    "PRISMError",
    # Ingestion
    "IngestionError",
    "CredentialError", "CredentialNotFoundError",
    "CredentialExpiredError", "CredentialZeroingError",
    "TransportError", "TLSVerificationError",
    "SSRFBlockedError", "FetchTimeoutError",
    "AuthenticationError", "TokenRevokedError",
    "RepositoryError", "CommitNotFoundError",
    "BranchNotFoundError", "CommitMismatchError",
    "IntegrityError", "SymlinkEscapeError",
    "ManifestSealError", "CopyIntegrityError",
    "ValidationError", "URLValidationError",
    "BranchNameError", "CommitSHAError",
    "SubmoduleError", "SubmoduleURLError",
    "SubmoduleDepthError", "SubmoduleCommitError",
    "SandboxError", "PathPolicyViolation", "DeliveryError",
    "AdapterError", "RateLimitError",
    "PermissionDeniedError", "RepositoryNotFoundError",
    # Vault
    "VaultError", "VaultUnavailableError",
    "VaultAuthError", "VaultSecretNotFoundError",
]