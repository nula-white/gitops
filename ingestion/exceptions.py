"""
PRISM Exception Hierarchy 

Single source of truth for all typed exceptions across the platform.

Design principles:
  1. Every exception carries: message (log-safe), code (machine-readable),
     details (structured context for audit events and LangGraph state)
  2. __cause__ chaining is always preserved — no bare `raise X` after `except`
  3. No exception message ever contains credential material
  4. Every exception is catchable at multiple levels of specificity:
       except TLSVerificationError   ← most specific
       except TransportError         ← category
       except IngestionError         ← layer
       except PRISMError             ← platform-wide

Agentic integration:
  Every exception's to_dict() output is safe to place in LangGraph state.
  The orchestration agent reads exception codes to decide routing:
    AUTHENTICATION_FAILED  → alert operator, halt pipeline
    RATE_LIMIT_EXCEEDED    → back off until reset_at, retry
    CREDENTIAL_NOT_FOUND   → try next credential provider
    COMMIT_MISMATCH        → security alert, quarantine session
    VAULT_UNAVAILABLE      → fall back to EnvCredentialProvider

Hierarchy:
  PRISMError
  ├── IngestionError
  │   ├── CredentialError
  │   │   ├── CredentialNotFoundError
  │   │   ├── CredentialExpiredError
  │   │   └── CredentialZeroingError
  │   ├── TransportError
  │   │   ├── TLSVerificationError
  │   │   ├── SSRFBlockedError
  │   │   └── FetchTimeoutError
  │   ├── AuthenticationError
  │   │   └── TokenRevokedError
  │   ├── RepositoryError
  │   │   ├── CommitNotFoundError
  │   │   ├── BranchNotFoundError
  │   │   └── CommitMismatchError
  │   ├── IntegrityError
  │   │   ├── SymlinkEscapeError
  │   │   ├── ManifestSealError
  │   │   └── CopyIntegrityError
  │   ├── ValidationError
  │   │   ├── URLValidationError
  │   │   ├── BranchNameError
  │   │   └── CommitSHAError
  │   ├── SubmoduleError
  │   │   ├── SubmoduleURLError
  │   │   ├── SubmoduleDepthError
  │   │   └── SubmoduleCommitError
  │   ├── SandboxError
  │   │   ├── PathPolicyViolation
  │   │   └── DeliveryError
  │   └── AdapterError
  │       ├── RateLimitError
  │       ├── PermissionDeniedError
  │       └── RepositoryNotFoundError
  ├── GraphBuildError                   ← graph builder layer
  │   ├── ParserUnavailableError
  │   ├── ASTBuildError
  │   ├── CFGBuildError
  │   ├── DFGBuildError
  │   ├── CPGAssemblyError
  │   ├── Neo4jWriteError
  │   ├── SARIFParseError
  │   └── TokenizationError
  └── VaultError
      ├── VaultUnavailableError
      ├── VaultAuthError
      └── VaultSecretNotFoundError
"""

from __future__ import annotations
from typing import Any


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------

class PRISMError(Exception):
    """
    Base class for all PRISM platform exceptions.

    Safe to log — message and details never contain credential material.
    Safe to serialize into LangGraph agent state via to_dict().
    """
    code: str = "PRISM_ERROR"

    def __init__(
        self,
        message:  str,
        code:     str | None            = None,
        details:  dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code    = code or self.__class__.code
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize to a dict safe for LangGraph state and audit logging.
        Used by the orchestration agent to read exception context.
        """
        return {
            "error":   self.__class__.__name__,
            "code":    self.code,
            "message": self.message,
            "details": self.details,
        }

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"code={self.code!r}, "
            f"message={self.message!r})"
        )


# ---------------------------------------------------------------------------
# Ingestion layer
# ---------------------------------------------------------------------------

class IngestionError(PRISMError):
    """
    Base for all errors in the repository ingestion pipeline.
    Raised by: validators, git_client, integrity_verifier,
                sandbox_delivery, submodule_resolver, VC adapters.
    """
    code = "INGESTION_ERROR"


# ── Credential errors ────────────────────────────────────────────────────────

class CredentialError(IngestionError):
    """
    Base for credential lifecycle failures.
    Agent routing: try next provider or alert operator.
    """
    code = "CREDENTIAL_ERROR"


class CredentialNotFoundError(CredentialError):
    """
    No credential exists for the requested reference key.
    Raised by: VaultCredentialProvider (path not found),
               EnvCredentialProvider (env var not set),
               CompositeCredentialProvider (all providers exhausted).

    Agent routing: if VAULT available → check path; else alert operator.
    """
    code = "CREDENTIAL_NOT_FOUND"


class CredentialExpiredError(CredentialError):
    """
    Token exists but has expired before or during use.
    Includes: SecureString accessed after zeroing, token TTL exceeded.

    Agent routing: request fresh token, retry once.
    """
    code = "CREDENTIAL_EXPIRED"


class CredentialZeroingError(CredentialError):
    """
    Failed to zero credential memory after use.
    Non-fatal — credential may persist in memory longer than intended.
    Always logged as WARNING; does not abort the pipeline.

    Agent routing: log to audit trail, continue pipeline.
    """
    code = "CREDENTIAL_ZEROING_FAILED"


# ── Transport errors ─────────────────────────────────────────────────────────

class TransportError(IngestionError):
    """
    Base for network and TLS errors during Git fetch or API calls.
    Always indicates a problem with the connection, not the content.
    """
    code = "TRANSPORT_ERROR"


class TLSVerificationError(TransportError):
    """
    TLS certificate validation failed.
    PRISM never accepts invalid certificates — connection is refused.

    details keys: hostname, certificate_subject, failure_reason
    Agent routing: security alert — possible MITM; do not retry.
    """
    code = "TLS_VERIFICATION_FAILED"


class SSRFBlockedError(TransportError):
    """
    Target URL resolves to a private/reserved/loopback IP range.
    Server-Side Request Forgery (SSRF) defence activated.

    details keys: hostname, resolved_ip, blocked_range
    Agent routing: security alert — possible SSRF attack in repo URL.
    """
    code = "SSRF_BLOCKED"


class FetchTimeoutError(TransportError):
    """
    Git fetch or API call exceeded the configured timeout.

    details keys: timeout_s, backend_used, bytes_received, url
    Agent routing: retry with exponential backoff (up to MAX_RETRIES).
    """
    code = "FETCH_TIMEOUT"


# ── Authentication errors ─────────────────────────────────────────────────────

class AuthenticationError(IngestionError):
    """
    Token was rejected by the remote Git host or API.
    Distinct from CredentialNotFoundError (token exists but doesn't work).

    details keys: status_code, url (sanitized, no credentials)
    Agent routing: alert operator to rotate token; halt pipeline.
    """
    code = "AUTHENTICATION_FAILED"


class TokenRevokedError(AuthenticationError):
    """
    Token existed in Vault but was explicitly revoked at the remote host.
    More specific than AuthenticationError — signals deliberate revocation
    vs. simple expiry or typo.

    Agent routing: force Vault secret rotation, alert operator.
    """
    code = "TOKEN_REVOKED"


# ── Repository errors ──────────────────────────────────────────────────────────

class RepositoryError(IngestionError):
    """Base for Git object and ref resolution errors."""
    code = "REPOSITORY_ERROR"


class CommitNotFoundError(RepositoryError):
    """
    Requested commit SHA does not exist in the fetched repository.
    Causes: SHA from different repo, force-push removed commit,
            shallow clone missing history.

    details keys: commit_sha, repo_url
    """
    code = "COMMIT_NOT_FOUND"


class BranchNotFoundError(RepositoryError):
    """
    Requested branch does not exist on the remote.

    details keys: branch, repo_url, available_branches (if known)
    """
    code = "BRANCH_NOT_FOUND"


class CommitMismatchError(RepositoryError):
    """
    Fetched HEAD commit does not match the caller-specified pinned SHA.
    SECURITY EVENT — possible repository tampering or race condition.

    details keys: expected_sha, actual_sha, repo_url, session_id
    Agent routing: SECURITY ALERT — quarantine session, emit blockchain event,
                   do NOT continue pipeline.
    """
    code = "COMMIT_MISMATCH"


# ── Integrity errors ──────────────────────────────────────────────────────────

class IntegrityError(IngestionError):
    """
    Base for post-fetch integrity verification failures.
    All subclasses are potential security events.
    """
    code = "INTEGRITY_ERROR"


class SymlinkEscapeError(IntegrityError):
    """
    A symlink in the repository resolves outside the repository root.
    SECURITY EVENT — symlink escape / zip-slip attack pattern.

    details keys: symlink_path, resolved_target, repo_root
    Agent routing: MALICIOUS classification candidate — route to
                   SecurityAnalysisAgent for MITRE ATT&CK correlation.
    """
    code = "SYMLINK_ESCAPE"


class ManifestSealError(IntegrityError):
    """
    Failed to compute or seal the repository file manifest.
    The audit trail entry cannot be created without a sealed manifest.

    details keys: stage_failed, file_count_processed, error_detail
    """
    code = "MANIFEST_SEAL_FAILED"


class CopyIntegrityError(IntegrityError):
    """
    SHA-256 of a delivered sandbox file does not match its manifest entry.
    SECURITY EVENT — file was modified between verification and delivery.

    details keys: file_path, expected_sha256, actual_sha256
    Agent routing: SECURITY ALERT — halt pipeline, audit the temp directory.
    """
    code = "COPY_INTEGRITY_MISMATCH"


# ── Validation errors ──────────────────────────────────────────────────────────

class ValidationError(IngestionError):
    """
    Base for request/input validation failures.
    These are caught before any network call is made.
    """
    code = "VALIDATION_ERROR"


class URLValidationError(ValidationError):
    """
    Repository URL failed validation.
    Causes: wrong scheme (not HTTPS), embedded credentials,
            SSRF target IP, malformed URL, excessive length.

    details keys: url_sanitized, failure_reason
    """
    code = "URL_INVALID"


class BranchNameError(ValidationError):
    """
    Branch name contains shell metacharacters or unsafe patterns.
    Prevents command injection in git subprocess calls.

    details keys: branch, rejected_pattern
    """
    code = "BRANCH_NAME_INVALID"


class CommitSHAError(ValidationError):
    """
    Commit SHA is not a valid 7–40 hex string.

    details keys: provided_sha
    """
    code = "COMMIT_SHA_INVALID"


# ── Submodule errors ───────────────────────────────────────────────────────────

class SubmoduleError(IngestionError):
    """
    Base for Git submodule resolution errors.
    Submodule failures are non-fatal by default — the manifest records
    blind spots and the pipeline continues with the parent repository.
    """
    code = "SUBMODULE_ERROR"


class SubmoduleURLError(SubmoduleError):
    """
    A submodule URL in .gitmodules failed validation.
    Causes: non-HTTPS scheme, embedded credentials,
            SSRF target, path traversal in URL.

    details keys: submodule_name, url_sanitized, failure_reason
    Agent routing: MALICIOUS classification candidate — malicious .gitmodules
                   is a supply-chain attack vector.
    """
    code = "SUBMODULE_URL_INVALID"


class SubmoduleDepthError(SubmoduleError):
    """
    Maximum submodule nesting depth or total count exceeded.
    Prevents recursive bomb attacks via nested submodules.

    details keys: current_depth, max_depth, total_count, max_count
    """
    code = "SUBMODULE_DEPTH_EXCEEDED"


class SubmoduleCommitError(SubmoduleError):
    """
    Cannot verify fetched submodule commit against parent's pinned SHA.
    Possible commit drift (benign) or supply-chain tampering (malicious).

    details keys: submodule_path, expected_sha, actual_sha
    """
    code = "SUBMODULE_COMMIT_MISMATCH"


# ── Sandbox errors ─────────────────────────────────────────────────────────────

class SandboxError(IngestionError):
    """Base for sandbox delivery and path enforcement errors."""
    code = "SANDBOX_ERROR"


class PathPolicyViolation(SandboxError):
    """
    A path operation attempted to access a location outside approved
    sandbox mount points. Possible path traversal attack.

    details keys: attempted_path, allowed_base, operation
    Agent routing: SECURITY ALERT — path traversal attempt.
    """
    code = "PATH_POLICY_VIOLATION"


class DeliveryError(SandboxError):
    """
    File copy to sandbox failed.
    Causes: permission error, disk full, target directory missing.

    details keys: source_path, dest_path, os_error
    """
    code = "DELIVERY_FAILED"


# ── VC Adapter errors ───────────────────────────────────────────────────────────

class AdapterError(IngestionError):
    """
    Base for Version Control platform adapter errors.
    Raised when the platform API returns an unexpected response.
    """
    code = "ADAPTER_ERROR"


class RateLimitError(AdapterError):
    """
    Remote API rate limit exceeded.
    Carries structured backoff information for the retry agent.

    details keys: reset_at (epoch s), limit (req/hr), remaining
    Agent routing: pause pipeline until reset_at, then retry.
    """
    code = "RATE_LIMIT_EXCEEDED"

    def __init__(
        self,
        message:   str,
        reset_at:  int = 0,
        limit:     int = 0,
        remaining: int = 0,
        **kwargs:  Any,
    ) -> None:
        super().__init__(
            message,
            details={
                "reset_at":  reset_at,
                "limit":     limit,
                "remaining": remaining,
            },
            **kwargs,
        )
        self.reset_at  = reset_at
        self.limit     = limit
        self.remaining = remaining


class PermissionDeniedError(AdapterError):
    """
    Token does not have required scopes for this operation.

    details keys: required_scopes, token_scopes, login, platform
    Agent routing: alert operator with specific scope requirements.
    """
    code = "PERMISSION_DENIED"


class RepositoryNotFoundError(AdapterError):
    """
    Repository does not exist or is inaccessible with the provided token.
    Causes: private repo + insufficient token scope, deleted repo, wrong URL.

    details keys: url_sanitized, status_code
    """
    code = "REPOSITORY_NOT_FOUND"


# ---------------------------------------------------------------------------
# Graph Builder layer
# ---------------------------------------------------------------------------

class GraphBuildError(PRISMError):
    """
    Base for all errors in the CPG construction pipeline.
    Raised by: AST parser, CFG builder, DFG builder,
               CPG assembler, Neo4j writer, SARIF parser,
               GraphCodeBERT tokenizer.

    Agent routing (RepositoryAnalysisAgent):
      - If file-level error: skip file, record blind spot, continue
      - If repo-level error: abort graph build, alert operator
    """
    code = "GRAPH_BUILD_ERROR"

    def __init__(
        self,
        message:   str,
        code:      str | None            = None,
        details:   dict[str, Any] | None = None,
        file_path: str | None            = None,
        language:  str | None            = None,
    ) -> None:
        super().__init__(message, code=code, details=details)
        if file_path:
            self.details["file_path"] = file_path
        if language:
            self.details["language"]  = language
        self.file_path = file_path
        self.language  = language


class ParserUnavailableError(GraphBuildError):
    """
    Tree-sitter grammar for the requested language is not installed
    or failed to load.

    details keys: language, available_languages
    Agent routing: skip files of this language, record coverage gap.
    """
    code = "PARSER_UNAVAILABLE"


class ASTBuildError(GraphBuildError):
    """
    Tree-sitter produced an AST with ERROR nodes, indicating a parse
    failure for the given source file.

    details keys: file_path, language, error_node_count,
                  error_positions (list of line:col)
    Agent routing: partial AST — attempt CFG/DFG on valid subtrees,
                   flag file as partially analyzed.
    """
    code = "AST_BUILD_ERROR"


class CFGBuildError(GraphBuildError):
    """
    Control Flow Graph construction failed for a function or block.
    Usually indicates an unsupported language construct in the CFG builder.

    details keys: file_path, function_name, language, construct_type
    Agent routing: skip this function's CFG edges, note as blind spot.
    """
    code = "CFG_BUILD_ERROR"


class DFGBuildError(GraphBuildError):
    """
    Data Flow Graph construction failed.
    Usually indicates a symbol table inconsistency or unsupported
    data flow pattern (e.g., complex destructuring, metaprogramming).

    details keys: file_path, function_name, language, variable_name
    """
    code = "DFG_BUILD_ERROR"


class CPGAssemblyError(GraphBuildError):
    """
    Merging AST + CFG + DFG into the unified CPG failed.
    Usually indicates a node ID collision or schema inconsistency.

    details keys: file_path, collision_node_ids, merge_stage
    """
    code = "CPG_ASSEMBLY_ERROR"


class Neo4jWriteError(GraphBuildError):
    """
    Writing the CPG to Neo4j failed.
    Causes: connection lost, constraint violation, transaction timeout,
            Neo4j unavailable.

    details keys: batch_size, nodes_written, edges_written, neo4j_error
    Agent routing: retry with smaller batch; if persistent, alert operator.
    """
    code = "NEO4J_WRITE_ERROR"


class SARIFParseError(GraphBuildError):
    """
    Failed to parse CodeQL SARIF output for security annotation injection.
    Non-fatal — graph is built without CodeQL security annotations.

    details keys: sarif_path, parse_error, results_count
    Agent routing: log warning, continue without SARIF annotations.
    """
    code = "SARIF_PARSE_ERROR"


class TokenizationError(GraphBuildError):
    """
    GraphCodeBERT tokenizer failed to encode a code fragment.
    Causes: fragment too long, encoding error, tokenizer unavailable.

    details keys: file_path, node_id, fragment_length, max_length
    Agent routing: store empty token_ids, flag node for manual review.
    """
    code = "TOKENIZATION_ERROR"


# ---------------------------------------------------------------------------
# Vault errors
# ---------------------------------------------------------------------------

class VaultError(PRISMError):
    """
    Base for HashiCorp Vault integration errors.
    Raised by VaultCredentialProvider.
    """
    code = "VAULT_ERROR"


class VaultUnavailableError(VaultError):
    """
    Vault server is not reachable or hvac library is not installed.
    Common causes: container not started, not unsealed, wrong VAULT_ADDR,
                   pip install hvac not run.

    details keys: vault_addr, reason
    Agent routing: fall back to EnvCredentialProvider if available.
    """
    code = "VAULT_UNAVAILABLE"


class VaultAuthError(VaultError):
    """
    Vault authentication failed.
    Causes: expired VAULT_TOKEN, wrong AppRole role_id/secret_id,
            AppRole policy does not permit reading the requested path.

    details keys: auth_method (token|approle), vault_addr
    Agent routing: alert operator — credential rotation may be needed.
    """
    code = "VAULT_AUTH_FAILED"


class VaultSecretNotFoundError(VaultError):
    """
    Secret path does not exist in Vault or the expected field
    (e.g., 'token') is missing from the secret's data.

    details keys: secret_path, expected_field, vault_addr
    Agent routing: alert operator — run setup_prism_secrets.sh
                   or populate the missing field manually.
    """
    code = "VAULT_SECRET_NOT_FOUND"


# ---------------------------------------------------------------------------
# Export all
# ---------------------------------------------------------------------------

__all__ = [
    # Base
    "PRISMError",
    # Ingestion
    "IngestionError",
    "CredentialError",
    "CredentialNotFoundError",
    "CredentialExpiredError",
    "CredentialZeroingError",
    "TransportError",
    "TLSVerificationError",
    "SSRFBlockedError",
    "FetchTimeoutError",
    "AuthenticationError",
    "TokenRevokedError",
    "RepositoryError",
    "CommitNotFoundError",
    "BranchNotFoundError",
    "CommitMismatchError",
    "IntegrityError",
    "SymlinkEscapeError",
    "ManifestSealError",
    "CopyIntegrityError",
    "ValidationError",
    "URLValidationError",
    "BranchNameError",
    "CommitSHAError",
    "SubmoduleError",
    "SubmoduleURLError",
    "SubmoduleDepthError",
    "SubmoduleCommitError",
    "SandboxError",
    "PathPolicyViolation",
    "DeliveryError",
    "AdapterError",
    "RateLimitError",
    "PermissionDeniedError",
    "RepositoryNotFoundError",
    # Graph Builder
    "GraphBuildError",
    "ParserUnavailableError",
    "ASTBuildError",
    "CFGBuildError",
    "DFGBuildError",
    "CPGAssemblyError",
    "Neo4jWriteError",
    "SARIFParseError",
    "TokenizationError",
    # Vault
    "VaultError",
    "VaultUnavailableError",
    "VaultAuthError",
    "VaultSecretNotFoundError",
]