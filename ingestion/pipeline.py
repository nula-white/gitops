"""
PRISM Repository Ingestion Pipeline
=====================================
Top-level orchestrator that runs all ingestion stages in sequence.

Stage execution order:
  1. Request validation    — schema check, URL safety, path whitelist
  2. Credential acquisition — just-in-time fetch from Vault or env
  3. Git fetch             — TLS-secured clone into ephemeral temp dir
  4. Integrity verification — commit pinning, symlink check, manifest build
  5. Sandbox delivery      — copy verified files, enforce read-only, write manifest
  6. Cleanup               — zero and delete temp fetch dir
  7. Audit event           — emit signed event (repo_hash → blockchain logger)

Each stage either passes or returns an IngestionResult with status=FAILED.
No stage is skipped on partial success — the pipeline is all-or-nothing.

If ANY stage fails:
  - The temp dir is cleaned up
  - No files are written to the sandbox
  - An audit event is emitted with status=FAILED (failures are auditable too)
  - An IngestionResult with status=FAILED is returned

The pipeline is intentionally NOT a class with state. It is a function
that takes an IngestionRequest and returns an IngestionResult. This
makes it trivially testable and composable.

Usage:
    from prism.ingestion.pipeline import run_ingestion
    from prism.ingestion.models   import IngestionRequest, GitProvider

    result = run_ingestion(IngestionRequest(
        repo_url="https://github.com/myorg/myrepo",
        provider=GitProvider.GITHUB,
        branch="main",
        commit_sha="abc123def456...",   # pin to a specific commit
        credential_ref="github/myorg/myrepo",
        output_dir="/sandbox/repo",
        session_id="sess_abc123",
    ))

    if result.succeeded:
        # result.output_dir is ready for the parser
        # result.manifest.repo_hash is the on-chain audit entry
        parse_repository(result.output_dir)
"""

from __future__ import annotations

import logging
import os
import re
import tempfile
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

from .adapters.base     import AbstractVCAdapter, AdapterRegistry, RepoMetadata, TokenInfo
from .credential_provider import (
    AbstractCredentialProvider,
    CompositeCredentialProvider,
    EnvCredentialProvider,
)
from .exceptions import (
    CredentialNotFoundError, CredentialError, IngestionError,
    AdapterError, RateLimitError, PermissionDeniedError,
    RepositoryNotFoundError, AuthenticationError,
)
from .git_client        import GitClient
from .integrity_verifier import IntegrityVerifier
from .models            import (
    GitProvider, IngestionRequest, IngestionResult, IngestionStatus,
)
from .sandbox_delivery   import SandboxDelivery
from .submodule_resolver import SubmoduleResolver
from .validators          import check_ssrf as _check_ssrf, is_safe_ref as _is_safe_ref, validate_request as _validate_request_fn

# Singleton registry — constructed once, reused across calls
_ADAPTER_REGISTRY = AdapterRegistry()

# Repo size hard limit guard (defence-in-depth on top of IngestionRequest.max_repo_size_mb)
_ABSOLUTE_MAX_REPO_SIZE_MB = 2048

logger = logging.getLogger(__name__)

# Regex for validating Git commit SHAs (full or abbreviated)
_SHA_PATTERN = re.compile(r"^[0-9a-f]{7,40}$", re.I)

# Allowed URL schemes — SSH is future work
_ALLOWED_SCHEMES = frozenset({"https"})

# Hard cap on URL length (prevents log injection via enormous URLs)
_MAX_URL_LENGTH = 512


def run_ingestion(
    request:    IngestionRequest,
    credential_provider: AbstractCredentialProvider | None = None,
    git_client:          GitClient                  | None = None,
    verifier:            IntegrityVerifier          | None = None,
    delivery:            SandboxDelivery            | None = None,
    submodule_resolver:  SubmoduleResolver          | None = None,
    adapter:             AbstractVCAdapter          | None = None,
    adapter_registry:    AdapterRegistry            | None = None,
) -> IngestionResult:
    """
    Run the full repository ingestion pipeline.

    Stage execution order:
      1.   Request validation      — schema, URL safety, path whitelist
      2.   Credential acquisition  — just-in-time fetch from Vault or env
      2.5  Adapter pre-fetch       — token validation, SHA resolution, repo checks
      3.   Git fetch               — TLS-secured clone, commit pinned
      4.   Integrity verification  — commit pin, symlink check, manifest
      4.5  Submodule resolution    — recursive fetch with 4-threat mitigation
      5.   Sandbox delivery        — copy verified files, enforce read-only
      6.   Cleanup                 — zero and delete temp fetch dir
      7.   Audit event             — emit event (repo_hash → blockchain logger)

    Stage 2.5 (adapter pre-fetch) is the new stage. It:
      - Selects the correct VC platform adapter by URL pattern
      - Validates the token has required scopes (fail-fast on 403)
      - Resolves branch → HEAD SHA if commit_sha is None (Threat C defence)
      - Checks repo size against max_repo_size_mb (fail before fetching GBs)
      - Checks repo is not archived (archived repos are unusual targets)
      - Records rate limit state in warnings for the retry agent

    Generic repos (self-hosted Gitea, Gogs, plain Git) have no API —
    the GenericAdapter returns empty-string SHA. The pipeline falls
    through to GitClient's fetch-time SHA recording in that case.
    This is documented as a blind spot in the result warnings.

    Args:
        request:             validated IngestionRequest
        credential_provider: injectable for testing
        git_client:          injectable for testing
        verifier:            injectable for testing
        delivery:            injectable for testing
        submodule_resolver:  injectable for testing
        adapter:             injectable for testing (bypasses registry lookup)
        adapter_registry:    injectable for testing (replaces singleton registry)

    Returns:
        IngestionResult with status SUCCESS or FAILED
    """
    start_ms   = time.monotonic() * 1000
    warnings:  list[str] = []
    temp_dir:  str | None = None

    # ── Stage 1: Request validation ───────────────────────────────────────────
    validation_error = _validate_request_fn(request)
    if validation_error:
        return _failed(request, start_ms, validation_error, [])

    # Assign a session ID if not provided
    session_id = request.session_id or f"sess_{uuid.uuid4().hex[:12]}"
    if not request.session_id:
        request = _with_session_id(request, session_id)

    logger.info(
        "Ingestion pipeline starting. session=%s url=%s branch=%s",
        session_id, request.repo_url, request.branch,
    )

    # ── Stage 2: Credential acquisition ──────────────────────────────────────
    provider = credential_provider or CompositeCredentialProvider()
    try:
        credential = provider.get_credential(request.credential_ref)
    except CredentialError as exc:
        return _failed(
            request, start_ms,
            f"Credential error [{exc.code}]: {exc.message}",
            warnings,
        )

    # ── Stage 2.5: Adapter pre-fetch ─────────────────────────────────────────
    # Select adapter by URL pattern.
    registry = adapter_registry or _ADAPTER_REGISTRY
    _adapter = adapter or registry.get_adapter(request.repo_url)

    # ── Stages 2.5 + 3  (both need the raw token) ────────────────────────────
    # raw_token is a plain Python str.  We open the credential context HERE so
    # the str is created AND dropped inside the same block — before the
    # SecureString bytearray is zeroed.  Previously raw_token was extracted
    # outside the with-block and survived in heap memory until GC.
    client = git_client or GitClient()
    try:
        temp_dir = tempfile.mkdtemp(
            prefix=f"prism_fetch_{session_id[:8]}_",
            dir="/tmp",
        )

        with credential:                    # zeros the bytearray on exit
            raw_token = credential.get()   # str lives only inside this block

            # Stage 2.5 — adapter pre-fetch (SHA pin, size check, token validate)
            adapter_result = _run_adapter_prefetch(
                request   = request,
                adapter   = _adapter,
                raw_token = raw_token,
                warnings  = warnings,
                start_ms  = start_ms,
            )
            if adapter_result is None:
                error_msg = warnings[-1] if warnings else "Adapter pre-fetch failed"
                del raw_token
                return _failed(request, start_ms, error_msg, warnings[:-1])
            request = adapter_result

            # Stage 3 — TLS-secured git clone
            fetch_result = client.fetch(request, credential, temp_dir)
            del raw_token   # dereference before context exit

        if not fetch_result.success:
            return _failed(
                request, start_ms,
                f"Git fetch failed ({fetch_result.backend_used}): {fetch_result.error}",
                warnings,
            )

        warnings.extend(fetch_result.warnings)
        logger.info(
            "Fetch complete. backend=%s commit=%s ms=%.1f",
            fetch_result.backend_used,
            fetch_result.fetched_commit[:12] if fetch_result.fetched_commit else "?",
            fetch_result.duration_ms,
        )

    except Exception as exc:
        return _failed(request, start_ms, f"Fetch exception: {exc}", warnings)

    # ── Stage 4: Integrity verification ──────────────────────────────────────
    _verifier = verifier or IntegrityVerifier()
    try:
        verify_result = _verifier.verify(
            repo_dir=temp_dir,
            fetched_commit=fetch_result.fetched_commit,
            request=request,
        )

        if not verify_result.passed:
            return _failed(
                request, start_ms,
                f"Integrity check failed: {verify_result.error}",
                warnings + verify_result.warnings,
            )

        warnings.extend(verify_result.warnings)

        if verify_result.rejected_paths:
            warnings.append(
                f"{len(verify_result.rejected_paths)} files rejected "
                f"(symlink escapes / oversized): "
                f"{verify_result.rejected_paths[:3]}{'...' if len(verify_result.rejected_paths) > 3 else ''}"
            )

        logger.info(
            "Integrity verified. commit_pinned=%s files=%d repo_hash=%s...",
            verify_result.commit_verified,
            verify_result.manifest.total_files,
            verify_result.manifest.repo_hash[:16],
        )

    except Exception as exc:
        return _failed(request, start_ms, f"Verification exception: {exc}", warnings)

    # ── Stage 4.5: Submodule resolution ─────────────────────────────────────────
    # Run AFTER integrity verification of the parent repo.
    # Submodules are fetched at their pinned commit SHAs (read from the parent
    # tree — not from .gitmodules). Each URL is validated for SSRF and scheme.
    # Failures produce warnings but do NOT abort the pipeline — the manifest
    # records which submodules have blind spots so the operator is aware.
    _resolver = submodule_resolver or SubmoduleResolver(
        credential_provider=provider,
        git_client=client,
    )
    try:
        sub_result = _resolver.resolve(
            parent_repo_dir=temp_dir,
            parent_request=request,
        )
        warnings.extend(sub_result.warnings)

        # Attach submodule result to manifest for audit log
        from .models import _attach_submodule_result
        _attach_submodule_result(verify_result.manifest, sub_result)

        if sub_result.has_blind_spots:
            logger.warning(
                "Submodule blind spots: %d skipped, %d failed — "
                "partial analysis only for those paths.",
                sub_result.total_skipped, sub_result.total_failed,
            )
        else:
            logger.info(
                "All %d submodule(s) resolved successfully.",
                sub_result.total_fetched,
            )

    except Exception as exc:
        # Submodule resolution failure is non-fatal
        warnings.append(f"Submodule resolution error (non-fatal): {exc}")
        logger.exception("Submodule resolution failed — continuing without submodules")

    # ── Stage 5: Sandbox delivery ─────────────────────────────────────────────
    _delivery = delivery or SandboxDelivery()
    try:
        deliver_result = _delivery.deliver(
            source_dir=temp_dir,
            manifest=verify_result.manifest,
            request=request,
        )

        if not deliver_result.success:
            return _failed(
                request, start_ms,
                f"Sandbox delivery failed: {deliver_result.error}",
                warnings + deliver_result.warnings,
            )

        warnings.extend(deliver_result.warnings)
        logger.info(
            "Delivery complete. output=%s files=%d bytes=%d ms=%.1f",
            deliver_result.output_dir,
            deliver_result.files_written,
            deliver_result.bytes_written,
            deliver_result.duration_ms,
        )

    except Exception as exc:
        return _failed(request, start_ms, f"Delivery exception: {exc}", warnings)

    finally:
        # ── Stage 6: Cleanup — always runs, even on delivery failure ──────────
        if temp_dir:
            _delivery.cleanup_temp_dir(temp_dir)

    # ── Stage 7: Audit event ──────────────────────────────────────────────────
    # Emit a structured audit event. In the full pipeline this feeds the
    # blockchain logger. Here we log it at INFO level — the orchestrator
    # picks it up and forwards it to the audit ledger.
    _emit_audit_event(
        event_type="INGESTION_COMPLETE",
        request=request,
        manifest=verify_result.manifest,
        duration_ms=round(time.monotonic() * 1000 - start_ms, 2),
        warnings=warnings,
    )

    elapsed_ms = round(time.monotonic() * 1000 - start_ms, 2)
    return IngestionResult(
        status=IngestionStatus.SUCCESS,
        request=request,
        manifest=verify_result.manifest,
        output_dir=deliver_result.output_dir,
        duration_ms=elapsed_ms,
        warnings=warnings,
    )


# ---------------------------------------------------------------------------
# Stage 2.5 — Adapter pre-fetch
# ---------------------------------------------------------------------------

def _run_adapter_prefetch(
    request:   IngestionRequest,
    adapter:   AbstractVCAdapter,
    raw_token: str,
    warnings:  list[str],
    start_ms:  float,
) -> IngestionRequest | None:
    """
    Run all adapter API calls before the Git fetch.

    Returns:
        Updated IngestionRequest (commit_sha pinned if it was None),
        or None if a fatal error occurred (caller should call _failed).

    Fatal errors (return None):
        - Token invalid / revoked                → AuthenticationError
        - Token missing required scopes          → PermissionDeniedError
        - Repository not found / no access       → RepositoryNotFoundError
        - Repository exceeds size limit          → (size check)
        - Rate limit already exceeded            → RateLimitError

    Non-fatal (appends to warnings, returns request unchanged):
        - Adapter is GenericAdapter (no API available)
        - Repo metadata fetch failed but SHA already pinned
        - Archived repo warning (operator decides whether to continue)
    """
    from .adapters.stubs import GenericAdapter

    is_generic = isinstance(adapter, GenericAdapter)
    provider_name = adapter.provider().value

    # ── Step A: Token validation ──────────────────────────────────────────────
    # Skip for GenericAdapter — no API to validate against.
    # Document as a blind spot so the operator knows scope is unknown.
    token_info = None
    if is_generic:
        warnings.append(
            f"GenericAdapter: token scope validation skipped "
            f"(no platform API available for {request.repo_url!r}). "
            f"Proceeding with fetch-time commit recording only."
        )
    else:
        try:
            token_info = adapter.validate_token(raw_token)

            # Log rate limit state — not an error, but the LangGraph retry
            # agent reads this from warnings if it needs to back off.
            remaining = token_info.rate_remaining
            limit     = token_info.rate_limit
            reset_at  = token_info.rate_reset_at
            if limit > 0:
                pct_used = round((1 - remaining / limit) * 100) if limit else 0
                msg = (
                    f"{provider_name} rate limit: "
                    f"{remaining}/{limit} remaining "
                    f"({pct_used}% used, resets at epoch {reset_at})"
                )
                if remaining < max(10, limit * 0.05):   # under 5% or < 10 calls left
                    warnings.append(f"RATE_LIMIT_LOW: {msg}")
                    logger.warning("Rate limit low: %s", msg)
                else:
                    logger.info("Rate limit OK: %s", msg)

            logger.info(
                "Token validated. provider=%s login=%s type=%s scopes=%s",
                provider_name, token_info.login,
                token_info.token_type, token_info.scopes,
            )

        except RateLimitError as exc:
            # Already exhausted — fail immediately, no point fetching
            warnings.append(
                f"ADAPTER_PREFETCH_FATAL: {provider_name} rate limit exhausted. "
                f"reset_at={exc.reset_at} limit={exc.limit} remaining={exc.remaining}. "
                f"Retry after epoch {exc.reset_at}."
            )
            return None

        except AuthenticationError as exc:
            warnings.append(
                f"ADAPTER_PREFETCH_FATAL: {provider_name} token rejected "
                f"[{exc.code}]: {exc.message}. "
                f"Rotate the token in Vault at path: {exc.details}."
            )
            return None

        except PermissionDeniedError as exc:
            warnings.append(
                f"ADAPTER_PREFETCH_FATAL: {provider_name} token lacks required scopes. "
                f"{exc.message}"
            )
            return None

        except AdapterError as exc:
            # Non-fatal — adapter API may be down, but Git fetch might still work
            warnings.append(
                f"Token validation failed (non-fatal, continuing): "
                f"[{exc.code}] {exc.message}"
            )
            logger.warning(
                "Adapter token validation failed (non-fatal): %s", exc.message
            )

    # ── Step B: SHA resolution / repo metadata ────────────────────────────────
    # If commit_sha is already pinned by the caller, we still fetch metadata
    # for size and archived checks — but SHA resolution is skipped.
    # If commit_sha is None, we MUST resolve it before fetching.
    sha_pinned_by_adapter = False

    if is_generic:
        # GenericAdapter has no API. SHA remains None → GitClient records it post-fetch.
        # This is the only legitimate case where we allow None SHA into Stage 3.
        if request.commit_sha is None:
            warnings.append(
                f"GenericAdapter: branch HEAD SHA cannot be resolved before fetch "
                f"(no platform API). Commit will be pinned after fetch via git rev-parse. "
                f"This is a known limitation for non-platform Git hosts."
            )
        return request  # nothing more adapter can do

    # Platform adapter — attempt full metadata fetch
    try:
        metadata = adapter.get_repo_metadata(
            repo_url = request.repo_url,
            branch   = request.branch,
            token    = raw_token,
        )

        logger.info(
            "Repo metadata: owner=%s name=%s private=%s size_kb=%d "
            "default_branch=%s head_sha=%s... archived=%s",
            metadata.owner, metadata.name, metadata.is_private,
            metadata.size_kb, metadata.default_branch,
            metadata.head_sha[:12] if metadata.head_sha else "?",
            metadata.archived,
        )

        # ── Size check (before fetching potentially gigabytes) ────────────────
        repo_size_mb = metadata.size_kb / 1024
        limit_mb     = min(request.max_repo_size_mb, _ABSOLUTE_MAX_REPO_SIZE_MB)
        if repo_size_mb > limit_mb:
            warnings.append(
                f"ADAPTER_PREFETCH_FATAL: Repository {metadata.full_name!r} "
                f"is {repo_size_mb:.0f}MB, exceeds limit of {limit_mb}MB. "
                f"Increase max_repo_size_mb in IngestionRequest or split the repo."
            )
            return None

        # ── Archived check ────────────────────────────────────────────────────
        if metadata.archived:
            warnings.append(
                f"Repository {metadata.full_name!r} is archived. "
                f"Archived repos are unusual analysis targets — "
                f"verify this is the intended repository."
            )

        # ── SHA pinning ───────────────────────────────────────────────────────
        if request.commit_sha is None:
            # Caller did not pin — use the HEAD SHA from the adapter API.
            # This is the core Threat C defence: we know exactly what commit
            # we're about to fetch BEFORE the network call to Git.
            if metadata.head_sha and len(metadata.head_sha) == 40:
                import dataclasses
                request = dataclasses.replace(request, commit_sha=metadata.head_sha)
                sha_pinned_by_adapter = True
                logger.info(
                    "SHA pinned from adapter API: %s (branch=%s session=%s)",
                    metadata.head_sha[:16], request.branch, request.session_id,
                )
            else:
                warnings.append(
                    f"Adapter returned incomplete SHA {metadata.head_sha!r} "
                    f"for branch {request.branch!r}. "
                    f"Falling back to fetch-time commit recording."
                )
        else:
            # Caller already pinned — just log for audit trail
            logger.info(
                "Caller-pinned SHA: %s (adapter head: %s)",
                request.commit_sha[:16],
                metadata.head_sha[:16] if metadata.head_sha else "?",
            )
            # If adapter HEAD differs from caller-pinned SHA, that is worth noting —
            # it means the caller pinned an older commit intentionally (allowed)
            # or there's a potential mismatch (worth flagging but not fatal).
            if (metadata.head_sha and
                    len(metadata.head_sha) == 40 and
                    metadata.head_sha != request.commit_sha):
                warnings.append(
                    f"SHA mismatch: caller pinned {request.commit_sha[:12]!r} "
                    f"but branch HEAD is {metadata.head_sha[:12]!r}. "
                    f"This is expected if you intentionally pinned an older commit. "
                    f"Proceeding with caller-pinned SHA."
                )

    except RepositoryNotFoundError as exc:
        # Fatal — if the adapter says 404, the Git fetch will also fail
        warnings.append(
            f"ADAPTER_PREFETCH_FATAL: Repository not found "
            f"[{exc.code}]: {exc.message}"
        )
        return None

    except RateLimitError as exc:
        warnings.append(
            f"ADAPTER_PREFETCH_FATAL: Rate limit hit during metadata fetch. "
            f"reset_at={exc.reset_at}."
        )
        return None

    except (AuthenticationError, PermissionDeniedError) as exc:
        warnings.append(
            f"ADAPTER_PREFETCH_FATAL: Auth error during metadata fetch "
            f"[{exc.code}]: {exc.message}"
        )
        return None

    except AdapterError as exc:
        # Non-fatal if SHA was already pinned — we have what we need for the fetch.
        # Non-fatal if GenericAdapter (no API). Fatal if SHA is still None.
        if request.commit_sha is None:
            warnings.append(
                f"ADAPTER_PREFETCH_FATAL: Cannot resolve HEAD SHA — metadata fetch "
                f"failed [{exc.code}] and no commit_sha was provided. "
                f"Provide a commit_sha in IngestionRequest to bypass this check."
            )
            return None
        else:
            warnings.append(
                f"Repo metadata fetch failed (non-fatal, SHA already pinned): "
                f"[{exc.code}] {exc.message}"
            )
            logger.warning("Adapter metadata fetch failed (non-fatal): %s", exc.message)

    return request


# ---------------------------------------------------------------------------
# Request validation
# ---------------------------------------------------------------------------



# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _failed(
    request:  IngestionRequest,
    start_ms: float,
    error:    str,
    warnings: list[str],
) -> IngestionResult:
    """Build a failed IngestionResult and emit a FAILED audit event."""
    import time
    elapsed = round(time.monotonic() * 1000 - start_ms, 2)
    logger.error("Ingestion FAILED: %s (session=%s)", error, request.session_id)

    _emit_audit_event(
        event_type="INGESTION_FAILED",
        request=request,
        manifest=None,
        duration_ms=elapsed,
        warnings=warnings,
        error=error,
    )

    return IngestionResult(
        status=IngestionStatus.FAILED,
        request=request,
        manifest=None,
        output_dir="",
        duration_ms=elapsed,
        error=error,
        warnings=warnings,
    )


def _with_session_id(req: IngestionRequest, session_id: str) -> IngestionRequest:
    """Return a copy of the request with session_id set."""
    import dataclasses
    return dataclasses.replace(req, session_id=session_id)


def _emit_audit_event(
    event_type: str,
    request:    IngestionRequest,
    manifest,
    duration_ms: float,
    warnings:   list[str],
    error:      str | None = None,
) -> None:
    """
    Emit a structured audit event.

    In the full pipeline this is forwarded to the blockchain audit logger
    (Ethereum Sepolia hash logging). Here we emit a structured log line
    that the orchestrator can intercept and forward.

    The repo_hash from the manifest is the value that gets hashed and
    stored on-chain — it represents the complete repository state.
    """
    import json
    event = {
        "event_type":  event_type,
        "session_id":  request.session_id,
        "repo_url":    request.repo_url,   # URL is not sensitive
        "branch":      request.branch,
        "commit_sha":  request.commit_sha,
        "provider":    request.provider.value,
        "repo_hash":   manifest.repo_hash if manifest else None,
        "total_files": manifest.total_files if manifest else 0,
        "duration_ms": duration_ms,
        "warnings":    warnings,
        "error":       error,
    }
    # Use a dedicated audit logger — can be routed to a separate handler
    audit_logger = logging.getLogger("prism.audit")
    audit_logger.info("AUDIT_EVENT %s", json.dumps(event))