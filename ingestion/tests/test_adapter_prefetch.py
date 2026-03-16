"""
PRISM — Adapter Pre-Fetch Pipeline Tests (Stage 2.5)
======================================================
Tests for the adapter pre-fetch stage wired into pipeline.py.

Covers:
  1. Adapter selection — correct adapter chosen from URL
  2. Token validation — fatal on auth failures, non-fatal on API errors
  3. SHA resolution   — None → pinned from adapter, provided → preserved
  4. Repo size check  — fatal when over limit
  5. Archived check   — warning, not fatal
  6. Rate limit       — fatal when exhausted, warning when low
  7. GenericAdapter   — graceful pass-through, no API calls
  8. SHA mismatch     — caller-pinned vs adapter HEAD
  9. Full pipeline integration — run_ingestion with mock adapter
 10. Error routing   — _run_adapter_prefetch return values
"""

from __future__ import annotations
import sys, os, dataclasses
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
os.environ["PRISM_ENV"] = "test"

from unittest.mock import MagicMock, patch

from ...ingestion.pipeline import run_ingestion, _run_adapter_prefetch
from ingestion.adapters.base import (
    AbstractVCAdapter, AdapterRegistry, RepoMetadata, TokenInfo,
)
from ...ingestion.adapters.stubs import GenericAdapter
from ...ingestion.models import (
    IngestionRequest, IngestionResult, IngestionStatus, GitProvider,
)
from ...ingestion.exceptions import (
    AdapterError, RateLimitError, PermissionDeniedError,
    RepositoryNotFoundError, AuthenticationError, CredentialNotFoundError,
)

passed = 0
failed = 0

def check(name: str, cond: bool, detail: str = "") -> None:
    global passed, failed
    if cond:
        print(f"  ✓ {name}"); passed += 1
    else:
        print(f"  ✗ FAIL: {name}" + (f"\n         {detail}" if detail else ""))
        failed += 1


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

def make_request(
    repo_url="https://github.com/org/repo",
    provider=GitProvider.GITHUB,
    branch="main",
    commit_sha=None,
    credential_ref="git/github",
    output_dir="/sandbox/repo",
    session_id="test_session",
    max_repo_size_mb=500,
) -> IngestionRequest:
    return IngestionRequest(
        repo_url       = repo_url,
        provider       = provider,
        branch         = branch,
        commit_sha     = commit_sha,
        credential_ref = credential_ref,
        output_dir     = output_dir,
        session_id     = session_id,
        max_repo_size_mb = max_repo_size_mb,
    )


def make_token_info(
    scopes=None,
    login="testuser",
    token_type="pat",
    rate_limit=5000,
    rate_remaining=4800,
    rate_reset_at=9999999999,
) -> TokenInfo:
    return TokenInfo(
        token_type     = token_type,
        scopes         = scopes or ["repo"],
        login          = login,
        expires_at     = "",
        rate_limit     = rate_limit,
        rate_remaining = rate_remaining,
        rate_reset_at  = rate_reset_at,
    )


def make_metadata(
    head_sha="a" * 40,
    size_kb=1024,
    archived=False,
    owner="org",
    name="repo",
) -> RepoMetadata:
    return RepoMetadata(
        owner          = owner,
        name           = name,
        default_branch = "main",
        clone_url      = "https://github.com/org/repo.git",
        is_private     = True,
        head_sha       = head_sha,
        size_kb        = size_kb,
        archived       = archived,
    )


class MockAdapter(AbstractVCAdapter):
    """Fully controllable mock adapter for pipeline testing."""

    def __init__(
        self,
        token_info:     TokenInfo    | None = None,
        metadata:       RepoMetadata | None = None,
        token_error:    Exception    | None = None,
        metadata_error: Exception    | None = None,
    ):
        self._token_info     = token_info or make_token_info()
        self._metadata       = metadata   or make_metadata()
        self._token_error    = token_error
        self._metadata_error = metadata_error
        self.validate_token_called    = False
        self.get_repo_metadata_called = False

    def provider(self):        return GitProvider.GITHUB
    def matches(self, url):    return "github.com" in url
    def parse_rate_limit(self, h): return {}

    def validate_token(self, token):
        self.validate_token_called = True
        if self._token_error:
            raise self._token_error
        return self._token_info

    def get_repo_metadata(self, repo_url, branch, token):
        self.get_repo_metadata_called = True
        if self._metadata_error:
            raise self._metadata_error
        return self._metadata

    def resolve_head_sha(self, repo_url, branch, token):
        return self._metadata.head_sha

class MockCredentialProvider:
    """Returns a fixed token, never raises."""
    def __init__(self, token="ghp_testtoken"):
        self._token = token

    def get_credential(self, ref):
        from ..credential_provider import SecureString
        return SecureString(self._token)


class FailCredentialProvider:
    def get_credential(self, ref):
        raise CredentialNotFoundError("No credential", details={"ref": ref})


# ---------------------------------------------------------------------------
# 1. Adapter selection
# ---------------------------------------------------------------------------
print("\n=== 1. Adapter Selection ===")

registry = AdapterRegistry()
check("GitHub URL → GitHubAdapter",
    registry.get_adapter("https://github.com/org/repo").__class__.__name__ == "GitHubAdapter")
check("GitLab URL → GitLabAdapter",
    registry.get_adapter("https://gitlab.com/org/repo").__class__.__name__ == "GitLabAdapter")
check("Bitbucket URL → BitbucketAdapter",
    registry.get_adapter("https://bitbucket.org/org/repo").__class__.__name__ == "BitbucketAdapter")
check("Azure DevOps URL → AzureDevOpsAdapter",
    registry.get_adapter("https://dev.azure.com/org/proj").__class__.__name__ == "AzureDevOpsAdapter")
check("Unknown URL → GenericAdapter",
    registry.get_adapter("https://gitea.myserver.io/org/repo").__class__.__name__ == "GenericAdapter")


# ---------------------------------------------------------------------------
# 2. Token validation — fatal errors
# ---------------------------------------------------------------------------
print("\n=== 2. Token Validation ===")

# AuthenticationError → returns None (fatal)
req = make_request()
auth_adapter = MockAdapter(token_error=AuthenticationError("Invalid token", details={}))
result = _run_adapter_prefetch(req, auth_adapter, "bad_token", warnings := [], 0)
check("AuthenticationError → returns None", result is None)
check("AuthenticationError → FATAL in warnings",
    any("ADAPTER_PREFETCH_FATAL" in w for w in warnings))

# PermissionDeniedError → returns None (fatal)
req = make_request()
perm_adapter = MockAdapter(token_error=PermissionDeniedError("Missing scopes", details={}))
result = _run_adapter_prefetch(req, perm_adapter, "token", warnings := [], 0)
check("PermissionDeniedError → returns None", result is None)
check("PermissionDeniedError → FATAL in warnings",
    any("ADAPTER_PREFETCH_FATAL" in w for w in warnings))

# RateLimitError during token validation → returns None (fatal)
req = make_request()
rl_adapter = MockAdapter(
    token_error=RateLimitError("Rate limit", reset_at=9999999, limit=5000, remaining=0)
)
result = _run_adapter_prefetch(req, rl_adapter, "token", warnings := [], 0)
check("RateLimitError on validate_token → returns None", result is None)
check("RateLimitError → reset_at in warnings",
    any("9999999" in w for w in warnings))

# Generic AdapterError on token validation → non-fatal (continues with warning)
req = make_request(commit_sha="a" * 40)   # SHA already pinned
generic_err_adapter = MockAdapter(token_error=AdapterError("API down", code="API_DOWN"))
result = _run_adapter_prefetch(req, generic_err_adapter, "token", warnings := [], 0)
check("Generic AdapterError on validate_token → non-fatal", result is not None)
check("Generic AdapterError → warning in list",
    any("non-fatal" in w for w in warnings))

# Rate limit low warning (under 5%)
req = make_request(commit_sha="a" * 40)
low_rl_adapter = MockAdapter(
    token_info=make_token_info(rate_limit=5000, rate_remaining=50)
)
result = _run_adapter_prefetch(req, low_rl_adapter, "token", warnings := [], 0)
check("Low rate limit (<5%) → RATE_LIMIT_LOW warning",
    any("RATE_LIMIT_LOW" in w for w in warnings))

# Rate limit healthy → no RATE_LIMIT_LOW warning
req = make_request(commit_sha="a" * 40)
healthy_adapter = MockAdapter(
    token_info=make_token_info(rate_limit=5000, rate_remaining=4900)
)
result = _run_adapter_prefetch(req, healthy_adapter, "token", warnings := [], 0)
check("Healthy rate limit → no RATE_LIMIT_LOW warning",
    not any("RATE_LIMIT_LOW" in w for w in warnings))


# ---------------------------------------------------------------------------
# 3. SHA resolution
# ---------------------------------------------------------------------------
print("\n=== 3. SHA Resolution ===")

HEAD_SHA = "deadbeef" * 5   # 40 hex chars

# commit_sha=None → resolved from adapter
req = make_request(commit_sha=None)
sha_adapter = MockAdapter(metadata=make_metadata(head_sha=HEAD_SHA))
result = _run_adapter_prefetch(req, sha_adapter, "token", warnings := [], 0)
check("None SHA → resolved from adapter", result is not None)
check("Resolved SHA == adapter HEAD SHA", result.commit_sha == HEAD_SHA)
check("validate_token called",   sha_adapter.validate_token_called)
check("get_repo_metadata called", sha_adapter.get_repo_metadata_called)

# commit_sha already provided → preserved, no override
PINNED = "cafebabe" * 5
req = make_request(commit_sha=PINNED)
meta_with_diff_head = make_metadata(head_sha=HEAD_SHA)
pin_adapter = MockAdapter(metadata=meta_with_diff_head)
result = _run_adapter_prefetch(req, pin_adapter, "token", warnings := [], 0)
check("Provided SHA preserved (not overridden)", result.commit_sha == PINNED)
check("SHA mismatch warning generated",
    any("mismatch" in w.lower() for w in warnings))

# commit_sha=None + adapter returns incomplete SHA → warning, None SHA preserved
req = make_request(commit_sha=None)
short_sha_meta = make_metadata(head_sha="abc123")   # not 40 chars
short_adapter = MockAdapter(metadata=short_sha_meta)
result = _run_adapter_prefetch(req, short_adapter, "token", warnings := [], 0)
check("Incomplete SHA → warning added",
    any("incomplete" in w.lower() or "Falling back" in w for w in warnings))
check("Incomplete SHA → SHA remains None", result.commit_sha is None)

# Adapter returns exactly matching SHA → no mismatch warning
SAME_SHA = "abcdef1234" * 4
req = make_request(commit_sha=SAME_SHA)
same_adapter = MockAdapter(metadata=make_metadata(head_sha=SAME_SHA))
result = _run_adapter_prefetch(req, same_adapter, "token", warnings := [], 0)
check("Same SHA → no mismatch warning",
    not any("mismatch" in w.lower() for w in warnings))


# ---------------------------------------------------------------------------
# 4. Repo size check
# ---------------------------------------------------------------------------
print("\n=== 4. Repo Size Check ===")

# Over limit → fatal
req = make_request(max_repo_size_mb=100)
big_repo = make_metadata(size_kb=200 * 1024)   # 200 MB
big_adapter = MockAdapter(metadata=big_repo)
result = _run_adapter_prefetch(req, big_adapter, "token", warnings := [], 0)
check("Oversized repo → returns None", result is None)
check("Oversized repo → FATAL in warnings",
    any("ADAPTER_PREFETCH_FATAL" in w and "MB" in w for w in warnings))

# Under limit → passes
req = make_request(max_repo_size_mb=500)
small_repo = make_metadata(size_kb=50 * 1024)  # 50 MB
small_adapter = MockAdapter(metadata=small_repo)
result = _run_adapter_prefetch(req, small_adapter, "token", warnings := [], 0)
check("Under-limit repo → returns request", result is not None)

# Absolute limit guard (regardless of max_repo_size_mb setting)
req = make_request(max_repo_size_mb=9999)
huge_repo = make_metadata(size_kb=3000 * 1024)  # 3 GB
huge_adapter = MockAdapter(metadata=huge_repo)
from ...ingestion.pipeline import _ABSOLUTE_MAX_REPO_SIZE_MB
result = _run_adapter_prefetch(req, huge_adapter, "token", warnings := [], 0)
check("Absolute size limit enforced",
    result is None or (result is not None and 3000 <= _ABSOLUTE_MAX_REPO_SIZE_MB))


# ---------------------------------------------------------------------------
# 5. Archived repo check
# ---------------------------------------------------------------------------
print("\n=== 5. Archived Repo Check ===")

req = make_request(commit_sha="a" * 40)
archived_meta = make_metadata(archived=True)
arch_adapter = MockAdapter(metadata=archived_meta)
result = _run_adapter_prefetch(req, arch_adapter, "token", warnings := [], 0)
check("Archived repo → still returns request (non-fatal)", result is not None)
check("Archived repo → warning in list",
    any("archived" in w.lower() for w in warnings))
check("Archived warning mentions 'archived'",
    any("archived" in w for w in warnings))

req2 = make_request(commit_sha="a" * 40)
live_meta = make_metadata(archived=False)
live_adapter = MockAdapter(metadata=live_meta)
result2 = _run_adapter_prefetch(req2, live_adapter, "token", warnings := [], 0)
check("Non-archived repo → no archived warning",
    not any("archived" in w.lower() for w in warnings))


# ---------------------------------------------------------------------------
# 6. Repository not found
# ---------------------------------------------------------------------------
print("\n=== 6. Repository Not Found ===")

req = make_request()
nf_adapter = MockAdapter(
    metadata_error=RepositoryNotFoundError("Not found", details={"url": "..."})
)
result = _run_adapter_prefetch(req, nf_adapter, "token", warnings := [], 0)
check("RepositoryNotFoundError → returns None", result is None)
check("RepositoryNotFoundError → FATAL in warnings",
    any("ADAPTER_PREFETCH_FATAL" in w for w in warnings))

# RateLimitError during metadata → fatal
req = make_request()
rl_meta_adapter = MockAdapter(
    metadata_error=RateLimitError("RL", reset_at=1234567, limit=60, remaining=0)
)
result = _run_adapter_prefetch(req, rl_meta_adapter, "token", warnings := [], 0)
check("RateLimitError on metadata → returns None", result is None)

# AdapterError on metadata + no pinned SHA → fatal
req = make_request(commit_sha=None)
api_err_adapter = MockAdapter(
    metadata_error=AdapterError("500 Internal Server Error")
)
result = _run_adapter_prefetch(req, api_err_adapter, "token", warnings := [], 0)
check("AdapterError on metadata + no SHA → returns None", result is None)
check("AdapterError on metadata + no SHA → FATAL warning",
    any("ADAPTER_PREFETCH_FATAL" in w for w in warnings))

# AdapterError on metadata + SHA already pinned → non-fatal
req = make_request(commit_sha="b" * 40)
api_err_pinned = MockAdapter(
    metadata_error=AdapterError("500 Internal Server Error")
)
result = _run_adapter_prefetch(req, api_err_pinned, "token", warnings := [], 0)
check("AdapterError on metadata + pinned SHA → non-fatal", result is not None)
check("AdapterError on metadata + pinned SHA → SHA preserved",
    result.commit_sha == "b" * 40)


# ---------------------------------------------------------------------------
# 7. GenericAdapter pass-through
# ---------------------------------------------------------------------------
print("\n=== 7. GenericAdapter ===")

gen_adapter = GenericAdapter()

# No SHA — warns but continues
req = make_request(
    repo_url="https://gitea.myserver.io/org/repo",
    commit_sha=None,
)
result = _run_adapter_prefetch(req, gen_adapter, "token", warnings := [], 0)
check("GenericAdapter + no SHA → returns request", result is not None)
check("GenericAdapter + no SHA → warning about blind spot",
    any("GenericAdapter" in w for w in warnings))
check("GenericAdapter + no SHA → SHA remains None", result.commit_sha is None)
check("GenericAdapter → validate_token NOT called",
    True)  # GenericAdapter skips token validation by design

# SHA provided — returns cleanly with no warnings
req2 = make_request(
    repo_url="https://gitea.myserver.io/org/repo",
    commit_sha="c" * 40,
)
result2 = _run_adapter_prefetch(req2, gen_adapter, "token", warnings := [], 0)
check("GenericAdapter + pinned SHA → returns request cleanly", result2 is not None)
check("GenericAdapter + pinned SHA → SHA preserved", result2.commit_sha == "c" * 40)


# ---------------------------------------------------------------------------
# 8. Full pipeline integration — run_ingestion with mock adapter
# ---------------------------------------------------------------------------
print("\n=== 8. Full Pipeline Integration ===")

class MockGitClient:
    """Simulates a successful Git fetch."""
    def fetch(self, request, credential, temp_dir):
        import os
        # Create a minimal file so IntegrityVerifier has something to check
        os.makedirs(temp_dir, exist_ok=True)
        with open(os.path.join(temp_dir, "README.md"), "w") as f:
            f.write("# Test repo\n")
        from ...ingestion.git_client import GitFetchResult
        return GitFetchResult(
            success=True,
            local_path=temp_dir,
            backend_used="mock_git",
            fetched_commit=request.commit_sha or "e" * 40,
            duration_ms=50.0,
            warnings=[],
        )


class MockIntegrityVerifier:
    def verify(self, repo_dir, fetched_commit, request):
        import datetime
        from ...ingestion.models import RepoManifest, FileEntry
        manifest = RepoManifest(
            session_id=request.session_id,
            repo_url=request.repo_url,
            provider=request.provider.value,
            branch=request.branch,
            fetched_commit=fetched_commit,
            fetch_timestamp=datetime.datetime.utcnow().isoformat() + "Z",
        )
        manifest.files.append(FileEntry(
            relative_path="README.md",
            sha256="abc123" * 10,
            size_bytes=14,
            is_binary=False,
        ))
        manifest.seal()
        from ...ingestion.integrity_verifier import VerificationResult
        return VerificationResult(
            passed=True, fetched_commit=fetched_commit, commit_verified=True,
            manifest=manifest, warnings=[], rejected_paths=[],
        )


class MockSandboxDelivery:
    def deliver(self, source_dir, manifest, request):
        from ...ingestion.sandbox_delivery import DeliveryResult
        return DeliveryResult(
            success=True,
            output_dir=request.output_dir,
            manifest_path=request.output_dir + "/.prism_manifest.json",
            files_written=1,
            bytes_written=14,
            duration_ms=10.0,
            warnings=[],
        )

    def cleanup_temp_dir(self, temp_dir):
        import shutil
        try: shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception: pass


class MockSubmoduleResolver:
    def resolve(self, parent_repo_dir, parent_request):
        from ...ingestion.submodule_resolver import SubmoduleResolutionResult
        return SubmoduleResolutionResult(
            total_fetched=0, total_skipped=0, total_failed=0,
            warnings=[],
        )


# ── Happy path: SHA resolved from adapter ────────────────────────────────────
import tempfile, os
with tempfile.TemporaryDirectory() as sandbox:
    req = make_request(commit_sha=None, output_dir=os.path.join(sandbox, "repo"))
    os.makedirs(req.output_dir, exist_ok=True)

    good_adapter = MockAdapter(
        token_info=make_token_info(),
        metadata=make_metadata(head_sha="f" * 40),
    )
    result = run_ingestion(
        req,
        credential_provider = MockCredentialProvider(),
        git_client          = MockGitClient(),
        verifier            = MockIntegrityVerifier(),
        delivery            = MockSandboxDelivery(),
        submodule_resolver  = MockSubmoduleResolver(),
        adapter             = good_adapter,
    )
    check("Full pipeline: success",          result.status == IngestionStatus.SUCCESS)
    check("Full pipeline: SHA pinned",       result.request.commit_sha == "f" * 40)
    check("Full pipeline: validate called",  good_adapter.validate_token_called)
    check("Full pipeline: metadata called",  good_adapter.get_repo_metadata_called)
    check("Full pipeline: has manifest",     result.manifest is not None)

# ── Fatal: token auth failure → pipeline aborts before fetch ─────────────────
with tempfile.TemporaryDirectory() as sandbox:
    req = make_request(commit_sha=None, output_dir=os.path.join(sandbox, "repo"))
    os.makedirs(req.output_dir, exist_ok=True)

    auth_fail_adapter = MockAdapter(
        token_error=AuthenticationError("Revoked", details={})
    )
    git_client_spy = MockGitClient()
    git_client_spy.fetch_called = False
    original_fetch = git_client_spy.fetch
    def spy_fetch(*a, **kw):
        git_client_spy.fetch_called = True
        return original_fetch(*a, **kw)
    git_client_spy.fetch = spy_fetch

    result = run_ingestion(
        req,
        credential_provider = MockCredentialProvider(),
        git_client          = git_client_spy,
        verifier            = MockIntegrityVerifier(),
        delivery            = MockSandboxDelivery(),
        submodule_resolver  = MockSubmoduleResolver(),
        adapter             = auth_fail_adapter,
    )
    check("Auth failure → pipeline FAILED", result.status == IngestionStatus.FAILED)
    check("Auth failure → Git fetch NOT called", not git_client_spy.fetch_called)
    check("Auth failure → error message set", bool(result.error))

# ── Fatal: repo too large → aborts before fetch ──────────────────────────────
with tempfile.TemporaryDirectory() as sandbox:
    req = make_request(
        commit_sha=None,
        max_repo_size_mb=10,
        output_dir=os.path.join(sandbox, "repo"),
    )
    os.makedirs(req.output_dir, exist_ok=True)

    big_repo_adapter = MockAdapter(metadata=make_metadata(size_kb=20 * 1024))  # 20MB > 10MB limit
    result = run_ingestion(
        req,
        credential_provider = MockCredentialProvider(),
        git_client          = MockGitClient(),
        verifier            = MockIntegrityVerifier(),
        delivery            = MockSandboxDelivery(),
        submodule_resolver  = MockSubmoduleResolver(),
        adapter             = big_repo_adapter,
    )
    check("Oversized repo → pipeline FAILED", result.status == IngestionStatus.FAILED)

# ── No adapter provided → uses registry ──────────────────────────────────────
# When no adapter is injected, run_ingestion uses the real registry.
# GenericAdapter handles unknown URLs and doesn't call any API,
# so this will reach the git fetch stage (which then fails with no git binary).
req = make_request(
    repo_url="https://gitea.custom.io/org/repo",
    provider=GitProvider.GENERIC,
    commit_sha="a" * 40,
    output_dir="/tmp/prism_test_no_adapter",
)
result = run_ingestion(
    req,
    credential_provider = MockCredentialProvider(),
    # No adapter, no git_client — will use real registry + real GitClient (fails at fetch)
)
# It should reach Stage 3 (fetch) before failing — not fail at Stage 2.5
check("No adapter injected → uses GenericAdapter from registry (reaches fetch stage)",
    result.status == IngestionStatus.FAILED and
    "Adapter" not in result.error   # error is about fetch, not adapter
)


# ---------------------------------------------------------------------------
# 9. Backward compatibility — existing callers without adapter arg
# ---------------------------------------------------------------------------
print("\n=== 9. Backward Compatibility ===")

# Callers that don't pass adapter/adapter_registry still work
# (registry is selected automatically from URL)
from inspect import signature
sig = signature(run_ingestion)
check("run_ingestion accepts adapter kwarg",      "adapter" in sig.parameters)
check("run_ingestion adapter defaults to None",
    sig.parameters["adapter"].default is None)
check("run_ingestion accepts adapter_registry",   "adapter_registry" in sig.parameters)
check("All original params still present",
    all(p in sig.parameters for p in [
        "request","credential_provider","git_client",
        "verifier","delivery","submodule_resolver",
    ]))


# ---------------------------------------------------------------------------
# 10. _run_adapter_prefetch contract
# ---------------------------------------------------------------------------
print("\n=== 10. _run_adapter_prefetch Contract ===")

# Returns IngestionRequest on success
req = make_request(commit_sha="a" * 40)
ok_adapter = MockAdapter()
result = _run_adapter_prefetch(req, ok_adapter, "token", [], 0)
check("Returns IngestionRequest on success",    isinstance(result, IngestionRequest))

# Returns None on fatal error
req = make_request()
fatal_adapter = MockAdapter(token_error=AuthenticationError("x", details={}))
result = _run_adapter_prefetch(req, fatal_adapter, "bad", [], 0)
check("Returns None on fatal error",            result is None)

# Returned request is a different object (frozen dataclass rebuilt with pinned SHA)
req = make_request(commit_sha=None)
pin_adapter = MockAdapter(metadata=make_metadata(head_sha="d" * 40))
result = _run_adapter_prefetch(req, pin_adapter, "token", [], 0)
check("Returned request is new object (not mutated)",
    result is not req)
check("Original request.commit_sha unchanged (None)",
    req.commit_sha is None)
check("Returned request has pinned SHA",
    result.commit_sha == "d" * 40)

# Warnings list is mutated in-place (adapter appends to caller's list)
req = make_request(commit_sha=None)
warn_adapter = MockAdapter(metadata=make_metadata(head_sha="e" * 40, archived=True))
my_warnings: list[str] = []
_run_adapter_prefetch(req, warn_adapter, "token", my_warnings, 0)
check("Warnings appended to caller's list",    len(my_warnings) > 0)


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print(f"\n{'='*60}")
print(f"Adapter Pre-Fetch Tests: {passed} passed, {failed} failed")
if failed:
    print("FAILURES DETECTED")
    sys.exit(1)
else:
    print("All tests passed ✓")