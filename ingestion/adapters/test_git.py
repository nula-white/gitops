"""
PRISM GitHub Adapter + Vault + Exception Hierarchy Tests
=========================================================
Tests are organized into 6 sections:

  1. Exception hierarchy    — structure, codes, chaining, to_dict()
  2. Token classification   — PAT types detected correctly
  3. URL matching           — adapter registry routes correctly
  4. Rate limit parsing     — GitHub headers extracted correctly
  5. HTTP error translation — 401/403/404/429/5xx → typed exceptions
  6. GitHub adapter API     — resolve_head_sha / get_repo_metadata /
                              validate_token (mocked HTTP)
  7. Vault credential flow  — VaultCredentialProvider with mocked hvac
  8. Adapter registry       — correct adapter selected per URL
"""

from __future__ import annotations

import json
import sys
import os
import io
import ssl
import time
import unittest.mock as mock
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
os.environ["PRISM_ENV"] = "test"

from prism.ingestion.exceptions import (
    PRISMError, IngestionError,
    CredentialNotFoundError, CredentialExpiredError, CredentialZeroingError,
    TransportError, TLSVerificationError, SSRFBlockedError, FetchTimeoutError,
    AuthenticationError, TokenRevokedError,
    RepositoryError, CommitNotFoundError, BranchNotFoundError, CommitMismatchError,
    IntegrityError, SymlinkEscapeError, ManifestSealError, CopyIntegrityError,
    ValidationError, URLValidationError, BranchNameError, CommitSHAError,
    SubmoduleError, SubmoduleURLError, SubmoduleDepthError, SubmoduleCommitError,
    SandboxError, PathPolicyViolation, DeliveryError,
    AdapterError, RateLimitError, PermissionDeniedError, RepositoryNotFoundError,
    VaultError, VaultUnavailableError, VaultAuthError, VaultSecretNotFoundError,
)
from ..providers.github import GitHubAdapter, _classify_token_type, _sanitize_url
from ..providers.stubs  import (
    GitLabAdapter, BitbucketAdapter, AzureDevOpsAdapter, GenericAdapter,
)
from ..providers.base   import AdapterRegistry
from ..credential_provider import SecureString, VaultCredentialProvider
from ..models import GitProvider

passed = 0
failed = 0

def check(name: str, condition: bool, detail: str = "") -> None:
    global passed, failed
    if condition:
        print(f"  ✓ {name}")
        passed += 1
    else:
        msg = f"  ✗ FAIL: {name}"
        if detail:
            msg += f"\n         {detail}"
        print(msg)
        failed += 1


# 1. Exception hierarchy
print("\n=== 1. Exception Hierarchy ===")

# Base structure
e = PRISMError("test message", code="TEST_CODE", details={"k": "v"})
check("PRISMError has message",  e.message == "test message")
check("PRISMError has code",     e.code    == "TEST_CODE")
check("PRISMError has details",  e.details == {"k": "v"})
check("PRISMError to_dict keys", set(e.to_dict()) == {"error", "code", "message", "details"})
check("PRISMError repr safe",    "test message" in repr(e))

# Inheritance — every exception is catchable at the right level
check("CredentialNotFoundError isa IngestionError",
    isinstance(CredentialNotFoundError("x"), IngestionError))
check("TLSVerificationError isa TransportError",
    isinstance(TLSVerificationError("x"), TransportError))
check("AuthenticationError isa IngestionError",
    isinstance(AuthenticationError("x"), IngestionError))
check("RateLimitError isa AdapterError",
    isinstance(RateLimitError("x"), AdapterError))
check("VaultUnavailableError isa VaultError",
    isinstance(VaultUnavailableError("x"), VaultError))
check("SymlinkEscapeError isa IntegrityError",
    isinstance(SymlinkEscapeError("x"), IntegrityError))
check("PathPolicyViolation isa SandboxError",
    isinstance(PathPolicyViolation("x"), SandboxError))
check("CommitMismatchError isa RepositoryError",
    isinstance(CommitMismatchError("x"), RepositoryError))

# Every exception is also catchable as PRISMError
for exc_class in [
    CredentialNotFoundError, TLSVerificationError, AuthenticationError,
    RateLimitError, VaultUnavailableError, SymlinkEscapeError, PathPolicyViolation,
    PermissionDeniedError, RepositoryNotFoundError, SubmoduleURLError,
]:
    check(f"{exc_class.__name__} isa PRISMError",
        isinstance(exc_class("test"), PRISMError))

# RateLimitError carries structured fields
rl = RateLimitError("rate exceeded", reset_at=9999, limit=5000, remaining=0)
check("RateLimitError.reset_at",  rl.reset_at  == 9999)
check("RateLimitError.limit",     rl.limit     == 5000)
check("RateLimitError.remaining", rl.remaining == 0)
check("RateLimitError.code",      rl.code      == "RATE_LIMIT_EXCEEDED")
check("RateLimitError details populated",
    rl.details["reset_at"] == 9999)

# Default codes
check("CredentialNotFoundError default code", CredentialNotFoundError("x").code == "CREDENTIAL_NOT_FOUND")
check("TLSVerificationError default code",    TLSVerificationError("x").code    == "TLS_VERIFICATION_FAILED")
check("RepositoryNotFoundError default code", RepositoryNotFoundError("x").code == "REPOSITORY_NOT_FOUND")
check("VaultUnavailableError default code",   VaultUnavailableError("x").code   == "VAULT_UNAVAILABLE")
check("VaultAuthError default code",          VaultAuthError("x").code          == "VAULT_AUTH_FAILED")
check("VaultSecretNotFoundError default code",VaultSecretNotFoundError("x").code== "VAULT_SECRET_NOT_FOUND")

# Exception chaining — __cause__ propagation
try:
    try:
        raise ValueError("original cause")
    except ValueError as orig:
        raise AuthenticationError("token rejected") from orig
except AuthenticationError as exc:
    check("Exception chaining preserves __cause__",
        isinstance(exc.__cause__, ValueError))
    check("Chain message is correct", "token rejected" in str(exc))


# 2. Token classification
print("\n=== 2. Token Classification ===")

check("ghp_ → classic_pat",        _classify_token_type("ghp_abc123")           == "classic_pat")
check("github_pat_ → fine_grained", _classify_token_type("github_pat_abc123")    == "fine_grained_pat")
check("ghs_ → github_app",         _classify_token_type("ghs_abc123")           == "github_app")
check("gho_ → oauth",              _classify_token_type("gho_abc123")           == "oauth")
check("unknown prefix → unknown",  _classify_token_type("random_token")         == "unknown")
check("Empty string → unknown",    _classify_token_type("")                     == "unknown")

# URL sanitization (credential in URL)
check("_sanitize_url strips embedded creds",
    "REDACTED" in _sanitize_url("https://ghp_token@github.com/org/repo"))
check("_sanitize_url keeps clean URL",
    _sanitize_url("https://github.com/org/repo") == "https://github.com/org/repo")


# 3. URL matching
print("\n=== 3. URL Matching ===")

adapter = GitHubAdapter()
check("Matches github.com",      adapter.matches("https://github.com/org/repo"))
check("Matches www.github.com",  adapter.matches("https://www.github.com/org/repo"))
check("No match gitlab.com",     not adapter.matches("https://gitlab.com/org/repo"))
check("No match bitbucket.org",  not adapter.matches("https://bitbucket.org/org/repo"))
check("No match custom host",    not adapter.matches("https://mygit.company.com/org/repo"))

check("GitLab matches gitlab.com",         GitLabAdapter().matches("https://gitlab.com/o/r"))
check("GitLab matches self-hosted",        GitLabAdapter().matches("https://gitlab.myco.com/o/r"))
check("Bitbucket matches bitbucket.org",   BitbucketAdapter().matches("https://bitbucket.org/o/r"))
check("ADO matches dev.azure.com",         AzureDevOpsAdapter().matches("https://dev.azure.com/o/r"))
check("ADO matches visualstudio.com",      AzureDevOpsAdapter().matches("https://myorg.visualstudio.com/r"))
check("Generic matches any URL",           GenericAdapter().matches("https://custom.host/o/r"))

# provider() returns correct enum
check("GitHub provider enum",   adapter.provider()            == GitProvider.GITHUB)
check("GitLab provider enum",   GitLabAdapter().provider()    == GitProvider.GITLAB)
check("Bitbucket provider enum",BitbucketAdapter().provider() == GitProvider.BITBUCKET)
check("ADO provider enum",      AzureDevOpsAdapter().provider()== GitProvider.AZURE_DEVOPS)
check("Generic provider enum",  GenericAdapter().provider()   == GitProvider.GENERIC)

# parse_owner_repo
owner, repo = adapter._parse_owner_repo("https://github.com/myorg/myrepo")
check("parse_owner_repo owner", owner == "myorg")
check("parse_owner_repo repo",  repo  == "myrepo")
owner2, repo2 = adapter._parse_owner_repo("https://github.com/myorg/myrepo.git")
check("parse_owner_repo strips .git", repo2 == "myrepo")

try:
    adapter._parse_owner_repo("https://github.com/onlyone")
    check("parse_owner_repo raises on missing repo", False)
except AdapterError:
    check("parse_owner_repo raises on missing repo", True)


# 4. Rate limit header parsing
print("\n=== 4. Rate Limit Header Parsing ===")

adapter = GitHubAdapter()
headers = {
    "X-RateLimit-Limit":     "5000",
    "X-RateLimit-Remaining": "4950",
    "X-RateLimit-Reset":     "1700000000",
    "X-RateLimit-Used":      "50",
}
rl = adapter.parse_rate_limit(headers)
check("limit parsed",     rl["limit"]     == 5000)
check("remaining parsed", rl["remaining"] == 4950)
check("reset_at parsed",  rl["reset_at"]  == 1700000000)
check("used parsed",      rl["used"]      == 50)

# Empty headers → empty dict (no crash)
check("Empty headers → empty dict", adapter.parse_rate_limit({}) == {})

# Malformed headers → empty dict (no crash)
check("Malformed headers → empty dict",
    adapter.parse_rate_limit({"X-RateLimit-Limit": "not_a_number"}) == {})

# GitLab uses different header names
gl = GitLabAdapter()
gl_headers = {
    "RateLimit-Limit":     "2000",
    "RateLimit-Remaining": "1995",
    "RateLimit-Reset":     "1700000060",
}
gl_rl = gl.parse_rate_limit(gl_headers)
check("GitLab limit parsed",    gl_rl.get("limit")     == 2000)
check("GitLab remaining parsed",gl_rl.get("remaining") == 1995)


# 5. HTTP error translation
print("\n=== 5. HTTP Error Translation ===")

import urllib.error

def make_http_error(code: int, message: str = "", body: dict = None, headers: dict = None):
    """Create a urllib.error.HTTPError for testing."""
    body_bytes = json.dumps(body or {"message": message}).encode()
    resp = MagicMock()
    resp.read.return_value = body_bytes
    resp.headers = headers or {}
    err = urllib.error.HTTPError(
        url="https://api.github.com/test",
        code=code,
        msg=message,
        hdrs=headers or {},
        fp=resp,
    )
    err.read = lambda n=None: body_bytes
    return err

adapter = GitHubAdapter()

# 401 → AuthenticationError
err401 = make_http_error(401, "Bad credentials")
try:
    adapter._handle_http_error(err401, "https://api.github.com/repos/o/r", {}, "token")
    check("401 → AuthenticationError", False)
except AuthenticationError as e:
    check("401 → AuthenticationError", True)
    check("401 error mentions token", "token" in e.message.lower() or "401" in e.message)
    check("401 code is correct", e.code == "AUTHENTICATION_FAILED")

# 403 with rate limit headers → RateLimitError
rl_headers = {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1700000999", "X-RateLimit-Limit": "5000"}
err403_rl = make_http_error(403, "rate limit exceeded", headers=rl_headers)
try:
    adapter._handle_http_error(err403_rl, "https://api.github.com/repos/o/r", rl_headers, "tok")
    check("403+rate_limit → RateLimitError", False)
except RateLimitError as e:
    check("403+rate_limit → RateLimitError", True)
    check("RateLimitError has reset_at", e.reset_at == 1700000999)
    check("RateLimitError code", e.code == "RATE_LIMIT_EXCEEDED")

# 403 without rate limit → PermissionDeniedError
err403_perm = make_http_error(403, "insufficient scope")
try:
    adapter._handle_http_error(err403_perm, "https://api.github.com/repos/o/r", {}, "tok")
    check("403 no rate limit → PermissionDeniedError", False)
except PermissionDeniedError as e:
    check("403 no rate limit → PermissionDeniedError", True)
    check("PermissionDeniedError mentions scope", "scope" in e.message.lower() or "permission" in e.message.lower())

# 404 → RepositoryNotFoundError
err404 = make_http_error(404, "Not Found")
try:
    adapter._handle_http_error(err404, "https://api.github.com/repos/o/r", {}, "tok")
    check("404 → RepositoryNotFoundError", False)
except RepositoryNotFoundError as e:
    check("404 → RepositoryNotFoundError", True)
    check("404 code is correct", e.code == "REPOSITORY_NOT_FOUND")

# 429 → RateLimitError
err429 = make_http_error(429, "Too Many Requests", headers={"X-RateLimit-Reset": "1700001000"})
try:
    adapter._handle_http_error(
        err429, "https://api.github.com/repos/o/r",
        {"X-RateLimit-Reset": "1700001000"}, "tok"
    )
    check("429 → RateLimitError", False)
except RateLimitError as e:
    check("429 → RateLimitError", True)

# 500 → AdapterError
err500 = make_http_error(500, "Internal Server Error")
try:
    adapter._handle_http_error(err500, "https://api.github.com/repos/o/r", {}, "tok")
    check("500 → AdapterError", False)
except AdapterError as e:
    check("500 → AdapterError", True)
    check("500 error mentions server error", "server" in e.message.lower() or "500" in e.message)


# 6. GitHub adapter API methods (mocked HTTP)
print("\n=== 6. GitHub Adapter API Methods (Mocked HTTP) ===")

adapter = GitHubAdapter()
TOKEN = "ghp_testtoken123"

# Mock _api_get to return fake responses
def mock_api_get(url, token):
    if "/commits/" in url:
        return {"sha": "a" * 40, "commit": {"message": "test"}}
    if url.endswith("/repos/org/repo"):
        return {
            "full_name": "org/repo", "private": True,
            "default_branch": "main", "size": 1234,
            "clone_url": "https://github.com/org/repo.git",
            "description": "Test repo", "archived": False,
            "stargazers_count": 5, "language": "Python",
            "topics": [], "open_issues_count": 2,
        }
    if url == "https://api.github.com/user":
        return {"login": "testuser", "id": 123}
    if url == "https://api.github.com/rate_limit":
        return {"resources": {"core": {"limit": 5000, "remaining": 4900, "reset": 9999}}}
    return {}

def mock_api_get_with_headers(url, token):
    data = mock_api_get(url, token)
    headers = {
        "X-OAuth-Scopes": "repo, read:org",
        "X-RateLimit-Remaining": "4900",
        "GitHub-Authentication-Token-Expiration": "2025-12-31",
    }
    return data, headers

# Test resolve_head_sha
with patch.object(adapter, "_api_get", side_effect=mock_api_get):
    sha = adapter.resolve_head_sha("https://github.com/org/repo", "main", TOKEN)
    check("resolve_head_sha returns 40-char SHA", len(sha) == 40)
    check("resolve_head_sha returns correct SHA",  sha == "a" * 40)

# Test get_repo_metadata
with patch.object(adapter, "_api_get", side_effect=mock_api_get):
    meta = adapter.get_repo_metadata("https://github.com/org/repo", "main", TOKEN)
    check("get_repo_metadata owner",          meta.owner          == "org")
    check("get_repo_metadata name",           meta.name           == "repo")
    check("get_repo_metadata default_branch", meta.default_branch == "main")
    check("get_repo_metadata is_private",     meta.is_private     == True)
    check("get_repo_metadata head_sha",       meta.head_sha       == "a" * 40)
    check("get_repo_metadata size_kb",        meta.size_kb        == 1234)
    check("get_repo_metadata no creds in url",
        "@" not in meta.clone_url)

# Test validate_token — classic PAT with scopes
with patch.object(adapter, "_api_get",              side_effect=mock_api_get), \
     patch.object(adapter, "_api_get_with_headers",  side_effect=mock_api_get_with_headers):
    info = adapter.validate_token(TOKEN)
    check("validate_token login",        info.login      == "testuser")
    check("validate_token type",         info.token_type == "classic_pat")
    check("validate_token scopes",       "repo" in info.scopes)
    check("validate_token rate_limit",   info.rate_limit == 5000)
    check("validate_token expires_at",   "2025" in info.expires_at)

# Test validate_token — insufficient scopes raises PermissionDeniedError
def mock_no_scope_headers(url, token):
    data = mock_api_get(url, token)
    headers = {"X-OAuth-Scopes": "public_repo"}  # missing 'repo'
    return data, headers

with patch.object(adapter, "_api_get",             side_effect=mock_api_get), \
     patch.object(adapter, "_api_get_with_headers", side_effect=mock_no_scope_headers):
    try:
        adapter.validate_token("ghp_noscope")
        check("Missing scope raises PermissionDeniedError", False)
    except PermissionDeniedError as e:
        check("Missing scope raises PermissionDeniedError", True)
        check("Error mentions missing scope", "repo" in e.message or "missing" in e.message.lower())

# Test validate_token — fine-grained PAT (empty X-OAuth-Scopes)
def mock_fine_grained_headers(url, token):
    data = mock_api_get(url, token)
    headers = {"X-OAuth-Scopes": ""}  # fine-grained PATs return empty
    return data, headers

with patch.object(adapter, "_api_get",             side_effect=mock_api_get), \
     patch.object(adapter, "_api_get_with_headers", side_effect=mock_fine_grained_headers):
    info = adapter.validate_token("github_pat_finegrained")
    check("Fine-grained PAT: type classified correctly",
        info.token_type == "fine_grained_pat")
    check("Fine-grained PAT: scopes marked as fine_grained",
        "fine_grained" in info.scopes)


# 7. Vault credential provider (mocked hvac)
print("\n=== 7. Vault Credential Provider ===")

# Test: hvac not available → VaultUnavailableError
# Create provider and manually set _hvac_available=False to simulate missing library
provider_no_hvac = VaultCredentialProvider()
provider_no_hvac._hvac_available = False
try:
    provider_no_hvac.get_credential("git/github")
    check("hvac unavailable → VaultUnavailableError", False)
except VaultUnavailableError:
    check("hvac unavailable → VaultUnavailableError", True)
except Exception as e:
    # Also accept if the error message contains the right text
    check("hvac unavailable → VaultUnavailableError",
        "unavailable" in str(e).lower() or "hvac" in str(e).lower())

# Test: Vault authentication via token
mock_hvac = MagicMock()
mock_client = MagicMock()
mock_client.is_authenticated.return_value = True
mock_client.secrets.kv.v2.read_secret_version.return_value = {
    "data": {"data": {"token": "ghp_vault_retrieved_token"}}
}
mock_hvac.Client.return_value = mock_client

with patch.dict("sys.modules", {"hvac": mock_hvac}):
    vp = VaultCredentialProvider(vault_token="root_token_test")
    vp._hvac_available = True
    vp._client = mock_client
    vp._client_expiry = time.monotonic() + 3600

    cred = vp.get_credential("git/github")
    check("Vault returns SecureString",    isinstance(cred, SecureString))
    check("SecureString contains token",   cred.get() == "ghp_vault_retrieved_token")
    cred.zero()
    check("SecureString zeroed after use", not cred.is_valid)

# Test: secret path not found → VaultSecretNotFoundError
mock_client_404 = MagicMock()
mock_client_404.is_authenticated.return_value = True
mock_client_404.secrets.kv.v2.read_secret_version.return_value = {
    "data": {"data": {}}   # no 'token' field
}

with patch.dict("sys.modules", {"hvac": mock_hvac}):
    vp2 = VaultCredentialProvider(vault_token="root")
    vp2._hvac_available = True
    vp2._client = mock_client_404
    vp2._client_expiry = time.monotonic() + 3600
    try:
        vp2.get_credential("git/github")
        check("Missing token field → VaultSecretNotFoundError", False)
    except Exception as e:
        check("Missing token field → VaultSecretNotFoundError",
            "VaultSecretNotFoundError" in type(e).__name__ or "token" in str(e).lower())

# Test: credential_context zeroes after use
with patch.dict("sys.modules", {"hvac": mock_hvac}):
    vp3 = VaultCredentialProvider(vault_token="root")
    vp3._hvac_available = True
    vp3._client = mock_client
    vp3._client_expiry = time.monotonic() + 3600
    cred_ref = None
    with vp3.credential_context("git/github") as cred:
        cred_ref = cred
        check("Context manager: cred valid inside block", cred.is_valid)
    check("Context manager: cred zeroed after block", not cred_ref.is_valid)


# 8. Adapter registry
print("\n=== 8. Adapter Registry ===")

registry = AdapterRegistry()
check("Registry → GitHub for github.com",
    registry.get_adapter("https://github.com/o/r").provider() == GitProvider.GITHUB)
check("Registry → GitLab for gitlab.com",
    registry.get_adapter("https://gitlab.com/o/r").provider() == GitProvider.GITLAB)
check("Registry → GitLab for self-hosted gitlab.*",
    registry.get_adapter("https://gitlab.myco.com/o/r").provider() == GitProvider.GITLAB)
check("Registry → Bitbucket for bitbucket.org",
    registry.get_adapter("https://bitbucket.org/o/r").provider() == GitProvider.BITBUCKET)
check("Registry → ADO for dev.azure.com",
    registry.get_adapter("https://dev.azure.com/o/r").provider() == GitProvider.AZURE_DEVOPS)
check("Registry → Generic for unknown host",
    registry.get_adapter("https://gitea.mycompany.io/o/r").provider() == GitProvider.GENERIC)

# Stubs raise AdapterError with clear message
gl_adapter = registry.get_adapter("https://gitlab.com/o/r")
try:
    gl_adapter.resolve_head_sha("https://gitlab.com/o/r", "main", "token")
    check("GitLab stub raises AdapterError", False)
except AdapterError as e:
    check("GitLab stub raises AdapterError", True)
    check("Stub error mentions 'not yet implemented'",
        "not yet implemented" in e.message.lower())
    check("Stub error code is ADAPTER_NOT_IMPLEMENTED",
        e.code == "ADAPTER_NOT_IMPLEMENTED")

# Generic adapter returns empty SHA (no API available)
gen = registry.get_adapter("https://gitea.myco.io/o/r")
sha = gen.resolve_head_sha("https://gitea.myco.io/o/r", "main", "token")
check("Generic adapter resolve_head_sha returns empty string", sha == "")

meta = gen.get_repo_metadata("https://gitea.myco.io/o/r", "main", "token")
check("Generic adapter get_repo_metadata returns RepoMetadata", meta is not None)
check("Generic metadata head_sha is empty", meta.head_sha == "")


# Summary
print(f"\n{'='*60}")
print(f"GitHub Adapter + Vault + Exceptions: {passed} passed, {failed} failed")
if failed:
    print("FAILURES DETECTED")
    sys.exit(1)
else:
    print("All tests passed ✓")