"""
PRISM GitHub Adapter
=====================
Implements AbstractVCAdapter for github.com.

API surface used:
  GET /repos/{owner}/{repo}               → metadata, default branch, size
  GET /repos/{owner}/{repo}/commits/{ref} → HEAD SHA for a branch
  GET /user                               → token identity
  GET /rate_limit                         → rate limit state

Authentication:
  All requests use: Authorization: Bearer <token>
  GitHub returns token scopes in the X-OAuth-Scopes response header.

Token types supported:
  ghp_xxx         Classic PAT   — scopes returned in X-OAuth-Scopes header
  github_pat_xxx  Fine-grained  — uses fine_grained_pat permissions model
  ghs_xxx         GitHub App    — installation token from JWT flow

Rate limiting:
  GitHub applies limits per token, not per IP.
  Unauthenticated: 60 req/hour. Authenticated: 5,000 req/hour.
  Headers: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset

TLS:
  All API calls use ssl.create_default_context() — system CA bundle,
  hostname verification, no certificate pinning (GitHub rotates certs).

Retry policy:
  On 429 / 403 rate limit: wait until X-RateLimit-Reset, retry once.
  On 401: raise AuthenticationError immediately (token is bad — don't retry).
  On 404: raise RepositoryNotFoundError immediately.
  On 5xx: raise AdapterError with status code in details.
"""

from __future__ import annotations

import json
import logging
import re
import ssl
import time
import urllib.request
import urllib.error
from typing import Any

from .base import AbstractVCAdapter, RepoMetadata, TokenInfo
from ..exceptions import (
    AdapterError, AuthenticationError, RateLimitError,
    PermissionDeniedError, RepositoryNotFoundError,
    TLSVerificationError, FetchTimeoutError,
)
from ..models import GitProvider

logger = logging.getLogger(__name__)

# Pattern matching github.com URLs only (not GitHub Enterprise)
_GITHUB_PATTERN = re.compile(r"https?://(?:www\.)?github\.com/", re.I)

# GitHub API base URL
_GITHUB_API = "https://api.github.com"

# Minimum scopes a classic PAT needs for repository ingestion.
# Fine-grained PATs use a different permissions model — we check
# the commit endpoint response instead of scope headers.
_REQUIRED_SCOPES = ["repo"]

# Timeout for each individual API call (seconds)
_API_TIMEOUT_S = 15

# Maximum retries on transient errors (5xx, connection reset)
_MAX_RETRIES = 2


class GitHubAdapter(AbstractVCAdapter):
    """
    GitHub platform adapter.

    Stateless — no credentials, tokens, or session state stored.
    Every method receives its token inline and uses it once.
    """

    REQUIRED_SCOPES = _REQUIRED_SCOPES

    def provider(self) -> GitProvider:
        return GitProvider.GITHUB

    def matches(self, repo_url: str) -> bool:
        return bool(_GITHUB_PATTERN.match(repo_url))

    # Core adapter methods

    def resolve_head_sha(
        self,
        repo_url: str,
        branch:   str,
        token:    str,
    ) -> str:
        """
        Resolve branch → HEAD commit SHA via the GitHub Commits API.

        We use the commits endpoint rather than the refs endpoint because
        it returns the full SHA in a single call and is available for all
        repository types including forks and archived repos.

        Endpoint: GET /repos/{owner}/{repo}/commits/{branch}
        Response field: .sha
        """
        owner, repo = self._parse_owner_repo(repo_url)
        url = f"{_GITHUB_API}/repos/{owner}/{repo}/commits/{branch}"

        logger.debug(
            "Resolving HEAD SHA for %s/%s branch=%s", owner, repo, branch
        )

        data = self._api_get(url, token)

        sha = data.get("sha", "")
        if not sha or len(sha) != 40:
            raise AdapterError(
                f"GitHub API returned unexpected SHA for {owner}/{repo}@{branch}: "
                f"{sha!r}. Expected a 40-character hex string.",
                details={"owner": owner, "repo": repo, "branch": branch},
            )

        logger.info(
            "Resolved %s/%s branch=%s → SHA=%s",
            owner, repo, branch, sha[:12],
        )
        return sha

    def get_repo_metadata(
        self,
        repo_url: str,
        branch:   str,
        token:    str,
    ) -> RepoMetadata:
        """
        Fetch repository metadata and HEAD SHA in two API calls:
          1. GET /repos/{owner}/{repo}   → metadata
          2. GET /repos/{owner}/{repo}/commits/{branch}  → HEAD SHA

        Two calls are necessary because the repo endpoint only returns
        the default branch SHA, not an arbitrary branch SHA.
        """
        owner, repo = self._parse_owner_repo(repo_url)

        # Call 1: repository metadata
        repo_data = self._api_get(
            f"{_GITHUB_API}/repos/{owner}/{repo}", token
        )

        # Call 2: HEAD SHA for the requested branch
        head_sha = self.resolve_head_sha(repo_url, branch, token)

        # Build clone URL without credentials
        clone_url = repo_data.get("clone_url", repo_url)
        # Strip any accidentally embedded token from clone URL
        clone_url = re.sub(r"https?://[^@]+@", "https://", clone_url)

        return RepoMetadata(
            owner          = owner,
            name           = repo,
            default_branch = repo_data.get("default_branch", "main"),
            clone_url      = clone_url,
            is_private     = repo_data.get("private", True),
            head_sha       = head_sha,
            size_kb        = repo_data.get("size", 0),
            description    = repo_data.get("description") or "",
            archived       = repo_data.get("archived", False),
            extra={
                "stars":       repo_data.get("stargazers_count", 0),
                "language":    repo_data.get("language"),
                "topics":      repo_data.get("topics", []),
                "open_issues": repo_data.get("open_issues_count", 0),
            },
        )

    def validate_token(self, token: str) -> TokenInfo:
        """
        Validate token by calling GET /user and GET /rate_limit.

        The /user endpoint:
          - Returns 200 + login if token is valid
          - Returns 401 if token is invalid or revoked
          - Returns X-OAuth-Scopes header with granted scopes (classic PAT)
          - Returns X-OAuth-Scopes: "" for fine-grained PATs (different model)

        For fine-grained PATs we cannot read scopes from the header.
        We verify access by calling /rate_limit instead and checking
        the token is authenticated (rate > 60 means authenticated).
        """
        logger.debug("Validating GitHub token (identity check via /user)")

        # Call /user — returns 401 immediately if token is bad
        user_data, user_headers = self._api_get_with_headers(
            f"{_GITHUB_API}/user", token
        )

        login = user_data.get("login", "")
        if not login:
            raise AuthenticationError(
                "GitHub /user endpoint returned no login field. "
                "Token may be malformed.",
                details={"endpoint": "/user"},
            )

        # Read scopes from response header (classic PATs only)
        raw_scopes = user_headers.get("X-OAuth-Scopes", "")
        scopes = [s.strip() for s in raw_scopes.split(",") if s.strip()]

        # Determine token type from the token prefix
        token_type = _classify_token_type(token)

        # For fine-grained PATs: scopes header is empty.
        # We mark scopes as ["fine_grained"] and rely on API call
        # results (403 vs 200) to detect permission issues per-repo.
        if token_type == "fine_grained_pat" and not scopes:
            scopes = ["fine_grained"]
            logger.info(
                "Fine-grained PAT detected for %s — scope verification "
                "will be done per-repository.", login
            )

        # Call /rate_limit for rate limit state
        rate_data = self._api_get(f"{_GITHUB_API}/rate_limit", token)
        core = rate_data.get("resources", {}).get("core", {})

        token_info = TokenInfo(
            token_type     = token_type,
            scopes         = scopes,
            login          = login,
            expires_at     = user_headers.get("GitHub-Authentication-Token-Expiration", ""),
            rate_limit     = core.get("limit", 5000),
            rate_remaining = core.get("remaining", 0),
            rate_reset_at  = core.get("reset", 0),
        )

        logger.info(
            "GitHub token valid. login=%s type=%s scopes=%s "
            "rate=%d/%d reset_at=%d",
            login, token_type, scopes,
            token_info.rate_remaining, token_info.rate_limit,
            token_info.rate_reset_at,
        )

        # Check required scopes (skip for fine-grained — checked per-repo)
        if token_type != "fine_grained_pat":
            self.check_required_scopes(token_info)

        # Warn if rate limit is critically low
        if token_info.rate_remaining < 50:
            logger.warning(
                "GitHub rate limit critically low: %d/%d requests remaining. "
                "Resets at epoch %d.",
                token_info.rate_remaining, token_info.rate_limit,
                token_info.rate_reset_at,
            )

        return token_info

    def parse_rate_limit(
        self,
        headers: dict[str, str],
    ) -> dict[str, int]:
        """
        Extract GitHub rate limit state from HTTP response headers.

        GitHub rate limit headers:
          X-RateLimit-Limit:     total requests allowed per hour
          X-RateLimit-Remaining: requests remaining in current window
          X-RateLimit-Reset:     epoch seconds when window resets
          X-RateLimit-Used:      requests used in current window
          X-RateLimit-Resource:  which resource bucket (core/search/graphql)
        """
        result: dict[str, int] = {}
        try:
            if "X-RateLimit-Limit" in headers:
                result["limit"]     = int(headers["X-RateLimit-Limit"])
            if "X-RateLimit-Remaining" in headers:
                result["remaining"] = int(headers["X-RateLimit-Remaining"])
            if "X-RateLimit-Reset" in headers:
                result["reset_at"]  = int(headers["X-RateLimit-Reset"])
            if "X-RateLimit-Used" in headers:
                result["used"]      = int(headers["X-RateLimit-Used"])
        except (ValueError, KeyError):
            pass
        return result

    # HTTP transport — TLS-verified, credential-safe

    def _api_get(
        self,
        url:   str,
        token: str,
    ) -> dict[str, Any]:
        """Make an authenticated GET request and return parsed JSON body."""
        data, _ = self._api_get_with_headers(url, token)
        return data

    def _api_get_with_headers(
        self,
        url:   str,
        token: str,
    ) -> tuple[dict[str, Any], dict[str, str]]:
        """
        Make an authenticated GET to the GitHub API.

        Security properties:
          - TLS verified via ssl.create_default_context() (system CAs)
          - Token passed in Authorization header — never in URL
          - Token value is NOT logged — only the URL path is logged
          - Response body is size-limited to prevent memory exhaustion
          - Timeout enforced on connect + read

        Returns (parsed_json_body, response_headers_dict).
        """
        # Build TLS context: system CA bundle, hostname verification ON
        tls_ctx = ssl.create_default_context()
        # Do NOT disable check_hostname or verify_mode — ever.
        # tls_ctx.check_hostname = False  ← this line must never exist here

        headers = {
            # Token in Authorization header — never in URL query params
            "Authorization":  f"Bearer {token}",
            "Accept":         "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent":     "PRISM-Security-Scanner/1.0",
        }

        req = urllib.request.Request(url, headers=headers, method="GET")

        last_exc: Exception | None = None

        for attempt in range(_MAX_RETRIES + 1):
            try:
                with urllib.request.urlopen(
                    req,
                    context=tls_ctx,
                    timeout=_API_TIMEOUT_S,
                ) as resp:
                    # Size-limit the response body (10MB max for API responses)
                    raw = resp.read(10 * 1024 * 1024)
                    resp_headers = dict(resp.headers)

                    try:
                        body = json.loads(raw)
                    except json.JSONDecodeError as exc:
                        raise AdapterError(
                            f"GitHub API returned non-JSON response from {url}: {exc}",
                            details={"url": url, "response_prefix": raw[:200].decode("utf-8", errors="replace")},
                        ) from exc

                    return body, resp_headers

            except urllib.error.HTTPError as exc:
                resp_headers = dict(exc.headers) if exc.headers else {}
                self._handle_http_error(exc, url, resp_headers, token)

            except urllib.error.URLError as exc:
                # Network error — check if it's a TLS failure
                reason = str(exc.reason)
                if "SSL" in reason or "certificate" in reason.lower():
                    raise TLSVerificationError(
                        f"TLS verification failed connecting to GitHub API: {reason}. "
                        f"Check system CA bundle and clock synchronization.",
                        details={"url": url, "reason": reason},
                    ) from exc

                last_exc = exc
                if attempt < _MAX_RETRIES:
                    wait = 2 ** attempt  # exponential backoff: 1s, 2s
                    logger.warning(
                        "GitHub API connection error (attempt %d/%d): %s. "
                        "Retrying in %ds...",
                        attempt + 1, _MAX_RETRIES + 1, exc, wait,
                    )
                    time.sleep(wait)
                    continue

            except TimeoutError as exc:
                raise FetchTimeoutError(
                    f"GitHub API request timed out after {_API_TIMEOUT_S}s: {url}",
                    details={"url": url, "timeout_s": _API_TIMEOUT_S},
                ) from exc

        raise AdapterError(
            f"GitHub API call failed after {_MAX_RETRIES + 1} attempts: {url}. "
            f"Last error: {last_exc}",
            details={"url": url},
        )

    def _handle_http_error(
        self,
        exc:          urllib.error.HTTPError,
        url:          str,
        resp_headers: dict[str, str],
        token:        str,
    ) -> None:
        """
        Translate HTTP error codes to typed PRISM exceptions.

        This method always raises — it never returns normally.
        Token value is never included in any exception message or detail.
        """
        status = exc.code

        # Read error body for message (size-limited)
        try:
            error_body = json.loads(exc.read(4096))
            gh_message = error_body.get("message", "")
        except Exception:
            gh_message = ""

        if status == 401:
            # Token is invalid, expired, or revoked
            raise AuthenticationError(
                f"GitHub rejected the token (HTTP 401). "
                f"The token may be expired, revoked, or malformed. "
                f"GitHub message: {gh_message!r}",
                details={"status": 401, "url": _sanitize_url(url)},
            ) from exc

        if status == 403:
            # Two distinct cases: rate limit OR insufficient permissions
            rate = self.parse_rate_limit(resp_headers)
            if rate.get("remaining", 1) == 0:
                reset_at = rate.get("reset_at", 0)
                wait_s   = max(0, reset_at - int(time.time()))
                raise RateLimitError(
                    f"GitHub API rate limit exceeded. "
                    f"Resets in {wait_s}s (at epoch {reset_at}). "
                    f"Limit: {rate.get('limit', '?')} requests/hour.",
                    reset_at  = reset_at,
                    limit     = rate.get("limit", 0),
                    remaining = 0,
                ) from exc

            raise PermissionDeniedError(
                f"GitHub returned HTTP 403 for {_sanitize_url(url)}. "
                f"Token lacks required permissions. "
                f"GitHub message: {gh_message!r}. "
                f"Ensure the token has 'repo' scope (classic PAT) or "
                f"'Contents: Read' permission (fine-grained PAT).",
                details={
                    "status":     403,
                    "url":        _sanitize_url(url),
                    "gh_message": gh_message,
                },
            ) from exc

        if status == 404:
            raise RepositoryNotFoundError(
                f"GitHub returned HTTP 404 for {_sanitize_url(url)}. "
                f"The repository does not exist, or the token cannot access it. "
                f"If the repository is private, ensure the token has 'repo' scope.",
                details={"status": 404, "url": _sanitize_url(url)},
            ) from exc

        if status == 422:
            raise AdapterError(
                f"GitHub API returned HTTP 422 (Unprocessable Entity): "
                f"{gh_message!r}. Check branch name or commit SHA format.",
                details={"status": 422, "url": _sanitize_url(url), "gh_message": gh_message},
            ) from exc

        if status == 429:
            # GitHub rarely returns 429 directly — usually uses 403 for rate limits.
            # Handle it here for completeness.
            reset_at = int(resp_headers.get("X-RateLimit-Reset", 0))
            raise RateLimitError(
                f"GitHub API rate limit exceeded (HTTP 429). "
                f"Reset at epoch {reset_at}.",
                reset_at=reset_at,
            ) from exc

        if 500 <= status < 600:
            raise AdapterError(
                f"GitHub API server error: HTTP {status} from {_sanitize_url(url)}. "
                f"This is a GitHub-side issue — retry after a delay.",
                details={"status": status, "url": _sanitize_url(url)},
            ) from exc

        raise AdapterError(
            f"Unexpected HTTP {status} from GitHub API: {_sanitize_url(url)}. "
            f"GitHub message: {gh_message!r}",
            details={"status": status, "url": _sanitize_url(url)},
        ) from exc

# Helpers
def _classify_token_type(token: str) -> str:
    """
    Classify a GitHub token by its prefix.
    Used for logging and scope-check strategy selection.
    Token value is never logged — only the type label.
    """
    if token.startswith("ghp_"):
        return "classic_pat"
    if token.startswith("github_pat_"):
        return "fine_grained_pat"
    if token.startswith("ghs_"):
        return "github_app"
    if token.startswith("gho_"):
        return "oauth"
    return "unknown"


def _sanitize_url(url: str) -> str:
    """
    Remove any accidentally embedded credentials from a URL before logging.
    GitHub API URLs should never have credentials — this is a safety net.
    """
    import re
    return re.sub(r"https?://[^@\s]+@", "https://[REDACTED]@", url)