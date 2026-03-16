"""
PRISM VC Adapter — Abstract Base & Registry
============================================
Defines the contract every Version Control adapter must fulfill.

An adapter is NOT a Git client. The Git client handles byte-level
transport (clone, fetch, checkout). The adapter handles the
platform-specific API layer that sits on top of Git:

  - Resolving a branch name → HEAD commit SHA         (pre-fetch)
  - Validating a token has the required scopes         (pre-fetch)
  - Detecting the default branch of a repo             (pre-fetch)
  - Parsing rate-limit headers from API responses      (retry logic)
  - Translating HTTP 401/403/404 into typed exceptions (error clarity)

This separation means the pipeline can:
  1. Ask the adapter: "what is HEAD of main?"   → get a pinned SHA
  2. Pass that SHA to GitClient.fetch()          → get bytes
  3. Never fetch without a pinned commit         → Threat C defence

Why is this worth the abstraction?
  GitHub's API returns rate limits in X-RateLimit-* headers.
  GitLab uses RateLimit-* headers with different semantics.
  Azure DevOps has no public rate limit headers at all.
  These differences belong in the adapter, not scattered across the pipeline.

Current adapter registry:
  github   → GitHubAdapter    (fully implemented, tested)
  gitlab   → GitLabAdapter    (interface only — stub)
  bitbucket → BitbucketAdapter (interface only — stub)
  azure_devops → AzureDevOpsAdapter (interface only — stub)
  generic  → GenericAdapter   (pass-through, no API calls)

Adding a new adapter:
  1. Subclass AbstractVCAdapter
  2. Implement the 5 abstract methods
  3. Register in AdapterRegistry.__init__
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..exceptions import (
    AdapterError, RateLimitError, PermissionDeniedError,
    RepositoryNotFoundError, AuthenticationError,
)
from ..models import GitProvider

logger = logging.getLogger(__name__)


# Data contracts returned by adapters

@dataclass(frozen=True)
class RepoMetadata:
    """
    Metadata about a repository fetched from the VC platform API.
    Used by the pipeline to resolve branch → SHA before fetching.
    """
    owner:           str
    name:            str
    default_branch:  str
    clone_url:       str          # HTTPS clone URL (no credentials embedded)
    is_private:      bool
    head_sha:        str          # HEAD commit SHA of the requested branch
    size_kb:         int          # repository size in KB (for limit checks)
    description:     str = ""
    archived:        bool = False
    extra:           dict[str, Any] = field(default_factory=dict)

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"


@dataclass(frozen=True)
class TokenInfo:
    """
    Information about an authenticated token's capabilities.
    Used to verify required scopes before starting the pipeline.
    """
    token_type:      str          # "pat", "github_app", "oauth"
    scopes:          list[str]    # granted scopes
    login:           str          # authenticated identity (username or app name)
    expires_at:      str          # ISO-8601 or "" if non-expiring
    rate_limit:      int          # requests/hour
    rate_remaining:  int          # requests remaining in current window
    rate_reset_at:   int          # epoch seconds when window resets


# Abstract adapter

class AbstractVCAdapter(ABC):
    """
    Platform-specific API adapter for a Version Control hosting service.

    Stateless — no credentials stored as instance attributes.
    All methods receive a token via SecureString and use it immediately.

    Error contract:
      - All methods raise typed exceptions from prism.ingestion.exceptions
      - Never raise generic Exception — always use the hierarchy
      - Never log token values — only log metadata (URLs, usernames, scopes)
    """

    # Required scopes to ingest a repository.
    # Subclasses override this with their platform's scope names.
    REQUIRED_SCOPES: list[str] = []

    @abstractmethod
    def provider(self) -> GitProvider:
        """Return the GitProvider enum value for this adapter."""
        ...

    @abstractmethod
    def matches(self, repo_url: str) -> bool:
        """Return True if this adapter handles the given repository URL."""
        ...

    @abstractmethod
    def resolve_head_sha(
        self,
        repo_url:  str,
        branch:    str,
        token:     str,
    ) -> str:
        """
        Resolve a branch name to its HEAD commit SHA via the platform API.

        This is the core pre-fetch operation. The pipeline calls this
        to obtain a pinned SHA before calling GitClient.fetch().

        Args:
            repo_url: HTTPS repository URL (no embedded credentials)
            branch:   branch name (e.g. "main", "develop")
            token:    raw credential value — use immediately, do not store

        Returns:
            Full 40-hex SHA-1 commit hash

        Raises:
            BranchNotFoundError:    branch does not exist
            RepositoryNotFoundError: repo not found or no access
            AuthenticationError:    token rejected
            RateLimitError:         API rate limit exceeded
            AdapterError:           other platform API error
        """
        ...

    @abstractmethod
    def get_repo_metadata(
        self,
        repo_url: str,
        branch:   str,
        token:    str,
    ) -> RepoMetadata:
        """
        Fetch repository metadata: default branch, size, visibility, HEAD SHA.

        Args:
            repo_url: HTTPS repository URL
            branch:   branch to resolve HEAD SHA for
            token:    raw credential value — use immediately, do not store

        Returns:
            RepoMetadata with all fields populated

        Raises:
            RepositoryNotFoundError, AuthenticationError, RateLimitError
        """
        ...

    @abstractmethod
    def validate_token(
        self,
        token: str,
    ) -> TokenInfo:
        """
        Verify the token is valid and has the required scopes.

        Called once at pipeline start — before any fetch is attempted.
        Ensures the pipeline fails fast with a clear error if the token
        lacks `repo` scope, rather than failing mid-fetch with a cryptic 403.

        Args:
            token: raw credential value — use immediately, do not store

        Returns:
            TokenInfo with scopes, identity, rate limit state

        Raises:
            AuthenticationError:    token is invalid or revoked
            PermissionDeniedError:  token lacks required scopes
            RateLimitError:         rate limit already exceeded
        """
        ...

    @abstractmethod
    def parse_rate_limit(
        self,
        headers: dict[str, str],
    ) -> dict[str, int]:
        """
        Extract rate limit state from HTTP response headers.

        Returns dict with keys: limit, remaining, reset_at (epoch seconds).
        Returns empty dict if this platform does not expose rate limit headers.
        """
        ...

    def check_required_scopes(
        self,
        token_info: TokenInfo,
    ) -> None:
        """
        Verify token_info.scopes contains all REQUIRED_SCOPES.
        Raises PermissionDeniedError if any required scope is missing.

        This default implementation works for most platforms.
        Subclasses may override for platform-specific scope hierarchies.
        """
        missing = [s for s in self.REQUIRED_SCOPES if s not in token_info.scopes]
        if missing:
            raise PermissionDeniedError(
                f"{self.provider().value} token is missing required scopes: "
                f"{missing}. "
                f"Token has scopes: {token_info.scopes}. "
                f"Grant the missing scopes at the platform's token settings page.",
                details={
                    "required":  self.REQUIRED_SCOPES,
                    "granted":   token_info.scopes,
                    "missing":   missing,
                    "login":     token_info.login,
                },
            )

    def _parse_owner_repo(self, repo_url: str) -> tuple[str, str]:
        """
        Extract owner and repo name from an HTTPS URL.
        e.g. https://github.com/myorg/myrepo.git → ("myorg", "myrepo")
        """
        from urllib.parse import urlparse
        parsed = urlparse(repo_url)
        parts  = parsed.path.strip("/").rstrip(".git").split("/")
        if len(parts) < 2:
            raise AdapterError(
                f"Cannot parse owner/repo from URL: {repo_url!r}. "
                f"Expected format: https://host/owner/repo"
            )
        return parts[0], "/".join(parts[1:])


# Adapter registry

class AdapterRegistry:
    """
    Maps repository URLs to the correct platform adapter.
    Detection is URL-pattern based — never from user input beyond the URL.
    """

    def __init__(self) -> None:
        from .github   import GitHubAdapter
        from .stubs    import GitLabAdapter, BitbucketAdapter, AzureDevOpsAdapter, GenericAdapter

        # Order matters: specific patterns before the generic catch-all
        self._adapters: list[AbstractVCAdapter] = [
            GitHubAdapter(),
            GitLabAdapter(),
            BitbucketAdapter(),
            AzureDevOpsAdapter(),
            GenericAdapter(),
        ]

    def get_adapter(self, repo_url: str) -> AbstractVCAdapter:
        """Return the first adapter that matches the URL."""
        for adapter in self._adapters:
            if adapter.matches(repo_url):
                return adapter
        # GenericAdapter always matches — we never reach here
        raise AdapterError(f"No adapter found for URL: {repo_url!r}")