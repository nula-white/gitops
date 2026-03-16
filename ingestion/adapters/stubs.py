"""
PRISM VC Adapter Stubs — GitLab, Bitbucket, Azure DevOps, Generic
===================================================================
These adapters implement the AbstractVCAdapter interface with stub
bodies that raise NotImplementedError. They are registered in the
AdapterRegistry so the system correctly identifies which platform
a URL belongs to, but defers actual API calls until implemented.

When to implement each:
  GitLabAdapter:       needed when adding GitLab.com / self-hosted GitLab support
  BitbucketAdapter:    needed when adding Bitbucket Cloud support
  AzureDevOpsAdapter:  needed when adding Azure DevOps / TFS support
  GenericAdapter:      catch-all — used for self-hosted Gitea, Forgejo, plain Git

Implementation guide for each stub:
  1. Replace _NOT_IMPLEMENTED() calls with real HTTP calls to the platform API
  2. Implement parse_rate_limit() with the platform's specific header names
  3. Set REQUIRED_SCOPES to the platform's scope strings
  4. Add adapter-specific exception handling in _handle_http_error()

The GitHubAdapter (github.py) is the reference implementation.
Follow the same pattern: stateless, no stored credentials, typed exceptions.
"""

from __future__ import annotations

import re
from typing import Any

from .base import AbstractVCAdapter, RepoMetadata, TokenInfo
from ..exceptions import AdapterError
from ..models import GitProvider


def _NOT_IMPLEMENTED(adapter_name: str, method: str) -> None:
    """Raise a clear error for unimplemented adapter methods."""
    raise AdapterError(
        f"{adapter_name}.{method}() is not yet implemented. "
        f"The {adapter_name} is registered for URL detection but "
        f"does not yet support API calls. "
        f"Use GitHubAdapter for now, or implement {adapter_name} "
        f"following the GitHubAdapter pattern in github.py.",
        code="ADAPTER_NOT_IMPLEMENTED",
        details={"adapter": adapter_name, "method": method},
    )


# ---------------------------------------------------------------------------
# GitLab
# ---------------------------------------------------------------------------

_GITLAB_PATTERN = re.compile(r"https?://(?:www\.)?gitlab\.(?:com|[a-z]+)/", re.I)
_GITLAB_SELF    = re.compile(r"https?://gitlab\.", re.I)


class GitLabAdapter(AbstractVCAdapter):
    """
    GitLab adapter — URL detection implemented, API calls stubbed.

    Implementation notes for when this is built out:
      - API base: https://gitlab.com/api/v4  (or https://host/api/v4)
      - Token header: PRIVATE-TOKEN: <token>  OR  Authorization: Bearer <token>
      - Commit SHA endpoint: GET /projects/{id}/repository/commits/{ref}
      - Rate limit headers: RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset
      - Required scope: read_repository (or api for full access)
      - Project ID: URL-encoded namespace/project (e.g. "myorg%2Fmyrepo")
    """
    REQUIRED_SCOPES = ["read_repository"]

    def provider(self) -> GitProvider:
        return GitProvider.GITLAB

    def matches(self, repo_url: str) -> bool:
        return bool(_GITLAB_PATTERN.match(repo_url) or _GITLAB_SELF.match(repo_url))

    def resolve_head_sha(self, repo_url: str, branch: str, token: str) -> str:
        _NOT_IMPLEMENTED("GitLabAdapter", "resolve_head_sha")

    def get_repo_metadata(self, repo_url: str, branch: str, token: str) -> RepoMetadata:
        _NOT_IMPLEMENTED("GitLabAdapter", "get_repo_metadata")

    def validate_token(self, token: str) -> TokenInfo:
        _NOT_IMPLEMENTED("GitLabAdapter", "validate_token")

    def parse_rate_limit(self, headers: dict[str, str]) -> dict[str, int]:
        # GitLab rate limit headers (for when this is implemented)
        # RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset, RateLimit-Observed
        result: dict[str, int] = {}
        try:
            if "RateLimit-Limit"     in headers: result["limit"]     = int(headers["RateLimit-Limit"])
            if "RateLimit-Remaining" in headers: result["remaining"] = int(headers["RateLimit-Remaining"])
            if "RateLimit-Reset"     in headers: result["reset_at"]  = int(headers["RateLimit-Reset"])
        except (ValueError, KeyError):
            pass
        return result


# ---------------------------------------------------------------------------
# Bitbucket
# ---------------------------------------------------------------------------

_BITBUCKET_PATTERN = re.compile(r"https?://(?:www\.)?bitbucket\.org/", re.I)


class BitbucketAdapter(AbstractVCAdapter):
    """
    Bitbucket Cloud adapter — URL detection implemented, API calls stubbed.

    Implementation notes:
      - API base: https://api.bitbucket.org/2.0
      - Auth: HTTP Basic with username=x-token-auth, password=<app_password>
        OR: OAuth2 Bearer token
      - Commit SHA endpoint: GET /repositories/{workspace}/{slug}/commits/{branch}
      - Rate limits: Bitbucket does not expose rate limit headers reliably
      - Required permission: Repository: Read (in app password settings)
    """
    REQUIRED_SCOPES = ["repository"]

    def provider(self) -> GitProvider:
        return GitProvider.BITBUCKET

    def matches(self, repo_url: str) -> bool:
        return bool(_BITBUCKET_PATTERN.match(repo_url))

    def resolve_head_sha(self, repo_url: str, branch: str, token: str) -> str:
        _NOT_IMPLEMENTED("BitbucketAdapter", "resolve_head_sha")

    def get_repo_metadata(self, repo_url: str, branch: str, token: str) -> RepoMetadata:
        _NOT_IMPLEMENTED("BitbucketAdapter", "get_repo_metadata")

    def validate_token(self, token: str) -> TokenInfo:
        _NOT_IMPLEMENTED("BitbucketAdapter", "validate_token")

    def parse_rate_limit(self, headers: dict[str, str]) -> dict[str, int]:
        # Bitbucket does not reliably expose rate limit headers
        return {}


# ---------------------------------------------------------------------------
# Azure DevOps
# ---------------------------------------------------------------------------

_ADO_PATTERN = re.compile(
    r"https?://(?:dev\.azure\.com|[a-zA-Z0-9-]+\.visualstudio\.com)/", re.I
)


class AzureDevOpsAdapter(AbstractVCAdapter):
    """
    Azure DevOps adapter — URL detection implemented, API calls stubbed.

    Implementation notes:
      - API base: https://dev.azure.com/{org}/{project}/_apis
      - Auth: HTTP Basic with empty username, PAT as password
        Authorization: Basic base64(":" + PAT)
      - Commit SHA endpoint: GET /_apis/git/repositories/{repo}/commits?branch={branch}
      - Rate limits: ADO does not publish rate limit headers
      - Required scope: Code (Read) in PAT settings
    """
    REQUIRED_SCOPES = ["code_read"]

    def provider(self) -> GitProvider:
        return GitProvider.AZURE_DEVOPS

    def matches(self, repo_url: str) -> bool:
        return bool(_ADO_PATTERN.match(repo_url))

    def resolve_head_sha(self, repo_url: str, branch: str, token: str) -> str:
        _NOT_IMPLEMENTED("AzureDevOpsAdapter", "resolve_head_sha")

    def get_repo_metadata(self, repo_url: str, branch: str, token: str) -> RepoMetadata:
        _NOT_IMPLEMENTED("AzureDevOpsAdapter", "get_repo_metadata")

    def validate_token(self, token: str) -> TokenInfo:
        _NOT_IMPLEMENTED("AzureDevOpsAdapter", "validate_token")

    def parse_rate_limit(self, headers: dict[str, str]) -> dict[str, int]:
        # Azure DevOps does not expose rate limit headers
        return {}


# ---------------------------------------------------------------------------
# Generic (self-hosted Git: Gitea, Forgejo, Gogs, plain cgit)
# ---------------------------------------------------------------------------

class GenericAdapter(AbstractVCAdapter):
    """
    Catch-all adapter for self-hosted Git servers.

    Because generic Git servers have no standard API, this adapter
    cannot resolve branch → SHA via API. It returns a sentinel that
    tells the pipeline to skip pre-fetch SHA resolution and rely
    entirely on commit pinning at the GitClient level.

    Matches all URLs — must be last in the registry.
    """

    def provider(self) -> GitProvider:
        return GitProvider.GENERIC

    def matches(self, repo_url: str) -> bool:
        return True   # catch-all

    def resolve_head_sha(self, repo_url: str, branch: str, token: str) -> str:
        """
        Generic servers have no standard API. Return empty string to
        signal the pipeline to fetch without pre-resolving the SHA.
        The pipeline will then pin to the fetched HEAD commit.
        """
        return ""   # empty = no pre-resolution available

    def get_repo_metadata(self, repo_url: str, branch: str, token: str) -> RepoMetadata:
        """Return minimal metadata parsed from the URL."""
        try:
            owner, repo_name = self._parse_owner_repo(repo_url)
        except AdapterError:
            owner, repo_name = "unknown", "unknown"

        return RepoMetadata(
            owner          = owner,
            name           = repo_name,
            default_branch = branch,
            clone_url      = repo_url,
            is_private     = True,   # assume private for generic hosts
            head_sha       = "",     # unknown without API
            size_kb        = 0,
        )

    def validate_token(self, token: str) -> TokenInfo:
        """
        Cannot validate token without an API.
        Return a minimal TokenInfo — actual validation happens at fetch time.
        """
        return TokenInfo(
            token_type     = "unknown",
            scopes         = [],
            login          = "unknown",
            expires_at     = "",
            rate_limit     = 0,
            rate_remaining = 0,
            rate_reset_at  = 0,
        )

    def parse_rate_limit(self, headers: dict[str, str]) -> dict[str, int]:
        return {}