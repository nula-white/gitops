"""
URL and input validation functions shared between pipeline.py and
submodule_resolver.py. Extracted here to break the circular import:

    pipeline.py → submodule_resolver.py → pipeline.py  ✗
    pipeline.py → validators.py ← submodule_resolver.py  ✓
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

_SHA_PATTERN  = re.compile(r"^[0-9a-f]{7,40}$", re.I)
_MAX_URL_LENGTH = 512
_ALLOWED_SCHEMES = frozenset({"https"})


def check_ssrf(hostname: str) -> str | None:
    """
    Block private/loopback/reserved IP ranges and localhost.
    Returns error string if blocked, None if safe.
    """
    h = hostname.lower().strip("[]")
    if h in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        return f"SSRF blocked: hostname {hostname!r} is localhost"
    try:
        ip = ipaddress.ip_address(h)
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            return (
                f"SSRF blocked: IP address {hostname!r} is in a "
                f"private/reserved range. Only public internet hosts allowed."
            )
    except ValueError:
        pass
    return None


def is_safe_ref(ref: str) -> bool:
    """Validate a Git branch/tag ref name. Blocks shell metacharacters."""
    return bool(re.match(r"^[a-zA-Z0-9_\-./]+$", ref))


def validate_request(request) -> str | None:
    """Full request validation. Returns error string or None."""
    if not request.repo_url:
        return "repo_url is required"
    if len(request.repo_url) > _MAX_URL_LENGTH:
        return f"repo_url exceeds maximum length ({_MAX_URL_LENGTH} chars)"
    try:
        parsed = urlparse(request.repo_url)
    except Exception as exc:
        return f"Invalid repo_url: {exc}"
    if parsed.scheme not in _ALLOWED_SCHEMES:
        return (
            f"Only HTTPS URLs are accepted. Got scheme: {parsed.scheme!r}. "
            f"SSH support is planned for a future release."
        )
    if parsed.username or parsed.password:
        return (
            "Embedded credentials in repo_url are not allowed. "
            "Provide credentials via credential_ref instead."
        )
    if not parsed.hostname:
        return "repo_url has no hostname"
    ssrf = check_ssrf(parsed.hostname)
    if ssrf:
        return ssrf
    if not is_safe_ref(request.branch):
        return (
            f"Branch name {request.branch!r} contains unsafe characters. "
            f"Only alphanumeric, -, _, /, and . are allowed."
        )
    if request.commit_sha and not _SHA_PATTERN.match(request.commit_sha):
        return (
            f"commit_sha {request.commit_sha!r} is not a valid Git SHA. "
            f"Expected 7-40 hex characters."
        )
    if request.depth < 1:
        return f"depth must be >= 1, got {request.depth}"
    if not request.credential_ref:
        return "credential_ref is required"
    return None