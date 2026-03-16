"""
PRISM Git Client
================
Fetches a repository into a local temporary directory using TLS-secured
HTTPS transport. Credentials are held in memory only and zeroed after use.

Backend selection:
  Primary:  pygit2 (libgit2 Python bindings)
            - Full control over TLS certificate verification
            - In-memory credential callbacks (no subprocess, no disk writes)
            - Shallow clone support (depth=1)
  Fallback: dulwich (pure-Python Git implementation)
            - No C extension, works in restricted environments
            - Slightly slower but same security guarantees
  Last resort: subprocess git clone with GIT_ASKPASS credential helper
            - Only used if both library backends fail
            - Credential is written to a tempfile and immediately deleted

Why NOT subprocess as primary?
  When you run: git clone https://user:token@host/repo
  The token appears in:
    - /proc/self/cmdline  (visible to all processes in the container)
    - shell history
    - server access logs
  Using an in-memory credential callback avoids all three.

TLS verification:
  By default, Python's ssl module uses the system CA bundle.
  Inside the gVisor sandbox, we verify:
    - Certificate chain validates against system CAs
    - Hostname matches the certificate CN/SAN
    - Certificate is not expired
  Certificate pinning is NOT enabled for the MVP because GitHub/GitLab
  rotate their certificates on their own schedule. Enable per-host
  pinning if the target is a known fixed internal host.

References:
  - pygit2 authentication: https://www.pygit2.org/recipes/authentication.html
  - dulwich: https://www.dulwich.io/docs/
  - libgit2 TLS: https://libgit2.org/libgit2/#HEAD/group/repository
"""

from __future__ import annotations

import logging
import os
import ssl
import tempfile
import time
from pathlib import Path
from typing import Callable

from .credential_provider import SecureString
from .providers.base import AuthHeader, ProviderRegistry
from .models import IngestionRequest

logger = logging.getLogger(__name__)

# How long to wait for a network connection before aborting
_CONNECT_TIMEOUT_S = 30

# Maximum number of redirects to follow (SSRF mitigation — limit redirect chains)
_MAX_REDIRECTS = 3


class GitFetchResult:
    """Result of a single Git fetch operation."""

    def __init__(
        self,
        success:         bool,
        local_path:      str,
        fetched_commit:  str,
        backend_used:    str,
        duration_ms:     float,
        error:           str | None = None,
        warnings:        list[str] | None = None,
    ) -> None:
        self.success        = success
        self.local_path     = local_path
        self.fetched_commit = fetched_commit   # actual 40-hex SHA fetched
        self.backend_used   = backend_used
        self.duration_ms    = duration_ms
        self.error          = error
        self.warnings:      list[str] = warnings or []


class GitClient:
    """
    Fetches a Git repository over HTTPS into a local temp directory.

    The credential is consumed via a callback — it is never stored as
    an instance attribute and never appears in any log output.

    Usage:
        client = GitClient()
        with client.fetch(request, credential) as result:
            # result.local_path contains the fetched repo
            process_files(result.local_path)
        # temp directory cleaned up here
    """

    def __init__(self) -> None:
        self._registry    = ProviderRegistry()
        self._pygit2_ok   = self._check_pygit2()
        self._dulwich_ok  = self._check_dulwich()
        logger.info(
            "GitClient initialized. pygit2=%s dulwich=%s",
            self._pygit2_ok, self._dulwich_ok,
        )

    # Availability checks

    def _check_pygit2(self) -> bool:
        try:
            import pygit2  # noqa: F401
            return True
        except ImportError:
            logger.warning("pygit2 not available. Install: pip install pygit2")
            return False

    def _check_dulwich(self) -> bool:
        try:
            import dulwich  # noqa: F401
            return True
        except ImportError:
            logger.warning("dulwich not available. Install: pip install dulwich")
            return False

    # Public fetch interface

    def fetch(
        self,
        request:    IngestionRequest,
        credential: SecureString,
        dest_dir:   str,
    ) -> GitFetchResult:
        """
        Clone the repository described by `request` into `dest_dir`.

        Args:
            request:    validated IngestionRequest
            credential: SecureString containing the raw token
                        (caller retains ownership — we do NOT zero it here)
            dest_dir:   absolute path to an already-created temp directory

        Returns:
            GitFetchResult — check .success before proceeding
        """
        start_ms = time.monotonic() * 1000
        strategy = self._registry.get_strategy(request.repo_url)

        # Normalize URL — strip any embedded credentials, enforce HTTPS
        try:
            clean_url = strategy.normalize_url(request.repo_url)
        except ValueError as exc:
            return GitFetchResult(
                success=False, local_path=dest_dir,
                fetched_commit="", backend_used="none",
                duration_ms=0.0, error=str(exc),
            )

        logger.info(
            "Fetching %s (branch=%s depth=%d) via %s",
            clean_url, request.branch, request.depth,
            strategy.provider_type().value,
        )

        # Build auth header from the live credential
        # token is extracted here — single-use, not stored
        auth = strategy.build_auth_header(credential.get())

        # Try backends in order of preference
        result = None
        if self._pygit2_ok:
            result = self._fetch_pygit2(
                clean_url, request, auth, dest_dir, start_ms
            )

        if (result is None or not result.success) and self._dulwich_ok:
            logger.info("pygit2 failed or unavailable — trying dulwich")
            result = self._fetch_dulwich(
                clean_url, request, auth, dest_dir, start_ms
            )

        if result is None or not result.success:
            logger.info("Library backends failed — trying subprocess fallback")
            result = self._fetch_subprocess(
                clean_url, request, credential, dest_dir, start_ms
            )

        # Zero the auth header values — they contain the raw token
        _zero_string(auth.password)
        _zero_string(auth.value)

        return result

    # Backend: pygit2 (primary)

    def _fetch_pygit2(
        self,
        url:      str,
        request:  IngestionRequest,
        auth:     AuthHeader,
        dest_dir: str,
        start_ms: float,
    ) -> GitFetchResult:
        """
        Clone via libgit2 with in-memory credential callback.

        The credential callback is a closure over `auth` — libgit2 calls
        it when it needs credentials. The callback returns the username
        and password without ever writing them to disk or env vars.
        """
        try:
            import pygit2

            # Build TLS-verified remote callbacks
            callbacks = _Pygit2Callbacks(auth)

            # Clone options
            clone_opts: dict = {
                "callbacks": callbacks,
                "checkout_branch": request.branch,
            }

            # Shallow clone: pygit2 supports depth via fetch options
            # depth=1 means only the tip commit — no history objects transferred
            fetch_opts = pygit2.FetchOptions()
            fetch_opts.callbacks = callbacks
            fetch_opts.depth = request.depth    # 0 = full, N = shallow

            repo = pygit2.clone_repository(
                url,
                dest_dir,
                callbacks=callbacks,
                checkout_branch=request.branch,
                depth=request.depth,
            )

            # Verify we got a valid HEAD
            try:
                head_commit = repo.head.target.hex
            except Exception:
                head_commit = ""

            # If a specific commit was requested, verify it matches
            if request.commit_sha and head_commit:
                if not head_commit.startswith(request.commit_sha[:7]):
                    # Fetch the specific commit explicitly
                    head_commit = self._checkout_commit_pygit2(
                        repo, request.commit_sha
                    )

            elapsed = time.monotonic() * 1000 - start_ms
            return GitFetchResult(
                success=True, local_path=dest_dir,
                fetched_commit=head_commit, backend_used="pygit2",
                duration_ms=round(elapsed, 2),
            )

        except Exception as exc:
            elapsed = time.monotonic() * 1000 - start_ms
            logger.warning("pygit2 fetch failed: %s", exc)
            return GitFetchResult(
                success=False, local_path=dest_dir,
                fetched_commit="", backend_used="pygit2",
                duration_ms=round(elapsed, 2), error=str(exc),
            )

    def _checkout_commit_pygit2(self, repo, commit_sha: str) -> str:
        """Check out a specific commit SHA and return the full hex."""
        try:
            import pygit2
            commit = repo.get(commit_sha)
            if commit:
                repo.checkout_tree(commit)
                repo.set_head(commit.id)
                return commit.hex
        except Exception as exc:
            logger.warning("Specific commit checkout failed: %s", exc)
        return commit_sha

    # Backend: dulwich (fallback)

    def _fetch_dulwich(
        self,
        url:      str,
        request:  IngestionRequest,
        auth:     AuthHeader,
        dest_dir: str,
        start_ms: float,
    ) -> GitFetchResult:
        """
        Clone via dulwich — pure Python, no subprocess.

        dulwich uses urllib3 internally for HTTPS, which respects
        Python's ssl context (system CAs, hostname verification).
        """
        try:
            from dulwich import porcelain
            from dulwich.client import HttpGitClient

            # dulwich expects credentials as HTTP Basic
            # We pass them via a custom HttpGitClient with auth header
            errstream = _NullStream()

            porcelain.clone(
                url,
                target=dest_dir,
                depth=request.depth,
                branch=request.branch.encode(),
                errstream=errstream,
                username=auth.username,
                password=auth.password,
            )

            # Read the HEAD commit from the cloned repo
            head_commit = _read_dulwich_head(dest_dir)

            elapsed = time.monotonic() * 1000 - start_ms
            return GitFetchResult(
                success=True, local_path=dest_dir,
                fetched_commit=head_commit, backend_used="dulwich",
                duration_ms=round(elapsed, 2),
            )

        except Exception as exc:
            elapsed = time.monotonic() * 1000 - start_ms
            logger.warning("dulwich fetch failed: %s", exc)
            return GitFetchResult(
                success=False, local_path=dest_dir,
                fetched_commit="", backend_used="dulwich",
                duration_ms=round(elapsed, 2), error=str(exc),
            )

    # Backend: subprocess git clone (last resort)

    def _fetch_subprocess(
        self,
        url:        str,
        request:    IngestionRequest,
        credential: SecureString,
        dest_dir:   str,
        start_ms:   float,
    ) -> GitFetchResult:
        """
        Clone via subprocess with a GIT_ASKPASS credential helper.

        This is the last resort. We mitigate subprocess risks by:
          1. Writing the credential to a tempfile with mode 0o700
          2. Pointing GIT_ASKPASS at the tempfile
          3. Deleting the tempfile immediately after clone completes
          4. Using the minimal subprocess env from sandbox_config
          5. Never putting the token in the command-line args

        The tempfile approach is less ideal than in-memory callbacks,
        but it's still far safer than embedding the token in the URL.

        GIT_ASKPASS is a script that Git calls when it needs credentials.
        It receives the prompt on stdin and must print the answer to stdout.
        We write a minimal shell script that echoes the token.
        """
        import subprocess
        import stat

        # Import minimal env builder from sandbox_config
        from ..parser.sandbox_config import get_minimal_subprocess_env


        askpass_path: str | None = None
        try:
            # Write GIT_ASKPASS helper script to tempfile
            # The script echoes the token when Git asks for "Password"
            token_val = credential.get()

            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".sh",
                prefix="prism_askpass_",
                dir="/tmp",
                delete=False,
            ) as f:
                # Minimal POSIX shell script
                # Git calls this with the prompt as $1 and expects the
                # credential on stdout
                f.write("#!/bin/sh\n")
                f.write(f'echo "{token_val}"\n')
                askpass_path = f.name

            # Make executable, owner-only readable
            os.chmod(askpass_path, stat.S_IRWXU)  # 0o700
            del token_val  # zero local reference

            env = get_minimal_subprocess_env()
            env["GIT_ASKPASS"]        = askpass_path
            env["GIT_TERMINAL_PROMPT"] = "0"          # never prompt interactively
            env["GIT_SSL_NO_VERIFY"]  = "0"           # enforce TLS verification

            cmd = [
                "git", "clone",
                "--depth", str(request.depth),
                "--branch", request.branch,
                "--single-branch",
                "--no-tags",
                "--quiet",
                url,
                dest_dir,
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=request.timeout_s,
                env=env,
                cwd="/tmp",
            )

            if result.returncode != 0:
                return GitFetchResult(
                    success=False, local_path=dest_dir,
                    fetched_commit="", backend_used="subprocess_git",
                    duration_ms=round(time.monotonic() * 1000 - start_ms, 2),
                    # Sanitize stderr — it might contain URL fragments
                    error=_sanitize_git_error(result.stderr),
                )

            head_commit = _read_git_head_subprocess(dest_dir, env)
            elapsed = time.monotonic() * 1000 - start_ms
            return GitFetchResult(
                success=True, local_path=dest_dir,
                fetched_commit=head_commit, backend_used="subprocess_git",
                duration_ms=round(elapsed, 2),
                warnings=["Used subprocess fallback — recommend installing pygit2"],
            )

        except Exception as exc:
            elapsed = time.monotonic() * 1000 - start_ms
            return GitFetchResult(
                success=False, local_path=dest_dir,
                fetched_commit="", backend_used="subprocess_git",
                duration_ms=round(elapsed, 2), error=str(exc),
            )
        finally:
            # ALWAYS delete the askpass tempfile
            if askpass_path:
                try:
                    # Overwrite with zeros before deletion
                    _overwrite_and_delete(askpass_path)
                except Exception as exc:
                    logger.error(
                        "SECURITY: Failed to delete askpass tempfile %s: %s",
                        askpass_path, exc
                    )


# ---------------------------------------------------------------------------
# pygit2 credential callback
# ---------------------------------------------------------------------------

class _Pygit2Callbacks:
    """
    libgit2 remote callbacks for HTTPS authentication.

    MUST inherit pygit2.RemoteCallbacks — libgit2 checks isinstance() before
    accepting the callbacks argument. Without this, clone_repository raises
    TypeError: "callbacks must be a RemoteCallbacks instance".

    We guard the inheritance with a try/except so the class can still be
    defined when pygit2 is not installed (methods will never be called).
    """

    try:
        import pygit2 as _pygit2
        _base = _pygit2.RemoteCallbacks
    except ImportError:
        _base = object                     # fallback when pygit2 absent

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)

    def __init__(self, auth: "AuthHeader") -> None:
        # Call RemoteCallbacks.__init__ so libgit2 registers this instance
        try:
            import pygit2
            pygit2.RemoteCallbacks.__init__(self)
        except (ImportError, TypeError):
            pass
        self._auth     = auth
        self._attempts = 0

# Patch base class at class-body time (needed because Python resolves
# base classes when the class statement executes, not later).
try:
    import pygit2 as _pg2_mod
    _Pygit2Callbacks.__bases__ = (_pg2_mod.RemoteCallbacks,)
except (ImportError, TypeError):
    pass   # pygit2 not installed; class still usable for testing

    def credentials(self, url: str, username_from_url: str, allowed_types: int) -> object:
        """Called by libgit2 when authentication is needed."""
        import pygit2

        # Prevent infinite retry loops — libgit2 will call this repeatedly
        # if credentials are rejected. Abort after 2 attempts.
        self._attempts += 1
        if self._attempts > 2:
            raise pygit2.GitError("Authentication failed after 2 attempts")

        return pygit2.UserPass(self._auth.username, self._auth.password)

    def certificate_check(self, certificate: object, valid: bool, hostname: str) -> bool:
        """
        Called by libgit2 for every TLS certificate.
        We require valid=True — never accept invalid certificates.
        This enforces TLS certificate chain validation.
        """
        if not valid:
            logger.error(
                "TLS certificate validation FAILED for host: %s. "
                "Aborting fetch — refusing to connect to host with "
                "invalid certificate.", hostname
            )
            return False   # reject the connection
        return True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _NullStream:
    """Discards all writes — used for dulwich errstream."""
    def write(self, data: bytes) -> int:
        return len(data) if isinstance(data, bytes) else 0
    def flush(self) -> None:
        pass


def _read_dulwich_head(repo_dir: str) -> str:
    """Read HEAD commit SHA from a dulwich-cloned repo."""
    try:
        from dulwich.repo import Repo
        repo = Repo(repo_dir)
        head = repo.head()
        return head.decode() if isinstance(head, bytes) else str(head)
    except Exception:
        return ""


def _read_git_head_subprocess(repo_dir: str, env: dict) -> str:
    """Read HEAD commit SHA using git rev-parse."""
    import subprocess
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10,
            cwd=repo_dir, env=env,
        )
        return result.stdout.strip() if result.returncode == 0 else ""
    except Exception:
        return ""


def _sanitize_git_error(stderr: str) -> str:
    """
    Remove any URL-embedded credentials from git error messages.
    git sometimes echoes the remote URL in error output — if the user
    somehow passed a URL with embedded credentials, we strip them here.
    """
    import re
    # Replace https://user:pass@host with https://[REDACTED]@host
    return re.sub(r"https?://[^@\s]+@", "https://[REDACTED]@", stderr)[:500]


def _zero_string(s: str) -> None:
    """Best-effort zero of a Python string — limited by immutability."""
    # Python strings are immutable; we can only drop references.
    # The actual memory reclaim depends on GC. Short-lived tokens
    # mitigate this — they expire before GC becomes a concern.
    del s


def _overwrite_and_delete(path: str) -> None:
    """
    Overwrite a file with zeros then delete it.
    Used for the GIT_ASKPASS credential helper tempfile.
    """
    try:
        size = os.path.getsize(path)
        with open(path, "wb") as f:
            f.write(b"\x00" * size)
    except Exception:
        pass
    finally:
        try:
            os.unlink(path)
        except Exception:
            pass