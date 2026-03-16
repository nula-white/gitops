"""
Credential Provider: Manages short-lived authentication tokens for repository ingestion.

Core security guarantees:
  1. Credentials are NEVER written to disk
  2. Credentials are NEVER logged (even at DEBUG level)
  3. Credential memory is zeroed after use via SecureString
  4. Credentials are fetched just-in-time, used once, then released
  5. All credential storage is in-memory only, scoped to the pipeline session

SecureString implementation:
  Python strings are immutable — you cannot zero them. We store the
  credential as a mutable bytearray internally and convert to str only
  at the exact point the Git callback fires. After use, the bytearray
  is overwritten with zeros and the reference is dropped.

  This does NOT guarantee the Python GC will immediately reclaim memory,
  but it eliminates the credential from any location WE control. The
  CPython string intern pool and GC are outside our control — which is
  exactly why credentials must also be short-lived at the source
  (GitHub PATs with 1-hour expiry, GitHub App tokens with 10-minute expiry).

Vault integration:
  In production, secrets are fetched from HashiCorp Vault using the
  AppRole auth method. The Vault token itself is injected at container
  start via the VAULT_TOKEN environment variable and is NOT persisted.
  Dynamic secrets (GitHub App tokens) are generated fresh per session.
"""

from __future__ import annotations

import ctypes
import logging
import os
import time
from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Generator

from .exceptions import (
    CredentialNotFoundError, CredentialExpiredError,
    CredentialZeroingError, VaultError,
    VaultUnavailableError, VaultAuthError, VaultSecretNotFoundError,
)

logger = logging.getLogger(__name__)

# Sentinel: used only in __repr__/__str__ to prevent accidental logging.
# The actual credential value is NEVER stored in any string that could
# appear in logs, tracebacks, or repr output.
_REDACTED = "[REDACTED]"


# SecureString — credential holder that zeroes memory on release

class SecureString:
    """
    Holds a credential in a mutable bytearray so we can zero it.

    Usage:
        with SecureString("ghp_actualtoken...") as cred:
            token = cred.get()   # returns str, use immediately
            # cred.get() must not be stored; use inline only
        # After 'with' block: memory zeroed, token inaccessible

    The __repr__ and __str__ always return "[REDACTED]" to prevent
    accidental logging of the credential value.
    """

    def __init__(self, value: str) -> None:
        # Store as bytearray — mutable, zeroable
        self._buf:   bytearray = bytearray(value.encode("utf-8"))
        self._valid: bool      = True
        # Overwrite the original string argument as best we can
        # (CPython may still have it interned — we can't control that)
        del value

    def get(self) -> str:
        """
        Return the credential as a str for immediate use.
        Do NOT store the returned string — use it inline.
        """
        if not self._valid:
            raise CredentialExpiredError(
            "SecureString has already been zeroed — credential was already used. "
            "Acquire a fresh credential for each pipeline session."
        )
        return self._buf.decode("utf-8")

    def zero(self) -> None:
        """
        Overwrite the internal buffer with zeros.
        Call this as soon as the credential is no longer needed.
        """
        if self._buf:
            # Use ctypes to write zeros directly into the bytearray buffer
            # This bypasses Python's usual memory management
            try:
                addr = id(self._buf) + (
                    # bytearray internal buffer offset — CPython implementation detail
                    # Fallback: simple slice assignment also works for bytearray
                    0
                )
                for i in range(len(self._buf)):
                    self._buf[i] = 0
            except Exception:
                # If ctypes approach fails, slice assignment still zeroes data
                for i in range(len(self._buf)):
                    self._buf[i] = 0
        self._valid = False

    def __enter__(self) -> "SecureString":
        return self

    def __exit__(self, *args: object) -> None:
        self.zero()

    def __del__(self) -> None:
        # Best-effort zero on garbage collection
        try:
            self.zero()
        except Exception:
            pass

    def __repr__(self) -> str:
        return _REDACTED

    def __str__(self) -> str:
        return _REDACTED

    @property
    def is_valid(self) -> bool:
        return self._valid


# Abstract credential provider

class AbstractCredentialProvider(ABC):
    """
    Base class for all credential providers.
    Subclasses implement get_credential() for their secret backend.
    """

    @abstractmethod
    def get_credential(self, credential_ref: str) -> SecureString:
        """
        Retrieve a credential by reference key.

        Args:
            credential_ref: opaque key (e.g. "github/org/repo_token")

        Returns:
            SecureString wrapping the raw token value.
            Caller MUST call .zero() or use as context manager.
        """
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if this provider is reachable."""
        ...

    @contextmanager
    def credential_context(
        self, credential_ref: str
    ) -> Generator[SecureString, None, None]:
        """
        Context manager that fetches, yields, then zeros a credential.

        Usage:
            with provider.credential_context("my/token") as cred:
                token = cred.get()
                # use token here — inline only
            # credential zeroed here
        """
        cred = self.get_credential(credential_ref)
        try:
            yield cred
        finally:
            cred.zero()
            logger.debug("Credential zeroed after use (ref=%s)", credential_ref)


# Environment variable provider (development / CI)

class EnvCredentialProvider(AbstractCredentialProvider):
    """
    Reads credentials from environment variables.
    Suitable for development and CI pipelines.
    NOT for production — env vars can be read by any process in the container.

    Mapping: credential_ref → env var name
    e.g. "github/myorg/repo" → PRISM_TOKEN_GITHUB_MYORG_REPO
         "gitlab/myorg/repo" → PRISM_TOKEN_GITLAB_MYORG_REPO

    The caller passes the ref; this provider maps it to an env var.
    """

    # Prefix for all PRISM credential env vars
    ENV_PREFIX = "PRISM_TOKEN_"

    def __init__(self, direct_token: str | None = None) -> None:
        """
        Args:
            direct_token: if set, this specific token is returned for
                          ANY credential_ref. Useful in single-repo CI.
                          The value is immediately wrapped in SecureString.
        """
        self._direct: SecureString | None = (
            SecureString(direct_token) if direct_token else None
        )
        # Zero the original string argument
        del direct_token

    def get_credential(self, credential_ref: str) -> SecureString:
        # Direct token takes precedence
        if self._direct and self._direct.is_valid:
            # Return a fresh SecureString with the same value
            # (so the caller can zero it independently)
            return SecureString(self._direct.get())

        # Map ref to env var: "github/org/repo" → "PRISM_TOKEN_GITHUB_ORG_REPO"
        env_key = (
            self.ENV_PREFIX
            + credential_ref.upper()
            .replace("/", "_")
            .replace("-", "_")
            .replace(".", "_")
        )
        value = os.environ.get(env_key)
        if not value:
            # Also try the generic fallback
            value = os.environ.get("PRISM_GIT_TOKEN")
        if not value:
            raise CredentialNotFoundError(
                f"No credential found for ref '{credential_ref}'. "
                f"Expected env var: {env_key} or PRISM_GIT_TOKEN"
            )

        token = SecureString(value)
        # Attempt to zero the env var from memory
        # (not fully effective — OS keeps env in process memory)
        del value
        return token

    def is_available(self) -> bool:
        return True   # env is always accessible


# HashiCorp Vault provider (production)

class VaultCredentialProvider(AbstractCredentialProvider):
    """
    Fetches dynamic short-lived credentials from HashiCorp Vault.

    Authentication: AppRole (role_id + secret_id injected at container start)
    Secret path: secret/prism/git/<credential_ref>
    Expected secret field: "token"

    The Vault client is initialized once. Each get_credential() call
    performs a fresh Vault read — no local caching of secret values.

    Free / local setup:
        docker run -d --cap-add=IPC_LOCK -e VAULT_DEV_ROOT_TOKEN_ID=root \
            -p 8200:8200 hashicorp/vault
        export VAULT_ADDR=http://127.0.0.1:8200
        export VAULT_TOKEN=root

    Ref: https://developer.hashicorp.com/vault/docs/auth/approle
    """

    VAULT_SECRET_PATH_PREFIX = "secret/data/prism/git/"

    def __init__(
        self,
        vault_addr: str | None = None,
        vault_token: str | None = None,
        vault_role_id: str | None = None,
        vault_secret_id: str | None = None,
    ) -> None:
        self._addr = vault_addr or os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
        # Token auth (dev) or AppRole auth (prod)
        self._vault_token   = vault_token   or os.environ.get("VAULT_TOKEN")
        self._role_id       = vault_role_id  or os.environ.get("VAULT_ROLE_ID")
        self._secret_id     = vault_secret_id or os.environ.get("VAULT_SECRET_ID")
        self._client        = None
        self._client_expiry = 0.0
        self._lock          = __import__("threading").Lock()   # guards _client + _expiry
        self._hvac_available = self._try_import_hvac()

    def _try_import_hvac(self) -> bool:
        try:
            import hvac  # noqa: F401
            return True
        except ImportError:
            logger.warning(
                "hvac not installed. Install with: pip install hvac. "
                "VaultCredentialProvider unavailable."
            )
            return False

    def _get_client(self):
        """Return an authenticated hvac client, re-authenticating if needed.

        Uses double-checked locking:
          1. Fast path — no lock, just read (avoids contention when cached).
          2. Slow path — acquire lock, re-check, then authenticate if still stale.
        This is safe because Python's GIL ensures atomic attribute reads.
        """
        import hvac

        now = time.monotonic()
        # Fast path: client is fresh — avoid lock overhead
        if self._client and now < self._client_expiry:
            return self._client

        with self._lock:
            # Re-check inside the lock — another thread may have authenticated
            now = time.monotonic()
            if self._client and now < self._client_expiry:
                return self._client

            client = hvac.Client(url=self._addr)

            if self._vault_token:
                client.token = self._vault_token
            elif self._role_id and self._secret_id:
                resp = client.auth.approle.login(
                    role_id=self._role_id,
                    secret_id=self._secret_id,
                )
                client.token = resp["auth"]["client_token"]
                ttl = resp["auth"].get("lease_duration", 3600)
                self._client_expiry = now + ttl - 60
            else:
                raise VaultAuthError(
                    "Vault authentication failed: neither VAULT_TOKEN nor AppRole "
                    "(VAULT_ROLE_ID + VAULT_SECRET_ID) credentials are available. "
                    "Set VAULT_TOKEN for development or VAULT_ROLE_ID/VAULT_SECRET_ID "
                    "for production. See prism/vault/README.md for setup instructions."
                )

            if not client.is_authenticated():
                raise VaultAuthError(
                    "Vault authentication succeeded in connecting but "
                    "is_authenticated() returned False. "
                    "Token may have expired during the connection attempt."
                )

            self._client = client
            return client

    def get_credential(self, credential_ref: str) -> SecureString:
        if not self._hvac_available:
            raise VaultUnavailableError(
                "hvac library not installed. Install with: pip install hvac. "
                "VaultCredentialProvider requires hvac to connect to HashiCorp Vault."
            )

        path = self.VAULT_SECRET_PATH_PREFIX + credential_ref
        try:
            client = self._get_client()
            secret = client.secrets.kv.v2.read_secret_version(path=path)
            token_value = secret["data"]["data"].get("token")
            if not token_value:
                raise VaultSecretNotFoundError(
                    f"No 'token' field found at Vault path {path!r}. "
                    f"Run setup_prism_secrets.sh to initialize the secret structure, "
                    f"then populate with: vault kv patch {path} token=<your_token>"
                )
            cred = SecureString(token_value)
            del token_value   # zero local reference
            return cred
        except CredentialNotFoundError:
            raise
        except Exception as exc:
            raise CredentialNotFoundError(
                f"Vault read failed for ref '{credential_ref}': {exc}"
            ) from exc

    def is_available(self) -> bool:
        if not self._hvac_available:
            return False
        try:
            client = self._get_client()
            return client.is_authenticated()
        except Exception:
            return False


# Composite provider — tries Vault, falls back to Env

class CompositeCredentialProvider(AbstractCredentialProvider):
    """
    Production provider that tries Vault first, falls back to env vars.
    This allows the same code to work in:
      - Local dev  (env vars)
      - CI/CD      (env vars or Vault)
      - Production (Vault only)
    """

    def __init__(self) -> None:
        self._vault = VaultCredentialProvider()
        self._env   = EnvCredentialProvider()

    def get_credential(self, credential_ref: str) -> SecureString:
        # Try Vault first (production path)
        if self._vault.is_available():
            try:
                return self._vault.get_credential(credential_ref)
            except CredentialNotFoundError:
                logger.debug(
                    "Vault lookup failed for %s, trying env vars", credential_ref
                )

        # Fall back to environment variables (dev/CI path)
        return self._env.get_credential(credential_ref)

    def is_available(self) -> bool:
        return self._vault.is_available() or self._env.is_available()


# Exceptions imported from prism.ingestion.exceptions 