"""
PRISM Tool Registry
====================
Dynamic availability checks for Vault, Neo4j, Joern, and CodeQL.
Called once at the start of each pipeline run (node_tool_health_check stage).

HEALTH POLICY (confirmed by operator):
  ALL FOUR tools are required when enabled.
  If any enabled tool is unavailable, the pipeline FAILS before ingestion.

  "Enabled" is determined by:
    Vault   — always required (no credentials without it)
    Neo4j   — always required (no CPG persistence or taint queries without it)
    Joern   — required when Settings.enable_joern = True
    CodeQL  — required when Settings.enable_codeql = True

  In PRISM_ENV=development, Vault has a softer failure mode:
  if Vault is down but PRISM_GIT_TOKEN is set, the pipeline warns rather
  than hard-failing, so local development without a running Vault instance
  remains possible. In production this exception does not apply.

Design:
  - Each check is independent; one tool failing does not block others from
    being checked (we collect all failures before aborting, so the operator
    sees the full picture in one run).
  - Hard timeouts prevent the health check from hanging the pipeline.
  - All subprocess checks use get_minimal_subprocess_env() so no secrets
    from the parent process leak into health-check subprocesses.
  - All error messages are sanitised — no credential values appear in logs.
"""

from __future__ import annotations

import logging
import os
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Per-tool check timeout in seconds.
# These must be long enough for slow JVM startups (Joern) but short enough
# that the health check does not meaningfully delay the pipeline.
_VAULT_TIMEOUT_S  = 8
_NEO4J_TIMEOUT_S  = 10
_JOERN_TIMEOUT_S  = 15   # JVM cold start on --version can take up to 10 s
_CODEQL_TIMEOUT_S = 10


# Data containers

@dataclass
class ToolStatus:
    """
    Result of checking a single external tool.

    available  True  → tool is reachable, authenticated, and operational
    available  False → tool is down, misconfigured, or disabled;
                       `reason` explains why (never contains secrets)
    required   True  → pipeline must fail if this tool is not available
    """
    name:       str
    available:  bool
    required:   bool  = False    # set by ToolRegistryResult based on Settings
    version:    str   = ""
    latency_ms: float = 0.0
    reason:     str   = ""
    metadata:   dict  = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name":       self.name,
            "available":  self.available,
            "required":   self.required,
            "version":    self.version,
            "latency_ms": round(self.latency_ms, 1),
            "reason":     self.reason,
            "metadata":   self.metadata,
        }


@dataclass
class ToolRegistryResult:
    """
    Aggregated health status after check_all().
    Stored in PipelineState.tool_status for the lifetime of the run.
    """
    vault:      ToolStatus
    neo4j:      ToolStatus
    joern:      ToolStatus
    codeql:     ToolStatus
    checked_at: float = field(default_factory=time.monotonic)

    def _mark_required(self) -> None:
        """
        Mark each tool as required or optional based on Settings.
        Called once after all checks complete.

        Policy:
          Vault   — always required in production; optional in development
                    when PRISM_GIT_TOKEN provides a fallback credential.
          Neo4j   — always required (no graph without it).
          Joern   — required when enable_joern=True.
          CodeQL  — required when enable_codeql=True.
        """
        try:
            from .config import get_settings
            s = get_settings()
            in_dev = s.prism_env in ("development", "test")

            # Vault: required always except dev-mode with a fallback token
            vault_has_fallback = bool(os.environ.get("PRISM_GIT_TOKEN")) and in_dev
            self.vault.required = not vault_has_fallback

            self.neo4j.required = True
            self.joern.required  = s.enable_joern
            self.codeql.required = s.enable_codeql

        except Exception:
            # If Settings is unavailable assume all are required 
            self.vault.required  = True
            self.neo4j.required  = True
            self.joern.required  = True
            self.codeql.required = True

    @property
    def all_required_available(self) -> bool:
        """
        True only when every required tool is available.

        A tool is required if `tool.required is True`.
        Required tools that are unavailable cause the pipeline to fail.
        """
        self._mark_required()
        return all(
            t.available
            for t in (self.vault, self.neo4j, self.joern, self.codeql)
            if t.required
        )

    @property
    def failing_required(self) -> list[ToolStatus]:
        """Return the list of required tools that are NOT available."""
        self._mark_required()
        return [
            t for t in (self.vault, self.neo4j, self.joern, self.codeql)
            if t.required and not t.available
        ]

    def summary(self) -> dict[str, Any]:
        """Serialisable dict suitable for PipelineState.tool_status."""
        self._mark_required()
        return {
            t.name: t.to_dict()
            for t in (self.vault, self.neo4j, self.joern, self.codeql)
        }

    def log_summary(self) -> None:
        """Write a formatted summary to the logger at INFO/WARNING level."""
        self._mark_required()
        for t in (self.vault, self.neo4j, self.joern, self.codeql):
            req_tag = "[required]" if t.required else "[optional]"
            if t.available:
                logger.info(
                    "  ✓ %-8s  %-11s  %s  (%.0f ms)",
                    t.name, req_tag,
                    (t.version[:40] if t.version else "ok"),
                    t.latency_ms,
                )
            else:
                logger.warning(
                    "  ✗ %-8s  %-11s  %s",
                    t.name, req_tag, t.reason,
                )


# Registry

class ToolRegistry:
    """
    Checks availability of all four external tools.
    Stateless — instantiate fresh per pipeline run.
    """

    def check_all(self) -> ToolRegistryResult:
        """
        Run all four checks and return aggregated results.
        Checks run sequentially; each has an independent timeout so one
        slow tool does not delay the others beyond its own limit.
        """
        vault  = self._check_vault()
        neo4j  = self._check_neo4j()
        joern  = self._check_joern()
        codeql = self._check_codeql()
        result = ToolRegistryResult(
            vault=vault, neo4j=neo4j, joern=joern, codeql=codeql,
        )
        result._mark_required()
        return result

    # Vault

    def _check_vault(self) -> ToolStatus:
        from .config import get_settings
        s = get_settings()
        t0 = time.monotonic()

        try:
            import hvac
        except ImportError:
            return ToolStatus(
                "vault", False,
                reason="hvac not installed: pip install hvac",
            )

        try:
            client = hvac.Client(url=s.vault_addr, timeout=_VAULT_TIMEOUT_S)

            if s.vault_token:
                # Token auth (development / CI)
                client.token = s.vault_token
            elif s.vault_role_id and s.vault_secret_id:
                # AppRole auth (production)
                resp = client.auth.approle.login(
                    role_id=s.vault_role_id,
                    secret_id=s.vault_secret_id,
                )
                client.token = resp["auth"]["client_token"]
            else:
                latency = (time.monotonic() - t0) * 1000
                return ToolStatus(
                    "vault", False,
                    latency_ms=latency,
                    reason=(
                        "No Vault credentials configured. "
                        "Set VAULT_TOKEN (dev) or "
                        "VAULT_ROLE_ID + VAULT_SECRET_ID (prod)."
                    ),
                )

            authenticated = client.is_authenticated()
            latency = (time.monotonic() - t0) * 1000

            if authenticated:
                try:
                    health = client.sys.read_health_status(method="GET")
                    version = (
                        health.get("version", "unknown")
                        if isinstance(health, dict)
                        else "unknown"
                    )
                except Exception:
                    version = "unknown"
                return ToolStatus(
                    "vault", True,
                    version=version,
                    latency_ms=latency,
                    metadata={
                        "addr":      s.vault_addr,
                        "auth_type": "token" if s.vault_token else "approle",
                    },
                )

            return ToolStatus(
                "vault", False,
                latency_ms=latency,
                reason=(
                    "Vault connected but is_authenticated() = False. "
                    "Token may be expired or policy insufficient."
                ),
            )

        except Exception as exc:
            latency = (time.monotonic() - t0) * 1000
            # Sanitise: never log the token value itself
            safe_msg = str(exc)
            if s.vault_token:
                safe_msg = safe_msg.replace(s.vault_token, "[REDACTED]")
            return ToolStatus(
                "vault", False,
                latency_ms=latency,
                reason=f"Vault unreachable at {s.vault_addr}: {safe_msg}",
            )

    # Neo4j

    def _check_neo4j(self) -> ToolStatus:
        from .config import get_settings
        s = get_settings()
        t0 = time.monotonic()

        try:
            from neo4j import GraphDatabase
        except ImportError:
            return ToolStatus(
                "neo4j", False,
                reason="neo4j driver not installed: pip install neo4j",
            )

        driver = None
        try:
            driver = GraphDatabase.driver(
                s.neo4j_uri,
                auth=(s.neo4j_user, s.neo4j_password),
                connection_timeout=_NEO4J_TIMEOUT_S,
                max_connection_pool_size=2,
            )
            driver.verify_connectivity()

            with driver.session(database=s.neo4j_database) as session:
                rec = session.run(
                    "CALL dbms.components() YIELD name, versions "
                    "WHERE name = 'Neo4j Kernel' "
                    "RETURN versions[0] AS version"
                ).single()
                version = rec["version"] if rec else "unknown"

            latency = (time.monotonic() - t0) * 1000
            return ToolStatus(
                "neo4j", True,
                version=version,
                latency_ms=latency,
                metadata={"uri": s.neo4j_uri, "database": s.neo4j_database},
            )

        except Exception as exc:
            latency = (time.monotonic() - t0) * 1000
            safe_msg = str(exc).replace(s.neo4j_password or "NOPW", "[REDACTED]")
            return ToolStatus(
                "neo4j", False,
                latency_ms=latency,
                reason=f"Neo4j unreachable at {s.neo4j_uri}: {safe_msg}",
            )
        finally:
            if driver:
                try:
                    driver.close()
                except Exception:
                    pass

    # Joern

    def _check_joern(self) -> ToolStatus:
        from .config import get_settings
        s = get_settings()

        if not s.enable_joern:
            return ToolStatus(
                "joern", False,
                reason=(
                    "Joern disabled (ENABLE_JOERN=false). "
                    "Set ENABLE_JOERN=true and configure JOERN_BIN or JOERN_HOME."
                ),
            )

        t0 = time.monotonic()

        # Server mode: probe HTTP endpoint
        if s.joern_server_url:
            return self._check_joern_server(s, t0)

        # Subprocess mode: probe binary
        return self._check_joern_subprocess(s, t0)

    def _check_joern_server(self, s, t0: float) -> ToolStatus:
        import urllib.request
        import json as json_mod
        url = s.joern_server_url.rstrip("/")
        try:
            req = urllib.request.Request(
                f"{url}/api/v1/version",
                headers={"Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=_JOERN_TIMEOUT_S) as resp:
                data = json_mod.loads(resp.read())
                version = data.get("version", "unknown")
            latency = (time.monotonic() - t0) * 1000
            return ToolStatus(
                "joern", True,
                version=version,
                latency_ms=latency,
                metadata={"mode": "server", "url": url},
            )
        except Exception as exc:
            latency = (time.monotonic() - t0) * 1000
            return ToolStatus(
                "joern", False,
                latency_ms=latency,
                reason=(
                    f"Joern server unreachable at {url}: {exc}. "
                    f"Start with: joern --server --server-host 0.0.0.0 --server-port 8080"
                ),
            )

    def _check_joern_subprocess(self, s, t0: float) -> ToolStatus:
        binary = self._resolve_joern_binary(s)
        if not binary:
            return ToolStatus(
                "joern", False,
                reason=(
                    f"joern-parse not found. "
                    f"Tried JOERN_BIN={s.joern_bin!r}, "
                    f"JOERN_HOME={s.joern_home!r}/bin/joern-parse, PATH. "
                    f"Download: https://github.com/joernio/joern/releases"
                ),
            )

        env = self._minimal_env(extra_keys=("JAVA_HOME", "PATH"))
        try:
            result = subprocess.run(
                [binary, "--version"],
                capture_output=True, text=True,
                timeout=_JOERN_TIMEOUT_S, env=env,
            )
            latency = (time.monotonic() - t0) * 1000
            version = (result.stdout or result.stderr or "").strip()[:80]
            # joern-parse --version may return non-zero on some builds
            # but still emit a version string — treat as available
            if binary and (result.returncode == 0 or version):
                return ToolStatus(
                    "joern", True,
                    version=version,
                    latency_ms=latency,
                    metadata={"mode": "subprocess", "binary": binary},
                )
            return ToolStatus(
                "joern", False,
                latency_ms=latency,
                reason=f"joern-parse exited {result.returncode}: {result.stderr[:200]}",
            )
        except subprocess.TimeoutExpired:
            return ToolStatus(
                "joern", False,
                latency_ms=(time.monotonic() - t0) * 1000,
                reason=f"joern-parse --version timed out after {_JOERN_TIMEOUT_S}s",
            )
        except Exception as exc:
            return ToolStatus(
                "joern", False,
                latency_ms=(time.monotonic() - t0) * 1000,
                reason=f"joern-parse check failed: {exc}",
            )

    def _resolve_joern_binary(self, s) -> str | None:
        import shutil
        # Priority 1: explicit JOERN_BIN setting
        if s.joern_bin and os.path.isfile(s.joern_bin) and os.access(s.joern_bin, os.X_OK):
            return s.joern_bin
        # Priority 2: JOERN_HOME/bin/joern-parse
        if s.joern_home:
            candidate = os.path.join(s.joern_home, "bin", "joern-parse")
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
        # Priority 3: PATH
        return shutil.which("joern-parse")

    # CodeQL

    def _check_codeql(self) -> ToolStatus:
        from .config import get_settings
        s = get_settings()

        if not s.enable_codeql:
            return ToolStatus(
                "codeql", False,
                reason=(
                    "CodeQL disabled (ENABLE_CODEQL=false). "
                    "Set ENABLE_CODEQL=true and configure CODEQL_CLI_PATH."
                ),
            )

        t0 = time.monotonic()
        cli = s.codeql_cli_path or "codeql"
        env = self._minimal_env(extra_keys=("JAVA_HOME", "CODEQL_JAVA_HOME", "PATH"))

        try:
            import json as json_mod
            result = subprocess.run(
                [cli, "version", "--format=json"],
                capture_output=True, text=True,
                timeout=_CODEQL_TIMEOUT_S, env=env,
            )
            latency = (time.monotonic() - t0) * 1000

            if result.returncode == 0:
                info = json_mod.loads(result.stdout)
                return ToolStatus(
                    "codeql", True,
                    version=info.get("version", "unknown"),
                    latency_ms=latency,
                    metadata={
                        "cli":         cli,
                        "unpack_dir":  info.get("unpackedLocation", ""),
                    },
                )
            return ToolStatus(
                "codeql", False,
                latency_ms=latency,
                reason=(
                    f"codeql version returned {result.returncode}: "
                    f"{result.stderr[:200]}"
                ),
            )

        except FileNotFoundError:
            return ToolStatus(
                "codeql", False,
                latency_ms=(time.monotonic() - t0) * 1000,
                reason=(
                    f"CodeQL CLI not found at '{cli}'. "
                    f"Set CODEQL_CLI_PATH or ensure 'codeql' is on PATH. "
                    f"Download: https://github.com/github/codeql-action/releases"
                ),
            )
        except subprocess.TimeoutExpired:
            return ToolStatus(
                "codeql", False,
                latency_ms=(time.monotonic() - t0) * 1000,
                reason=f"codeql version timed out after {_CODEQL_TIMEOUT_S}s",
            )
        except Exception as exc:
            return ToolStatus(
                "codeql", False,
                latency_ms=(time.monotonic() - t0) * 1000,
                reason=f"codeql check failed: {exc}",
            )

    # Shared helper

    def _minimal_env(self, extra_keys: tuple[str, ...] = ()) -> dict[str, str]:
        """
        Build a minimal subprocess environment with no parent secrets.
        Falls back gracefully if sandbox_config is not importable.
        """
        try:
            try:
                from parser.sandbox_config import get_minimal_subprocess_env
            except ImportError:
                from ...parser.sandbox_config import get_minimal_subprocess_env
            extra = {k: os.environ[k] for k in extra_keys if k in os.environ}
            return get_minimal_subprocess_env(extra)
        except Exception:
            env: dict[str, str] = {
                "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                "HOME": "/tmp",
                "LANG": "en_US.UTF-8",
            }
            for k in extra_keys:
                if k in os.environ:
                    env[k] = os.environ[k]
            return env


# Public API

def check_tools() -> ToolRegistryResult:
    """
    Check availability and required-status of all four tools.

    Returns a ToolRegistryResult.  Inspect:
      result.all_required_available  → bool  (pipeline may proceed)
      result.failing_required        → list  (tools to fix before retrying)
      result.summary()               → dict  (for PipelineState.tool_status)
      result.log_summary()           → None  (writes to logger)
    """
    return ToolRegistry().check_all()