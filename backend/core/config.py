"""
PRISM Central Configuration
============================
Single source of truth for all runtime settings.
Read once at startup via @lru_cache; validated by Pydantic.

Secrets (tokens, passwords) come from Vault (production) or
PRISM_GIT_TOKEN env var (development fallback).
Tool paths come from .env / environment variables.

codeql_timeout_analyze = 0 means NO TIMEOUT — the pipeline waits
indefinitely for CodeQL to finish.  This is the correct setting when
you want to guarantee complete SARIF results regardless of repository
size.  The frontend streams progress events during the wait.
Set to a positive integer (seconds) to enable a hard timeout.
"""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):

    # ── Neo4j ────────────────────────────────────────────────────────────────
    neo4j_uri:          str = "bolt://localhost:7687"
    neo4j_user:         str = "neo4j"
    neo4j_password:     str = "password"
    neo4j_database:     str = "neo4j"
    neo4j_max_pool:     int = 50
    neo4j_timeout_s:    int = 30       # connection / query timeout

    # ── Joern ────────────────────────────────────────────────────────────────
    # enable_joern=False  →  JoernDelegate.can_parse() returns False;
    #                        pipeline falls through to Tree-sitter without error.
    # enable_joern=True   →  Joern is REQUIRED; pipeline fails if unavailable.
    enable_joern:       bool = False
    joern_bin:          str  = ""      # explicit path: /opt/joern/bin/joern-parse
    joern_home:         str  = ""      # directory; bin/joern-parse resolved from here
    joern_timeout:      int  = 300     # seconds per joern-parse subprocess
    joern_max_heap:     str  = "2G"    # JVM -Xmx value
    joern_server_url:   str  = ""      # if set, use server mode (persistent JVM)

    # ── CodeQL ───────────────────────────────────────────────────────────────
    # enable_codeql=False  →  CodeQL stage is skipped; heuristic annotator used.
    # enable_codeql=True   →  CodeQL is REQUIRED; pipeline fails if unavailable.
    enable_codeql:             bool = False
    codeql_cli_path:           str  = ""   # explicit path: /opt/codeql/codeql
    codeql_search_path:        str  = ""   # path to codeql-repo query libraries
    codeql_timeout_create:     int  = 600  # seconds for `codeql database create`
    # 0 = NO TIMEOUT — wait indefinitely.  Positive integer = hard timeout in s.
    # The user confirmed: always wait; streaming events keep the frontend live.
    codeql_timeout_analyze:    int  = 0
    codeql_timeout_query:      int  = 120  # seconds for inline QL queries
    codeql_threads:            int  = 2    # --threads flag

    # ── HashiCorp Vault ───────────────────────────────────────────────────────
    vault_addr:         str  = "http://127.0.0.1:8200"
    vault_role_id:      str  = ""   # AppRole — from vault-appole-setup.sh
    vault_secret_id:    str  = ""   # AppRole — from vault-appole-setup.sh
    vault_token:        str  = ""   # Token auth (development only)
    vault_required:     bool = False

    # ── Git token fallback ────────────────────────────────────────────────────
    # Used ONLY when Vault is unreachable AND prism_env=development.
    prism_git_token:    str = ""

    # ── Analysis sandbox ──────────────────────────────────────────────────────
    max_file_size_mb:        int = 10
    sandbox_timeout_seconds: int = 120

    # ── WebSocket ────────────────────────────────────────────────────────────
    ws_heartbeat_interval: int = 15

    # ── Runtime environment ───────────────────────────────────────────────────
    # development: Vault optional (PRISM_GIT_TOKEN fallback OK); verbose logging
    # test:        same as development
    # production:  Vault required when vault_required=True; strict error handling
    prism_env: str = "development"

    model_config = {
        "env_file":          ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive":    False,
        "extra":             "ignore",
    }


@lru_cache()
def get_settings() -> Settings:
    return Settings()