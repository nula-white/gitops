from pydantic_settings import BaseSettings
from functools import lru_cache
import os
from dotenv import load_dotenv
load_dotenv()
neo4j_uri=os.getenv("NEO4J_URI")
neo4j_password=os.getenv("NEO4J_PASSWORD")
neo4j_user=os.getenv("NEO4J_URI")

class Settings(BaseSettings):

    # ── Neo4j ────────────────────────────────────────────────
    neo4j_uri: str      = neo4j_uri
    neo4j_user: str     = neo4j_user
    neo4j_password: str = neo4j_password
    neo4j_database: str = "neo4j"

    # ── Joern ────────────────────────────────────────────────
    enable_joern: bool   = False
    joern_bin: str       = "/opt/joern/joern-cli/joern"
    joern_home: str      = ""
    joern_timeout: int   = 300     # seconds per file
    joern_max_heap: str  = "2G"    # JVM heap e.g. "4G"

    # ── CodeQL ───────────────────────────────────────────────
    codeql_cli_path: str    = ""
    codeql_search_path: str = ""

    # ── HashiCorp Vault ──────────────────────────────────────
    vault_addr: str      = "http://127.0.0.1:8200"
    vault_role_id: str   = ""
    vault_secret_id: str = ""
    vault_token: str     = ""      # root token for admin commands only

    # ── Analysis sandbox ─────────────────────────────────────
    max_file_size_mb: int        = 10
    sandbox_timeout_seconds: int = 120

    # ── Git ingestion ─────────────────────────────────────────
    prism_git_token: str = ""      # GitHub PAT (fine-grained)

    # ── WebSocket ────────────────────────────────────────────
    ws_heartbeat_interval: int = 15

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
        # Silently ignore any .env keys not declared above.
        # This means adding new vars to .env never breaks startup.
        "extra": "ignore",
    }


@lru_cache()
def get_settings() -> Settings:
    return Settings()