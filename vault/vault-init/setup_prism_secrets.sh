#!/bin/sh
# PRISM Vault Secret Structure Setup
# ===================================
# Run this script ONCE after Vault is initialized and unsealed.
# It creates the secret engine, policies, and AppRole for PRISM.
#
# Usage:
#   docker exec -it prism-vault sh /vault/init/setup_prism_secrets.sh
#
# Requires: VAULT_TOKEN env var set to the root token (first run only)
#           After setup, rotate to a less-privileged token.

set -e

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"

echo "=== PRISM Vault Setup ==="
echo "Vault address: $VAULT_ADDR"

# ── 1. Enable KV v2 secrets engine at secret/ ────────────────────────────────
echo "[1/5] Enabling KV v2 secrets engine..."
vault secrets enable -path=secret kv-v2 2>/dev/null || echo "  Already enabled"

# ── 2. Create secret paths structure ─────────────────────────────────────────
# Structure: secret/prism/<category>/<name>
# Categories:
#   git/       — VCS platform tokens (GitHub, GitLab, etc.)
#   llm/       — LLM API keys (Anthropic, OpenAI, local)
#   blockchain/ — Ethereum/Ganache keys for audit logging
#   db/        — Database credentials (Neo4j, etc.)
#   infra/     — Infrastructure credentials (Azure, AWS, GCP)

echo "[2/5] Creating placeholder secrets..."

# Git tokens (replace values with real tokens)
vault kv put secret/prism/git/github \
    token="REPLACE_WITH_GITHUB_PAT" \
    token_type="classic_pat" \
    scopes="repo,read:org" \
    expires_at="REPLACE_WITH_EXPIRY_ISO8601"

vault kv put secret/prism/git/gitlab \
    token="REPLACE_WITH_GITLAB_PAT" \
    token_type="pat" \
    scopes="read_repository"

vault kv put secret/prism/git/bitbucket \
    token="REPLACE_WITH_BITBUCKET_APP_PASSWORD" \
    username="REPLACE_WITH_USERNAME"

vault kv put secret/prism/git/azure_devops \
    token="REPLACE_WITH_ADO_PAT" \
    organization="REPLACE_WITH_ORG"

# LLM API keys
vault kv put secret/prism/llm/anthropic \
    api_key="REPLACE_WITH_ANTHROPIC_KEY"

# Blockchain
vault kv put secret/prism/blockchain/ethereum_sepolia \
    private_key="REPLACE_WITH_ETH_PRIVATE_KEY" \
    rpc_url="REPLACE_WITH_SEPOLIA_RPC_URL"

vault kv put secret/prism/blockchain/ganache_local \
    private_key="REPLACE_WITH_GANACHE_KEY" \
    rpc_url="http://localhost:8545"

# Neo4j
vault kv put secret/prism/db/neo4j \
    password="REPLACE_WITH_NEO4J_PASSWORD" \
    uri="bolt://localhost:7687" \
    username="neo4j"

echo "  Secret paths created."

# ── 3. Create PRISM policy ────────────────────────────────────────────────────
echo "[3/5] Creating PRISM access policy..."
vault policy write prism-pipeline - << 'POLICY'
# PRISM Pipeline Policy
# Grants read-only access to all PRISM secrets
# The pipeline never needs to write secrets — only read them

path "secret/data/prism/*" {
  capabilities = ["read"]
}

path "secret/metadata/prism/*" {
  capabilities = ["list", "read"]
}

# Deny access to everything else
path "*" {
  capabilities = ["deny"]
}
POLICY
echo "  Policy 'prism-pipeline' created."

# ── 4. Enable AppRole auth method ────────────────────────────────────────────
echo "[4/5] Setting up AppRole authentication..."
vault auth enable approle 2>/dev/null || echo "  AppRole already enabled"

vault write auth/approle/role/prism-pipeline \
    secret_id_ttl=24h \
    token_ttl=1h \
    token_max_ttl=4h \
    token_policies="prism-pipeline" \
    bind_secret_id=true

# Get the role_id (not sensitive — can be stored in config)
echo ""
echo "=== AppRole Credentials (save these) ==="
ROLE_ID=$(vault read -field=role_id auth/approle/role/prism-pipeline/role-id)
echo "ROLE_ID:   $ROLE_ID"

# Generate a secret_id (sensitive — treat like a password)
SECRET_ID=$(vault write -f -field=secret_id auth/approle/role/prism-pipeline/secret-id)
echo "SECRET_ID: $SECRET_ID"
echo ""
echo "Add to your .env file:"
echo "  VAULT_ROLE_ID=$ROLE_ID"
echo "  VAULT_SECRET_ID=$SECRET_ID"
echo ""

# ── 5. Enable audit logging ───────────────────────────────────────────────────
echo "[5/5] Enabling audit log..."
vault audit enable file file_path=/vault/logs/audit.log 2>/dev/null || \
    echo "  Audit log already enabled"

echo ""
echo "=== PRISM Vault Setup Complete ==="
echo "UI available at: http://localhost:8200/ui"
echo "Next: populate real tokens with:"
echo "  vault kv patch secret/prism/git/github token=<your_real_token>"