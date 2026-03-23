#!/usr/bin/env bash
# =============================================================================
# PRISM — Vault AppRole Setup Script
# =============================================================================
# What this script does:
#   1.  Enables the KV v2 secrets engine at secret/
#   2.  Enables the AppRole auth method
#   3.  Creates a PRISM policy (read-only on secret/prism/*)
#   4.  Creates the prism-pipeline AppRole with that policy
#   5.  Writes the GitHub PAT into Vault at secret/prism/git/github
#   6.  Retrieves the role_id and secret_id and writes them to vault-keys.txt
#   7.  Enables the file audit log at /vault/logs/audit.log
#
# Prerequisites:
#   - Vault server running (docker-compose up -d from this directory)
#   - VAULT_ADDR exported (default: http://127.0.0.1:8200)
#   - VAULT_TOKEN exported with root/admin privileges (from initial unseal)
#   - PRISM_GIT_TOKEN exported with your GitHub Fine-Grained PAT
#
# Usage (Linux / macOS / WSL2):
#   export VAULT_ADDR=http://127.0.0.1:8200
#   export VAULT_TOKEN=<your-root-token>
#   export PRISM_GIT_TOKEN=github_pat_XXXX
#   bash vault-approle-setup.sh
#
# Usage (Windows PowerShell — run inside WSL2 or Git Bash):
#   $env:VAULT_ADDR  = "http://127.0.0.1:8200"
#   $env:VAULT_TOKEN = "<your-root-token>"
#   $env:PRISM_GIT_TOKEN = "github_pat_XXXX"
#   bash vault-approle-setup.sh
#
# After running, copy the values from vault-keys.txt into your .env:
#   VAULT_ROLE_ID=<from vault-keys.txt>
#   VAULT_SECRET_ID=<from vault-keys.txt>
# =============================================================================

set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${VAULT_TOKEN:?ERROR: VAULT_TOKEN must be set}"
PRISM_GIT_TOKEN="${PRISM_GIT_TOKEN:?ERROR: PRISM_GIT_TOKEN must be set}"

KEYS_FILE="$(dirname "$0")/vault-keys.txt"
POLICY_NAME="prism-pipeline"
ROLE_NAME="prism-pipeline"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()  { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Helper: call Vault API via curl (no vault CLI required)
# ---------------------------------------------------------------------------
vault_api() {
    local method="$1"; local path="$2"; local data="${3:-}"
    local url="${VAULT_ADDR}/v1/${path}"
    if [[ -n "$data" ]]; then
        curl -sf -X "$method" \
            -H "X-Vault-Token: ${VAULT_TOKEN}" \
            -H "Content-Type: application/json" \
            -d "$data" \
            "$url"
    else
        curl -sf -X "$method" \
            -H "X-Vault-Token: ${VAULT_TOKEN}" \
            "$url"
    fi
}

# ---------------------------------------------------------------------------
# 0. Verify Vault is reachable and sealed status
# ---------------------------------------------------------------------------
log "Checking Vault connectivity at ${VAULT_ADDR}..."
STATUS=$(curl -sf "${VAULT_ADDR}/v1/sys/health" || true)
if [[ -z "$STATUS" ]]; then
    die "Cannot reach Vault at ${VAULT_ADDR}. Is it running?"
fi

SEALED=$(echo "$STATUS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('sealed','true'))" 2>/dev/null || echo "true")
if [[ "$SEALED" == "true" ]]; then
    die "Vault is sealed. Unseal it first: docker exec -it prism-vault vault operator unseal"
fi
log "Vault is reachable and unsealed."

# ---------------------------------------------------------------------------
# 1. Enable KV v2 secrets engine at secret/
# ---------------------------------------------------------------------------
log "Enabling KV v2 secrets engine..."
vault_api POST "sys/mounts/secret" \
    '{"type":"kv","options":{"version":"2"}}' 2>/dev/null || warn "KV already enabled (skipping)"
log "KV v2 engine ready at secret/"

# ---------------------------------------------------------------------------
# 2. Enable AppRole auth method
# ---------------------------------------------------------------------------
log "Enabling AppRole auth method..."
vault_api POST "sys/auth/approle" \
    '{"type":"approle"}' 2>/dev/null || warn "AppRole already enabled (skipping)"
log "AppRole auth method enabled."

# ---------------------------------------------------------------------------
# 3. Create PRISM policy (read-only on secret/data/prism/*)
# ---------------------------------------------------------------------------
log "Writing PRISM pipeline policy..."
POLICY_HCL=$(cat <<'EOF'
# PRISM Pipeline Policy
# Grants read access to all PRISM secrets.
# This policy is assigned to the prism-pipeline AppRole.

# Read secrets under secret/prism/
path "secret/data/prism/*" {
  capabilities = ["read", "list"]
}

# Allow metadata listing
path "secret/metadata/prism/*" {
  capabilities = ["list"]
}

# Token self-renewal (for long-running pipelines)
path "auth/token/renew-self" {
  capabilities = ["update"]
}

# Token lookup (health check)
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
EOF
)

# Encode policy as JSON string
POLICY_JSON=$(python3 -c "
import json, sys
policy = sys.stdin.read()
print(json.dumps({'policy': policy}))
" <<< "$POLICY_HCL")

vault_api POST "sys/policies/acl/${POLICY_NAME}" "$POLICY_JSON" > /dev/null
log "Policy '${POLICY_NAME}' created."

# ---------------------------------------------------------------------------
# 4. Create AppRole with the PRISM policy
# ---------------------------------------------------------------------------
log "Creating AppRole '${ROLE_NAME}'..."
vault_api POST "auth/approle/role/${ROLE_NAME}" \
    "{
        \"policies\": [\"${POLICY_NAME}\"],
        \"token_ttl\": \"1h\",
        \"token_max_ttl\": \"4h\",
        \"token_num_uses\": 0,
        \"secret_id_ttl\": \"24h\",
        \"secret_id_num_uses\": 0,
        \"bind_secret_id\": true
    }" > /dev/null
log "AppRole '${ROLE_NAME}' created with policy '${POLICY_NAME}'."

# ---------------------------------------------------------------------------
# 5. Write the GitHub PAT into Vault
# ---------------------------------------------------------------------------
log "Writing GitHub PAT to secret/prism/git/github..."
vault_api POST "secret/data/prism/git/github" \
    "{\"data\": {\"token\": \"${PRISM_GIT_TOKEN}\"}}" > /dev/null
log "GitHub PAT stored at secret/prism/git/github"

# Also write a placeholder for GitLab (can be updated later)
vault_api POST "secret/data/prism/git/gitlab" \
    '{"data": {"token": "PLACEHOLDER_REPLACE_WITH_GITLAB_TOKEN"}}' > /dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# 6. Retrieve role_id and generate secret_id
# ---------------------------------------------------------------------------
log "Fetching role_id..."
ROLE_ID_JSON=$(vault_api GET "auth/approle/role/${ROLE_NAME}/role-id")
ROLE_ID=$(echo "$ROLE_ID_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['role_id'])")

log "Generating secret_id..."
SECRET_ID_JSON=$(vault_api POST "auth/approle/role/${ROLE_NAME}/secret-id" '{}')
SECRET_ID=$(echo "$SECRET_ID_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['secret_id'])")

# ---------------------------------------------------------------------------
# 7. Enable file audit log
# ---------------------------------------------------------------------------
log "Enabling file audit log at /vault/logs/audit.log..."
vault_api PUT "sys/audit/file" \
    '{"type":"file","options":{"file_path":"/vault/logs/audit.log"}}' > /dev/null 2>&1 || \
    warn "Audit log may already be enabled (skipping)"
log "Audit log enabled."

# ---------------------------------------------------------------------------
# 8. Verify AppRole login works
# ---------------------------------------------------------------------------
log "Verifying AppRole login..."
LOGIN_RESULT=$(vault_api POST "auth/approle/login" \
    "{\"role_id\": \"${ROLE_ID}\", \"secret_id\": \"${SECRET_ID}\"}")
APP_TOKEN=$(echo "$LOGIN_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])")

if [[ -z "$APP_TOKEN" ]]; then
    die "AppRole login verification failed — check Vault logs"
fi
log "AppRole login verified successfully."

# Verify the token can read the GitHub secret
SECRET_TEST=$(curl -sf \
    -H "X-Vault-Token: ${APP_TOKEN}" \
    "${VAULT_ADDR}/v1/secret/data/prism/git/github")
TOKEN_CHECK=$(echo "$SECRET_TEST" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['data']['token'][:10])" 2>/dev/null || echo "FAIL")

if [[ "$TOKEN_CHECK" == "FAIL" ]]; then
    warn "Token read verification failed — check policy settings"
else
    log "Secret read verified: token starts with ${TOKEN_CHECK}..."
fi

# ---------------------------------------------------------------------------
# 9. Write output to vault-keys.txt
# ---------------------------------------------------------------------------
cat > "$KEYS_FILE" <<EOF
# PRISM Vault AppRole Credentials
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# WARNING: Keep this file SECRET. Add to .gitignore. Never commit to git.
#
# Copy these values into your .env file:

VAULT_ADDR=${VAULT_ADDR}
VAULT_ROLE_ID=${ROLE_ID}
VAULT_SECRET_ID=${SECRET_ID}

# Verification token (TTL 1h — for testing only, not for .env):
# VAULT_TOKEN=${APP_TOKEN}

# Secret paths written:
#   secret/prism/git/github  ← GitHub PAT
#   secret/prism/git/gitlab  ← GitLab placeholder
EOF

chmod 600 "$KEYS_FILE"
log "Credentials written to: ${KEYS_FILE}"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN} PRISM Vault AppRole Setup Complete${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
echo "  Vault address:     ${VAULT_ADDR}"
echo "  AppRole name:      ${ROLE_NAME}"
echo "  Policy:            ${POLICY_NAME}"
echo "  role_id:           ${ROLE_ID}"
echo "  secret_id:         ${SECRET_ID:0:8}... (truncated)"
echo ""
echo "  Next steps:"
echo "  1. Copy VAULT_ROLE_ID and VAULT_SECRET_ID from vault-keys.txt to .env"
echo "  2. Set VAULT_TOKEN= (leave empty) in .env — AppRole is used instead"
echo "  3. Restart the PRISM backend: uvicorn backend.main:app --reload"
echo ""
echo -e "${YELLOW}  IMPORTANT: vault-keys.txt contains secrets — never commit it!${NC}"
echo ""