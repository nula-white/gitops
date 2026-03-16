# PRISM Vault — Local Secret Management

HashiCorp Vault running in Docker. Stores all PRISM credentials with
zero secrets in source code or environment variables.

## Quick Start

```bash
# 1. Start Vault
cd prism/vault
docker compose up -d

# 2. Initialize (first time only — saves unseal keys + root token)
docker exec -it prism-vault vault operator init > vault-init-output.txt
# Store vault-init-output.txt in a password manager, then delete it

# 3. Unseal (required after every restart — 3 of 5 keys)
docker exec -it prism-vault vault operator unseal
# Enter key 1 of 3
docker exec -it prism-vault vault operator unseal
# Enter key 2 of 3
docker exec -it prism-vault vault operator unseal
# Enter key 3 of 3

# 4. Set root token and run setup
export VAULT_TOKEN=<root_token_from_step_2>
docker exec -e VAULT_TOKEN=$VAULT_TOKEN -it prism-vault \
    sh /vault/init/setup_prism_secrets.sh

# 5. Add real credentials
docker exec -e VAULT_TOKEN=$VAULT_TOKEN -it prism-vault \
    vault kv patch secret/prism/git/github token=ghp_yourRealToken

# 6. Copy AppRole credentials from setup output to .env
cp .env.example .env
# Edit .env with VAULT_ROLE_ID and VAULT_SECRET_ID from setup output
```

## Secret Structure

```
secret/prism/
├── git/
│   ├── github          { token, token_type, scopes, expires_at }
│   ├── gitlab          { token, token_type, scopes }
│   ├── bitbucket       { token, username }
│   └── azure_devops    { token, organization }
├── llm/
│   └── anthropic       { api_key }
├── blockchain/
│   ├── ethereum_sepolia { private_key, rpc_url }
│   └── ganache_local    { private_key, rpc_url }
└── db/
    └── neo4j            { password, uri, username }
```

## Daily Operations

```bash
# Check status
docker exec -it prism-vault vault status

# Read a secret (requires auth)
docker exec -e VAULT_TOKEN=$VAULT_TOKEN -it prism-vault \
    vault kv get secret/prism/git/github

# Rotate a token
docker exec -e VAULT_TOKEN=$VAULT_TOKEN -it prism-vault \
    vault kv patch secret/prism/git/github token=ghp_newToken

# View UI
open http://localhost:8200/ui
```

## How PRISM reads secrets at runtime

```python
from prism.ingestion.credential_provider import VaultCredentialProvider

provider = VaultCredentialProvider()
with provider.credential_context("git/github") as cred:
    token = cred.get()   # used inline, never stored
# token is zeroed here
```

UI at http://localhost:8200/ui after step 2