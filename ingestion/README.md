### Running HashiCorp Vault with Docker

1. Make sure you have Docker installed.
2. Generate self-signed TLS certificates in `config`:

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/C=TN/ST=Ariana/L=Ariana/O=dev/OU=dev/CN=localhost"
```
#### Run Vault Docker container ( in my case these were the paths)
docker run -d `
--name vault `
--restart=unless-stopped `
-p 8200:8200 `
-v "C:\Users\MSI\Downloads\prism\vault-mvp\config":"C:/vault/config" `
-v "C:\Users\MSI\Downloads\prism\vault-mvp\data":"C:/vault/data" `
hashicorp/vault `
server -config="C:/vault/config/vault.hcl"
 
- This runs Vault in server mode (not dev mode)
- Listens on HTTP port 8200
- Persists secrets in local data folder

### Set Vault CLI environment variable
$env:VAULT_ADDR = "http://127.0.0.1:8200"$env:VAULT_ADDR = "http://127.0.0.1:8200"