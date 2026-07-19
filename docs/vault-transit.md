# Vault Transit backend

PAM-olive keeps the self-contained `local` backend as the Community default and also
supports HashiCorp Vault Transit. In Vault mode, encryption, decryption, and audit HMAC
operations occur in Vault. A fresh PAM-olive installation does not create
`/data/master.key`.

## Vault preparation

Enable Transit and create one application key:

```sh
vault secrets enable transit
vault write -f transit/keys/pamolive type=aes256-gcm96
```

Grant the PAM-olive machine identity only these capabilities:

```hcl
path "transit/encrypt/pamolive" { capabilities = ["update"] }
path "transit/decrypt/pamolive" { capabilities = ["update"] }
path "transit/hmac/pamolive"    { capabilities = ["update"] }
path "transit/verify/pamolive"  { capabilities = ["update"] }
```

Use a short-lived token delivered by an orchestrator or Vault Agent. Never place the
token in `.env`. Mount it read-only into the keyring container, for example with a
deployment-specific Compose override:

```yaml
services:
  keyring:
    volumes:
      - /secure/runtime/pamolive-vault-token:/run/secrets/pamolive_vault_token:ro
      - /secure/runtime/vault-ca.crt:/run/secrets/vault-ca.crt:ro
```

Configure PAM-olive:

```env
PAMOLIVE_KEYRING_CRYPTO_BACKEND=vault-transit
PAMOLIVE_VAULT_ADDR=https://vault.example.internal
PAMOLIVE_VAULT_TRANSIT_MOUNT=transit
PAMOLIVE_VAULT_KEY_NAME=pamolive
PAMOLIVE_VAULT_TOKEN_FILE=/run/secrets/pamolive_vault_token
PAMOLIVE_VAULT_CA_PATH=/run/secrets/vault-ca.crt
```

Only HTTPS Vault addresses without embedded credentials are accepted. The system CA
store is used when `PAMOLIVE_VAULT_CA_PATH` is empty. Network errors fail closed and
keyring operations return HTTP 503 without exposing Vault response details.

## Migrating an existing local deployment

Back up PostgreSQL and `keyring_data`, configure Vault, mount its token and CA, then
restart only the keyring. In Vault mode the keyring reads legacy local Fernet values
but writes new Vault ciphertexts. First validate every protected value and signature:

```sh
docker compose exec web python manage.py migrate_keyring_backend
```

Apply the all-or-nothing database migration:

```sh
docker compose exec web python manage.py migrate_keyring_backend \
  --apply --confirm MIGRATE-KEYRING-BACKEND
docker compose exec web python manage.py verify_restore
```

The command decrypts and re-encrypts every protected field, validates the complete
audit hash chain, and re-signs every event through Vault. If any operation fails, the
database transaction is rolled back. After an independent restore rehearsal succeeds,
stop the keyring, archive the old `master.key` offline according to the retention
policy, remove it from the live volume, and restart. Do not destroy the offline copy
until the migration backup and retention window have expired.

Vault key rotation does not require database downtime because ciphertexts contain the
Vault key version. Rotation and rewrap procedures should nevertheless be rehearsed,
audited, and backed up before production use.
