# Sprint 1 — isolated keyring

## Delivered boundary

- Dedicated FastAPI service with encrypt, decrypt, sign, and verify operations.
- A 32-byte master key generated once in `/data/master.key` with mode `0600`.
- Separate encryption and audit-signing subkeys derived with HKDF-SHA256.
- Dedicated `keyring_data` volume mounted only by the keyring.
- No published keyring port and no membership of target-facing networks.
- Django vault operations and audit signatures delegated to the internal API.
- Transactional, dry-run-first migration for legacy ciphertext and audit signatures.
- Legacy vault and HMAC keys removed from the new-install environment template.

## Validation

- Keyring container built and started with network mode `none` for the runtime smoke
  test.
- Master-key size: 32 bytes.
- Master-key permissions: `0600`.
- Published ports: none.
- Encrypt/decrypt/sign/verify synthetic smoke test: passed.
- Django test suite: 138 passed.
- Coverage: 90.02%, above the mandatory 90% release threshold.
- Ruff: passed.
- Django migration drift check: no changes detected.

## Reference NAS deployment

- Verified backups created before migration: PostgreSQL archive, recordings, source,
  and protected legacy environment escrow.
- Dry run validated 5 encrypted fields and 152 audit events.
- Transactional migration re-encrypted 5 fields and re-signed 152 audit events.
- Post-migration verification validated 153 audit events, all 5 encrypted fields,
  and zero pending migrations.
- Legacy vault and audit-signing variables are absent from the active release
  environment.
- All PAM-olive services are healthy; readiness reports database and cache `ok`.
- The `pam-olive_keyring_data` volume is mounted only by the keyring container.
- Live SSH password flow passed after migration: ticket authorised, password injected
  by the gateway, harmless marker command confirmed, and session closed/audited.

## Explicit residual risk

The service boundary prevents Django and PostgreSQL from possessing the master key.
It does not prevent a compromised authorised Django process on the internal network
from requesting decryption. External HSM/Vault support remains a post-V1 backend.
