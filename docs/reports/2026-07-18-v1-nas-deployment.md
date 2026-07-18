# Community V1.0.1 NAS deployment

Date: 2026-07-18

## Release evidence

- GitHub `main`, tag `v1.0.1`, Release, CodeQL, isolated Compose tests,
  backup/restore rehearsal, network-isolation checks, and the critical-CVE gate passed.
- The deployed package reported version `1.0.1`.
- Twelve long-running PAM-olive services were active; every configured health check
  passed. The Redis TLS and recording-volume initializers exited successfully.
- The public PAM readiness endpoint and dedicated RDP endpoint returned HTTP 200.
- No migration remained pending. Restore verification checked 209 audit events and
  five encrypted fields against active key `keyring-v1`.

## Data protection

Before deployment, a sealed backup was created and verified at
`/volume1/docker/pam-olive-backups/20260718-v1.0.1-predeploy`. It contains the
PostgreSQL archive, migration plan, Compose model, Caddy configuration, encrypted
recordings, and a SHA-256 manifest.

The deployment reused only the six production volumes owned by Compose project
`pam-olive`: PostgreSQL, Redis, keyring, recordings, Redis TLS server material, and
Redis TLS client CA material. No volume was reset or recreated as an empty replacement.

## Historical cleanup

After V1 verification, obsolete CBPAM, CI, sprint, staging, and historical PAM-olive
containers, volumes, networks, images, and source copies were removed. Before removal,
their source trees and every obsolete Docker volume were archived and checksum-verified
under `/volume1/docker/pam-olive-backups/20260718-obsolete-docker-cleanup`.

The surviving PAM-olive deployment consists of:

- `/volume1/docker/pam-olive-release-v1.0.1`;
- `/volume1/docker/pam-olive-v1.0.1.tar.gz`;
- `/volume1/docker/pam-olive-backups`;
- Compose project `pam-olive`, its six production volumes, and its three networks.

BunkerWeb, Odoo, Psono, NAS accounts, and all non-PAM data remained active and were
not targeted by deployment or cleanup commands.
