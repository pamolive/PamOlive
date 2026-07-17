# SSH recording-volume permission incident

Date: 2026-07-17

## Symptom

An authorized browser SSH session closed immediately with the generic message that
the secure SSH connection had been refused.

## Root cause

The hardened gateway runs as a non-root account, while the persistent
`recordings_data` volume retained ownership from an older image. The gateway could
reach the SSH target and the stored host-key fingerprint matched, but it could not
create the mandatory encrypted recording. The resulting `PermissionError` occurred
before SSH authentication and was incorrectly classified as a transport failure.

## Correction

- The gateway runtime UID and GID are fixed at `10001:10001`.
- A one-shot, network-disabled Compose initializer changes ownership only inside the
  PAM-olive recording volume and preserves every existing recording.
- Recording directories and encrypted `.pamrec` files are normalized to modes `0700`
  and `0600` respectively.
- Recording-storage failures have a dedicated internal reason and safe user message.
- The SSH bridge is never started when mandatory encrypted recording storage is not
  available.

## Validation before deployment

- Ruff passed.
- Django system check passed.
- Migration drift check passed.
- 148 tests passed.
- Coverage: 90.24%.
- The dedicated test confirms that an unavailable recording volume prevents SSH from
  opening and is reported as `recording_storage_unavailable`.

## Deployment evidence

- Pre-deployment backup:
  `/volume1/docker/pam-olive-backups/20260717-ssh-recording-fix-predeploy`.
- Active source release:
  `/volume1/docker/pam-olive-release-20260717-v7`.
- Only the PAM-olive SSH gateway and RDP broker containers were recreated.
- The initializer completed successfully with no network and without deleting any
  recording.
- Gateway identity: `10001:10001`.
- Recording-volume owner and mode: `10001:10001`, `0700`.
- Preserved encrypted recording files: 217.
- Restore verification: 184 audit events, 5 encrypted fields, active key
  `keyring-v1`, 0 pending migrations.
- The configured NAS credential already used the case-sensitive username `Cyriel`;
  no credential data required modification.
- Public readiness endpoint returned HTTP 200 with database and cache healthy.
- Both the SSH gateway and RDP broker passed their container health checks.
