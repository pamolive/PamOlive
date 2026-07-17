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

To be completed after the NAS rollout.
