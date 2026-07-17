# V1 release-gate closure

Date: 2026-07-17

## Scope

This increment closes the remaining Community V1 process and transport-security gates:

- evidence-backed checklist for all twelve `v1-scope.md` criteria;
- per-operation rate limiting inside the isolated keyring;
- verified TLS for every Redis application connection;
- historical v0.2 schema and encrypted-data upgrade rehearsal;
- deterministic Compose readiness checks that understand one-shot initializers;
- MOPACY.eu authorship and release governance metadata.

## Security boundaries

The keyring limiter reduces bulk extraction after compromise of an authorised internal
caller; it does not turn the local keyring into an HSM. Redis TLS protects data in
transit and certificate verification, while password authentication and Docker network
isolation remain independent controls. Client containers receive only the Redis CA
certificate. The CA private key and server private key remain in a server-only volume.

## Upgrade evidence

The automated upgrade test migrates the exact v0.2 application migration leaves to the
current graph. It preserves a historical user, SSH target, labels, target credential,
and personal vault item. Legacy ciphertext is then migrated transactionally to the
isolated keyring and decrypted to prove semantic preservation.

## NAS rule

Deployment uses new source and TLS volumes plus existing PAM-olive data volumes. It
does not delete or reset any NAS data, user, unrelated container, image, or volume.
