# Terminal, image hygiene, and installation report

Date: 2026-07-16

## Scope

This delivery covers the SSH browser terminal, MFA recovery-code export, immutable
container images, critical-CVE enforcement, first-install secret generation, startup
secret validation, and final removal of the legacy project identifier.

No application database, vault volume, recording volume, or master-key volume is
deleted or reinitialized by these changes.

## SSH terminal

- The browser terminal now uses the vendored xterm.js 6.0.0 distribution.
- Gateway output remains bytes from AsyncSSH through Base64 transport into xterm.js.
  ANSI escape sequences and UTF-8 characters are no longer printed as literal text.
- Normal keyboard input and browser paste are supported by the emulator.
- A separate, reviewable multi-line command box sends normalized terminal newlines
  only after an explicit click.
- Input and output continue to be written to the encrypted session recording.
- Automated tests prove byte-for-byte preservation of ANSI/UTF-8 output and pasted
  UTF-8 input.

## MFA recovery codes

The one-time recovery-code screen can create a local UTF-8 text download. The file is
assembled in the browser from codes already present on the one-time page. No new
cleartext endpoint or server-side recovery-code file was introduced. Stored recovery
codes remain hashed and single-use.

## Container supply chain

Critical third-party runtime images are pinned by SHA256 digest. The final application,
gateway, worker, test, keyring, PostgreSQL, Redis, Caddy, Guacamole, and guacd images
are scanned with Trivy 0.70.0.

The current official PostgreSQL image included a vulnerable `gosu` binary. The
PAM-olive derivative removes it and provides the narrow user-switch behavior required
by the upstream entrypoint using the base operating system. The Guacamole derivative
keeps the 1.6.0 application and JSON authentication contract, replaces the Tomcat
runtime with a clean pinned official image, and removes disabled optional extensions.
The CI gate has no silent `CRITICAL` exception.

## Installation secrets

`make init`, `sh install.sh`, or `install.ps1` creates `.env` once with independent
random values. Existing `.env` files are never overwritten. The web entrypoint refuses
to start if a required secret is blank, too short, or a known placeholder. The
keyring's master key remains inside its dedicated volume, while access to its internal
cryptographic API requires an independent Bearer token.

## Validation evidence

- Ruff: passed.
- Django system check: passed.
- Migration drift check: passed.
- Final PostgreSQL suite from the release archive: 147 tests passed.
- Coverage: 90.26%, above the 90% release gate.
- MkDocs strict build: passed.
- Full isolated Compose stack: all services healthy.
- Target-only network probe: PostgreSQL and Redis unreachable as required.
- Final Compose image scan: every image passed the `CRITICAL` gate.

The complete 147-test suite was rerun from the final release archive before the active
PAM-olive containers were rebuilt.
