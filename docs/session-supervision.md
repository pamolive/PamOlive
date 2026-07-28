# Session supervision

PAM-olive provides a first operational layer for privileged-session supervision:
session inventory, administrative termination, encrypted SSH recording replay,
command-control rules, web-session launch tracking, and upgrade preflight checks.

## Session inventory and termination

Administrators with session-control permissions can open **Surveillance → Sessions**.
The page lists recent privileged sessions with:

- user and source address;
- target, protocol and privileged account;
- start/expiry time;
- current state;
- sealed recording reference when available;
- replay/export actions;
- termination action for created, active or terminating sessions.

Termination requests do not require MFA inside an already opened SSH or RDP stream.
MFA is required before opening or administrating sensitive areas, not repeatedly
while an interactive session is in progress.

## SSH replay and export

SSH recordings are written by the gateway as encrypted `.pamrec` events. The web
node mounts the recording volume read-only and can display a forensic replay or
export a text transcript. The export action is audited.

Required configuration:

```env
PAMOLIVE_RECORDING_KEY=...
PAMOLIVE_RECORDING_DIR=/recordings
```

The recording key must match the gateway key. If the key is missing, replay and
export are refused.

## SSH command control

Access policies can define two command-rule lists:

- **Commandes SSH bloquées**: regular expressions that prevent the command from
  being sent to the target;
- **Commandes SSH à alerter**: regular expressions that allow the command but
  create an audit event.

Examples:

```text
^rm\s+-rf\s+/
^shutdown\b
^reboot\b
```

Blocked commands are recorded as `session.command_denied`. Alerted commands are
recorded as `session.command_alerted`. Audit metadata stores a short command
preview, a SHA-256 hash of the command, and the matched rule.

## Web Session Manager

Targets using protocol `WEB` can be launched through PAM-olive. The launch creates
an active audited session and presents a controlled "open application" page.

This first web-session layer does not inject passwords or cookies into the remote
application. It is intended as a safe base for later browser isolation, SSO/OIDC
handoff, cookie vaulting, and web-recording features.

## Installation and upgrade preflight

Administrators can open **Système → État système** to check:

- license edition and validity;
- cluster authorization and current node id;
- database reachability;
- Redis/cache reachability;
- pending Django migrations.

The same check is available from the container:

```bash
python manage.py preflight_status
```

Run it before and after upgrades. A clean upgrade should report no pending
migrations and healthy database/cache probes.
