# Terminal copy and authorization clarity

Date: 2026-07-17

## Objective

This increment improves developer usability in browser sessions and makes the
authorization model understandable without weakening its deny-by-default behavior.
The functional reference material was used to identify general PAM concepts only;
PAM-olive retains its own implementation, terminology, interface, and source code.

## Session usability

- SSH terminal output can be selected and copied through a visible button.
- `Ctrl+Shift+C` copies a selection. `Ctrl+C` copies only when text is selected and
  otherwise remains a remote interrupt signal.
- A second action copies the complete retained terminal scrollback for support cases.
- A normally closed SSH WebSocket attempts to close the tab. Failures and abnormal
  transport closures remain visible for diagnosis.
- A minimal Guacamole extension watches removal of its dedicated authentication token
  and attempts to close the RDP tab during logout. Browser close restrictions remain
  authoritative.

## Rights foundation

The console now makes two independent concepts explicit:

- permission profiles control administrative console features;
- access authorizations control who may use which target accounts and under which
  conditions.

Permission profiles use domain-specific levels rather than a raw multiselect list.
Prerequisites are normalized server-side: manage includes view, approval decisions
include approval view, audit export includes audit view, and session control includes
session view. Secret reveal and credential rotation remain separate sensitive rights.

Access-authorization forms are split into beneficiaries, resources, allowed uses,
approval workflow, session security, calendar/origin, and activation. Their directory
summary displays the user-group to target-group relationship and approval behavior.

## Compatibility and safety

- Existing role capability arrays remain the persistence format and require no data
  migration.
- Legacy form submissions are accepted and normalized.
- System permission profiles remain read-only and versioned.
- Existing access policies and target assignments are preserved.
- No NAS data or Docker volume is deleted by this increment.

## Verification

Automated coverage includes permission-level normalization, form structure, terminal
copy behavior markers, session close handling, and the Guacamole lifecycle extension.
