# V1 Permission Matrix

## Principles

- Deny by default: absence of permission denies the action.
- Separate read, modify, and sensitive-action permissions.
- Rights inherited from multiple groups are combined, but an access policy is still
  required to reach a target or reveal a target secret.
- Django `is_superuser` status is reserved for the technical Super Administrator.
- The PAM-olive Administrator role never grants access to `/django-admin/`.

## System profiles

| Domain | Super admin | Administrator | Auditor | Approver | User |
| --- | --- | --- | --- | --- | --- |
| Product console | full | full | read | approvals | no |
| Users / groups | full | manage | read | no | self |
| Permission profiles | full | manage non-system | read | no | no |
| LDAP/OIDC sources | full | manage / synchronize | read | no | no |
| Targets / domains | full | manage | read | no | authorized targets |
| Account metadata | full | manage | read without secret | no | authorized accounts |
| Secret reveal | by policy | by policy | never | never | by policy |
| Policies | full | manage | read | no | no |
| Approvals | full | decide for others | read | decide for others | own requests |
| Sessions | full | view / terminate | view | no | own sessions |
| Audit | full | view | view / export | limited | own events |
| Django administration | yes | no | no | no | no |

## Capability families

Technical capabilities use the stable `resource.action` notation:

- `users.view`, `users.manage`
- `groups.view`, `groups.manage`
- `roles.view`, `roles.manage`
- `identity_sources.view`, `identity_sources.manage`, `identity_sources.sync`
- `targets.view`, `targets.manage`
- `target_groups.view`, `target_groups.manage`
- `domains.view`, `domains.manage`
- `credentials.view_metadata`, `credentials.manage`, `credentials.reveal`,
  `credentials.rotate`
- `policies.view`, `policies.manage`
- `approvals.view`, `approvals.decide`
- `sessions.view`, `sessions.terminate`, `sessions.join`
- `audit.view`, `audit.export`
- `system.view`, `system.manage`

System profiles are provided by migrations and cannot be deleted. Their content may
evolve through versioned migrations so upgrades remain reproducible.
