# V1 Permission Matrix

## Principles

- Deny by default: absence of permission denies the action.
- Separate read, modify, and sensitive-action permissions.
- Rights inherited from multiple groups are combined, but an access policy is still
  required to reach a target or reveal a target secret.
- Django `is_superuser` status is reserved for the technical Super Administrator.
- The PAM-olive Administrator role never grants access to `/django-admin/`.

## Two separate control planes

PAM-olive deliberately separates administrative permission profiles from target
authorizations:

1. A **permission profile** answers which console domains an operator can read,
   manage, or operate. It never grants access to a target account by itself.
2. An **access authorization** links one or more user groups to one or more target
   groups and states which target operations are allowed, with protocols, approval,
   MFA, schedules, source networks, duration, concurrency, and clipboard controls.

This separation prevents an administrator who can configure equipment from silently
receiving access to its credentials. Users may belong to multiple groups; effective
console permissions are additive, while every target operation still requires a
current authorization.

The product console presents profiles through explicit levels instead of an opaque
capability list. `Manage` always includes `View`; approval decisions include approval
view; session control includes session view; and exports include audit view. Secret
reveal and password rotation remain distinct sensitive operations.

Access authorizations are displayed as a readable chain:

```text
User groups -> target groups/accounts -> allowed use -> approval and security conditions
```

Administrative actions such as managing targets or deciding approvals are not valid
target-policy actions. They belong exclusively to permission profiles.

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
