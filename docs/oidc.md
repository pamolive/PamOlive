# OpenID Connect

PAM-olive can expose several external login domains at the same time. For
example, one installation can offer local accounts, Infomaniak, Google Workspace,
Microsoft Entra ID, Keycloak, and Authentik side by side.

Local username/password login always remains available. Enabling OIDC adds
buttons to the login page; it does not replace local emergency access.

## Safe configuration flow

1. Open **Administration → Identités et droits → Domaines de connexion**.
2. Create the provider with **Source active** disabled.
3. Choose a stable technical identifier, for example `infomaniak`, `google`,
   `entra`, or `keycloak`.
4. Copy the displayed callback URL into the provider application.
5. Save the provider.
6. Use **Tester la découverte OIDC avant activation**.
7. Create at least one group mapping under **Correspondances de groupes**.
8. Enable the provider only after the discovery test succeeds.

The callback URL has this shape:

```text
https://pamolive.example.com/accounts/oidc/<identifiant-technique>/callback/
```

For an Infomaniak provider with the technical identifier `infomaniak`, use:

```text
https://pamolive.example.com/accounts/oidc/infomaniak/callback/
```

The login URL shown by PAM-olive has this shape:

```text
https://pamolive.example.com/accounts/oidc/<identifiant-technique>/login/
```

Users normally do not need this direct URL because the login page lists every
enabled provider.

## Provider fields

| PAM-olive field | Meaning |
| --- | --- |
| Nom de la source | Display name shown to administrators and on the login page |
| Identifiant technique | Slug used in the callback and login URLs |
| Source active | Makes the provider visible on the login page |
| Émetteur OIDC | HTTPS issuer URL, not the authorization endpoint |
| Client ID | Application/client identifier from the provider |
| Secret client | Application/client secret from the provider |
| Scopes OIDC | Usually `openid email profile` |
| Claim des groupes | Usually `groups`, depending on the provider |

## Infomaniak example

In Infomaniak Cloud Computing → Auth:

1. Create a **Web Front-End** application.
2. Name it `PamOlive`.
3. Add the PAM-olive callback URL:

   ```text
   https://pamolive.mopacy.be/accounts/oidc/infomaniak/callback/
   ```

4. Copy the client ID and client secret into PAM-olive.
5. Configure the Infomaniak issuer URL in PAM-olive.
6. Save the provider disabled, test discovery, then enable it.

## Multiple login domains

Create one PAM-olive OIDC provider per external identity domain:

| Provider | Suggested technical identifier |
| --- | --- |
| Infomaniak | `infomaniak` |
| Google Workspace | `google` |
| Microsoft Entra ID | `entra` |
| Keycloak | `keycloak` |
| Authentik | `authentik` |

Each provider receives its own callback URL. Only enabled providers appear on
the login page.

## Group mapping

OIDC login is governed by group mappings. A user is accepted only when the OIDC
claims contain a group mapped to a PAM-olive group. This avoids silently creating
privileged accounts without an authorization rule.

If users can authenticate at the provider but PAM-olive rejects them, check:

- the `groups` claim name;
- the exact external group value;
- the corresponding PAM-olive group mapping;
- whether automatic user creation is enabled on that mapping.

## What the test button verifies

The pre-activation test checks that:

- the issuer is HTTPS;
- the discovery document is reachable;
- the provider returns valid JSON;
- the issuer returned by the provider matches the configured issuer;
- the authorization, token, and signing-key endpoints are present.

It does not perform a full user login. After enabling the provider, use the
normal login page to validate the full authentication and group-mapping flow.
