---
title: Keycloak recipe
description: Use a public Keycloak client with an audience mapper, a scope and realm roles read from a nested claim.
pageType: how-to
---

# Keycloak recipe

Use one public Keycloak client, an Audience mapper and a client scope, and read administrator roles from the nested `realm_access` claim.

**Before you start:** you need realm admin rights. About 25 minutes.

## Set up the app

1. Create a client with **Client authentication off** (public) and the standard flow on. Under Advanced, set the PKCE code challenge method to `S256`.
2. Set Valid redirect URIs to the callback and silent-renew URIs from [Redirect URIs, CORS and CSP](../identity-provider.md#redirect-uris-cors-and-csp), Valid post logout redirect URIs to the console origin, and Web origins to the console origin.
3. Create a client scope named `hemlig.admin` and add it to the client as a default or optional scope. Make sure it is included in the token's `scope` claim. The setting is on the client scope; verify in your tenant.
4. In that client scope, add an **Audience** mapper that adds this client to the access token, so `aud` contains the client ID. By default Keycloak's `aud` is `account`.
5. Create a realm role such as `hemlig-admin` and assign it to your administrators or a group. Realm roles appear in `realm_access.roles` through the default `roles` client scope.
6. Raise the realm or client access-token lifespan from the default if it is only a few minutes. A short lifespan makes every console renew and CLI hand-off tight.

## Token shape

| Claim | Value |
| --- | --- |
| `iss` | `https://login.example.com/realms/REALM` |
| `aud` | Contains the client ID, once the Audience mapper is in place |
| `scope` | A space-delimited string containing `hemlig.admin` |
| `realm_access` | An object with `roles`, an array of realm role names |
| `sub` | A stable user ID |

## Hemlig config

```json
{
  "context": {
    "oidcIssuer": "https://login.example.com/realms/REALM",
    "oidcClientId": "hemlig-console",
    "oidcAdminScope": "hemlig.admin",
    "oidcRoleClaim": "/realm_access/roles",
    "oidcAdminRole": "hemlig-admin"
  }
}
```

For client roles, use `/resource_access/hemlig-console/roles` instead. For a groups claim, add a Group Membership mapper and set `oidcRoleClaim` to its claim name; Keycloak emits full group paths such as `/admins`, and the role value must match exactly, leading slash included.

No `oidcAuthorizeParams` or `oidcProviderOrigins` are needed when the token endpoint is on the issuer's origin.

## Caveats

- **Nested claim binding:** the gateway cannot render `realm_access` reliably, so the Lambda binds nested claims by presence only. See the [threat model](../../security/threat-model.md#access-and-identity).
- **Audience mapper missing:** `aud` stays `account` and the gateway returns `401`. Decode the token and check.
- **Short tokens:** the CLI keeps the console's bearer, so a very short lifespan limits how long it works.
- **Logout:** Keycloak publishes an end-session endpoint. A post-logout URI missing from the client makes it show an error page instead of returning.

## Next steps

- [Verify your token](../identity-provider.md#verify-your-token)
- [Troubleshoot sign-in and authorization](../identity-provider.md#troubleshoot-sign-in-and-authorization)
- [Host the console](../console.md)
