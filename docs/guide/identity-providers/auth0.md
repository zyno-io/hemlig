---
title: Auth0 recipe
description: Use an Auth0 single-page application with an API, the audience authorize parameter and RBAC permissions.
pageType: how-to
---

# Auth0 recipe

Use one Auth0 single-page application and an Auth0 API, so the console gets a JWT access token for your audience with a permission claim.

**Before you start:** you need Auth0 tenant admin rights. About 25 minutes.

## Set up the app

1. Create an **API** with an identifier of your choice, for example `https://hemlig.example.com/api`, and signing algorithm RS256.
2. Under the API's Permissions, add `hemlig.admin`. Under Settings, enable **RBAC** and **Add Permissions in the Access Token**.
3. Create a **Single Page Web Application**. Set Allowed Callback URLs to the callback and silent-renew URIs from [Redirect URIs, CORS and CSP](../identity-provider.md#redirect-uris-cors-and-csp), Allowed Logout URLs to the console origin, and both Allowed Web Origins and Allowed Origins (CORS) to the console origin.
4. Create a role such as `Hemlig Admin` that holds the `hemlig.admin` permission, and assign it to your administrators.
5. Make the console send the API identifier as the `audience` parameter. Without it Auth0 returns an opaque access token and the gateway answers `401`.

## Token shape

| Claim | Value |
| --- | --- |
| `iss` | `https://<tenant domain>/`, with the trailing slash |
| `aud` | The API identifier. Auth0 may also list the `/userinfo` URL, which makes `aud` an array; any matching entry is enough. Verify in your tenant |
| `scope` | A space-delimited string containing `hemlig.admin` |
| `permissions` | An array of permission names, once RBAC is on |
| `sub` | A stable user ID such as `auth0|abc` |

## Hemlig config

```json
{
  "context": {
    "oidcIssuer": "https://example.auth0.com/",
    "oidcClientId": "AUTH0_CLIENT_ID",
    "oidcAudience": "https://hemlig.example.com/api",
    "oidcAdminScope": "hemlig.admin",
    "oidcRoleClaim": "permissions",
    "oidcAdminRole": "hemlig.admin",
    "oidcAuthorizeParams": { "audience": "https://hemlig.example.com/api" }
  }
}
```

Auth0 also puts the permission in `scope`, so the same value serves as scope and role here. If you want a separate gate, add an Action that writes a namespaced roles claim and point `oidcRoleClaim` at it, such as `https://hemlig.example.com/roles`. Auth0 recommends a namespaced claim name for custom claims, and reserves some names.

`oidcAuthorizeParams` is sent on sign-in only; sign-out does not send it. In CDK context pass it as a JSON object or a JSON object string.

## Caveats

- **Issuer slash:** the trailing slash is part of the issuer. Without it every token fails the issuer check.
- **Missing `audience`:** the symptom is a `401` with an opaque token. Check `auth.extraQueryParams` in the console's `config.json`, which `oidcAuthorizeParams` writes.
- **Sign-out:** whether discovery advertises an end-session endpoint can depend on your tenant settings. Verify in your tenant; without one the console signs out locally only.
- **Token lifetime:** the API's token expiration is a setting. Lower it for administrators.

## Next steps

- [Verify your token](../identity-provider.md#verify-your-token)
- [Troubleshoot sign-in and authorization](../identity-provider.md#troubleshoot-sign-in-and-authorization)
- [Host the console](../console.md)
