---
title: Okta recipe
description: Use an Okta single-page app with a custom authorization server for JWT access tokens, scopes and a groups claim.
pageType: how-to
---

# Okta recipe

Use one Okta single-page app and a custom authorization server, so access tokens are JWTs with your own audience, scope and groups claim.

**Before you start:** you need Okta admin rights and a plan that includes custom authorization servers (verify in your tenant). About 25 minutes.

## Set up the app

1. Create an **OIDC, Single-Page Application** app. Use the authorization-code flow with PKCE and no client secret. Okta app types are exclusive, so do not reuse a web or native app.
2. Set the sign-in redirect URIs to the callback and silent-renew URIs from [Redirect URIs, CORS and CSP](../identity-provider.md#redirect-uris-cors-and-csp), and the sign-out redirect URI to the console origin.
3. Under Security, API, Trusted Origins, add the console origin with **CORS** and **Redirect** enabled. Without CORS the token request fails in the browser.
4. Under Security, API, Authorization Servers, create or choose a custom server. Set its **Audience** to a value you choose, for example `hemlig-api`. The issuer is the server's issuer URI; the org authorization server is not meant for your own APIs.
5. Add a custom scope `hemlig.admin` to that server.
6. Add an access policy with a rule that lets the app request the scope for the users and grant types you want.
7. Create a group such as `Hemlig Admins`, assign people to it, and assign it to the app.

## Token shape

| Claim | Value |
| --- | --- |
| `iss` | The custom server's issuer URI |
| `aud` | The server's Audience, not the client ID |
| `scp` | An array that contains `hemlig.admin` |
| `groups` | Present once you add the claim below |
| `uid` | The Okta user ID. Verify in your tenant that your access token carries it |

Add a claim on the custom server: name `groups`, include in the access token, value type Groups, with a filter such as matches `Hemlig.*`. Narrow the filter so it returns only what you need: the claim has a size limit (verify in your tenant).

## Hemlig config

```json
{
  "context": {
    "oidcIssuer": "https://example.okta.com/oauth2/AUTH_SERVER_ID",
    "oidcClientId": "0oa0000000000000000",
    "oidcAudience": "hemlig-api",
    "oidcAdminScope": "hemlig.admin",
    "oidcSubjectClaim": "uid",
    "oidcRoleClaim": "groups",
    "oidcAdminRole": "Hemlig Admins"
  }
}
```

The audience differs from the client ID, so set `oidcAudience`. The console requests the bare scope `hemlig.admin`, because the issuer is not an Entra host. No `oidcAuthorizeParams` or `oidcProviderOrigins` are needed when the token endpoint is on the issuer's origin; if you use a custom domain for the authorization server, check that the issuer and token endpoint share it.

## Caveats

- **Subject:** `sub` is the user's login in Okta, which can change. Use `uid` and confirm it is in your access token.
- **Group names:** a role value may contain spaces, as `Hemlig Admins` does, but not a comma.
- **Access token lifetime:** set by the access policy rule. A very short lifetime makes the CLI hand-off nearly useless.
- **Loopback and native flows:** not used. The CLI goes through the console.

## Next steps

- [Verify your token](../identity-provider.md#verify-your-token)
- [Troubleshoot sign-in and authorization](../identity-provider.md#troubleshoot-sign-in-and-authorization)
- [Host the console](../console.md)
