---
title: Authentik, Zitadel and Cognito recipes
description: Short recipes for Authentik, Zitadel and Amazon Cognito, with the settings that are known and the ones to verify.
pageType: how-to
---

# Authentik, Zitadel and Cognito recipes

These providers work with the same one-app model. Each section states only what is confident and marks the rest **verify in your tenant**.

**Before you start:** read the [guide](../identity-provider.md) first. Each section takes about 20 minutes.

## Authentik

1. Create an **OAuth2/OpenID provider** with client type **Public** and redirect URIs from [Redirect URIs, CORS and CSP](../identity-provider.md#redirect-uris-cors-and-csp).
2. Select an **RSA signing key** for the provider. Without one Authentik signs tokens with HS256, which the gateway rejects. This is mandatory.
3. Use the client ID as the audience, which is the default. Make sure the access token is a JWT.
4. Create a group such as `hemlig-admins` and expose it in the `groups` claim.

```json
{
  "context": {
    "oidcIssuer": "https://auth.example.com/application/o/hemlig/",
    "oidcClientId": "AUTHENTIK_CLIENT_ID",
    "oidcAdminScope": "hemlig.admin",
    "oidcRoleClaim": "groups",
    "oidcAdminRole": "hemlig-admins"
  }
}
```

Verify in your tenant:

- whether access tokens carry a `scope` claim containing your admin scope, which the gateway requires;
- whether the token endpoint allows CORS for the console origin;
- the exact issuer string, including the trailing slash.

## Zitadel

1. Create a project and an application of type **User Agent** with PKCE, and set the auth token type to **JWT**.
2. Add the console redirect URIs and allow the console origin.
3. Define a project role such as `hemlig-admin`, grant it to users, and turn on **Assert roles on authentication** so the roles are in the token.

Zitadel emits roles as an object, `urn:zitadel:iam:org:project:roles`, whose keys are the role names. The Lambda uses the keys, so no mapping is needed.

```json
{
  "context": {
    "oidcIssuer": "https://zitadel.example.com",
    "oidcClientId": "ZITADEL_CLIENT_ID",
    "oidcAudience": "ZITADEL_PROJECT_ID",
    "oidcAdminScope": "hemlig.admin",
    "oidcRoleClaim": "urn:zitadel:iam:org:project:roles",
    "oidcAdminRole": "hemlig-admin"
  }
}
```

Verify in your tenant:

- the contents of `aud` in the JWT access token, so you can pick `oidcAudience`;
- whether the access token carries a `scope` claim with your admin scope;
- that the nested role object passes binding. The Lambda binds objects by key presence only.

## Cognito

1. Create a user pool app client of type **Public** with no secret, the authorization-code grant, and the console redirect URIs.
2. Create a resource server with an identifier and a scope `hemlig.admin`. The token's scope is the full `<identifier>/hemlig.admin`, so set `oidcAdminScope` to that string.
3. Create a user pool group such as `hemlig-admins` and add administrators to it.
4. Add the managed-login domain to `oidcProviderOrigins`: the token endpoint is on that host, not on the issuer's.

Cognito access tokens have no `aud`, only `client_id`. The Lambda and the gateway fall back to `client_id`, so the client ID works as the audience. Groups arrive in `cognito:groups`.

```json
{
  "context": {
    "oidcIssuer": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_EXAMPLE",
    "oidcClientId": "COGNITO_APP_CLIENT_ID",
    "oidcAdminScope": "hemlig-api/hemlig.admin",
    "oidcRoleClaim": "cognito:groups",
    "oidcAdminRole": "hemlig-admins",
    "oidcProviderOrigins": ["https://example.auth.us-east-1.amazoncognito.com"]
  }
}
```

Caveats:

- Discovery is believed to have no `end_session_endpoint`, in which case sign-out clears only the console session. Verify in your tenant.
- Whether the token endpoint allows CORS for a public client from the console origin: verify in your tenant.

## Next steps

- [Verify your token](../identity-provider.md#verify-your-token)
- [Troubleshoot sign-in and authorization](../identity-provider.md#troubleshoot-sign-in-and-authorization)
- [Host the console](../console.md)
